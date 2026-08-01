"""Run a program with libdebug and turn syscall callbacks into replay records.

Unlike the strace backend, libdebug owns the ptrace stop.  ``run()`` returns
immediately after the target's first exec, before one instruction of the new
image has run, so the initial maps snapshot is a synchronous read rather than
a race against a delayed process.  Later successful execs are handled in the
same way from their syscall-exit callback.

The rest of the application deliberately does not know about libdebug.  This
module translates its architecture-neutral syscall registers into the small
``Record`` interface consumed by :mod:`asview.replay`; parse and summary keep
working exactly as they do on the strace branch.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import threading
import time
from dataclasses import dataclass
from importlib import metadata

from . import syscalls
from .replay import Snapshot
from .straceout import Record


@dataclass
class Options:
    baseline: bool = True


@dataclass
class Run:
    """What one libdebug session produced."""

    records: list[Record]
    snapshots: list[Snapshot]
    argv: list[str]
    exit_code: int
    warnings: list[str]


@dataclass
class _Entry:
    order: int
    pid: int
    time: float
    name: str
    args: list[str]
    values: tuple[int, ...]
    clone_flags: int = 0


def backend_version() -> str | None:
    """Return the installed libdebug version without importing the backend."""
    try:
        return metadata.version("libdebug")
    except metadata.PackageNotFoundError:
        return None


def run(argv: list[str], opts: Options) -> Run:
    """Trace ``argv`` until it and every followed child have exited."""
    try:
        from libdebug import debugger
    except ImportError as exc:  # pragma: no cover - exercised by the CLI
        raise RuntimeError(
            "libdebug is not installed; install requirements-libdebug.txt"
        ) from exc

    capture = _Capture(opts)
    _enable_vfork_following(capture._start_child)
    root = debugger(
        argv=list(argv),
        continue_to_binary_entrypoint=False,
        follow_children=True,
        kill_on_exit=True,
    )

    debuggers = []
    try:
        root.run(redirect_pipes=False)
        debuggers.append(root)
        capture.add_debugger(root)
        capture.initial(root, argv)
        capture.install(root)
        root.cont()

        # Child debuggers are installed and continued from the parent's fork
        # callback.  The list can grow while an earlier member is waiting.
        index = 0
        while index < len(capture.debuggers):
            current = capture.debuggers[index]
            current.wait()
            index += 1

        code = root.exit_code
        if code is None:
            number = root.threads[0].exit_signal if root.threads else None
            code = 128 + _signal_number(number) if number else 1
        return Run(
            records=capture.records(),
            snapshots=capture.snapshots,
            argv=list(argv),
            exit_code=code,
            warnings=capture.warnings,
        )
    finally:
        # terminate() also joins libdebug's per-process worker thread.  Do it
        # for children first because each child owns an independent debugger.
        for current in reversed(capture.debuggers or debuggers):
            try:
                current.terminate()
            except (ProcessLookupError, RuntimeError):
                pass


class _Capture:
    def __init__(self, opts: Options) -> None:
        self.opts = opts
        self.snapshots: list[Snapshot] = []
        self.warnings: list[str] = []
        self.debuggers: list = []
        self._debugger_pids: set[int] = set()
        self._pending: dict[int, _Entry] = {}
        self._records: list[tuple[float, Record]] = []
        self._next_order = 0
        self._lock = threading.RLock()

    def add_debugger(self, debugger) -> bool:
        with self._lock:
            if debugger.pid in self._debugger_pids:
                return False
            self._debugger_pids.add(debugger.pid)
            self.debuggers.append(debugger)
            return True

    def initial(self, debugger, argv: list[str]) -> None:
        """Synthesize the exec that libdebug's bootstrap stopped after."""
        when = time.time()
        args = [json.dumps(argv[0]), json.dumps(argv), "/* env */"]
        entry = _Entry(self._order(), debugger.pid, when, "execve", args, ())
        self._append(entry.order, _call(entry, 0))
        if self.opts.baseline:
            self._snapshot(debugger.pid, when)

    def install(self, debugger) -> None:
        """Install asynchronous handlers while this debugger is stopped."""
        for name in syscalls.TRACED:
            try:
                debugger.handle_syscall(
                    name,
                    on_enter=lambda thread, handler, name=name:
                        self._enter(name, thread),
                    on_exit=lambda thread, handler, name=name:
                        self._exit(name, thread),
                )
            except ValueError:
                # Syscall tables are architecture-specific.  The strace
                # implementation has the same notion of optional names.
                continue
        try:
            debugger.catch_signal("*", callback=self._signal)
        except ValueError:
            # Signals enrich the timeline but do not affect its layout.
            self.warnings.append("libdebug could not install the all-signal catcher")

    def _enter(self, name: str, thread) -> None:
        values = tuple(getattr(thread, f"syscall_arg{i}") for i in range(6))
        entry = _Entry(
            order=self._order(),
            pid=thread.tid,
            time=time.time(),
            name=name,
            args=_format_args(name, values, thread),
            values=values,
            clone_flags=_clone_flags(name, values, thread),
        )

        # exit and exit_group never have a syscall-exit stop.  They are the
        # only calls emitted on entry; the adjacent exit records give replay
        # the process-lifetime information strace would print separately.
        if name in ("exit", "exit_group"):
            self._append(entry.order, _call(entry, 0))
            threads = list(thread.debugger.threads) \
                if name == "exit_group" else [thread]
            for offset, member in enumerate(threads, 1):
                detail = f"exited with {values[0] & 0xff}"
                rec = Record(
                    kind="exit", pid=member.tid, time=entry.time,
                    raw=f"{member.tid} {entry.time:.9f} +++ {detail} +++",
                    detail=detail,
                )
                self._append(entry.order + offset / 1000, rec)
            return

        with self._lock:
            self._pending[thread.tid] = entry

    def _exit(self, name: str, thread) -> None:
        with self._lock:
            entry = self._pending.pop(thread.tid, None)
        if entry is None:
            return

        returned = _signed(thread.syscall_return, _word_bits(thread))
        self._append(entry.order, _call(entry, returned))

        if name in ("execve", "execveat") and returned == 0 and self.opts.baseline:
            self._snapshot(thread.pid, time.time())

        if returned > 0 and _creates_process(entry):
            self._start_child(thread.debugger, returned)

    def _start_child(self, parent, pid: int) -> None:
        child = next((item for item in parent.children if item.pid == pid), None)
        if child is None:
            self.warnings.append(
                f"libdebug did not expose debugger for child {pid}; "
                "its later syscalls are absent"
            )
            return
        if not self.add_debugger(child):
            return
        self.install(child)
        child.cont()

    def _signal(self, thread, catcher) -> None:
        number = thread.signal_number
        try:
            name = signal.Signals(number).name
        except (TypeError, ValueError):
            name = f"SIG{number}"
        when = time.time()
        detail = f"{{si_signo={name}}}"
        rec = Record(
            kind="signal", pid=thread.tid, time=when,
            raw=f"{thread.tid} {when:.9f} --- {name} {detail} ---",
            name=name, detail=detail,
        )
        self._append(self._order(), rec)

    def _snapshot(self, pid: int, when: float) -> None:
        try:
            with open(f"/proc/{pid}/maps") as fp:
                text = fp.read()
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError as exc:
            self.warnings.append(f"cannot snapshot /proc/{pid}/maps: {exc}")
            return
        self.snapshots.append(Snapshot(time=when, pid=pid, exe=exe, text=text))

    def _order(self) -> int:
        with self._lock:
            value = self._next_order
            self._next_order += 1
            return value

    def _append(self, order: float, record: Record) -> None:
        with self._lock:
            self._records.append((order, record))

    def records(self) -> list[Record]:
        with self._lock:
            ordered = sorted(
                self._records,
                key=lambda item: (
                    item[1].time if item[1].time is not None else 0,
                    item[0],
                ),
            )
        return [record for _, record in ordered]


def _call(entry: _Entry, returned: int) -> Record:
    error = errno.errorcode.get(-returned) if -4095 <= returned < 0 else None
    args_raw = ", ".join(entry.args)
    suffix = f" {error}" if error else ""
    raw = (
        f"{entry.pid} {entry.time:.9f} {entry.name}({args_raw}) "
        f"= {returned}{suffix}"
    )
    return Record(
        kind="call", pid=entry.pid, time=entry.time, raw=raw,
        name=entry.name, args=entry.args, args_raw=args_raw,
        ret_raw=f"{returned}{suffix}", ret=returned, error=error,
    )


def _format_args(name: str, values: tuple[int, ...], thread) -> list[str]:
    v = values
    bits = _word_bits(thread)

    def number(value: int) -> str:
        return str(_signed(value, bits))

    if name == "old_mmap":
        words = _read_words(thread, v[0], 6)
        if words is not None:
            v = tuple(words)
    if name in ("mmap", "mmap2", "old_mmap"):
        return [
            _pointer(v[0]), str(v[1]), _prot(v[2]), _map_flags(v[3]),
            _fd(thread.pid, _signed(v[4], bits)), hex(v[5]),
        ]
    if name in ("munmap", "mseal"):
        return [_pointer(v[0]), str(v[1])]
    if name == "mprotect":
        return [_pointer(v[0]), str(v[1]), _prot(v[2])]
    if name == "pkey_mprotect":
        return [_pointer(v[0]), str(v[1]), _prot(v[2]), number(v[3])]
    if name == "mremap":
        return [
            _pointer(v[0]), str(v[1]), str(v[2]),
            _mremap_flags(v[3]), _pointer(v[4]),
        ]
    if name == "brk":
        return [_pointer(v[0])]
    if name in ("shmget", "shmat", "shmdt", "shmctl"):
        return [
            number(value) if i == 0 else
            _pointer(value) if name == "shmat" and i == 1 else str(value)
            for i, value in enumerate(v[:3])
        ]
    if name == "map_shadow_stack":
        return [_pointer(v[0]), str(v[1]), hex(v[2])]
    if name in {
        "madvise", "process_madvise", "msync", "mlock", "mlock2",
        "munlock", "mlockall", "munlockall", "remap_file_pages",
    }:
        return [_pointer(v[0]), str(v[1]), hex(v[2]), hex(v[3]), hex(v[4])]
    if name == "prctl":
        first = "PR_SET_VMA" if v[0] == 0x53564D41 else hex(v[0])
        second = "PR_SET_VMA_ANON_NAME" \
            if first == "PR_SET_VMA" and v[1] == 0 else hex(v[1])
        fifth = _read_string(thread, v[4]) if first == "PR_SET_VMA" else _pointer(v[4])
        return [first, second, _pointer(v[2]), str(v[3]), fifth]
    if name == "arch_prctl":
        operation = {0x1001: "ARCH_SET_GS", 0x1002: "ARCH_SET_FS"}.get(v[0], hex(v[0]))
        return [operation, _pointer(v[1])]
    if name == "personality":
        return [hex(v[0])]
    if name == "execve":
        return [_read_string(thread, v[0]), _read_argv(thread, v[1]), "/* env */"]
    if name == "execveat":
        return [number(v[0]), _read_string(thread, v[1]), _read_argv(thread, v[2]),
                "/* env */", hex(v[4])]
    if name == "clone":
        return [f"flags={_clone_flag_names(v[0])}", f"child_stack={_pointer(v[1])}"]
    if name == "clone3":
        flags = _clone_flags(name, values, thread)
        return [f"{{flags={_clone_flag_names(flags)}}}", str(v[1])]
    if name in ("fork", "vfork"):
        return []
    if name in ("exit", "exit_group"):
        return [number(v[0])]
    if name in ("open", "creat"):
        return [_read_string(thread, v[0]), hex(v[1]), oct(v[2])]
    if name in ("openat", "openat2"):
        return [number(v[0]), _read_string(thread, v[1]), hex(v[2]), oct(v[3])]
    if name in ("memfd_create", "memfd_secret"):
        return [_read_string(thread, v[0]), hex(v[1])]
    if name in ("close", "dup", "dup2", "dup3", "fcntl", "fcntl64",
                "userfaultfd", "io_uring_setup", "pkey_alloc", "pkey_free"):
        return [number(value) for value in v[:3]]
    return [hex(value) for value in v]


def _word_bits(thread) -> int:
    return 32 if thread.debugger.arch == "i386" else 64


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    mask = (1 << bits) - 1
    value &= mask
    return value - (1 << bits) if value & sign else value


def _pointer(value: int) -> str:
    return "NULL" if value == 0 else hex(value)


def _read_string(thread, address: int, limit: int = 4096) -> str:
    if not address:
        return "NULL"
    try:
        data = bytes(thread.memory[address, limit, "absolute"])
        data = data.split(b"\0", 1)[0]
        return json.dumps(data.decode(errors="replace"))
    except (OSError, OverflowError, RuntimeError, ValueError):
        return _pointer(address)


def _read_argv(thread, address: int, limit: int = 256) -> str:
    if not address:
        return "NULL"
    width = _word_bits(thread) // 8
    out = []
    try:
        for index in range(limit):
            raw = thread.memory[address + index * width, width, "absolute"]
            pointer = int.from_bytes(raw, "little")
            if not pointer:
                break
            text = _read_string(thread, pointer)
            out.append(json.loads(text) if text.startswith('"') else text)
    except (OSError, OverflowError, RuntimeError, ValueError):
        pass
    return json.dumps(out) if out else _pointer(address)


def _read_words(thread, address: int, count: int) -> list[int] | None:
    width = _word_bits(thread) // 8
    try:
        data = thread.memory[address, count * width, "absolute"]
    except (OSError, OverflowError, RuntimeError, ValueError):
        return None
    return [
        int.from_bytes(data[i * width:(i + 1) * width], "little")
        for i in range(count)
    ]


def _fd(pid: int, fd: int) -> str:
    if fd < 0:
        return str(fd)
    try:
        path = os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        return str(fd)
    return f"{fd}<{path}>"


def _named_bits(value: int, names: list[tuple[int, str]]) -> str:
    out = []
    remaining = value
    for bit, name in names:
        if remaining & bit:
            out.append(name)
            remaining &= ~bit
    if remaining:
        out.append(hex(remaining))
    return "|".join(out) if out else "0"


def _prot(value: int) -> str:
    if value == 0:
        return "PROT_NONE"
    return _named_bits(value, [
        (1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC"),
        (8, "PROT_SEM"), (0x01000000, "PROT_GROWSDOWN"),
        (0x02000000, "PROT_GROWSUP"),
    ])


def _map_flags(value: int) -> str:
    sharing = value & 0x3
    out = {
        1: ["MAP_SHARED"], 2: ["MAP_PRIVATE"],
        3: ["MAP_SHARED_VALIDATE"],
    }.get(sharing, [])
    rest = value & ~0x3
    text = _named_bits(rest, [
        (0x10, "MAP_FIXED"), (0x20, "MAP_ANONYMOUS"), (0x40, "MAP_32BIT"),
        (0x100, "MAP_GROWSDOWN"), (0x800, "MAP_DENYWRITE"),
        (0x1000, "MAP_EXECUTABLE"), (0x2000, "MAP_LOCKED"),
        (0x4000, "MAP_NORESERVE"), (0x8000, "MAP_POPULATE"),
        (0x10000, "MAP_NONBLOCK"), (0x20000, "MAP_STACK"),
        (0x40000, "MAP_HUGETLB"), (0x80000, "MAP_SYNC"),
        (0x100000, "MAP_FIXED_NOREPLACE"),
    ])
    if text != "0":
        out += text.split("|")
    return "|".join(out) if out else "0"


def _mremap_flags(value: int) -> str:
    return _named_bits(value, [
        (1, "MREMAP_MAYMOVE"), (2, "MREMAP_FIXED"), (4, "MREMAP_DONTUNMAP"),
    ])


_CLONE_FLAGS = [
    (0x00000100, "CLONE_VM"), (0x00000200, "CLONE_FS"),
    (0x00000400, "CLONE_FILES"), (0x00000800, "CLONE_SIGHAND"),
    (0x00001000, "CLONE_PIDFD"), (0x00002000, "CLONE_PTRACE"),
    (0x00004000, "CLONE_VFORK"), (0x00008000, "CLONE_PARENT"),
    (0x00010000, "CLONE_THREAD"), (0x00020000, "CLONE_NEWNS"),
    (0x00040000, "CLONE_SYSVSEM"), (0x00080000, "CLONE_SETTLS"),
    (0x00100000, "CLONE_PARENT_SETTID"), (0x00200000, "CLONE_CHILD_CLEARTID"),
    (0x00400000, "CLONE_DETACHED"), (0x00800000, "CLONE_UNTRACED"),
    (0x01000000, "CLONE_CHILD_SETTID"), (0x02000000, "CLONE_NEWCGROUP"),
    (0x04000000, "CLONE_NEWUTS"), (0x08000000, "CLONE_NEWIPC"),
    (0x10000000, "CLONE_NEWUSER"), (0x20000000, "CLONE_NEWPID"),
    (0x40000000, "CLONE_NEWNET"), (0x80000000, "CLONE_IO"),
]


def _clone_flag_names(value: int) -> str:
    # The low byte is the exit signal rather than a clone flag.
    flags = _named_bits(value & ~0xff, _CLONE_FLAGS)
    exit_signal = value & 0xff
    if exit_signal:
        try:
            tail = signal.Signals(exit_signal).name
        except ValueError:
            tail = hex(exit_signal)
        return tail if flags == "0" else f"{flags}|{tail}"
    return flags


def _clone_flags(name: str, values: tuple[int, ...], thread) -> int:
    if name == "clone":
        return values[0]
    if name == "clone3":
        words = _read_words(thread, values[0], 1)
        return words[0] if words else 0
    return 0


def _creates_process(entry: _Entry) -> bool:
    if entry.name in ("fork", "vfork"):
        return True
    if entry.clone_flags & 0x4000:  # CLONE_VFORK has a separate task/debugger
        return True
    return entry.name in ("clone", "clone3") and not (
        entry.clone_flags & 0x100 or entry.clone_flags & 0x10000
    )


def _signal_number(value) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return signal.Signals[value].value
        except KeyError:
            pass
    return 0


_vfork_child_callback = None


def _enable_vfork_following(on_child) -> None:
    """Teach libdebug 0.9's process follower about PTRACE_EVENT_VFORK.

    Version 0.9 asks ptrace for vfork events but its Python status dispatcher
    handles only ordinary fork events.  A program using ``posix_spawn`` then
    leaves both sides stopped forever.  Keep this narrowly feature-detected:
    once upstream dispatches VFORK_EVENT itself, the shim is not installed.
    """
    global _vfork_child_callback

    import inspect

    _vfork_child_callback = on_child

    from libdebug.ptrace.ptrace_constants import StopEvents
    from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler
    from libdebug.state.resume_context import EventType

    original = PtraceStatusHandler._internal_signal_handler
    if getattr(original, "_asview_handles_vfork", False):
        return
    if "StopEvents.VFORK_EVENT" in inspect.getsource(original):
        return

    def with_vfork(self, pid, signum, results, status, thread):
        if signum == signal.SIGTRAP and status >> 8 == StopEvents.VFORK_EVENT:
            child_pid = self.ptrace_interface._get_event_msg(pid)
            follow = self.internal_debugger.follow_children
            self.ptrace_interface.lib_trace.detach_from_child(child_pid, follow)
            if follow:
                self.internal_debugger.set_child_debugger(child_pid)
                if _vfork_child_callback is not None:
                    _vfork_child_callback(self.internal_debugger.debugger, child_pid)
            self.forward_signal = False
            self.internal_debugger.resume_context.event_type[pid] = EventType.FORK
            return None
        return original(self, pid, signum, results, status, thread)

    with_vfork._asview_handles_vfork = True
    PtraceStatusHandler._internal_signal_handler = with_vfork
