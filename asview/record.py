"""Running strace, and catching the tracee stopped to read /proc/<pid>/maps.

Syscalls describe changes, never the starting point: the executable, the
loader, the stack and the vdso are all placed by execve, which reports
nothing.  The only account of that state is /proc/<pid>/maps, and reading it
is a race unless the process is standing still.

strace can hold it still.  `--inject=execve:delay_exit=N` pauses the tracee
after execve returned and before it runs an instruction of the new program,
which is exactly the state we are missing.  strace cannot inject into the
first execve -- it performs that one itself, before tracing is established --
so the program is run through a one-line shell trampoline whose `exec` is a
second execve, and the shell is dropped from the output.

That is the whole mechanism, and one stop per exec is all it costs.  Without
it (`--no-baseline`, or no shell to run) the timeline starts from an empty
address space and shows only what the syscalls say.

Nothing here measures how long a stop lasted.  /proc/<pid>/auxv is rewritten
by every successful exec, so a change to it says the new image is in place --
and the delay is what guarantees we get to look before it moves.  The replay
then keeps a snapshot only if it lands on an execve, so anything read at some
other stop is discarded rather than guessed about.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass

from . import syscalls
from .replay import Snapshot

POLL_SECONDS = 0.002                 # only has to be shorter than the delay


@dataclass
class Options:
    baseline: bool = True            # hold the tracee after exec, and read maps
    delay_ms: int = 120
    strace: str = "strace"
    shell: str = "/bin/sh"
    keep_log: str | None = None
    extra_strace: tuple[str, ...] = ()


@dataclass
class Run:
    """What one traced execution produced."""

    log: str
    snapshots: list[Snapshot]
    argv: list[str]
    strace_argv: list[str]
    exit_code: int
    trampoline: bool                 # whether the shell is in the trace
    warnings: list[str]


def strace_version(strace: str = "strace") -> str | None:
    try:
        out = subprocess.run([strace, "--version"], capture_output=True, text=True)
    except OSError:
        return None
    return out.stdout.splitlines()[0].strip() if out.returncode == 0 else None


def build_command(argv: list[str], log: str, opts: Options,
                  trampoline: bool) -> list[str]:
    """The strace invocation, including the injections that give us a window."""
    cmd = [opts.strace, "-f", "-ttt", "-y", "-s", "512", "-o", log]
    cmd += ["-e", "trace=" + _trace_expression(opts.strace)]

    if trampoline:
        # Every exec after the first -- which is every exec of the program,
        # the trampoline having spent the one strace cannot pause at.
        cmd += [f"--inject={','.join(syscalls.DELAY_AT_EXIT)}"
                f":delay_exit={opts.delay_ms * 1000}:when=1+"]

    cmd += list(opts.extra_strace)
    cmd += ["--"]
    if trampoline:
        cmd += [opts.shell, "-c", 'exec "$0" "$@"']
    return cmd + argv


def run(argv: list[str], opts: Options) -> Run:
    """Trace `argv`, returning the log and every maps snapshot we caught."""
    warnings: list[str] = []
    trampoline = opts.baseline
    if trampoline and not os.path.exists(opts.shell):
        warnings.append(f"{opts.shell} is missing, so there is no exec to pause "
                        f"at: the timeline starts from an empty address space")
        trampoline = False
    if trampoline and not _can_read_maps():
        warnings.append("/proc is not readable: the timeline starts from an "
                        "empty address space")
        trampoline = False

    handle, log = tempfile.mkstemp(prefix="as-trace-", suffix=".strace")
    os.close(handle)
    command = build_command(argv, log, opts, trampoline)

    watcher = _Watcher() if trampoline else None
    proc = subprocess.Popen(command)
    if watcher is not None:
        watcher.start(proc.pid)
    code = proc.wait()
    if watcher is not None:
        watcher.stop()

    # A read taken while the tracee slipped away is dropped and tried again on
    # the next look, so watcher.torn is a retry rather than a loss; what a
    # missing baseline looks like is a space that never got one, which the
    # replay reports per address space.
    snapshots = watcher.snapshots if watcher is not None else []
    if trampoline and not snapshots:
        warnings.append(
            "no maps snapshot was caught: the timeline starts from an empty "
            "address space.  A very short-lived program can outrun the "
            "snapshot; try a larger --delay-ms")

    if opts.keep_log:
        shutil.copyfile(log, opts.keep_log)
    return Run(log=log, snapshots=snapshots, argv=argv, strace_argv=command,
               exit_code=code, trampoline=trampoline, warnings=warnings)


def _can_read_maps() -> bool:
    try:
        with open("/proc/self/maps"):
            return True
    except OSError:
        return False


def _trace_expression(strace: str) -> str:
    """The syscall set this strace will accept.

    A name it does not know is fatal, and which names it knows depends on both
    its version and the architecture -- mseal is recent, old_mmap only exists
    on some.  The '?' prefix asks it to skip the ones it cannot resolve; older
    versions have no such prefix, and older ones still are asked by class,
    which costs a noisier and slower trace but always works.
    """
    candidates = [
        ",".join("?" + name for name in syscalls.TRACED),
        ",".join(syscalls.TRACED),
        syscalls.TRACED_CLASSES,
    ]
    probe = shutil.which("true") or "/bin/true"
    if not os.path.exists(probe):
        return candidates[0]
    for expression in candidates:
        ok = subprocess.run(
            [strace, "-qq", "-e", f"trace={expression}", "-o", os.devnull, probe],
            capture_output=True)
        if ok.returncode == 0:
            return expression
    return syscalls.TRACED_CLASSES


class _Watcher:
    """Reads /proc/<pid>/maps of a tracee that has just replaced its image.

    The one thing it has to recognise is a new image, and auxv says so
    exactly: the kernel writes a fresh vector -- new AT_BASE, AT_ENTRY,
    AT_RANDOM -- onto the new stack for every successful exec.  Reading it is
    a few hundred bytes and needs no judgement about how long anything took.
    """

    def __init__(self) -> None:
        self.snapshots: list[Snapshot] = []
        self.torn = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._auxv: dict[int, bytes] = {}

    def start(self, strace_pid: int) -> None:
        self._thread = threading.Thread(target=self._loop, args=(strace_pid,),
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _loop(self, strace_pid: int) -> None:
        while not self._stop.is_set():
            for pid in _descendants(strace_pid):
                self._look(pid)
            time.sleep(POLL_SECONDS)

    def _look(self, pid: int) -> None:
        auxv = _read_bytes(pid, "auxv")
        if auxv is None or auxv == self._auxv.get(pid):
            return                            # same image as the last look
        if _state(pid) != "t":
            # Between execs, or an exec strace was not asked to pause at.  The
            # image is noted only once its maps have been read, so a window we
            # arrive at late is still taken when the process next stops.
            return

        # Before the read, not after: a tracee that resumes and stops again at
        # the next syscall still reads as 't', and a timestamp taken then would
        # anchor this snapshot to the following event instead of this one.
        when = time.time()
        text = _read(pid, "maps")
        if not text:
            return
        # Two identical reads while stopped: the file is a seq_file that only
        # holds the address space lock for one read at a time, so this is what
        # rules out a snapshot stitched from two different moments.
        if _state(pid) != "t" or _read(pid, "maps") != text:
            self.torn += 1
            return
        self._auxv[pid] = auxv
        self.snapshots.append(
            Snapshot(time=when, pid=pid, exe=_readlink(pid, "exe"), text=text))


def _descendants(pid: int) -> list[int]:
    out: list[int] = []
    frontier = [pid]
    while frontier:
        current = frontier.pop()
        for child in _children(current):
            if child not in out:
                out.append(child)
                frontier.append(child)
    return out


def _children(pid: int) -> list[int]:
    out: list[int] = []
    try:
        tasks = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return out
    for task in tasks:
        try:
            with open(f"/proc/{pid}/task/{task}/children") as fp:
                out += [int(x) for x in fp.read().split()]
        except OSError:
            continue
    return out


def _read(pid: int, what: str) -> str | None:
    try:
        with open(f"/proc/{pid}/{what}") as fp:
            return fp.read()
    except OSError:
        return None


def _read_bytes(pid: int, what: str) -> bytes | None:
    try:
        with open(f"/proc/{pid}/{what}", "rb") as fp:
            return fp.read()
    except OSError:
        return None


def _state(pid: int) -> str | None:
    """The one-letter state from /proc/<pid>/stat; 't' is a tracing stop."""
    return _state_of(f"/proc/{pid}/stat")


def _state_of(path: str) -> str | None:
    try:
        with open(path) as fp:
            data = fp.read()
    except OSError:
        return None
    # The command is in parentheses and can contain anything, spaces included.
    tail = data.rsplit(")", 1)
    return tail[1].split()[0] if len(tail) == 2 and tail[1].split() else None


def _readlink(pid: int, what: str) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/{what}")
    except OSError:
        return None
