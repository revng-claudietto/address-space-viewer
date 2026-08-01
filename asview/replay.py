"""Records and maps snapshots -> processes, address spaces and timed events.

The output is a replay: start from nothing, apply every event's delta in
order, and you have the address space at that point in time.  A snapshot of
/proc/<pid>/maps enters the timeline as the delta of the execve that created
the space, so the replay covers the state execve produced as well.

Where a snapshot lands relative to an event follows from strace's timestamps
being taken at syscall *entry*: a snapshot read while the tracee is held at
the entry of call E is the state *before* E, and one read while it is held at
the exit of an execve is the state *after* it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from . import elfinfo, procmaps, space, straceout, syscalls
from .space import Desc, Region, page_down, page_up
from .straceout import Record, descriptor, integer, keyword_args, quoted


@dataclass
class Snapshot:
    """A read of /proc/<pid>/maps, and where it belongs in the timeline."""

    time: float
    pid: int
    exe: str | None
    text: str
    supplied: bool = False           # handed to us, rather than read by us
    used: str = "unused"             # baseline | check | unused


@dataclass
class Space:
    id: str
    created_by: int                  # event seq
    reason: str                      # execve | fork | initial | unknown
    creator: int | None              # pid
    members: set = field(default_factory=set)   # everyone who ever used it
    live: set = field(default_factory=set)      # and who still does
    role: str = "target"             # target | trampoline
    baseline: str = "none"           # proc-maps | inherited | none
    destroyed_by: int | None = None
    peak_regions: int = 0
    peak_bytes: int = 0


@dataclass
class Proc:
    pid: int
    parent: int | None = None
    space: str | None = None
    exe: str | None = None
    argv: list | None = None
    thread_of: int | None = None     # tgid, when it shares an address space
    fds: dict = field(default_factory=dict)
    alive: bool = True
    exit: dict | None = None


class Machine:
    """Applies a trace to a model of the machine's address spaces."""

    def __init__(self, merging: bool = True, trampoline: bool = False,
                 elves: elfinfo.Library | None = None,
                 injected_delay: float = 0.0) -> None:
        self.spaces: dict[str, space.AddressSpace] = {}
        self.info: dict[str, Space] = {}
        self.procs: dict[int, Proc] = {}
        self.events: list[dict] = []
        self.warnings: list[str] = []
        self.checks: list[dict] = []
        self.merging = merging
        self.trampoline = trampoline
        self.elves = elves if elves is not None else elfinfo.Library(enabled=False)
        self.shm: dict[int, int] = {}          # shmid -> size, from shmget
        self.time_base: float | None = None
        self.root: int | None = None
        # Holding the tracee still is how we get to read its maps, but it also
        # stretches the trace.  Each stop covers a known interval, and what a
        # viewer animates has their union taken back out; `t_wall` keeps the
        # measured value for anyone who wants it.
        self.injected_delay = injected_delay
        self._stalls: list[tuple[float, float]] = []
        self._parentage: dict[int, tuple[int | None, Record]] = {}
        self._root_execs = 0
        self._seq = 0
        self._space_n = 0
        self._region_n = 0

    # -- ids ---------------------------------------------------------------- #

    def _new_region_id(self) -> str:
        self._region_n += 1
        return f"r{self._region_n}"

    def _new_space(self, reason: str, creator: int | None) -> str:
        ident = f"as{self._space_n}"
        self._space_n += 1
        self.spaces[ident] = space.AddressSpace(ident, self._new_region_id, self.merging)
        self.info[ident] = Space(id=ident, created_by=self._seq, reason=reason,
                                 creator=creator)
        return ident

    # -- driving ------------------------------------------------------------ #

    def run(self, records: list[Record], snapshots: list[Snapshot]) -> None:
        records = _clones_before_their_children(records)
        self._learn_pids(records)
        pending = sorted(snapshots, key=lambda s: s.time)

        for i, rec in enumerate(records):
            if rec.time is not None and self.time_base is None:
                self.time_base = rec.time
            before, after = self._due(pending, records, i)
            if before or after:
                # We only ever get to read maps because strace was told to
                # hold the tracee here, so this call took longer than it does
                # when nobody is watching.  strace marks most such lines, but
                # not one that never returns, like exit_group.
                rec.delayed = True
            for snap in before:
                self._snapshot(snap, where="before")
            self._record(rec)
            for snap in after:
                self._snapshot(snap, where="after")

        for snap in pending:
            if snap.used == "unused":
                self._snapshot(snap, where="after")

    def _learn_pids(self, records: list[Record]) -> None:
        for rec in records:
            if _spawn_of(rec) is not None:
                self._parentage.setdefault(rec.ret, (rec.pid, rec))
        # The root is the first process that nothing in the trace gave birth
        # to; taking the first line's pid instead would crown a child on a
        # trace that starts with one.
        self.root = next((rec.pid for rec in records
                          if rec.pid is not None and rec.pid not in self._parentage),
                         None)

    def _due(self, pending: list[Snapshot], records, i):
        """Snapshots anchored to record `i`, split by which side they go on."""
        rec = records[i]
        if rec.time is None:
            return [], []
        # The anchor of a snapshot is the last record of the same pid at or
        # before its timestamp; the tracee was held inside that call.
        nxt = next((r.time for r in records[i + 1:]
                    if r.pid == rec.pid and r.time is not None), None)
        before, after = [], []
        for snap in pending:
            if snap.used != "unused" or snap.pid != rec.pid:
                continue
            if snap.time < rec.time or (nxt is not None and snap.time >= nxt):
                continue
            if rec.name in ("execve", "execveat") and rec.ok:
                after.append(snap)          # the space the exec just built
            elif snap.supplied:
                before.append(snap)         # someone else vouches for it
            else:
                # Caught at some other stop.  Whether the call it is standing
                # in has run yet is not knowable from the trace, so there is
                # no point in time this describes.
                snap.used = "unplaceable"
        return before, after

    # -- one record --------------------------------------------------------- #

    def _record(self, rec: Record) -> None:
        if rec.kind == "note":
            return
        proc = self._proc(rec.pid)
        if rec.kind == "signal":
            self._signal(rec, proc)
            return
        if rec.kind == "exit":
            self._exited(rec, proc)
            return
        if rec.kind != "call":
            return
        if rec.unfinished:
            return                              # never returned: no effect known

        handler = HANDLERS.get(rec.name)
        if handler is None:
            self._fd_bookkeeping(rec, proc)
            return
        if rec.name in FD_ALSO:
            self._fd_bookkeeping(rec, proc)
        self._ensure_space(proc)
        handler(self, rec, proc)

    def _ensure_space(self, proc: Proc) -> str:
        """A process we thought was gone still has to have somewhere to live."""
        if proc.space is not None and proc.space in self.info:
            return proc.space
        proc.space = self._new_space("unknown", proc.pid)
        proc.alive = True
        self.info[proc.space].members.add(proc.pid)
        self.info[proc.space].live.add(proc.pid)
        self.warnings.append(
            f"pid {proc.pid} kept going after its address space was accounted "
            f"for; a new empty one was started for it")
        return proc.space

    def _proc(self, pid: int | None) -> Proc:
        if pid is None:
            pid = self.root if self.root is not None else 0
        proc = self.procs.get(pid)
        if proc is not None:
            return proc

        parent_pid, _ = self._parentage.get(pid, (None, None))
        proc = Proc(pid=pid, parent=parent_pid)
        self.procs[pid] = proc
        if proc.space is None:
            if parent_pid is not None and parent_pid in self.procs:
                # Seen before its clone was reported: attach to the parent's
                # space, which is right for a thread and corrected on the
                # clone record for a fork.
                proc.space = self.procs[parent_pid].space
            else:
                proc.space = self._new_space("unknown", pid)
                self.info[proc.space].baseline = "none"
                if self.root is not None and pid != self.root:
                    self.warnings.append(
                        f"pid {pid} appeared without a clone; its address space "
                        f"starts empty")
        self.info[proc.space].members.add(pid)
        self.info[proc.space].live.add(pid)
        return proc

    # -- events ------------------------------------------------------------- #

    def _event(self, rec: Record, proc: Proc, category: str, summary: str,
               space_id: str | None = None, **extra) -> dict:
        wall = round(rec.time - self.time_base, 6) \
            if rec.time is not None and self.time_base is not None else None
        ev = {
            "seq": self._seq,
            "t": wall,                          # made monotone in _settle_time
            "pid": proc.pid,
            "space": space_id or proc.space,
            "syscall": rec.name or None,
            "category": category,
            "summary": summary,
        }
        if rec.delayed:
            ev["delayed"] = True
            if wall is not None and self.injected_delay:
                self._stalls.append((wall, wall + self.injected_delay))
        if rec.error:
            ev["error"] = rec.error
            ev["ok"] = False
        ev.update({k: v for k, v in extra.items() if v is not None})
        ev["raw"] = rec.raw.strip()
        self._seq += 1
        self.events.append(ev)
        return ev

    def _apply(self, ev: dict, space_id: str, layout: list[Desc]) -> None:
        """Adopt a new layout for a space and attach the delta to `ev`."""
        as_ = self.spaces[space_id]
        removed, added = as_.rebuild(layout, ev["seq"])
        if removed or added:
            ev["delta"] = {"removed": removed, "added": self._regions(added, as_)}
        info = self.info[space_id]
        info.peak_regions = max(info.peak_regions, len(as_.regions))
        info.peak_bytes = max(info.peak_bytes, space.total_bytes(as_.layout))

    def _regions(self, regions: list[Region], as_: space.AddressSpace) -> list[dict]:
        """Serialise regions, each with the ELF object it is a window onto."""
        layout = as_.layout
        out = []
        for region in regions:
            entry = region.to_json()
            entry.update(self.elves.annotate(region.desc, layout))
            out.append(entry)
        return out

    # -- snapshots ---------------------------------------------------------- #

    def _snapshot(self, snap: Snapshot, where: str) -> None:
        proc = self.procs.get(snap.pid)
        if proc is None or proc.space is None:
            snap.used = "unused"
            return
        info = self.info[proc.space]
        as_ = self.spaces[proc.space]
        layout = procmaps.parse(snap.text)

        if info.baseline == "none" and not as_.regions:
            # The state execve produced: it belongs to the event that created
            # the space, not to a separate step in the timeline.
            snap.used = "baseline"
            info.baseline = "proc-maps"
            birth = next((e for e in self.events if e["seq"] == info.created_by), None)
            seq = birth["seq"] if birth else self._seq
            removed, added = as_.rebuild(layout, seq)
            if birth is not None and added:
                birth["delta"] = {"removed": removed,
                                  "added": self._regions(added, as_)}
                birth["baseline"] = "proc-maps"
            info.peak_regions = max(info.peak_regions, len(as_.regions))
            info.peak_bytes = max(info.peak_bytes, space.total_bytes(as_.layout))
            self._brk_from_maps(as_, layout)
            return

        if len(info.live) > 1:
            # More than one thread lives here, and strace prints one line per
            # thread as each call returns.  A read of the whole space cannot
            # be placed between two lines of one thread when another was
            # running: there is no single point in the timeline it describes.
            snap.used = "unplaceable"
            return

        # A second account of a space we have been keeping ourselves: worth
        # comparing, and worth saying so when the two disagree.
        snap.used = "check"
        result = procmaps.compare(as_.layout, layout)
        result.update({"t": round(snap.time - self.time_base, 6)
                       if self.time_base else snap.time,
                       "pid": snap.pid, "space": proc.space,
                       "at_event": self._seq, "where": where})
        self.checks.append(result)

    def _brk_from_maps(self, as_: space.AddressSpace, layout) -> None:
        heap = next((d for d in layout if d.kind == "heap"), None)
        if heap is not None:
            as_.brk_base, as_.brk = heap.start, heap.end

    # -- descriptors -------------------------------------------------------- #

    def _fd_bookkeeping(self, rec: Record, proc: Proc) -> None:
        """Only a fallback: with -y strace names the file on the mmap itself."""
        if not rec.ok or rec.ret is None or rec.ret < 0:
            return
        if rec.name in ("open", "creat"):
            proc.fds[rec.ret] = quoted(rec.args[0]) if rec.args else None
        elif rec.name in ("openat", "openat2"):
            proc.fds[rec.ret] = quoted(rec.args[1]) if len(rec.args) > 1 else None
        elif rec.name == "memfd_create":
            proc.fds[rec.ret] = f"/memfd:{quoted(rec.args[0])} (deleted)" if rec.args else None
        elif rec.name == "close":
            proc.fds.pop(integer(rec.args[0]) if rec.args else -1, None)
        elif rec.name in ("dup", "dup2", "dup3"):
            src, _ = descriptor(rec.args[0]) if rec.args else (None, None)
            if src in proc.fds:
                proc.fds[rec.ret] = proc.fds[src]
        if rec.ret_path:
            proc.fds[rec.ret] = rec.ret_path

    def _file(self, proc: Proc, arg: str) -> tuple[int | None, str | None]:
        fd, path = descriptor(arg)
        if path is None and fd is not None:
            path = proc.fds.get(fd)
        return fd, path

    # -- memory syscalls ---------------------------------------------------- #

    def do_mmap(self, rec: Record, proc: Proc) -> None:
        args = rec.args
        if len(args) < 6:
            return self._unparsed(rec, proc)
        prot = syscalls.prot_bits(args[2])
        flags = syscalls.flag_names(args[3])
        length = integer(args[1], 0) or 0
        fd, path = self._file(proc, args[4])
        offset = integer(args[5], 0) or 0
        if rec.name == "mmap2":
            offset *= space.PAGE_SIZE               # 32-bit: offset in pages
        anonymous = syscalls.is_anonymous(flags) or fd is None or fd < 0
        shared = syscalls.is_shared(flags)

        summary = (f"map {_bytes(length)} "
                   f"{'anonymous' if anonymous else path or 'file'} "
                   f"{syscalls.prot_string(prot)}{'s' if shared else 'p'}")
        ev = self._event(rec, proc, "map", summary, args={
            "addr": args[0], "length": length, "prot": args[2],
            "flags": args[3], "fd": fd, "path": None if anonymous else path,
            "offset": hex(offset),
        }, result=hex(rec.ret) if rec.ok and rec.ret is not None else None)
        if not rec.ok or rec.ret is None:
            return

        start = rec.ret
        desc = Desc(start=start, end=start + page_up(length), prot=prot,
                    shared=shared, path=None if anonymous else path,
                    offset=0 if anonymous else offset,
                    kind="anon" if anonymous else _kind_for(path),
                    flags=tuple(f for f in flags if f in syscalls.STICKY_MAP_FLAGS))
        as_ = self.spaces[proc.space]
        self._apply(ev, proc.space, space.place(as_.layout, desc))

    def do_munmap(self, rec: Record, proc: Proc) -> None:
        if len(rec.args) < 2:
            return self._unparsed(rec, proc)
        start = integer(rec.args[0], 0) or 0
        length = integer(rec.args[1], 0) or 0
        ev = self._event(rec, proc, "unmap",
                         f"unmap {_bytes(length)} at {hex(start)}",
                         args={"addr": hex(start), "length": length})
        if not rec.ok:
            return
        as_ = self.spaces[proc.space]
        self._apply(ev, proc.space,
                    space.carve(as_.layout, start, start + page_up(length)))

    def do_mprotect(self, rec: Record, proc: Proc) -> None:
        if len(rec.args) < 3:
            return self._unparsed(rec, proc)
        start = integer(rec.args[0], 0) or 0
        length = integer(rec.args[1], 0) or 0
        prot = syscalls.prot_bits(rec.args[2])
        pkey = integer(rec.args[3]) if rec.name == "pkey_mprotect" and len(rec.args) > 3 else None
        ev = self._event(rec, proc, "protect",
                         f"protect {_bytes(length)} at {hex(start)} "
                         f"as {syscalls.prot_string(prot)}",
                         args={"addr": hex(start), "length": length,
                               "prot": rec.args[2], "pkey": pkey})
        if not rec.ok:
            return
        as_ = self.spaces[proc.space]
        self._apply(ev, proc.space,
                    space.transform(as_.layout, start, start + page_up(length),
                                    lambda d: replace(d, prot=prot)))

    def do_mremap(self, rec: Record, proc: Proc) -> None:
        if len(rec.args) < 4:
            return self._unparsed(rec, proc)
        old_start = integer(rec.args[0], 0) or 0
        old_size = page_up(integer(rec.args[1], 0) or 0)
        new_size = page_up(integer(rec.args[2], 0) or 0)
        flags = syscalls.flag_names(rec.args[3])
        ev = self._event(rec, proc, "remap",
                         f"remap {_bytes(old_size)} at {hex(old_start)} "
                         f"to {_bytes(new_size)}",
                         args={"old_addr": hex(old_start), "old_size": old_size,
                               "new_size": new_size, "flags": rec.args[3]},
                         result=hex(rec.ret) if rec.ok and rec.ret is not None else None)
        if not rec.ok or rec.ret is None:
            return

        as_ = self.spaces[proc.space]
        layout = as_.layout
        source = next((d for d in layout if d.start <= old_start < d.end), None)
        if source is None:
            self.warnings.append(f"mremap of an unknown range at {hex(old_start)}")
            return
        new_start = rec.ret
        keep_old = old_size == 0 or syscalls.MREMAP_DONTUNMAP in flags
        if not keep_old:
            layout = space.carve(layout, old_start, old_start + old_size)
        moved = replace(source, start=new_start, end=new_start + new_size,
                        offset=source.offset + (old_start - source.start)
                        if source.path is not None else source.offset)
        self._apply(ev, proc.space, space.place(layout, moved))

    def do_brk(self, rec: Record, proc: Proc) -> None:
        as_ = self.spaces[proc.space]
        want = integer(rec.args[0], 0) if rec.args else 0
        asking = bool(want)
        ev = self._event(rec, proc, "brk",
                         f"break to {hex(want)}" if asking else "read the break",
                         args={"addr": hex(want or 0)},
                         result=hex(rec.ret) if rec.ok and rec.ret is not None else None)
        if not rec.ok or rec.ret is None:
            return
        if as_.brk_base is None:
            as_.brk_base = rec.ret if not asking else page_down(rec.ret)
        as_.brk = rec.ret
        if not asking:
            return

        base = as_.brk_base
        end = page_up(as_.brk)
        # The break can move either way, so clear the union of where the heap
        # was and where it is going before laying it down again.
        was = next((d for d in as_.layout if d.kind == "heap"), None)
        layout = space.carve(as_.layout, base, max(base, end, was.end if was else 0))
        if end > base:
            layout = space.place(layout, Desc(start=base, end=end,
                                              prot=syscalls.PROT_READ | syscalls.PROT_WRITE,
                                              name="[heap]", kind="heap"))
        self._apply(ev, proc.space, layout)

    def do_shmget(self, rec: Record, proc: Proc) -> None:
        if rec.ok and rec.ret is not None and len(rec.args) > 1:
            self.shm[rec.ret] = integer(rec.args[1], 0) or 0

    def do_shmat(self, rec: Record, proc: Proc) -> None:
        shmid = integer(rec.args[0], 0) if rec.args else None
        size = self.shm.get(shmid)
        ev = self._event(rec, proc, "map",
                         f"attach shm {shmid} ({_bytes(size or 0)})",
                         args={"shmid": shmid, "size": size},
                         result=hex(rec.ret) if rec.ok and rec.ret is not None else None)
        if not rec.ok or rec.ret is None:
            return
        if not size:
            self.warnings.append(
                f"shmat of segment {shmid} whose size was never seen; "
                f"the attachment is not shown")
            return
        desc = Desc(start=rec.ret, end=rec.ret + page_up(size),
                    prot=syscalls.PROT_READ | syscalls.PROT_WRITE, shared=True,
                    path=f"/SYSV{shmid:08x} (deleted)", kind="shm")
        self._apply(ev, proc.space, space.place(self.spaces[proc.space].layout, desc))

    def do_shmdt(self, rec: Record, proc: Proc) -> None:
        start = integer(rec.args[0], 0) if rec.args else 0
        ev = self._event(rec, proc, "unmap", f"detach shm at {hex(start or 0)}",
                         args={"addr": hex(start or 0)})
        if not rec.ok:
            return
        as_ = self.spaces[proc.space]
        found = next((d for d in as_.layout if d.start == start), None)
        if found is None:
            return
        self._apply(ev, proc.space, space.carve(as_.layout, found.start, found.end))

    def do_mseal(self, rec: Record, proc: Proc) -> None:
        if len(rec.args) < 2:
            return self._unparsed(rec, proc)
        start = integer(rec.args[0], 0) or 0
        length = page_up(integer(rec.args[1], 0) or 0)
        ev = self._event(rec, proc, "protect",
                         f"seal {_bytes(length)} at {hex(start)}",
                         args={"addr": hex(start), "length": length})
        if not rec.ok:
            return
        as_ = self.spaces[proc.space]
        self._apply(ev, proc.space,
                    space.transform(as_.layout, start, start + length,
                                    lambda d: replace(d, sealed=True)))

    def do_shadow_stack(self, rec: Record, proc: Proc) -> None:
        size = integer(rec.args[1], 0) if len(rec.args) > 1 else 0
        ev = self._event(rec, proc, "map", f"shadow stack of {_bytes(size or 0)}",
                         args={"size": size},
                         result=hex(rec.ret) if rec.ok and rec.ret is not None else None)
        if not rec.ok or rec.ret is None or not size:
            return
        desc = Desc(start=rec.ret, end=rec.ret + page_up(size),
                    prot=syscalls.PROT_READ | syscalls.PROT_WRITE,
                    kind="shadow-stack", name="[shadow stack]")
        self._apply(ev, proc.space, space.place(self.spaces[proc.space].layout, desc))

    def do_advice(self, rec: Record, proc: Proc) -> None:
        """madvise and friends: the range keeps its shape, not its contents."""
        start = integer(rec.args[0], 0) if rec.args else None
        length = integer(rec.args[1], 0) if len(rec.args) > 1 else None
        what = rec.args[2] if len(rec.args) > 2 else rec.name
        if rec.name in ("mlockall", "munlockall"):
            start, length, what = None, None, rec.args[0] if rec.args else ""
        self._event(rec, proc, "advise",
                    f"{rec.name} {what}" if length is None else
                    f"{rec.name} {_bytes(length)} at {hex(start or 0)}: {what}",
                    args={"addr": hex(start) if start is not None else None,
                          "length": length, "advice": what})

    def do_remap_file_pages(self, rec: Record, proc: Proc) -> None:
        self._event(rec, proc, "advise", "remap_file_pages (emulated by the kernel)",
                    args={"raw": rec.args_raw})
        if rec.ok:
            self.warnings.append(
                "remap_file_pages is emulated with an ordinary mmap by the "
                "kernel and its effect on the layout is not modelled")

    def do_prctl(self, rec: Record, proc: Proc) -> None:
        args = rec.args
        if not args or args[0] != "PR_SET_VMA":
            return
        if len(args) < 5 or args[1] != "PR_SET_VMA_ANON_NAME":
            return
        start = integer(args[2], 0) or 0
        length = page_up(integer(args[3], 0) or 0)
        name = quoted(args[4])
        ev = self._event(rec, proc, "annotate",
                         f"name {_bytes(length)} at {hex(start)} \"{name}\"",
                         args={"addr": hex(start), "length": length, "name": name})
        if not rec.ok:
            return
        as_ = self.spaces[proc.space]
        self._apply(ev, proc.space,
                    space.transform(as_.layout, start, start + length,
                                    lambda d: replace(d, name=name)))

    def do_arch_prctl(self, rec: Record, proc: Proc) -> None:
        if rec.args and rec.args[0] in ("ARCH_SET_FS", "ARCH_SET_GS"):
            self._event(rec, proc, "annotate",
                        f"{rec.args[0]} {rec.args[1] if len(rec.args) > 1 else ''}".strip(),
                        args={"what": rec.args[0],
                              "value": rec.args[1] if len(rec.args) > 1 else None})

    def do_personality(self, rec: Record, proc: Proc) -> None:
        self._event(rec, proc, "annotate", f"personality {rec.args_raw}",
                    args={"personality": rec.args_raw})

    # -- process syscalls --------------------------------------------------- #

    def do_execve(self, rec: Record, proc: Proc) -> None:
        if rec.name == "execveat":
            path = quoted(rec.args[1]) if len(rec.args) > 1 else None
            argv = rec.args[2] if len(rec.args) > 2 else None
        else:
            path = quoted(rec.args[0]) if rec.args else None
            argv = rec.args[1] if len(rec.args) > 1 else None

        if not rec.ok:
            self._event(rec, proc, "process", f"execve {path} failed",
                        args={"path": path})
            return

        old = proc.space
        info = self.info[old]
        info.live.discard(proc.pid)
        # The other threads of this process do not survive the exec.  Anyone
        # else sharing the space does: a vfork child exec'ing hands its
        # parent's address space back rather than destroying it.
        group = proc.thread_of or proc.pid
        for pid in list(info.live):
            other = self.procs.get(pid)
            if other is not None and (other.thread_of or other.pid) == group:
                other.alive = False
                other.space = None
                info.live.discard(pid)
        destroyed = []
        if not info.live:
            info.destroyed_by = self._seq
            destroyed = [old]

        new = self._new_space("execve", proc.pid)
        if proc.pid == self.root:
            self._root_execs += 1
        # The trampoline is the shell we inserted to get an execve that strace
        # can be made to pause at.  Its own address space, and the one it
        # inherited from strace's fork, are artefacts of how we measured.
        if self.trampoline and proc.pid == self.root and self._root_execs == 1:
            self.info[old].role = "trampoline"
            self.info[new].role = "trampoline"
        self.info[new].members.add(proc.pid)
        self.info[new].live.add(proc.pid)
        proc.space = new
        proc.exe = path
        proc.argv = argv
        proc.thread_of = None

        self._event(rec, proc, "process", f"execve {path}", space_id=new,
                    args={"path": path, "argv": argv},
                    space_created=new, space_destroyed=destroyed or None)

    def do_clone(self, rec: Record, proc: Proc) -> None:
        if not rec.ok or rec.ret is None or rec.ret <= 0:
            self._event(rec, proc, "process", f"{rec.name} failed",
                        args={"raw": rec.args_raw})
            return

        if rec.name == "clone3":
            fields = keyword_args(straceout.split_args(rec.args[0].strip("{}"))) \
                if rec.args else {}
        else:
            fields = keyword_args(rec.args)
        flags = fields.get("flags", "")
        shares_vm = syscalls.CLONE_VM in flags or rec.name == "vfork"

        child = Proc(pid=rec.ret, parent=proc.pid)
        self.procs[child.pid] = child
        child.exe, child.argv = proc.exe, proc.argv
        child.fds = proc.fds if syscalls.CLONE_FILES in flags else dict(proc.fds)

        if shares_vm:
            child.space = proc.space
            child.thread_of = (proc.thread_of or proc.pid) \
                if syscalls.CLONE_THREAD in flags else None
            self.info[proc.space].members.add(child.pid)
            self.info[proc.space].live.add(child.pid)
            kind = "thread" if syscalls.CLONE_THREAD in flags else \
                   ("vfork" if rec.name == "vfork" else "process sharing the space")
            self._event(rec, proc, "process", f"{rec.name}: {kind} {child.pid}",
                        args={"child": child.pid, "flags": flags or None,
                              "shares_space": True})
            return

        new = self._new_space("fork", proc.pid)
        child.space = new
        self.info[new].members.add(child.pid)
        self.info[new].live.add(child.pid)
        self.info[new].baseline = "inherited"
        ev = self._event(rec, proc, "process",
                         f"{rec.name}: copy of the space for {child.pid}",
                         space_id=new,
                         args={"child": child.pid, "flags": flags or None,
                               "shares_space": False},
                         space_created=new, forked_from=proc.space)
        self.spaces[proc.space].copy_into(self.spaces[new], ev["seq"])
        ev["delta"] = {"removed": [],
                       "added": self._regions(self.spaces[new].regions,
                                              self.spaces[new])}
        self.info[new].peak_regions = len(self.spaces[new].regions)
        self.info[new].peak_bytes = space.total_bytes(self.spaces[new].layout)

    def do_exit(self, rec: Record, proc: Proc) -> None:
        status = integer(rec.args[0], 0) if rec.args else 0
        self._event(rec, proc, "process",
                    f"{rec.name}({status})", args={"status": status})

    def _exited(self, rec: Record, proc: Proc) -> None:
        proc.alive = False
        proc.exit = {"detail": rec.detail}
        ev = self._event(rec, proc, "process", rec.detail)
        old = proc.space
        if old is None:
            return
        info = self.info[old]
        info.live.discard(proc.pid)
        if not info.live:
            info.destroyed_by = ev["seq"]
            ev["space_destroyed"] = [old]
        proc.space = None

    def _signal(self, rec: Record, proc: Proc) -> None:
        detail = rec.detail
        addr = None
        for part in detail.replace("{", "").replace("}", "").split(","):
            key, sep, value = part.partition("=")
            if sep and key.strip() == "si_addr":
                addr = value.strip()
        self._event(rec, proc, "signal", f"{rec.name}{' at ' + addr if addr else ''}",
                    args={"signal": rec.name, "si_addr": addr, "detail": detail})

    def _unparsed(self, rec: Record, proc: Proc) -> None:
        self.warnings.append(f"line {rec.line}: cannot read {rec.name} arguments")
        self._event(rec, proc, "other", f"{rec.name} (arguments not understood)")

    # -- result ------------------------------------------------------------- #

    def document(self, extra: dict) -> dict:
        from . import SCHEMA, __version__

        for info in self.info.values() if self.trampoline else ():
            if info.reason == "execve" and info.baseline == "none" \
                    and info.role == "target":
                self.warnings.append(
                    f"{info.id} has no starting layout: what execve gave pid "
                    f"{info.creator} was not read in time, so its regions "
                    f"begin at whatever the syscalls map next")

        if self.trampoline and self._root_execs < 2:
            self.warnings.append(
                "the trampoline never reached the program: nothing was traced. "
                "Check the command, or use --baseline stop")

        hidden = {i.id for i in self.info.values() if i.role == "trampoline"}
        # strace's own child has an address space before it execs the program;
        # it is a copy of strace's, nothing happens in it, and it is gone by
        # the first line of the trace.
        touched = {e["space"] for e in self.events}
        hidden |= {i.id for i in self.info.values()
                   if i.peak_regions == 0 and i.id not in touched}
        events = [e for e in self.events if e["space"] not in hidden]
        for ev in events:
            ev["space_destroyed"] = [s for s in ev.get("space_destroyed", [])
                                     if s not in hidden] or None
            if ev["space_destroyed"] is None:
                ev.pop("space_destroyed", None)
        self.checks = [c for c in self.checks if c["space"] not in hidden]
        base = self._settle_time(events)

        doc = {
            "schema": SCHEMA,
            "generator": {"tool": "as-trace", "version": __version__},
            "page_size": space.PAGE_SIZE,
            "time_base": base,
            "processes": [self._proc_json(p) for p in
                          sorted(self.procs.values(), key=lambda p: p.pid)],
            "spaces": [self._space_json(i) for i in self.info.values()
                       if i.id not in hidden],
            "objects": self.elves.objects,
            "events": events,
            "checks": self.checks,
            "warnings": self.warnings + self.elves.warnings,
        }
        doc.update(extra)
        _renumber(doc)
        return doc

    def _settle_time(self, events: list[dict]) -> float | None:
        """Take our own stops back out of the timeline, and rebase it.

        The stops overlap when several processes are held at once, so what is
        subtracted is the union of their intervals rather than their sum: the
        result stays ordered the way the trace was, which a timeline shared by
        every process has to be.  Zero is then moved to the first event that
        survived -- with a trampoline the shell's startup is not shown, and a
        timeline starting before anything it shows would be a strange thing to
        hand to an animation.
        """
        stalls = _union(self._stalls)

        def stalled_by(when: float) -> float:
            return sum(max(0.0, min(end, when) - start) for start, end in stalls)

        for ev in events:
            if ev.get("t") is None:
                continue
            wall = ev["t"]
            ev["t"] = round(wall - stalled_by(wall), 6)
            if wall != ev["t"]:
                ev["t_wall"] = wall
        for check in self.checks:
            if check.get("t") is not None:
                check["t"] = round(check["t"] - stalled_by(check["t"]), 6)

        first = next((e["t"] for e in events if e.get("t") is not None), None)
        if not first:
            return self.time_base
        for ev in events:
            for key in ("t", "t_wall"):
                if ev.get(key) is not None:
                    ev[key] = round(ev[key] - first, 6)
        for check in self.checks:
            if check.get("t") is not None:
                check["t"] = round(check["t"] - first, 6)
        return None if self.time_base is None else round(self.time_base + first, 6)

    def _proc_json(self, p: Proc) -> dict:
        out = {"pid": p.pid, "parent": p.parent, "exe": p.exe}
        if p.argv:
            out["argv"] = p.argv
        if p.thread_of is not None:
            out["thread_of"] = p.thread_of
        if p.exit:
            out["exit"] = p.exit["detail"]
        return out

    def _space_json(self, i: Space) -> dict:
        as_ = self.spaces[i.id]
        return {
            "id": i.id,
            "created_by": i.created_by,
            "reason": i.reason,
            "creator": i.creator,
            "baseline": i.baseline,
            "destroyed_by": i.destroyed_by,
            "members": sorted(i.members),
            "peak_regions": i.peak_regions,
            "peak_bytes": i.peak_bytes,
            "final_regions": self._regions(as_.regions, as_),
        }


SPAWNS = ("clone", "clone3", "fork", "vfork")


def _spawn_of(rec: Record) -> int | None:
    """The pid a record brought into the world, if it is that kind of record."""
    if rec.kind != "call" or rec.name not in SPAWNS or not rec.ok:
        return None
    return rec.ret if rec.ret and rec.ret > 0 else None


def _clones_before_their_children(records: list[Record]) -> list[Record]:
    """Put a clone ahead of the child it produced.

    strace prints a line when the call returns, and the child is off running
    before the parent gets there: with -f the child's first syscalls are
    printed between the parent's `<unfinished ...>` and its `resumed`.  Read
    in that order a process would appear from nowhere, so the clone is moved
    back to just before the first line of its child -- which is also where the
    entry timestamps say it belongs.
    """
    first: dict[int, int] = {}
    for index, rec in enumerate(records):
        if rec.pid is not None:
            first.setdefault(rec.pid, index)

    order: list[float] = list(range(len(records)))
    moved = False
    for index, rec in enumerate(records):
        child = _spawn_of(rec)
        born = first.get(child) if child is not None else None
        if born is not None and born < index:
            order[index] = born - 0.5
            moved = True
    if not moved:
        return records
    return [records[i] for i in sorted(range(len(records)), key=order.__getitem__)]


def _union(intervals: list[tuple[float, float]]) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def _renumber(doc: dict) -> None:
    """Close the gaps the dropped events left, so `seq` is also an index.

    Everything that points at an event -- when a region appeared, when a space
    was created or destroyed, where a check was taken -- is rewritten with it.
    """
    mapping = {ev["seq"]: i for i, ev in enumerate(doc["events"])}

    def fix(value: int | None) -> int | None:
        return None if value is None else mapping.get(value)

    for index, ev in enumerate(doc["events"]):
        ev["seq"] = index
        for region in (ev.get("delta") or {}).get("added", []):
            region["since"] = fix(region["since"])
    for sp in doc["spaces"]:
        sp["created_by"] = fix(sp["created_by"])
        sp["destroyed_by"] = fix(sp["destroyed_by"])
        for region in sp["final_regions"]:
            region["since"] = fix(region["since"])
    for check in doc["checks"]:
        check["at_event"] = fix(check["at_event"])


def _kind_for(path: str | None) -> str:
    if not path:
        return "anon"
    if path.startswith("/SYSV"):
        return "shm"
    if path.startswith("/memfd:") or path.startswith("/dev/shm/"):
        return "shm"
    if path.startswith("anon_inode:"):
        return "special"
    return "file"


def _bytes(n: int | None) -> str:
    if n is None:
        return "?"
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f}".rstrip("0").rstrip(".") + f" {unit}"
        size /= 1024
    return f"{n} B"


HANDLERS = {
    "mmap": Machine.do_mmap, "mmap2": Machine.do_mmap, "old_mmap": Machine.do_mmap,
    "munmap": Machine.do_munmap,
    "mprotect": Machine.do_mprotect, "pkey_mprotect": Machine.do_mprotect,
    "mremap": Machine.do_mremap,
    "brk": Machine.do_brk,
    "mseal": Machine.do_mseal,
    "map_shadow_stack": Machine.do_shadow_stack,
    "shmget": Machine.do_shmget, "shmat": Machine.do_shmat, "shmdt": Machine.do_shmdt,
    "madvise": Machine.do_advice, "process_madvise": Machine.do_advice,
    "msync": Machine.do_advice,
    "mlock": Machine.do_advice, "mlock2": Machine.do_advice,
    "munlock": Machine.do_advice,
    "mlockall": Machine.do_advice, "munlockall": Machine.do_advice,
    "remap_file_pages": Machine.do_remap_file_pages,
    "execve": Machine.do_execve, "execveat": Machine.do_execve,
    "clone": Machine.do_clone, "clone3": Machine.do_clone,
    "fork": Machine.do_clone, "vfork": Machine.do_clone,
    "exit": Machine.do_exit, "exit_group": Machine.do_exit,
    "prctl": Machine.do_prctl, "arch_prctl": Machine.do_arch_prctl,
    "personality": Machine.do_personality,
}

# Handled above, but their result also names a descriptor.
FD_ALSO = {"memfd_create"}
