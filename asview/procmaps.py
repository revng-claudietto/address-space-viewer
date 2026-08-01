"""/proc/<pid>/maps -> descriptors, for the state no syscall reports.

Used twice: for the address space execve produced, which is where every trace
starts, and for checking the reconstruction against the kernel at any later
point we manage to catch the tracee stopped.
"""

from __future__ import annotations

import re

from . import space, syscalls

_LINE = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+"
    r"(?P<perms>[-rwxsp]{4})\s+"
    r"(?P<offset>[0-9a-f]+)\s+"
    r"(?P<dev>[0-9a-f]+:[0-9a-f]+)\s+"
    r"(?P<inode>\d+)\s*"
    r"(?P<path>.*)$"
)

# Names the kernel gives to mappings that have no file behind them.
KINDS = {
    "[heap]": "heap",
    "[stack]": "stack",
    "[vdso]": "vdso",
    "[vvar]": "vvar",
    "[vvar_vclock]": "vvar",
    "[vsyscall]": "vsyscall",
    "[uprobes]": "special",
    "[sigpage]": "special",
}


def parse(text: str) -> list[space.Desc]:
    out = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        out.append(_desc(m))
    out.sort(key=lambda d: d.start)
    return out


def _desc(m: re.Match) -> space.Desc:
    perms = m.group("perms")
    prot = 0
    if perms[0] == "r":
        prot |= syscalls.PROT_READ
    if perms[1] == "w":
        prot |= syscalls.PROT_WRITE
    if perms[2] == "x":
        prot |= syscalls.PROT_EXEC

    path = m.group("path").strip() or None
    name = None
    kind = "anon"
    if path in KINDS:
        kind, name, path = KINDS[path], path, None
    elif path and path.startswith("[anon:"):            # PR_SET_VMA_ANON_NAME
        name, path = path[len("[anon:"):-1], None
    elif path and path.startswith("[anon_shmem:"):
        name, path, kind = path[len("[anon_shmem:"):-1], None, "shm"
    elif path and path.startswith("/SYSV"):
        kind = "shm"
    elif path:
        kind = "file"

    return space.Desc(
        start=int(m.group("start"), 16),
        end=int(m.group("end"), 16),
        prot=prot,
        shared=perms[3] == "s",
        path=path,
        offset=int(m.group("offset"), 16),
        name=name,
        kind=kind,
    )


def compare(model: list[space.Desc], kernel: list[space.Desc]) -> dict:
    """Where the reconstruction and the kernel disagree.

    Both sides are merged the same way first, so a difference in how eagerly
    neighbouring VMAs are coalesced does not show up as a difference in the
    layout.  Two disagreements are expected rather than wrong:

      * the stack grows on page faults, which no syscall reports, so the
        kernel's [stack] usually starts lower than ours;
      * a file unlinked after being mapped gains a " (deleted)" suffix.
    """
    ours = space.merge(model)
    theirs = space.merge(kernel)

    expected, differences = [], []
    for a, b in _pair(ours, theirs):
        if a is not None and b is not None and _same(a, b):
            continue
        entry = {"model": a.to_json() if a else None,
                 "kernel": b.to_json() if b else None}
        (expected if _is_expected(a, b) else differences).append(entry)

    return {
        "match": not differences,
        "regions": {"model": len(ours), "kernel": len(theirs)},
        "differences": differences,
        "expected_differences": expected,
    }


def _pair(ours, theirs):
    """Line the two layouts up: by start address, then by end address.

    The second pass is what keeps a stack that grew downwards from being
    reported as one region missing and one unexpected.
    """
    left = {d.start: d for d in ours}
    right = {d.start: d for d in theirs}
    pairs = [(left.pop(s), right.pop(s)) for s in sorted(set(left) & set(right))]

    by_end_left = {d.end: d for d in left.values()}
    by_end_right = {d.end: d for d in right.values()}
    for end in sorted(set(by_end_left) & set(by_end_right)):
        a, b = by_end_left[end], by_end_right[end]
        del left[a.start], right[b.start]
        pairs.append((a, b))

    pairs += [(d, None) for d in left.values()]
    pairs += [(None, d) for d in right.values()]
    return sorted(pairs, key=lambda p: (p[0] or p[1]).start)


def _same(a: space.Desc, b: space.Desc) -> bool:
    if (a.start, a.end, a.prot, a.shared) != (b.start, b.end, b.prot, b.shared):
        return False
    if _path(a) != _path(b):
        return False
    if a.path and a.offset != b.offset:
        return False
    return True


def _path(d: space.Desc) -> str | None:
    if d.path is None:
        return d.name
    return d.path.removesuffix(" (deleted)")


def _is_expected(a: space.Desc | None, b: space.Desc | None) -> bool:
    """Differences that follow from what a syscall trace cannot see."""
    if a is None or b is None:
        return False
    if (a.kind == "stack" or b.kind == "stack") and a.end == b.end:
        return True                          # grown downwards by page faults
    if a.path and b.path and _path(a) == _path(b) and a.path != b.path:
        return True                          # the file was unlinked meanwhile
    return False
