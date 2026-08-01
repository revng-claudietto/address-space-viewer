"""The address space: what a region is, and what the syscalls do to one.

A layout is a list of `Desc`, sorted by address and never overlapping.  Every
operation is a pure function from one such list to another, which keeps the
kernel's semantics (mmap replaces whatever was there, mprotect splits a VMA in
three, munmap can punch a hole) in one readable place.

Identity is layered on top by `AddressSpace`: after each operation the new
layout is matched against the old one, descriptors that did not change keep
their region id, and the ones that did are reported as a removed/added pair.
That is what lets a viewer animate a region rather than redraw everything, and
it is why splitting off `Desc` from `Region` is worth the extra type.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from . import syscalls

PAGE_SIZE = 4096


def set_page_size(size: int) -> None:
    global PAGE_SIZE
    PAGE_SIZE = size


def page_up(value: int) -> int:
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def page_down(value: int) -> int:
    return value & ~(PAGE_SIZE - 1)


@dataclass(frozen=True)
class Desc:
    """A region, by value.  Two equal descs are the same mapping."""

    start: int
    end: int
    prot: int
    shared: bool = False
    path: str | None = None
    offset: int = 0
    name: str | None = None          # [heap], or a PR_SET_VMA_ANON_NAME
    kind: str = "anon"               # file anon heap stack vdso vvar shm ...
    flags: tuple[str, ...] = ()      # the sticky MAP_* only
    sealed: bool = False

    @property
    def size(self) -> int:
        return self.end - self.start

    def to_json(self) -> dict:
        out = {
            "start": hex(self.start),
            "end": hex(self.end),
            "size": self.size,
            "prot": syscalls.prot_string(self.prot),
            "shared": self.shared,
            "kind": self.kind,
        }
        if self.path:
            out["path"] = self.path
            out["offset"] = hex(self.offset)
        if self.name:
            out["name"] = self.name
        if self.flags:
            out["flags"] = list(self.flags)
        if self.sealed:
            out["sealed"] = True
        return out


@dataclass(frozen=True)
class Region:
    """A desc with an identity, so a viewer can follow it over time."""

    id: str
    desc: Desc
    since: int = 0                   # event that produced it
    origin: tuple[str, ...] = ()     # regions it came from

    def to_json(self) -> dict:
        out = {"id": self.id}
        out.update(self.desc.to_json())
        out["since"] = self.since
        if self.origin:
            out["origin"] = list(self.origin)
        return out


# --------------------------------------------------------------------------- #
# Operations on a layout.
# --------------------------------------------------------------------------- #

def carve(layout: list[Desc], start: int, end: int) -> list[Desc]:
    """Remove [start, end).  Overlapped regions are trimmed or split."""
    if end <= start:
        return list(layout)
    out = []
    for d in layout:
        if d.end <= start or d.start >= end:
            out.append(d)
            continue
        if d.start < start:
            out.append(replace(d, end=start))
        if d.end > end:
            out.append(replace(d, start=end, offset=_advance(d, end)))
    return out


def place(layout: list[Desc], d: Desc) -> list[Desc]:
    """mmap: whatever was under [d.start, d.end) is gone."""
    if d.size <= 0:
        return list(layout)
    out = carve(layout, d.start, d.end)
    out.append(d)
    out.sort(key=lambda x: x.start)
    return out


def transform(layout: list[Desc], start: int, end: int, fn) -> list[Desc]:
    """Apply `fn` to the part of each region inside [start, end)."""
    if end <= start:
        return list(layout)
    out = []
    for d in layout:
        if d.end <= start or d.start >= end:
            out.append(d)
            continue
        lo, hi = max(d.start, start), min(d.end, end)
        if d.start < lo:
            out.append(replace(d, end=lo))
        middle = replace(d, start=lo, end=hi, offset=_advance(d, lo))
        out.append(fn(middle))
        if d.end > hi:
            out.append(replace(d, start=hi, offset=_advance(d, hi)))
    out.sort(key=lambda x: x.start)
    return out


def merge(layout: list[Desc]) -> list[Desc]:
    """Coalesce neighbours the kernel would keep as a single VMA.

    An approximation of vma_merge(): it does not model anon_vma reuse, so two
    private anonymous mappings that the kernel keeps apart may be shown as one.
    Everything else that distinguishes two VMAs is compared.
    """
    out: list[Desc] = []
    for d in sorted(layout, key=lambda x: x.start):
        if out and _mergeable(out[-1], d):
            out[-1] = replace(out[-1], end=d.end)
        else:
            out.append(d)
    return out


def _mergeable(a: Desc, b: Desc) -> bool:
    if a.end != b.start:
        return False
    if (a.prot, a.shared, a.name, a.kind, a.flags, a.sealed) != \
       (b.prot, b.shared, b.name, b.kind, b.flags, b.sealed):
        return False
    if a.path != b.path:
        return False
    if a.path is not None and a.offset + a.size != b.offset:
        return False
    return True


def _advance(d: Desc, addr: int) -> int:
    """The file offset at `addr`, for a region that starts earlier."""
    return d.offset + (addr - d.start) if d.path is not None else d.offset


def total_bytes(layout) -> int:
    return sum(d.size for d in layout)


# --------------------------------------------------------------------------- #
# Identity over time.
# --------------------------------------------------------------------------- #

class AddressSpace:
    """A layout plus stable region ids, and the deltas between the two."""

    def __init__(self, ident: str, allocate, merging: bool = True) -> None:
        self.id = ident
        self.regions: list[Region] = []
        self.merging = merging
        self._allocate = allocate            # () -> a fresh region id
        self.brk_base: int | None = None
        self.brk: int | None = None

    @property
    def layout(self) -> list[Desc]:
        return [r.desc for r in self.regions]

    def copy_into(self, other: "AddressSpace", seq: int) -> None:
        """fork: the child starts with the same layout, as its own regions."""
        other.regions = [
            Region(id=other._allocate(), desc=r.desc, since=seq, origin=(r.id,))
            for r in self.regions
        ]
        other.brk_base, other.brk = self.brk_base, self.brk

    def rebuild(self, layout: list[Desc], seq: int) -> tuple[list[str], list[Region]]:
        """Adopt `layout`, keeping ids where the descriptor is unchanged.

        Returns what changed: the ids that are gone and the regions that are
        new.  A region that only moved house within the list -- an mprotect of
        its middle, say -- comes back as one removal and up to three additions,
        each naming the old id in `origin`.
        """
        if self.merging:
            layout = merge(layout)
        layout = sorted(layout, key=lambda d: d.start)

        old = self.regions
        by_desc = {r.desc: r for r in old}
        kept: set[str] = set()
        new: list[Region] = []
        added: list[Region] = []

        for d in layout:
            keep = by_desc.get(d)
            if keep is not None and keep.id not in kept:
                kept.add(keep.id)
                new.append(keep)
                continue
            region = Region(id=self._allocate(), desc=d, since=seq,
                            origin=tuple(r.id for r in old
                                         if r.desc.start < d.end and d.start < r.desc.end))
            new.append(region)
            added.append(region)

        removed = [r.id for r in old if r.id not in kept]
        self.regions = new
        return removed, added
