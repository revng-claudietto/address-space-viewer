"""What the file behind a mapping says about itself.

A file-backed region is a window onto an ELF file, and the interesting
structure -- .text, .rodata, .data, .bss, the TLS template -- lives inside
that window.  For every path we see mapped we read the ELF once with
pyelftools and keep its segments and sections in one place; a region then
only has to say which object it belongs to and at what bias, and a viewer can
place every section itself with `bias + section.addr`.

The bias also reaches one region that has no file behind it: the tail of a
PT_LOAD whose memsz exceeds its filesz is mapped anonymously by the loader,
and that is where .bss ends up.  Recognising it is what makes .bss visible.

pyelftools is optional.  Without it the tool works exactly as before, minus
the `objects` section of the output.
"""

from __future__ import annotations

from dataclasses import dataclass

from .space import Desc, page_down

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import NoteSection
    HAVE_PYELFTOOLS = True
except ImportError:                                  # pragma: no cover
    ELFFile = None
    HAVE_PYELFTOOLS = False

SHF = [(0x4, "X"), (0x2, "A"), (0x1, "W"), (0x10, "M"), (0x20, "S"),
       (0x40, "I"), (0x200, "G"), (0x400, "T"), (0x100, "L")]


@dataclass
class _Object:
    json: dict
    loads: list[tuple[int, int, int, int]]           # offset filesz vaddr memsz


class Library:
    """Every ELF we were able to look at, by the path the mapping named."""

    def __init__(self, enabled: bool = True, all_sections: bool = False) -> None:
        self.enabled = enabled and HAVE_PYELFTOOLS
        self.all_sections = all_sections
        self.objects: dict[str, dict] = {}
        self.warnings: list[str] = []
        self._cache: dict[str, _Object | None] = {}

    def annotate(self, desc: Desc, layout: list[Desc]) -> dict:
        """The `object`/`bias` a region carries, if we can work them out."""
        if not self.enabled:
            return {}
        if desc.path is not None:
            obj = self._object(desc.path)
            if obj is None:
                return {}
            bias = _bias(obj, desc.offset, desc.start)
            return {} if bias is None else {"object": _key(desc.path), "bias": hex(bias)}
        return self._bss(desc, layout)

    def _bss(self, desc: Desc, layout: list[Desc]) -> dict:
        """An anonymous region right after a mapping, inside its memsz."""
        if desc.kind != "anon":
            return {}
        before = [d for d in layout if d.end == desc.start and d.path]
        for d in before:
            obj = self._object(d.path)
            if obj is None:
                continue
            bias = _bias(obj, d.offset, d.start)
            if bias is None:
                continue
            for _, filesz, vaddr, memsz in obj.loads:
                if memsz <= filesz:
                    continue
                if bias + vaddr + filesz <= desc.start < bias + vaddr + memsz:
                    return {"object": _key(d.path), "bias": hex(bias),
                            "zero_fill": True}
        return {}

    def _object(self, path: str) -> _Object | None:
        real = _key(path)
        if real in self._cache:
            return self._cache[real]
        obj = self._read(real)
        self._cache[real] = obj
        if obj is not None:
            self.objects[real] = obj.json
        return obj

    def _read(self, path: str) -> _Object | None:
        if not path.startswith("/"):
            return None
        try:
            fp = open(path, "rb")
        except OSError:
            return None
        with fp:
            try:
                if fp.read(4) != b"\x7fELF":
                    return None
                fp.seek(0)
                elf = ELFFile(fp)
                return _describe(elf, path, self.all_sections)
            except Exception as exc:                 # a truncated or odd ELF
                self.warnings.append(f"cannot read the ELF at {path}: {exc}")
                return None


def _key(path: str) -> str:
    return path.removesuffix(" (deleted)")


def _bias(obj: _Object, offset: int, start: int) -> int | None:
    """Where the object's address zero sits, given one of its windows.

    The kernel maps a PT_LOAD from page_down(p_offset) at page_down(p_vaddr),
    so that is the pair to reason with rather than the raw header values --
    which are not page aligned, and whose skew between offset and vaddr is
    what a linker's `-z separate-code` layout introduces.

    Two segments can share one file page, and then two of them contain the
    same offset; the later one owns the page in the mapping that starts there,
    so the candidate with the highest base offset wins.
    """
    best: tuple[int, int] | None = None
    for p_offset, filesz, vaddr, _ in obj.loads:
        base_offset, base_vaddr = page_down(p_offset), page_down(vaddr)
        if base_offset <= offset < max(p_offset + filesz, base_offset + 1):
            if best is None or base_offset > best[0]:
                best = (base_offset, base_vaddr)
    if best is None:
        return None
    return start - (best[1] + (offset - best[0]))


def _describe(elf: "ELFFile", path: str, all_sections: bool) -> _Object:
    loads: list[tuple[int, int, int, int]] = []
    segments = []
    interp = None
    for seg in elf.iter_segments():
        header = seg.header
        segments.append({
            "type": _segment_type(header.p_type),
            "flags": _prot(header.p_flags),
            "offset": hex(header.p_offset),
            "vaddr": hex(header.p_vaddr),
            "filesz": header.p_filesz,
            "memsz": header.p_memsz,
            "align": header.p_align,
        })
        if header.p_type == "PT_LOAD":
            loads.append((header.p_offset, header.p_filesz,
                          header.p_vaddr, header.p_memsz))
        elif header.p_type == "PT_INTERP":
            interp = seg.get_interp_name()

    sections = []
    for sec in elf.iter_sections():
        header = sec.header
        allocated = bool(header.sh_flags & 0x2)
        if not allocated and not all_sections:
            continue                                 # never part of an image
        sections.append({
            "name": sec.name,
            "type": str(header.sh_type),
            "flags": _section_flags(header.sh_flags),
            "addr": hex(header.sh_addr),
            "offset": hex(header.sh_offset),
            "size": header.sh_size,
        })

    json = {
        "path": path,
        "type": str(elf.header.e_type),
        "machine": str(elf.header.e_machine),
        "entry": hex(elf.header.e_entry),
        "segments": segments,
        "sections": sections,
    }
    if interp:
        json["interp"] = interp
    soname = _soname(elf)
    if soname:
        json["soname"] = soname
    build_id = _build_id(elf)
    if build_id:
        json["build_id"] = build_id
    return _Object(json=json, loads=loads)


def _soname(elf: "ELFFile") -> str | None:
    try:
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is None:
            return None
        for tag in dynamic.iter_tags("DT_SONAME"):
            return tag.soname
    except Exception:
        return None
    return None


def _build_id(elf: "ELFFile") -> str | None:
    try:
        for sec in elf.iter_sections():
            if not isinstance(sec, NoteSection):
                continue
            for note in sec.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    return note["n_desc"]
    except Exception:
        return None
    return None


def _segment_type(value) -> str:
    if isinstance(value, int):
        return hex(value)
    return str(value)


def _prot(flags: int) -> str:
    return ("r" if flags & 4 else "-") + \
           ("w" if flags & 2 else "-") + \
           ("x" if flags & 1 else "-")


def _section_flags(value: int) -> str:
    return "".join(letter for bit, letter in SHF if value & bit)
