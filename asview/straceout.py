"""strace's text output -> structured records.

Written against `strace -f -ttt -y`, which prefixes every line with a pid and a
unix timestamp and decorates file descriptors with their path.  The timestamp
is taken when the syscall is *entered* (verified against an injected delay:
the delay shows up in the gap to the next line, not in this line's stamp).

The parser never raises on a line it does not understand -- an odd line becomes
a record of kind "other" and the caller decides.  Traces are gathered from
programs we do not control; refusing to produce a timeline because of one
strange line is not a useful behaviour.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Record:
    """One thing that happened, as strace reported it."""

    kind: str                       # call | signal | exit | note | other
    pid: int | None
    time: float | None
    raw: str
    name: str = ""                  # syscall or signal name
    args: list[str] = field(default_factory=list)
    args_raw: str = ""
    ret_raw: str | None = None      # everything right of the '='
    ret: int | None = None          # the numeric part, when there is one
    ret_path: str | None = None     # -y decoration on a returned descriptor
    error: str | None = None        # ENOENT, ERESTARTSYS, ...
    detail: str = ""                # signal payload, exit reason, note text
    unfinished: bool = False        # never resumed (the process died first)
    delayed: bool = False           # strace held the tracee here on our behalf
    line: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None and self.ret is not None


_HEAD = re.compile(r"^(?:(?P<pid>\d+)\s+)?(?:(?P<time>\d+\.\d+|\d+:\d+:\d+\.\d+)\s+)?(?P<rest>.*)$")
_CALL = re.compile(r"^(?P<name>[a-zA-Z_][\w:]*)\((?P<args>.*)\)\s*=\s*(?P<ret>.*)$", re.S)
_START = re.compile(r"^(?P<name>[a-zA-Z_][\w:]*)\((?P<args>.*?)\s*<unfinished \.\.\.>$")
_RESUME = re.compile(r"^<\.\.\.\s*(?P<name>[a-zA-Z_][\w:]*)\s*resumed>\s*(?P<rest>.*)$")
_SIGNAL = re.compile(r"^---\s*(?P<name>\w+)\s*(?P<detail>.*?)\s*---$")
_EXIT = re.compile(r"^\+\+\+\s*(?P<detail>.*?)\s*\+\+\+$")
_RET = re.compile(
    r"^(?P<val>-?\d+|0x[0-9a-fA-F]+|\?)"
    r"(?:<(?P<path>[^>]*)>)?"
    r"(?:\s+(?P<err>[A-Z][A-Z0-9_]*))?"
    r"(?:\s+\((?P<msg>.*)\))?\s*$"
)
# strace marks calls it interfered with; the marker sits after the value.
_INJECTED = re.compile(r"\s*\((?:DELAYED|INJECTED)\)\s*$")


class Parser:
    """Feed it lines, get back records.  Keeps per-pid unfinished calls."""

    def __init__(self) -> None:
        self.pending: dict[int | None, tuple[str, str, float | None, str]] = {}
        self.lineno = 0

    def feed(self, text: str) -> list[Record]:
        out = []
        for line in text.splitlines():
            rec = self.line(line)
            if rec is not None:
                out.append(rec)
        out.extend(self.finish())
        return out

    def line(self, line: str) -> Record | None:
        self.lineno += 1
        raw = line.rstrip("\n")
        if not raw.strip():
            return None

        head = _HEAD.match(raw)
        pid = int(head.group("pid")) if head.group("pid") else None
        time = _timestamp(head.group("time"))
        rest = head.group("rest")

        if rest.startswith("strace: ") or rest.startswith("strace-"):
            return self._make("note", pid, time, raw, detail=rest)

        m = _RESUME.match(rest)
        if m:
            start = self.pending.pop(pid, None)
            if start is None:
                return self._make("other", pid, time, raw, detail="resumed without start")
            name, head_args, start_time, start_raw = start
            joined = f"{name}({head_args}{m.group('rest')}"
            rec = self._call(pid, start_time, f"{start_raw} ... {raw}", joined)
            return rec

        m = _START.match(rest)
        if m:
            # Held until the matching "resumed" line; the child's syscalls are
            # printed in between and must not be reordered around it.
            self.pending[pid] = (m.group("name"), m.group("args"), time, raw)
            return None

        m = _SIGNAL.match(rest)
        if m:
            return self._make("signal", pid, time, raw,
                              name=m.group("name"), detail=m.group("detail"))

        m = _EXIT.match(rest)
        if m:
            return self._make("exit", pid, time, raw, detail=m.group("detail"))

        if _CALL.match(rest):
            return self._call(pid, time, raw, rest)

        return self._make("other", pid, time, raw, detail=rest)

    def finish(self) -> list[Record]:
        """Calls that were never resumed, e.g. a thread killed while blocked."""
        out = []
        for pid, (name, args, time, raw) in sorted(
                self.pending.items(), key=lambda kv: (kv[1][2] or 0)):
            rec = self._make("call", pid, time, raw, name=name,
                             args=split_args(args), args_raw=args)
            rec.unfinished = True
            out.append(rec)
        self.pending.clear()
        return out

    def _call(self, pid, time, raw, text) -> Record:
        m = _CALL.match(text)
        if not m:
            return self._make("other", pid, time, raw, detail=text)
        rec = self._make("call", pid, time, raw, name=m.group("name"),
                         args=split_args(m.group("args")), args_raw=m.group("args"))
        rec.ret_raw = m.group("ret").strip()
        value = _INJECTED.sub("", rec.ret_raw)
        rec.delayed = value != rec.ret_raw
        r = _RET.match(value)
        if r:
            val = r.group("val")
            if val != "?":
                rec.ret = int(val, 0)
            rec.ret_path = r.group("path")
            rec.error = r.group("err")
            # "0x7f.. (DELAYED)" has no errno; the marker landed in the message.
            if rec.error is None and r.group("msg") and rec.ret is None:
                rec.detail = r.group("msg")
        return rec

    def _make(self, kind, pid, time, raw, **kw) -> Record:
        return Record(kind=kind, pid=pid, time=time, raw=raw, line=self.lineno, **kw)


def _timestamp(text: str | None) -> float | None:
    if not text:
        return None
    if ":" in text:                                   # -tt style, no date
        h, m, s = text.split(":")
        return int(h) * 3600 + int(m) * 60 + float(s)
    return float(text)


def split_args(text: str) -> list[str]:
    """Split an argument list on top-level commas.

    Nesting comes from structs {}, arrays [], calls (), quoted strings, and
    the <path> strace appends to a descriptor.  A bare '<' only opens a group
    when it follows a descriptor number, so the '=>' strace uses for modified
    output arguments does not unbalance anything.
    """
    out: list[str] = []
    cur: list[str] = []
    depth = angle = 0
    in_string = escaped = False

    for i, ch in enumerate(text):
        if in_string:
            cur.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "<" and i and (text[i - 1].isalnum() or text[i - 1] == "]"):
            angle += 1
        elif ch == ">" and angle:
            angle -= 1
        elif ch == "," and depth == 0 and angle == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)

    tail = "".join(cur).strip()
    if tail or out:
        out.append(tail)
    return out


def keyword_args(args: list[str]) -> dict[str, str]:
    """clone-style `name=value` arguments, ignoring the positional ones."""
    out = {}
    for a in args:
        key, sep, value = a.partition("=")
        if sep and re.fullmatch(r"[a-z_][a-z0-9_]*", key.strip()):
            out[key.strip()] = value.strip()
    return out


def integer(text: str, default: int | None = None) -> int | None:
    """One argument as a number.  NULL is 0; anything else is left to caller."""
    text = (text or "").strip()
    if not text:
        return default
    if text == "NULL":
        return 0
    m = re.match(r"^(0x[0-9a-fA-F]+|-?\d+)", text)
    if not m:
        return default
    return int(m.group(1), 0)


def descriptor(text: str) -> tuple[int | None, str | None]:
    """`3</usr/lib/libc.so.6>` -> (3, '/usr/lib/libc.so.6')."""
    text = (text or "").strip()
    m = re.match(r"^(-?\d+)(?:<(.*)>)?$", text)
    if not m:
        return integer(text), None
    return int(m.group(1)), m.group(2)


def quoted(text: str) -> str:
    """The value of a strace-printed string argument, without the quotes."""
    text = (text or "").strip()
    if text.startswith('"'):
        end = 1
        while end < len(text):
            if text[end] == "\\":
                end += 2
                continue
            if text[end] == '"':
                break
            end += 1
        body = text[1:end]
        return body.encode().decode("unicode_escape", errors="replace")
    return text
