"""The command line: one entry point, five subcommands.

  record   run a program under strace and write the timeline as JSON
  parse    turn an strace log that already exists into the same JSON
  summary  print a JSON timeline as text, to read without a browser
  view     serve the viewer with a timeline loaded, and open it
  shot     render the viewer on a timeline and write a PNG
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import webbrowser
from pathlib import Path
from typing import Sequence

from . import __version__, elfinfo, record, replay, space, straceout, web


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return 2
    return args.handler(args)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="as-trace",
        description="Collect how a program's address space evolves, as JSON.")
    parser.add_argument("--version", action="version",
                        version=f"as-trace {__version__}")
    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-o", "--output", metavar="FILE", default="-",
                        help="where to write the JSON (default: stdout)")
    common.add_argument("--indent", type=int, default=1, metavar="N",
                        help="JSON indentation, 0 for one line (default: 1)")
    common.add_argument("--no-merge", dest="merge", action="store_false",
                        help="keep every mapping separate instead of "
                             "coalescing neighbours the way the kernel does")
    common.add_argument("--page-size", type=int, default=os.sysconf("SC_PAGE_SIZE"),
                        metavar="N", help="page size to round lengths to")
    common.add_argument("--no-elf", dest="elf", action="store_false",
                        help="do not read the ELF files behind the mappings, "
                             "so no segments or sections are reported")
    common.add_argument("--all-sections", action="store_true",
                        help="report sections that are not SHF_ALLOC too, "
                             "which are present in the file but never mapped")

    tracing = argparse.ArgumentParser(add_help=False)
    tracing.add_argument("--no-baseline", dest="baseline", action="store_false",
                         help="do not pause the program after exec to read "
                              "/proc/pid/maps; the timeline then starts from "
                              "an empty address space, showing only what the "
                              "syscalls say")
    tracing.add_argument("--delay-ms", type=int, default=120, metavar="N",
                         help="how long to hold the tracee at each stop")
    tracing.add_argument("--strace", default="strace", metavar="PATH",
                         help="the strace binary to use")
    tracing.add_argument("--shell", default="/bin/sh", metavar="PATH",
                         help="the shell used as the exec trampoline")
    tracing.add_argument("--strace-log", metavar="FILE",
                         help="also keep strace's raw output here")
    tracing.add_argument("--strace-option", action="append", default=[],
                         metavar="OPT", help="pass another option to strace")

    p = subs.add_parser("record", parents=[common, tracing],
                        help="run a program and record its address space")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   metavar="-- COMMAND [ARG...]")
    p.set_defaults(handler=_record)

    p = subs.add_parser("parse", parents=[common],
                        help="convert an existing strace log")
    p.add_argument("log", help="output of strace -f -ttt -y")
    p.add_argument("--maps", metavar="FILE", action="append", default=[],
                   help="a /proc/pid/maps dump to use as the starting state; "
                        "repeatable as PID:FILE")
    p.set_defaults(handler=_parse)

    p = subs.add_parser("summary", help="print a JSON timeline as text")
    p.add_argument("json", nargs="?", default="-", help="a file from record")
    p.add_argument("--regions", action="store_true",
                   help="also print the final layout of every address space")
    p.set_defaults(handler=_summary)

    page = argparse.ArgumentParser(add_help=False)
    page.add_argument("--axis", choices=("collapsed", "log", "linear"),
                      default="collapsed",
                      help="how the address axis is scaled (default: collapsed)")

    p = subs.add_parser("view", parents=[page],
                        help="serve the viewer and open it in a browser")
    p.add_argument("json", nargs="?", help="a file from record")
    p.add_argument("--port", type=int, default=0, metavar="N",
                   help="port to serve on (default: any free one)")
    p.add_argument("--host", default="127.0.0.1", metavar="ADDR")
    p.add_argument("--autoplay", action="store_true",
                   help="start stepping through as soon as it loads")
    p.add_argument("--no-open", dest="open", action="store_false",
                   help="print the URL instead of opening a browser")
    p.set_defaults(handler=_view)

    p = subs.add_parser("shot", parents=[page],
                        help="render the viewer headless and write a PNG")
    p.add_argument("json", help="a file from record")
    p.add_argument("-o", "--output", default="shot.png", metavar="FILE")
    p.add_argument("--event", type=int, default=0, metavar="N",
                   help="which step to draw (default: 0)")
    p.add_argument("--size", default="1600x900", metavar="WxH")
    p.add_argument("--browser", metavar="PATH",
                   help="the browser binary, when playwright cannot find one")
    p.set_defaults(handler=_shot)

    return parser


# --------------------------------------------------------------------------- #
# Subcommands.
# --------------------------------------------------------------------------- #

def _record(args: argparse.Namespace) -> int:
    code, doc = _trace(args)
    if doc is None:
        return code
    _write(doc, args.output, args.indent)
    _report(doc, doc["target"]["exit_code"])
    return code


def _trace(args: argparse.Namespace) -> tuple[int, dict | None]:
    command = _command_of(args)
    if not command:
        print("as-trace: nothing to run", file=sys.stderr)
        return 2, None

    version = record.strace_version(args.strace)
    if version is None:
        print(f"as-trace: cannot run {args.strace}", file=sys.stderr)
        return 1, None

    space.set_page_size(args.page_size)
    options = record.Options(
        baseline=args.baseline, delay_ms=args.delay_ms, strace=args.strace,
        shell=args.shell, keep_log=args.strace_log,
        extra_strace=tuple(args.strace_option))

    started = time.time()
    run = record.run(command, options)
    elapsed = time.time() - started

    doc = _document(args, run.log, run.snapshots, run.trampoline, extra={
        "target": {
            "argv": command,
            "cwd": os.getcwd(),
            "exit_code": run.exit_code,
            "traced_at": started,
            "wall_seconds": round(elapsed, 3),
        },
        "generator": {"tool": "as-trace", "version": __version__,
                      "strace": version, "command": run.strace_argv},
    })
    doc["warnings"] = run.warnings + doc["warnings"]
    if not args.strace_log:
        os.unlink(run.log)
    return 0, doc


def _parse(args: argparse.Namespace) -> int:
    space.set_page_size(args.page_size)
    with open(args.log, errors="replace") as fp:
        text = fp.read()

    snapshots = []
    for item in args.maps:
        pid, sep, path = item.partition(":")
        if not sep:
            pid, path = "0", item
        with open(path, errors="replace") as fp:
            snapshots.append(replay.Snapshot(time=0.0, pid=int(pid), exe=None,
                                             text=fp.read(), supplied=True))

    doc = _document(args, args.log, snapshots, trampoline=False, text=text,
                    extra={"target": {"argv": None, "cwd": None,
                                      "source": args.log, "exit_code": None}})
    _write(doc, args.output, args.indent)
    _report(doc, None)
    return 0


def _summary(args: argparse.Namespace) -> int:
    if args.json == "-":
        doc = json.load(sys.stdin)
    else:
        with open(args.json) as fp:
            doc = json.load(fp)
    target = doc.get("target") or {}
    print(f"# {' '.join(target.get('argv') or ['(from a log)'])}")
    print(f"# {len(doc['events'])} events, {len(doc['spaces'])} address space(s), "
          f"{len(doc['processes'])} process(es)")

    live: dict[str, int] = {}
    for ev in doc["events"]:
        delta = ev.get("delta") or {}
        count = live.get(ev["space"], 0)
        count += len(delta.get("added", [])) - len(delta.get("removed", []))
        live[ev["space"]] = count
        stamp = f"{ev['t']:9.6f}" if ev.get("t") is not None else " " * 9
        change = ""
        if delta:
            change = f"  [-{len(delta.get('removed', []))} " \
                     f"+{len(delta.get('added', []))} -> {count}]"
        print(f"{ev['seq']:5} {stamp} {ev['pid']:>7} {ev['space']:>4} "
              f"{ev['category']:<8} {ev['summary']}{change}")

    for check in doc.get("checks", []):
        verdict = "matches the kernel" if check["match"] else \
            f"{len(check['differences'])} difference(s) from the kernel"
        print(f"# check at event {check['at_event']} ({check['space']}): {verdict}")

    for warning in doc.get("warnings", []):
        print(f"# warning: {warning}")

    if args.regions:
        for sp in doc["spaces"]:
            print(f"\n# {sp['id']} final layout ({len(sp['final_regions'])} regions)")
            for r in sp["final_regions"]:
                print(f"  {r['start']}-{r['end']} {r['prot']}"
                      f"{'s' if r['shared'] else 'p'} {r.get('path') or r.get('name') or ''}")
    return 0


def _view(args: argparse.Namespace) -> int:
    problem = web.check_viewer()
    if problem:
        print(f"as-trace: {problem}", file=sys.stderr)
        return 1

    trace = None
    if args.json:
        trace = Path(args.json)
        problem = web.check_trace(trace)
        if problem:
            print(f"as-trace: {problem}", file=sys.stderr)
            return 1

    query: dict = {}
    if trace is not None:
        query["trace"] = web.TRACE_URL.lstrip("/")
    if args.axis != "collapsed":
        query["axis"] = args.axis
    if args.autoplay:
        query["autoplay"] = None

    try:
        serving = web.Serving(trace, host=args.host, port=args.port)
    except OSError as e:
        print(f"as-trace: cannot listen on {args.host}:{args.port}: "
              f"{e.strerror}", file=sys.stderr)
        return 1

    with serving:
        url = serving.url(**query)
        print(url, flush=True)      # the caller may be waiting to read it
        if trace is None:
            print("as-trace: no trace given; drop one on the page",
                  file=sys.stderr)
        if args.open and not webbrowser.open(url):
            print("as-trace: no browser to open; the URL is above",
                  file=sys.stderr)
        print("as-trace: serving; Ctrl-C to stop", file=sys.stderr)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print(file=sys.stderr)
    return 0


def _shot(args: argparse.Namespace) -> int:
    problem = web.check_viewer() or web.check_trace(Path(args.json))
    if problem:
        print(f"as-trace: {problem}", file=sys.stderr)
        return 1
    try:
        width, _, height = args.size.partition("x")
        size = (int(width), int(height))
    except ValueError:
        print(f"as-trace: --size wants WxH, not {args.size}", file=sys.stderr)
        return 2

    try:
        web.screenshot(Path(args.json), Path(args.output), event=args.event,
                       axis=args.axis, size=size,
                       browser=args.browser or os.environ.get("AS_TRACE_BROWSER"))
    except ImportError:
        print("as-trace: shot needs playwright and a browser; "
              "`nix run .#dev` has both", file=sys.stderr)
        return 1
    except Exception as e:                       # playwright raises its own
        print(f"as-trace: {e}", file=sys.stderr)
        return 1
    print(f"as-trace: wrote {args.output}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# Shared.
# --------------------------------------------------------------------------- #

def _document(args: argparse.Namespace, log: str, snapshots: list[replay.Snapshot],
              trampoline: bool, extra: dict, text: str | None = None) -> dict:
    if text is None:
        with open(log, errors="replace") as fp:
            text = fp.read()
    records = straceout.Parser().feed(text)
    elves = elfinfo.Library(enabled=args.elf, all_sections=args.all_sections)
    machine = replay.Machine(merging=args.merge, trampoline=trampoline, elves=elves,
                             injected_delay=getattr(args, "delay_ms", 0) / 1000)
    machine.run(records, snapshots)
    doc = machine.document(extra)
    if args.elf and not elfinfo.HAVE_PYELFTOOLS:
        doc["warnings"].append(
            "pyelftools is not installed: no segments or sections are reported")
    return doc


def _command_of(args: argparse.Namespace) -> list[str]:
    command = list(args.command)
    while command and command[0] == "--":
        command.pop(0)
    return command


def _write(doc: dict, path: str, indent: int) -> None:
    text = json.dumps(doc, indent=indent or None,
                      separators=(",", ":") if not indent else None)
    if path == "-":
        sys.stdout.write(text + "\n")
        return
    with open(path, "w") as fp:
        fp.write(text + "\n")


def _report(doc: dict, exit_code: int | None) -> None:
    spaces = doc["spaces"]
    peak = max((s["peak_regions"] for s in spaces), default=0)
    exited = "" if exit_code is None else f"; the program exited with {exit_code}"
    print(f"as-trace: {len(doc['events'])} events, {len(spaces)} address space(s), "
          f"peak {peak} regions{exited}", file=sys.stderr)
    for check in doc.get("checks", []):
        if not check["match"]:
            print(f"as-trace: at event {check['at_event']} the reconstruction "
                  f"and the supplied maps differ in "
                  f"{len(check['differences'])} region(s)", file=sys.stderr)
    for warning in doc["warnings"]:
        print(f"as-trace: warning: {warning}", file=sys.stderr)
