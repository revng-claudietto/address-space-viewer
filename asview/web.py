"""Putting the viewer in front of a browser.

The page is three static files and a JSON, and it will take the JSON by drag
and drop from anywhere.  The only reason a server is involved at all is that
a browser refuses to `fetch` a `file://` URL, so `?trace=` needs one.

`screenshot` drives the same page headless, which is how a recording turns
into a picture without anyone having to look at it.
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import socketserver
import threading
import time
from pathlib import Path

VIEWER = Path(__file__).resolve().parent.parent / "viewer"
TRACE_URL = "/trace.json"


class _Handler(http.server.SimpleHTTPRequestHandler):
    """The viewer directory, plus the trace at a fixed path."""

    trace: Path | None = None

    def do_GET(self) -> None:
        if self.path.split("?")[0] == TRACE_URL and self.trace is not None:
            body = self.trace.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def end_headers(self) -> None:
        # Everything here is a file on disk being worked on, and none of it
        # may be remembered.  Without this the page and its script go out
        # with only a Last-Modified, which lets a browser decide for itself
        # how long they stay fresh -- and it decides in proportion to how old
        # the file is, so an edit to a file that had not changed in a while
        # is the one least likely to be asked for again.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, *args) -> None:
        pass                        # the page is not a web site


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Serving:
    """A running server, as a context manager.  Port 0 means any free one."""

    def __init__(self, trace: Path | None = None, host: str = "127.0.0.1",
                 port: int = 0) -> None:
        served = type("Handler", (_Handler,), {"trace": trace})
        self._server = _Server((host, port),
                               functools.partial(served, directory=str(VIEWER)))
        self.host, self.port = self._server.server_address[:2]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)

    def url(self, **query: str) -> str:
        parts = "&".join(k if v is None else f"{k}={v}"
                         for k, v in query.items())
        return f"http://{self.host}:{self.port}/index.html" + \
               (f"?{parts}" if parts else "")

    def __enter__(self) -> "Serving":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()


def check_viewer() -> str | None:
    """Complain in words rather than with a 404."""
    if not (VIEWER / "index.html").is_file():
        return f"the viewer is not where it should be ({VIEWER})"
    return None


def check_trace(path: Path) -> str | None:
    try:
        doc = json.loads(path.read_text())
    except OSError as e:
        return f"cannot read {path}: {e.strerror}"
    except ValueError as e:
        return f"{path} is not valid JSON: {e}"
    if not isinstance(doc, dict) or not isinstance(doc.get("events"), list):
        return f"{path} is not a trace: it has no \"events\""
    if not doc["events"]:
        return f"{path} has no events"
    return None


def bundled_browser() -> str | None:
    """A chromium sitting next to playwright, when the two disagree on names.

    Distributions package the browsers separately from the python bindings,
    and the build numbers the bindings look for are not the ones on disk.
    The binary itself is fine; it is only the lookup that fails.
    """
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if not root or root == "0":
        return None
    found = sorted(Path(root).glob("chromium-*/chrome-linux*/chrome"))
    return str(found[-1]) if found else None


def frames(trace: Path, into: Path, size: tuple[int, int] = (1600, 900),
           ms_per_step: int = 700, hold_ms: int = 1500, axis: str = "collapsed",
           browser: str | None = None, first: int = 0, last: int | None = None,
           fps: int = 8, zoom: float = 1.0) -> list[tuple[Path, float]]:
    """Step through a recording, photographing the page as it goes.

    Not the browser's own video recorder: that writes VP8 at a bitrate meant
    for a screen share, and every artefact it introduces is inherited by
    whatever the frames are turned into afterwards -- including, absurdly, a
    lossless encode of them.  A screenshot is the pixels the page was drawn
    with.

    Screenshots take as long as they take, so each frame is returned with
    the wall time it stood for rather than with an assumed one; the caller
    resamples.  Motion inside a step is what the interval buys: a mapping
    that grows takes a little over half a second, and is worth several.

    `zoom` is the browser's device scale factor, so `size` stays the layout
    the page is given -- the viewer asks for 1280 and will not go below it --
    while the pixels come out at `size * zoom`.  The page is drawn at that
    size rather than drawn large and shrunk, so nothing is resampled: the
    glyphs are rasterised at the size they are shown at.
    """
    from playwright.sync_api import sync_playwright

    into.mkdir(parents=True, exist_ok=True)
    interval = 1.0 / max(1, fps)
    shots: list[tuple[Path, float]] = []

    with Serving(trace) as serving, sync_playwright() as play:
        chromium = play.chromium.launch(executable_path=browser or bundled_browser())
        try:
            page = chromium.new_page(viewport={"width": size[0], "height": size[1]},
                                     device_scale_factor=zoom)
            problems: list[str] = []
            page.on("pageerror", lambda e: problems.append(str(e)))
            # Opening on the first step of a segment rather than stepping to
            # it keeps the walk there out of the film.
            page.goto(serving.url(trace=TRACE_URL.lstrip("/"), axis=axis,
                                  event=str(first)))
            page.wait_for_selector("#log-scroll .log-row")
            steps = page.locator("#log-scroll .log-row").count()
            stop = steps - 1 if last is None else min(last, steps - 1)

            def snap() -> None:
                path = into / f"f{len(shots) + 1:05d}.png"
                started = time.monotonic()
                page.screenshot(path=str(path), caret="hide")
                shots.append((path, started))

            def cover(seconds: float) -> None:
                until = time.monotonic() + seconds
                while True:
                    snap()
                    left = until - time.monotonic()
                    if left <= 0:
                        break
                    page.wait_for_timeout(min(interval, left) * 1000)

            cover(hold_ms / 1000)
            for _ in range(max(0, stop - first)):
                page.keyboard.press("ArrowRight")
                cover(ms_per_step / 1000)
            cover(hold_ms / 1000)
            snap()
            if problems:
                raise RuntimeError("; ".join(problems))
        finally:
            chromium.close()

    # What each frame stood for: the gap to the next one, and for the last
    # one, the interval it was aiming at.
    out = []
    for i, (path, when) in enumerate(shots):
        nxt = shots[i + 1][1] if i + 1 < len(shots) else when + interval
        out.append((path, max(0.001, nxt - when)))
    return out


def film(trace: Path, out: Path, size: tuple[int, int] = (1600, 900),
         ms_per_step: int = 700, hold_ms: int = 1500, axis: str = "collapsed",
         browser: str | None = None, first: int = 0, last: int | None = None,
         fps: int = 8, zoom: float = 1.0,
         keep_frames: Path | None = None) -> None:
    """Photograph a recording being stepped through, and encode it."""
    import shutil
    import subprocess
    import tempfile

    if shutil.which("ffmpeg") is None:
        raise RuntimeError("ffmpeg is needed to write a video")

    with tempfile.TemporaryDirectory() as scratch:
        into = Path(keep_frames) if keep_frames else Path(scratch) / "frames"
        shot = frames(trace, into, size=size, ms_per_step=ms_per_step,
                      hold_ms=hold_ms, axis=axis, browser=browser,
                      first=first, last=last, fps=fps, zoom=zoom)

        # A concat list rather than a frame rate, so the timings the capture
        # actually achieved are the ones the video plays at.
        listing = Path(scratch) / "frames.txt"
        with open(listing, "w") as fp:
            for path, seconds in shot:
                fp.write(f"file '{path.resolve()}'\nduration {seconds:.4f}\n")
            fp.write(f"file '{shot[-1][0].resolve()}'\n")

        # 4:4:4 and lossless.  The usual yuv420p halves the chroma
        # resolution, which on coloured text at this size changes every
        # pixel in the frame; measured against the screenshots it went
        # from 99% of pixels differing to none of them differing by more
        # than the rounding of the colour conversion itself.  Flat panels
        # of colour cost almost nothing to keep exactly, so this is also
        # the smaller file.
        out.parent.mkdir(parents=True, exist_ok=True)
        done = subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
             "-i", str(listing), "-vf", f"fps={fps},format=yuv444p",
             "-c:v", "libx264", "-preset", "veryslow", "-qp", "0",
             "-movflags", "+faststart", str(out)],
            capture_output=True, text=True)
        if done.returncode != 0:
            raise RuntimeError(f"ffmpeg failed: {done.stderr.strip()}")


def screenshot(trace: Path, out: Path, event: int | None = None,
               axis: str = "collapsed", size: tuple[int, int] = (1600, 900),
               browser: str | None = None, full: bool = False,
               settle_ms: int = 900) -> None:
    """Render the viewer on a trace and write a PNG.  Needs playwright."""
    from playwright.sync_api import sync_playwright

    with Serving(trace) as serving, sync_playwright() as play:
        chromium = play.chromium.launch(
            executable_path=browser or bundled_browser())
        try:
            page = chromium.new_page(viewport={"width": size[0],
                                               "height": size[1]})
            problems: list[str] = []
            page.on("pageerror", lambda e: problems.append(str(e)))
            page.goto(serving.url(trace=TRACE_URL.lstrip("/")))
            page.wait_for_selector("#log-scroll .log-row")
            if axis != "collapsed":
                page.click(f'#axis-seg button[data-mode="{axis}"]')
            if event:
                page.locator("#log-scroll .log-row").nth(event).click()
            page.wait_for_timeout(settle_ms)
            page.screenshot(path=str(out), full_page=full)
            if problems:
                raise RuntimeError("; ".join(problems))
        finally:
            chromium.close()
