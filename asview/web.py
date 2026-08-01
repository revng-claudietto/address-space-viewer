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
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

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


def film(trace: Path, out: Path, size: tuple[int, int] = (1600, 900),
         ms_per_step: int = 700, hold_ms: int = 1500, axis: str = "collapsed",
         browser: str | None = None, first: int = 0,
         last: int | None = None) -> None:
    """Step through a whole recording with the browser recording video.

    playwright writes webm when the context closes; anything else is left to
    ffmpeg, which is asked for by the suffix of `out`.
    """
    import shutil
    import subprocess
    import tempfile
    from playwright.sync_api import sync_playwright

    with Serving(trace) as serving, sync_playwright() as play, \
            tempfile.TemporaryDirectory() as scratch:
        chromium = play.chromium.launch(executable_path=browser or bundled_browser())
        try:
            view = {"width": size[0], "height": size[1]}
            context = chromium.new_context(viewport=view, record_video_dir=scratch,
                                           record_video_size=view)
            page = context.new_page()
            problems: list[str] = []
            page.on("pageerror", lambda e: problems.append(str(e)))
            # Opening on the first step of the segment rather than stepping
            # to it keeps the walk there out of the film.
            page.goto(serving.url(trace=TRACE_URL.lstrip("/"), axis=axis,
                                  event=str(first)))
            page.wait_for_selector("#log-scroll .log-row")
            steps = page.locator("#log-scroll .log-row").count()
            stop = steps - 1 if last is None else min(last, steps - 1)

            page.wait_for_timeout(hold_ms)
            for _ in range(max(0, stop - first)):
                page.keyboard.press("ArrowRight")
                page.wait_for_timeout(ms_per_step)
            page.wait_for_timeout(hold_ms)

            source = Path(page.video.path())
            context.close()             # only now is the file complete
            if problems:
                raise RuntimeError("; ".join(problems))
        finally:
            chromium.close()

        out.parent.mkdir(parents=True, exist_ok=True)
        if out.suffix == ".webm":
            shutil.copyfile(source, out)
            return
        if shutil.which("ffmpeg") is None:
            raise RuntimeError(f"ffmpeg is needed to write {out.suffix}; "
                               f"ask for a .webm instead")
        done = subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-i", str(source),
             "-c:v", "libx264", "-preset", "slow", "-crf", "26",
             "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(out)],
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
