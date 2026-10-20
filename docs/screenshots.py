"""The README's screenshots and the social preview, taken from the demo. Run from the repository root:

    pip install playwright && python -m playwright install chromium
    python docs/screenshots.py              # CHROMIUM=<path> to use a browser you already have

They are regenerated rather than edited, so they always show the dashboard as it is."""
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PORT = 8098
URL = f"http://127.0.0.1:{PORT}"
JPEG = {"type": "jpeg", "quality": 88}
RANGES = {"3 h": 10800, "24 h": 86400, "7 d": 604800, "30 d": 2592000}


def new_page(browser, theme="dark", view="heat", **kw):
    page = browser.new_page(**kw)
    # the README is in English; the theme and the dashboard's view are the viewer's choices, set here
    page.add_init_script(f"localStorage.setItem('lang', 'en'); localStorage.setItem('theme', '{theme}');"
                         f"localStorage.setItem('view', '{view}'); localStorage.setItem('brange', '86400')")
    return page


def dashboard(page, hash_="#/"):
    page.goto(f"{URL}/{hash_}")
    page.wait_for_function("S.b && document.querySelector('#mainp')")
    page.wait_for_timeout(900)          # the cards' small charts


def open_target(page, tid, range_label=None):
    page.goto(f"{URL}/#/t/{tid}")
    page.wait_for_function("S.det && S.trace && S.geo")
    if range_label:
        page.get_by_role("button", name=range_label, exact=True).click()
        page.wait_for_function(f"S.det && S.det.to - S.det.from === {RANGES[range_label]}")
    page.wait_for_timeout(300)


def click_route(page, label, last=True):
    """Click the chart in the middle of a segment with that route letter; wait for its traceroute."""
    xy = page.evaluate("""([l, last]) => {
        const segs = S.det.segments.filter(s => s.label === l), s = last ? segs.pop() : segs[0];
        const r = document.querySelector('#chart').getBoundingClientRect();
        return [r.left + S.geo.X((s.from + s.end) / 2), r.top + 110]; }""", [label, last])
    page.mouse.click(*xy)
    page.wait_for_function(f"S.trace && S.trace.cur && S.trace.cur.label === '{label}' && S.sel")


def click_loss(page):
    """Click the first point whose loss reaches every hop to the end (the demo's real-loss hour)."""
    xy = page.evaluate("""() => {
        const p = S.det.points.find(p => p[2] >= 10), r = document.querySelector('#chart').getBoundingClientRect();
        return [r.left + S.geo.X(p[0]) + S.geo.bw * 4, r.top + 110]; }""")
    page.mouse.click(*xy)
    page.wait_for_function("S.trace && S.trace.cur && S.trace.cur.origin != null")


def section(page, locator, path, right=24):
    """A part of the page with a little of the page around it: the sections have no side padding of their own."""
    box, top = locator.bounding_box(), page.evaluate("scrollY")     # the box is on screen, the clip on the page
    page.screenshot(path=path, full_page=True, clip={"x": box["x"] - 24, "y": box["y"] + top, "width": box["width"] + 24 + right,
                                                     "height": box["height"]}, **JPEG)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        server = subprocess.Popen([sys.executable, str(ROOT / "smoketrace.py"), "--demo", "--port", str(PORT),
                                   "--db", str(Path(tmp, "demo.db"))])
        try:
            for _ in range(120):
                try:
                    urllib.request.urlopen(URL + "/api/overview", timeout=2)
                    break
                except OSError:
                    time.sleep(0.5)
            shoot()
        finally:
            server.terminate()
            server.wait()
    print("screenshots written to", DOCS)


def shoot():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None)

        for theme, name in (("dark", "overview.jpg"), ("light", "overview-light.jpg")):
            page = new_page(browser, theme, viewport={"width": 1600, "height": 1000})
            dashboard(page)
            page.screenshot(path=DOCS / name, **JPEG)
            page.close()
        page = new_page(browser, view="cards", viewport={"width": 1600, "height": 1000})
        dashboard(page, "#/?st=down,crit,warn")
        page.screenshot(path=DOCS / "cards.jpg", **JPEG)
        page.close()
        page = new_page(browser, view="table", viewport={"width": 1600, "height": 1000})
        dashboard(page, "#/?g=Sites")
        page.screenshot(path=DOCS / "table.jpg", **JPEG)
        page.close()

        page = new_page(browser, viewport={"width": 1600, "height": 1000})
        open_target(page, "internet-cloudflare-dns")
        click_route(page, "B")
        page.mouse.move(10, 10)
        page.wait_for_timeout(400)
        page.screenshot(path=DOCS / "detail.jpg", full_page=True, **JPEG)
        section(page, page.locator("#trace"), DOCS / "trace.jpg", right=0)

        open_target(page, "internet-quad9")
        click_loss(page)
        section(page, page.locator("#trace"), DOCS / "loss.jpg", right=0)

        open_target(page, "internet-google-dns", "3 h")
        box = page.locator("#chart").bounding_box()
        page.mouse.move(box["x"] + box["width"] * 0.56, box["y"] + 120)
        page.wait_for_timeout(200)
        section(page, page.locator("#chart").locator("xpath=ancestor::section[1]"), DOCS / "flap.jpg")
        page.close()

        page = new_page(browser, viewport={"width": 390, "height": 844}, device_scale_factor=2, is_mobile=True, has_touch=True)
        open_target(page, "internet-cloudflare-dns")
        page.screenshot(path=DOCS / "phone.jpg", **JPEG)
        page.close()

        card = browser.new_page(viewport={"width": 1280, "height": 640})
        card.goto((DOCS / "social" / "preview.html").as_uri())
        card.wait_for_load_state("networkidle")
        card.screenshot(path=DOCS / "social-preview.png")
        browser.close()


if __name__ == "__main__":
    main()
