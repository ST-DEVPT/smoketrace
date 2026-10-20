"""The dashboard in a real browser: navigation, back, the address, and answers that arrive out of order.

    python smoketrace.py --demo &          # or any running demo
    pip install playwright && python -m playwright install chromium
    python test_ui.py [http://127.0.0.1:8099]      # CHROMIUM=<path> to use a browser you already have

Each check slows one kind of answer on purpose (a week-long board, a target's range, a traceroute) and then
does what a person does next, so a late answer has the chance to paint over the newer one."""
import os
import sys

from playwright.sync_api import sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8099"
SLOW = """
window.__slow = [];   // [substring, ms]: answers for matching URLs arrive late
const realFetch = window.fetch;
window.fetch = async (u, o) => {
  const rule = window.__slow.find(([s]) => String(u).includes(s));
  const r = await realFetch(u, o);
  if (rule) await new Promise(res => setTimeout(res, rule[1]));
  return r;
};
if (!sessionStorage.getItem('init')) {
  sessionStorage.setItem('init', '1');
  localStorage.setItem('lang', 'en'); localStorage.setItem('theme', 'dark'); localStorage.setItem('view', 'heat');
  localStorage.setItem('brange', '86400'); localStorage.setItem('range', '86400');
}
"""
fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        fails.append(name)


with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None)
    pg = b.new_page(viewport={"width": 1440, "height": 900})
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.add_init_script(SLOW)
    pg.goto(URL + "/#/")
    pg.wait_for_function("S.b && document.querySelector('#hm')")

    # 1. a slow week-long board answered after the day it was replaced by
    pg.evaluate("window.__slow = [['range=604800', 1500]]")
    pg.click("[data-brange='604800']")
    pg.wait_for_timeout(100)
    pg.click("[data-brange='86400']")
    pg.wait_for_timeout(2200)
    r = pg.evaluate("[S.range, S.b.range, document.querySelector('[data-brange][aria-pressed=true]').dataset.brange]")
    check("board: the last range clicked wins over a slower earlier one", r == [86400, 86400, "86400"], r)

    # 2. a refresh racing a source switch
    pg.evaluate("window.__slow = [['src=local', 1200]]")
    pg.evaluate("loadBoard()")                      # a refresh for 'local', slowed
    pg.click("[data-src='porto']")
    pg.wait_for_timeout(1800)
    r = pg.evaluate("[S.src, S.b.source]")
    check("board: a slow refresh does not switch the source back", r == ["porto", "porto"], r)
    pg.evaluate("window.__slow = []")
    pg.click("[data-src='local']")
    pg.wait_for_function("S.b.source === 'local'")

    # 3. the overview keeps its place: scroll the heatmap, open a target, come back
    pg.evaluate("document.querySelector('#hmScroll').scrollTop = 300")
    pg.wait_for_timeout(100)
    top = pg.evaluate("document.querySelector('#hmScroll').scrollTop")
    pg.evaluate("openTarget('internet-cloudflare-dns')")
    pg.wait_for_function("S.det && S.trace")
    pg.go_back()
    pg.wait_for_function("!S.id && document.querySelector('#hmScroll')")
    pg.wait_for_timeout(200)
    r = pg.evaluate("document.querySelector('#hmScroll').scrollTop")
    check("back: the heatmap is where it was left", abs(r - top) < 2, [top, r])

    # 4. ranges on a target's page, the slow one first
    pg.evaluate("openTarget('internet-cloudflare-dns')")
    pg.wait_for_function("S.det && S.trace && S.id === 'internet-cloudflare-dns'")
    pg.evaluate("window.__slow = [['range=2592000', 1500]]")
    pg.click("[data-drange='2592000']")
    pg.wait_for_timeout(100)
    pg.click("[data-drange='10800']")
    pg.wait_for_timeout(2200)
    r = pg.evaluate("[S.drange, S.det.to - S.det.from]")
    check("target: the last range clicked wins", r == [10800, 10800], r)
    pg.evaluate("window.__slow = []")

    # 5. two moments picked quickly, the first answer slowed: the second one shows, and it is in the address
    pts = pg.evaluate("S.det.points.map(p => p[0])")
    a, c = pts[5], pts[20]
    pg.evaluate(f"window.__slow = [['ts={a + 299}', 1200]]")
    pg.evaluate(f"pickMoment({a + 299})")
    pg.wait_for_timeout(50)
    pg.evaluate(f"pickMoment({c + 299})")
    pg.wait_for_timeout(1700)
    r = pg.evaluate("[S.sel, S.traceFor, S.trace.cur.ts <= S.sel, location.hash]")
    check("trace: the last moment picked wins and is in the URL", r[0] == c + 299 and r[1] == c + 299 and r[2] and r[3].endswith(f"at={c + 299}"), r)
    pg.evaluate("window.__slow = []")

    # 6. reload keeps the moment
    pg.reload()
    pg.wait_for_function("S.det && S.trace && S.trace.cur")
    r = pg.evaluate("[S.sel, S.traceFor]")
    check("reload: the picked moment survives", r == [c + 299, c + 299], r)

    # 7. the address changes the moment on the same target (back and forward between two moments)
    pg.goto(URL + f"/#/t/internet-cloudflare-dns?at={a + 299}")
    pg.wait_for_function(f"S.traceFor === {a + 299}")
    pg.goto(URL + f"/#/t/internet-cloudflare-dns?at={c + 299}")
    pg.wait_for_function(f"S.traceFor === {c + 299}", timeout=5000)
    check("address: a new ?at= on the same target loads that moment", True)

    # 8. leaving a target while its answers are in flight: nothing paints over the overview
    pg.evaluate("window.__slow = [['/api/target', 1000], ['/api/trace', 1000]]")
    pg.evaluate("openTarget('internet-quad9')")
    pg.wait_for_timeout(100)
    pg.evaluate("location.hash = '#/?g=Sites'")
    pg.wait_for_timeout(1600)
    r = pg.evaluate("[S.id, S.det, document.querySelector('#view').dataset.view, S.f.g, !!document.querySelector('#hm')]")
    check("late answers for a page already left are dropped", r == [None, None, "dash", "Sites", True], r)
    pg.evaluate("window.__slow = []")

    # 9. A to B: B's page never shows A's data
    pg.evaluate("window.__slow = [['id=internet-quad9', 1200]]")
    pg.evaluate("openTarget('internet-quad9')")
    pg.wait_for_timeout(100)
    pg.evaluate("openTarget('internet-google-dns')")
    pg.wait_for_function("S.det && S.trace && S.trace.cur")
    pg.wait_for_timeout(1500)
    r = pg.evaluate("[S.id, S.det.target.id, document.querySelector('#view h1').textContent]")
    check("A then B: B's page shows B", r[0] == r[1] == "internet-google-dns" and "Google" in r[2], r)
    pg.evaluate("window.__slow = []")

    # 10. Escape goes back to the overview it came from, without a new history entry
    pg.goto(URL + "/#/?g=Internet")
    pg.wait_for_function("S.b && document.querySelector('#hm') && S.f.g === 'Internet'")
    n0 = pg.evaluate("history.length")
    pg.evaluate("openTarget('internet-quad9')")
    pg.wait_for_function("S.det")
    pg.keyboard.press("Escape")
    pg.wait_for_function("!S.id")
    r = pg.evaluate("[location.hash, S.f.g]")
    check("Escape returns to the same overview", r == ["#/?g=Internet", "Internet"], r)

    # 11. a stale saved view value does not break the heatmap (0.5 bug)
    pg.evaluate("localStorage.setItem('view', 'list')")
    pg.reload()
    pg.wait_for_function("S.b && document.querySelector('#hm')")
    r = pg.evaluate("[S.view, HROWS.filter(r => r.x).every(r => shownList().some(x => x.id === r.x.id))]")
    check("an old saved view falls back to the heatmap", r == ["heat", True], r)

    check("no page errors", not errors, errors)
    b.close()

print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
