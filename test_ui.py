"""The dashboard in a real browser: navigation, back, the address, and answers that arrive out of order.

    python smoketrace.py --demo &          # or any running demo
    pip install playwright && python -m playwright install chromium
    python test_ui.py [http://127.0.0.1:8099]      # CHROMIUM=<path> to use a browser you already have

Then the targets page, on a server of its own: add, refuse a bad address on its field, rename (the id and so
the history stay), filter without losing a half-filled form, remove.

Each navigation check slows one kind of answer on purpose (a week-long board, a target's range, a traceroute) and then
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
    r = pg.evaluate("[S.id, S.det, document.querySelector('#view').dataset.page, S.f.g, !!document.querySelector('#hm')]")
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

    # 12. a click on empty space keeps the view (0.11: the page's own data-view was read as a view button)
    pg.goto(URL + "/#/")
    pg.wait_for_function("S.b && document.querySelector('#hm')")
    box = pg.locator("#hm").bounding_box()
    pg.mouse.click(box["x"] + 5, box["y"] + 8)                 # the heatmap's header row: no row, no cell
    head = pg.locator(".page-head").bounding_box()
    pg.mouse.click(head["x"] + head["width"] / 2, head["y"] + head["height"] - 6)
    pg.wait_for_timeout(200)
    r = pg.evaluate("[S.view, [...document.querySelectorAll('[data-view][aria-pressed=true]')].map(b => b.dataset.view), localStorage.getItem('view')]")
    check("clicks on empty space keep the heatmap selected", r == ["heat", ["heat"], "heat"] or r[:2] == ["heat", ["heat"]], r)
    pg.click("[data-mode=latency]")
    pg.wait_for_timeout(100)
    r = pg.evaluate("[S.mode, [...document.querySelectorAll('[data-mode][aria-pressed=true]')].map(b => b.dataset.mode)]")
    check("the heatmap's colour buttons still answer", r == ["latency", ["latency"]], r)
    pg.click("[data-mode=status]")

    # 13. the sites page: where each site is, then back to the overview from the sidebar
    pg.goto(URL + "/#/sites")
    pg.wait_for_selector("table.slist tbody tr")
    r = pg.evaluate("""[S.tpage, document.querySelectorAll('table.slist tbody tr').length,
        document.querySelector('.side a[href="#/sites"]').getAttribute('aria-current'),
        document.querySelector('table.slist tbody').innerText.includes('Lisbon, office'),
        S.b.sources[0].place]""")
    check("the sites page lists both demo sites, where they are", r == ["sites", 2, "true", True, "Lisbon, office"], r)
    pg.reload()
    pg.wait_for_selector("table.slist tbody tr")
    check("a reload stays on the sites page", pg.evaluate("[S.tpage, location.hash]") == ["sites", "#/sites"])
    r = pg.evaluate("[[...document.querySelectorAll('table.slist thead th')].map(th => th.innerText).includes(t('sVer')), document.querySelector('table.slist tbody tr').innerText.includes(S.b.version), $('#upd').hidden]")
    check("each site's version shows, and no update notice when none is out", r == [True, True, True], r)
    pg.click(".side [data-g='']")
    pg.wait_for_function("!S.tpage && document.querySelector('#hm')")
    check("the overview comes back from the sites page", pg.evaluate("[S.tpage, S.view]") == [False, "heat"])

    # 12. every site at once by default; one site when picked; a target shows its worst site and all of them
    pg.evaluate("localStorage.removeItem('src')")
    pg.goto(URL + "/#/")
    pg.reload()
    pg.wait_for_function("S.b && S.b.source === 'all'")
    r = pg.evaluate("[...document.querySelectorAll('.head-meta [data-src]')].map(b => b.dataset.src + ':' + b.getAttribute('aria-pressed'))")
    check("All is the default, before each site", r == ["all:true", "local:false", "porto:false"], r)
    pg.click(".head-meta [data-src=porto]")
    pg.wait_for_function("S.b.source === 'porto'")
    pg.click(".head-meta [data-src=all]")
    pg.wait_for_function("S.b.source === 'all'")
    worst = pg.evaluate("S.b.targets.find(x => x.status === 'crit').id")
    pg.evaluate(f"openTarget('{worst}')")
    pg.wait_for_function("S.det && S.cmp")
    r = pg.evaluate(f"[S.det.source === S.b.targets.find(x => x.id === '{worst}').src, S.cmp.sources.length]")
    check("a target in All shows its worst site with every site on the chart", r == [True, 2], r)
    pg.wait_for_function("(S.traces || []).length === 1 && document.querySelectorAll('#trace table.hops').length === 2")
    r = pg.evaluate("[...document.querySelectorAll('#trace .tsite b')].map(b => b.textContent)")
    check("and every site's traceroute, under its name", sorted(r) == ["local", "porto"], r)
    pg.keyboard.press("Escape")
    pg.wait_for_function("!S.id")

    check("no page errors", not errors, errors)
    b.close()



# ---------- the targets page: its own server on a temporary targets.ini, with a password ----------
import argparse  # noqa: E402
import json  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402
from pathlib import Path  # noqa: E402

import smoketrace as st  # noqa: E402

d = Path(tempfile.mkdtemp())
ini = d / "targets.ini"
ini.write_text("[Internet]\nCloudflare = 1.1.1.1\nGoogle = 8.8.8.8\n\n[Sites / Lisbon]\nRouter = 10.40.1.1\n", encoding="utf-8")
a = argparse.Namespace(smokeping=None, targets=ini, agents="porto=" + "x" * 24, name="home")
st.init_db(d / "s.db", "home")
st.Handler.db = d / "s.db"
st.apply_config(a, st.load_config(a))
st.PASSWORD = "pw-for-the-test"
srv = ThreadingHTTPServer(("127.0.0.1", 0), st.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
EDIT_URL = f"http://127.0.0.1:{srv.server_address[1]}"

with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None)
    pg = b.new_page(viewport={"width": 1440, "height": 900})
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.add_init_script("localStorage.setItem('lang','en');localStorage.setItem('theme','dark')")
    pg.goto(EDIT_URL + "/login")
    pg.fill("#p", "pw-for-the-test")
    pg.click("#b")
    pg.wait_for_url(EDIT_URL + "/")
    pg.goto(EDIT_URL + "/#/targets")
    pg.wait_for_function("TG.data && document.querySelector('#tlist table')")
    check("the list shows the three targets", pg.evaluate("TG.data.targets.length") == 3)
    check("the sidebar marks Targets", pg.evaluate("document.querySelector('a.node[href=\"#/targets\"]').getAttribute('aria-current')") == "true")

    # add
    pg.click("[data-act=tadd]")
    pg.fill("#tform [name=group]", "Internet")
    pg.fill("#tform [name=name]", "Quad9")
    pg.fill("#tform [name=address]", "not a host!")
    pg.click("#tform button[type=submit]")
    pg.wait_for_function("document.querySelector('.ferr[data-for=address]').textContent.length > 0")
    check("a bad address is shown on its field", pg.evaluate("document.querySelector('[name=address]').getAttribute('aria-invalid')") == "true")
    pg.fill("#tform [name=address]", "9.9.9.9")
    pg.fill("#tform [name=loss_warn]", "5")
    pg.uncheck("#tform [name=agent][value=porto]")
    pg.click("#tform button[type=submit]")
    pg.wait_for_function("!TG.edit && TG.data.targets.some(x => x.name === 'Quad9')")
    q9 = pg.evaluate("TG.data.targets.find(x => x.name === 'Quad9')")
    check("added with its limit and only the server probing", q9["loss_warn"] == 5 and q9["slaves"] == [] and q9["master"] is True, q9)
    saved = json.loads((d / "targets.json").read_text(encoding="utf-8"))
    check("targets.json now holds the list", [t["name"] for t in saved["targets"]] == ["Cloudflare", "Google", "Router", "Quad9"], saved)
    check("the server probes it now", any(t["name"] == "Quad9" for t in st.Handler.targets))

    # edit: rename and move keeps the id
    pg.click("[data-tedit='internet-cloudflare']")
    pg.wait_for_function("TG.edit && TG.edit.id === 'internet-cloudflare'")
    pg.fill("#tform [name=group]", "DNS")
    pg.fill("#tform [name=name]", "Cloudflare 1.0.0.1")
    pg.fill("#tform [name=address]", "1.0.0.1")
    pg.keyboard.press("Enter")
    pg.wait_for_function("!TG.edit && TG.data.targets.some(x => x.group === 'DNS')")
    cf = next(t for t in st.Handler.targets if t["group"] == "DNS")
    check("a rename keeps the id (and the history)", cf["id"] == "internet-cloudflare" and cf["host"] == "1.0.0.1", cf)

    # filter keeps a half-filled form
    pg.click("[data-act=tadd]")
    pg.fill("#tform [name=name]", "half typed")
    pg.fill("#tq", "goo")
    pg.wait_for_timeout(100)
    check("filtering keeps what the form holds", pg.input_value("#tform [name=name]") == "half typed"
          and pg.evaluate("document.querySelectorAll('#tlist tbody tr:not(.grp)').length") == 1)
    pg.click("[data-act=tcancel]")

    # delete, with the confirmation
    pg.fill("#tq", "")
    pg.click("[data-tedit='internet-google']")
    pg.once("dialog", lambda dlg: dlg.accept())
    pg.click("[data-act=tdel]")
    pg.wait_for_function("!TG.data.targets.some(x => x.name === 'Google')")
    check("removed", not any(t["name"] == "Google" for t in st.Handler.targets))

    # the overview shows the new list
    pg.goto(EDIT_URL + "/#/")
    pg.wait_for_function("S.b && S.b.targets.length === 3")
    check("the overview has the edited list", sorted(x["name"] for x in pg.evaluate("S.b.targets")) == ["Cloudflare 1.0.0.1", "Quad9", "Router"])

    # edit where you are: a target's own page, add from a group's page, Esc closes without leaving
    pg.goto(EDIT_URL + "/#/t/internet-quad9")
    pg.wait_for_selector("#dhead [data-tedit]")
    pg.click("#dhead [data-tedit]")
    pg.wait_for_function("document.querySelector('#tdlg').open && document.querySelector('#tform')")
    pg.fill("#tform [name=name]", "Quad9 DNS")
    pg.click("#tform button[type=submit]")
    pg.wait_for_function("!document.querySelector('#tdlg').open && S.det && S.det.target.name === 'Quad9 DNS'")
    check("edited on its own page, which stays open", pg.evaluate("location.hash") == "#/t/internet-quad9")
    pg.goto(EDIT_URL + "/#/?g=Internet")
    pg.wait_for_selector(".head-meta [data-act=tadd]")
    pg.click(".head-meta [data-act=tadd]")
    pg.wait_for_function("document.querySelector('#tdlg').open && document.querySelector('#tform')")
    check("Add target on a group fills the group in", pg.input_value("#tform [name=group]") == "Internet")
    pg.keyboard.press("Escape")
    pg.wait_for_function("!document.querySelector('#tdlg').open && TG.edit === null")    # "close" comes a moment later
    check("Esc closes the form and stays on the group", pg.evaluate("location.hash") == "#/?g=Internet")

    # the sidebar from the targets page opens the group (it used to change only the address)
    pg.goto(EDIT_URL + "/#/targets")
    pg.wait_for_function("TG.data && document.querySelector('#tlist table')")
    pg.click("#tree [data-g='Internet']")
    pg.wait_for_function("document.querySelector('#view').dataset.page === 'dash'", timeout=3000)
    check("a group picked on the targets page opens", pg.evaluate("location.hash") == "#/?g=Internet"
          and pg.text_content("#view h1") == "Internet")
    check("no page errors", not errors, errors)
    b.close()
srv.shutdown()

print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILED: {fails}"))
sys.exit(1 if fails else 0)
