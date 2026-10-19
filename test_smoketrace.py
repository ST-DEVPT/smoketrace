"""Self-checks for smoketrace's pure logic (no network). Run: python test_smoketrace.py  (or pytest)."""
import json
import tempfile
from pathlib import Path

import smoketrace as st


def hop(ttl, ip, loss=0.0):
    return {"ttl": ttl, "ip": ip, "loss": loss, "avg": 10.0 if ip else None, "best": None, "wrst": None, "sd": None}


def test_parse_fping():
    out = st.parse_fping("1.1.1.1 : 12.10 - 11.90\n"
                         "ICMP Host Unreachable from 10.0.0.1 for ICMP Echo sent to 10.0.0.9\n"
                         "nope.invalid: Name or service not known\n"
                         "10.0.0.9 : - - -\n")
    assert out == {"1.1.1.1": [12.1, None, 11.9], "10.0.0.9": [None, None, None]}


def test_summarize():
    med, loss, jit, ok = st.summarize([10.0, None, 12.0, 11.0])
    assert (med, loss, ok) == (11.0, 25.0, [10.0, 11.0, 12.0])
    assert jit == 1.5                      # |12-10| and |11-12| -> mean 1.5
    assert st.summarize([None, None]) == (None, 100.0, None, [])


def test_parse_mtr():
    raw = {"report": {"hubs": [
        {"count": "1", "host": "192.168.1.1", "Loss%": 0.0, "Avg": 0.5, "Best": 0.3, "Wrst": 0.9, "StDev": 0.1},
        {"count": 2, "host": "???", "Loss%": 100.0, "Avg": 0.0, "Best": 0.0, "Wrst": 0.0, "StDev": 0.0}]}}
    a, b = st.parse_mtr(json.dumps(raw))
    assert a == {"ttl": 1, "ip": "192.168.1.1", "loss": 0.0, "avg": 0.5, "best": 0.3, "wrst": 0.9, "sd": 0.1}
    assert b["ttl"] == 2 and b["ip"] is None and b["avg"] is None


def test_route_segments():
    A = [hop(1, "a"), hop(2, "b"), hop(3, "c")]
    A_silent = [hop(1, "a"), hop(2, None, 100), hop(3, "c"), hop(4, None, 100)]   # silent mid + trailing hop
    B = [hop(1, "a"), hop(2, "x"), hop(3, "c")]
    segs, known = st.route_segments([(0, A), (300, A_silent), (600, B), (900, A)])
    assert [s["route"] for s in segs] == [0, 1, 0]           # silent hops are not a change; A comes back as A
    assert [(s["from"], s["to"], s["end"]) for s in segs] == [(0, 300, 600), (600, 600, 900), (900, 900, 1200)]
    assert known == [["a", "b", "c"], ["a", "x", "c"]]
    assert not st.same_path(["a", "b"], ["a", "b", "c"])     # different hop count = different route


def test_loss_origin():
    rate_limited = [hop(1, "a"), hop(2, "b", 50), hop(3, "c")]
    assert st.loss_origin(rate_limited) is None              # loss does not reach the end: ICMP rate-limit
    real = [hop(1, "a"), hop(2, "b", 40), hop(3, "c"), hop(4, "d", 10), hop(5, None, 100), hop(6, "e", 10)]
    assert st.loss_origin(real) == 4                         # persists to the end, silent hop skipped


def test_diff_hops():
    prev = [hop(1, "a"), hop(2, "b"), hop(3, "c")]
    cur = [hop(1, "a"), hop(2, "x"), hop(3, None, 100), hop(4, "d")]
    assert [r["state"] for r in st.diff_hops(prev, cur)] == ["same", "changed", "unknown", "added"]
    assert [r["state"] for r in st.diff_hops(cur, prev)][-1] == "removed"
    assert {r["state"] for r in st.diff_hops(None, cur)} == {None}


def test_status_and_bucketize():
    now = 10_000
    assert st.status_of(now, None, None, None, None) == "stale"
    assert st.status_of(now, now, None, 100.0, 20) == "down"
    assert st.status_of(now, now, 20, 25.0, 20) == "crit"
    assert st.status_of(now, now, 41, 0.0, 20) == "warn"     # 41 > 20 * 1.5 + 10
    assert st.status_of(now, now, 39, 0.0, 20) == "ok"
    rows = [(0, 10.0, 0.0, 1.0, json.dumps([9.0, 10.0, 11.0])), (300, 20.0, 50.0, None, json.dumps([20.0]))]
    (pt,) = st.bucketize(rows, 600)
    assert pt[0] == 0 and pt[1] == 10.5 and pt[2] == 25.0 and pt[3] == 1.0 and len(pt[4]) == st.PINGS


def test_slug():
    assert st.slug("Serviços-VPS Frankfurt") == "servicos-vps-frankfurt"


def test_load_targets_rejects_option_like_host():
    with tempfile.TemporaryDirectory() as d:
        ok, bad = Path(d, "ok.ini"), Path(d, "bad.ini")
        ok.write_text("[Internet]\nCloudflare DNS = 1.1.1.1  # comentário\n", encoding="utf-8")
        bad.write_text("[x]\nevil = -f/etc/passwd\n", encoding="utf-8")
        assert st.load_targets(ok) == [{"id": "internet-cloudflare-dns", "group": "Internet",
                                        "name": "Cloudflare DNS", "host": "1.1.1.1"}]
        try:
            st.load_targets(bad)
        except SystemExit:
            pass
        else:
            raise AssertionError("option-like host accepted")


def test_trace_detail_compares_previous_route():
    A = [hop(1, "a"), hop(2, "b")]
    B = [hop(1, "a"), hop(2, "x")]
    with tempfile.TemporaryDirectory() as d:
        db = Path(d, "t.db")
        st.init_db(db)
        st.store(db, [], [("t", ts, json.dumps(h)) for ts, h in ((0, A), (300, A), (600, B), (900, B))], 900)
        with st.db_open(db) as c:
            r = st.trace_detail(c, "t", None, "route")
            assert (r["cur"]["ts"], r["cur"]["label"], r["prev"]["ts"], r["prev"]["label"]) == (900, "B", 300, "A")
            assert [x["state"] for x in r["rows"]] == ["same", "changed"]
            r = st.trace_detail(c, "t", 299, "route")        # inside the first route: falls back to previous round
            assert r["fallback"] and r["cur"]["ts"] == 0 and r["prev"] is None
            assert st.trace_detail(c, "t", 900, "round")["prev"]["ts"] == 600


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok")
