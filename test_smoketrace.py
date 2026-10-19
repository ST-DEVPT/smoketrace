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
                                        "name": "Cloudflare DNS", "host": "1.1.1.1",
                                        "slaves": None, "master": True}]
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
        st.init_db(db, "local")
        st.store(db, [], [("local", "t", ts, json.dumps(h)) for ts, h in ((0, A), (300, A), (600, B), (900, B))], 900)
        with st.db_open(db) as c:
            r = st.trace_detail(c, "local", "t", None, "route")
            assert (r["cur"]["ts"], r["cur"]["label"], r["prev"]["ts"], r["prev"]["label"]) == (900, "B", 300, "A")
            assert [x["state"] for x in r["rows"]] == ["same", "changed"]
            r = st.trace_detail(c, "local", "t", 299, "route")   # inside the first route: falls back to previous round
            assert r["fallback"] and r["cur"]["ts"] == 0 and r["prev"] is None
            assert st.trace_detail(c, "local", "t", 900, "round")["prev"]["ts"] == 600
            assert st.trace_detail(c, "porto", "t", None, "route") == {"cur": None}   # sources never mix


def test_old_database_is_upgraded():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d, "old.db")
        with st.db_open(db) as c:   # the 0.1 schema
            c.execute("CREATE TABLE ping (target TEXT, ts INTEGER, median REAL, loss REAL, jitter REAL, rtts TEXT,"
                      " PRIMARY KEY (target, ts)) WITHOUT ROWID")
            c.execute("CREATE TABLE trace (target TEXT, ts INTEGER, hops TEXT, PRIMARY KEY (target, ts)) WITHOUT ROWID")
            c.execute("INSERT INTO ping VALUES ('t', 300, 10.0, 0.0, 1.0, '[10.0]')")
            c.execute("INSERT INTO trace VALUES ('t', 300, '[]')")
        st.init_db(db, "home")
        st.init_db(db, "home")      # idempotent
        with st.db_open(db) as c:
            assert c.execute("SELECT * FROM ping").fetchall() == [("home", "t", 300, 10.0, 0.0, 1.0, "[10.0]")]
            assert c.execute("SELECT source, target, ts FROM trace").fetchall() == [("home", "t", 300)]


def test_clean_round():
    now = 1_000_000
    good = {"ts": now - 7, "pings": {"t": [1.5, None]},
            "traces": {"t": [{"ttl": 1, "ip": "10.0.0.1", "loss": 0, "avg": 1.2, "extra": "dropped"},
                             {"ttl": 2, "ip": None, "loss": 100}]}}
    ts, pings, traces = st.clean_round(good, {"t"}, now)
    assert ts == (now - 7) // st.STEP * st.STEP and pings == {"t": [1.5, None]}
    assert traces["t"][0] == {"ttl": 1, "ip": "10.0.0.1", "loss": 0.0, "avg": 1.2, "best": None, "wrst": None, "sd": None}
    assert st.clean_round({"ts": now, "pings": None, "traces": {}}, {"t"}, now)[1] is None   # fping failed there
    bad = [
        {"ts": now, "pings": {"unknown": [1.0]}},                       # target the server does not have
        {"ts": now, "pings": {"t": [float("nan")]}},
        {"ts": now, "pings": {"t": ["1"]}},
        {"ts": True, "pings": {}},
        {"ts": now - 40 * 86400},                                       # older than the retention
        {"ts": now, "traces": {"t": [{"ttl": 1, "ip": "1.1.1.1; rm -rf /", "loss": 0}]}},
        {"ts": now, "traces": {"t": [{"ttl": 99, "ip": None, "loss": 0}]}},
        {"ts": now, "traces": {"t": ["x"]}},
        [],
    ]
    for b in bad:
        try:
            st.clean_round(b, {"t"}, now)
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        raise AssertionError(f"accepted {b!r}")


SMOKEPING_MAIN = """\
*** General ***
owner = Someone
@include config.d/Probes
@include config.d/Targets

*** Slaves ***
secrets = smokeping_secrets
+porto
display_name = Porto
+Lisbon
+office

*** Database ***
step = 300
pings = 10
"""
SMOKEPING_PROBES = """\
*** Probes ***
+ FPing
binary = /usr/bin/fping
++ FPingFast
pings = 5
+ DNS
binary = /usr/bin/dig
"""
SMOKEPING_TARGETS = """\
*** Targets ***
probe = FPing
menu = Top
title = Network

+ Internet
menu = Internet
title = The internet

++ Cloudflare
menu = Cloudflare DNS
host = 1.1.1.1

++ Fast
probe = FPingFast
host = 8.8.8.8

++ Resolver
probe = DNS
host = 9.9.9.9

++ Both
host = /Internet/Cloudflare /Internet/Fast

+ Remote
slaves = porto
# a comment
++ VPS
title = VPS in Frankfurt
host = 203.0.113.10
nomasterpoll = yes

+++ Deep
slaves = porto office
host = 203.0.113.11
"""


def smokeping_dir(d):
    (Path(d) / "config.d").mkdir()
    Path(d, "config").write_text(SMOKEPING_MAIN, encoding="utf-8")
    Path(d, "config.d", "Probes").write_text(SMOKEPING_PROBES, encoding="utf-8")
    Path(d, "config.d", "Targets").write_text(SMOKEPING_TARGETS, encoding="utf-8")
    Path(d, "smokeping_secrets").write_text("porto:short\noffice:a-long-enough-office-secret\n", encoding="utf-8")
    return Path(d, "config")


def args(**kw):
    import argparse
    base = dict(smokeping=None, targets=Path("nowhere.ini"), agents="", name="home")
    return argparse.Namespace(**{**base, **kw})


def test_smokeping_config():
    with tempfile.TemporaryDirectory() as d:
        cfg = st.load_config(args(smokeping=smokeping_dir(d)))
        t = {x["id"]: x for x in cfg["targets"]}
        assert list(t) == ["internet-cloudflare", "internet-fast", "remote-vps", "remote-vps-deep"], list(t)  # no DNS, no multi-host
        assert (t["internet-cloudflare"]["group"], t["internet-cloudflare"]["name"]) == ("Internet", "Cloudflare DNS")
        assert t["internet-cloudflare"]["slaves"] == [] and t["internet-cloudflare"]["master"]
        assert t["internet-fast"]["host"] == "8.8.8.8"                       # FPingFast is an FPing
        assert t["remote-vps"]["name"] == "VPS in Frankfurt" and not t["remote-vps"]["master"]
        assert t["remote-vps"]["slaves"] == ["porto"]
        assert t["remote-vps-deep"]["group"] == "Remote / VPS in Frankfurt"
        assert t["remote-vps-deep"]["slaves"] == ["porto", "office"] and not t["remote-vps-deep"]["master"]  # inherited
        assert cfg["agents"] == {"porto": "short", "office": "a-long-enough-office-secret"}   # Lisbon: no secret, bad name
        assert (cfg["step"], cfg["pings"]) == (300, 10)
        assert len(cfg["files"]) == 4                                         # config, Probes, Targets, secrets
        cfg = st.load_config(args(smokeping=smokeping_dir(d + "/x") if False else Path(d, "config"),
                                  agents="porto=0123456789abcdefXYZ"))
        assert cfg["agents"]["porto"] == "0123456789abcdefXYZ"                # AGENTS wins over the secrets file
        sources = ["home", "porto", "office"]
        assert st.probers(t["internet-cloudflare"], sources) == ["home"]
        assert st.probers(t["remote-vps"], sources) == ["porto"]
        assert st.probers(t["remote-vps-deep"], sources) == ["porto", "office"]
        assert st.probers({"id": "x"}, sources) == sources                   # targets.ini: everyone probes everything


def test_bare_targets_file_and_reload():
    import os
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "Targets")
        f.write_text("probe = FPing\n+ LAN\n++ Router\nhost = 192.168.1.1\n", encoding="utf-8")
        a = args(smokeping=f)
        st.apply_config(a, st.load_config(a))
        assert [t["id"] for t in st.Handler.targets] == ["lan-router"] and st.Handler.sources == ["home"]
        f.write_text("+ LAN\n++ Router\nhost = 192.168.1.1\n++ NAS\nhost = 192.168.1.20\n", encoding="utf-8")
        os.utime(f, (1000, 1000))                                              # a different mtime, whatever the clock
        st.maybe_reload(a)
        assert [t["id"] for t in st.Handler.targets] == ["lan-router", "lan-nas"]
        f.write_text("+ LAN\n++ Router\nhost = -oops\n++ Bad\nhost = /x\n", encoding="utf-8")
        os.utime(f, (2000, 2000))
        st.maybe_reload(a)                                                    # bad hosts are skipped, not fatal
        assert [t["id"] for t in st.Handler.targets] == []
        Path(d, "Targets").write_text("*** Database ***\nstep = 5\n", encoding="utf-8")
        os.utime(f, (3000, 3000))
        st.maybe_reload(a)                                                    # invalid: the last good config stays
        assert st.STEP == 300


def test_parse_agents():
    assert st.parse_agents("porto=0123456789abcdef, lisbon=fedcba9876543210", "local") == {
        "porto": "0123456789abcdef", "lisbon": "fedcba9876543210"}
    assert st.parse_agents("", "local") == {}
    for spec in ("porto=short", "Porto=0123456789abcdef", "local=0123456789abcdef", "porto"):
        try:
            st.parse_agents(spec, "local")
        except SystemExit:
            continue
        raise AssertionError(spec)


def test_agent_push_end_to_end():
    import threading
    import urllib.error
    import urllib.request
    with tempfile.TemporaryDirectory() as d:
        db = Path(d, "s.db")
        st.init_db(db, "local")
        st.Handler.db, st.Handler.sources = db, ["local", "porto"]
        st.Handler.targets = [{"id": "t", "group": "g", "name": "T", "host": "10.0.0.9"},
                              {"id": "u", "group": "g", "name": "U", "host": "10.0.0.8", "slaves": ["office"]}]
        st.Handler.agents = {"porto": "0123456789abcdef"}
        srv = st.ThreadingHTTPServer(("127.0.0.1", 0), st.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}"

        def call(path, body=None, token="0123456789abcdef"):
            req = urllib.request.Request(url + path, data=body and json.dumps(body).encode(),
                                         headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.load(r)

        try:
            got = call("/api/agent/targets")
            assert got["targets"] == [{"id": "t", "host": "10.0.0.9"}] and got["pings"] == st.PINGS   # not office's "u"
            now = int(__import__("time").time())
            call("/api/agent/push", {"ts": now, "pings": {"t": [5.0] * 20},
                                     "traces": {"t": [{"ttl": 1, "ip": "10.0.0.9", "loss": 0, "avg": 5.0}]}})
            ov = call(f"/api/overview?src=porto")
            assert ov["targets"][0]["status"] == "ok" and ov["targets"][0]["by_source"] == {"local": "stale", "porto": "ok"}
            assert [s["name"] for s in ov["sources"]] == ["local", "porto"]
            for path, body, token in (("/api/agent/targets", None, "wrong-token-xxxxxx"),
                                      ("/api/agent/push", {"ts": now, "pings": {"x": [1.0]}}, "0123456789abcdef"),
                                      ("/api/agent/push", {"ts": now, "pings": {"u": [1.0]}}, "0123456789abcdef"),
                                      ("/api/overview?src=nowhere", None, "")):
                try:
                    call(path, body, token)
                except urllib.error.HTTPError as e:
                    assert e.code in (400, 401), e.code
                else:
                    raise AssertionError(path)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok")
