"""Self-checks for smoketrace (loopback only, no internet). Run: python test_smoketrace.py  (or pytest)."""
import argparse
import json
import math
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import smoketrace as st

TOKEN = "0123456789abcdef"


def hop(ttl, ip, loss=0.0, asn=None):
    return {"ttl": ttl, "ip": ip, "asn": asn, "loss": loss, "avg": 10.0 if ip else None, "best": None, "wrst": None,
            "sd": None}


def target(tid, host="10.0.0.9", **kw):
    return st.make_target(tid, "g", tid.upper(), host, **kw)


def args(**kw):
    base = dict(smokeping=None, targets=Path("nowhere.ini"), agents="", name="home")
    return argparse.Namespace(**{**base, **kw})


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def call(url, body=None, token=TOKEN, cookie=None, form=None):
    headers = {"Authorization": f"Bearer {token}"}
    if cookie:
        headers["Cookie"] = cookie
    data = form.encode() if form else body and json.dumps(body).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=5) as r:
        raw = r.read()
        return json.loads(raw) if r.headers.get("Content-Type", "").startswith("application/json") else raw.decode()


def expect_http(code, fn):
    try:
        fn()
    except urllib.error.HTTPError as e:
        assert e.code == code, (e.code, code)
        return e
    raise AssertionError(f"expected HTTP {code}")


# ---------- parsing ----------

def test_fping_timeout():
    assert st.fping_timeout(5) == st.PINGS * 3 + 30                  # few hosts: the old floor
    assert st.fping_timeout(640) > 640 * st.PINGS * 0.010             # many hosts: room for every packet at -i10
    assert st.fping_timeout(100000) <= st.STEP - 10                   # never past the next round


def test_trace_plan():
    ts = 1_000_200
    few = [target(f"t{i}", f"10.0.0.{i}") for i in range(10)]
    assert st.trace_plan(few, ts) == few and st.trace_workers(10) == 4         # few targets: all, every round
    many = [target(f"t{i:03d}", f"10.0.{i // 250}.{i % 250}") for i in range(555)]
    room, w = st.trace_capacity(), st.trace_workers(st.trace_capacity())
    assert w == st.TRACE_PARALLEL and math.ceil(room / w) * (st.MTR_CYCLES + 5) <= st.STEP   # a round's traces fit
    plans = [st.trace_plan(many, ts + r * st.STEP, lossy={"t554"}) for r in range(8)]
    assert all(len(p) <= room and "t554" in {t["id"] for t in p} for p in plans)   # lossy ones every round
    k = math.ceil(555 / (room * 3 // 4))
    assert len({t["id"] for p in plans[:k] for t in p}) == 555                       # everyone within k rounds
    assert st.lost({"a": [1.0, None], "b": [1.0, 2.0]}) == {"a"}


def test_trace_step():
    ts, few = 1_000_200, [target(f"t{i}", f"10.0.0.{i}") for i in range(10)]
    old = st.TRACE_STEP
    try:
        st.TRACE_STEP = st.STEP * 5            # pings every round, each target traced every fifth
        plans = [st.trace_plan(few, ts + r * st.STEP) for r in range(5)]
        assert all(len(p) == 2 for p in plans) and len({t["id"] for p in plans for t in p}) == 10
        assert {t["id"] for t in st.trace_plan(few, ts, lossy={"t9"})} >= {"t9"}          # loss starting: out of turn
        assert st.steps()["trace_step"] == st.STEP * 5
        st.take_steps({"step": 180, "pings": 20})                                         # an older server: no TRACE_STEP
        assert st.TRACE_STEP is None and st.trace_plan(few, ts) == few
    finally:
        st.TRACE_STEP, st.STEP = old, st.DEFAULT_STEP
    assert [st.duration(v, "X") for v in ("180", "3m", "15m", "90s", "1h")] == [180, 180, 900, 90, 3600]
    try:
        st.duration("soon", "TRACE_STEP")
        raise AssertionError("accepted a bad duration")
    except SystemExit as e:
        assert "TRACE_STEP" in str(e)
    lossy = st.Lossy()
    lossy.update({"a": [None], "b": [1.0]})
    assert lossy.fresh == {"a"}
    lossy.update({"a": [None], "b": [None]})
    assert lossy.fresh == {"b"}                # "a" kept losing: traced in its turn, not every round


def test_new_agents_probe_every_target():
    ts = [target("a", slaves=["porto"]), target("b", slaves=[]), target("c")]
    assert st.add_new_agents(ts, ["porto", "lisboa"], None) == ["lisboa"]       # porto is named, lisboa is new
    assert [t["slaves"] for t in ts] == [["porto", "lisboa"], ["lisboa"], None]
    ts = [target("a", slaves=["porto"]), target("b", slaves=[])]
    assert st.add_new_agents(ts, ["porto", "lisboa"], {"porto", "lisboa"}) == []  # lisboa taken off on purpose
    assert ts[1]["slaves"] == []
    assert st.add_new_agents([target("c")], ["porto"], None) == []                # every agent probes it already
    with tempfile.TemporaryDirectory() as d:
        ini, js = Path(d, "targets.ini"), Path(d, "targets.json")
        ini.write_text("[g]\n", encoding="utf-8")
        st.save_json_targets(js, [target("a", slaves=["porto"]), target("b", slaves=[])])
        body = json.loads(js.read_text(encoding="utf-8"))
        del body["agents"]                     # a targets.json from before the agents list
        js.write_text(json.dumps(body), encoding="utf-8")
        cfg = st.load_config(args(targets=ini, agents="porto=" + "p" * 24 + ",faro=" + "f" * 24))
        assert [t["slaves"] for t in cfg["targets"]] == [["porto", "faro"], ["faro"]]
        assert json.loads(js.read_text(encoding="utf-8"))["agents"] == ["faro", "porto"]   # remembered
        cfg["targets"][1]["slaves"] = []       # faro taken off b on the page
        st.save_json_targets(js, cfg["targets"], ["porto", "faro"])
        cfg = st.load_config(args(targets=ini, agents="porto=" + "p" * 24 + ",faro=" + "f" * 24))
        assert cfg["targets"][1]["slaves"] == []                                            # and it stays off


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


def test_parse_mtr_with_asn():
    raw = {"report": {"hubs": [
        {"count": "1", "host": "192.168.1.1", "ASN": "AS???", "Loss%": 0.0, "Avg": 0.5, "Best": 0.3, "Wrst": 0.9,
         "StDev": 0.1},
        {"count": 2, "host": "1.1.1.1", "ASN": "AS13335", "Loss%": 0.0, "Avg": 9.5, "Best": 9.1, "Wrst": 10.2,
         "StDev": 0.2},
        {"count": 3, "host": "???", "Loss%": 100.0, "Avg": 0.0, "Best": 0.0, "Wrst": 0.0, "StDev": 0.0}]}}
    a, b, c = st.parse_mtr(json.dumps(raw))
    assert a == {"ttl": 1, "ip": "192.168.1.1", "asn": None, "loss": 0.0, "avg": 0.5, "best": 0.3, "wrst": 0.9, "sd": 0.1}
    assert b["asn"] == "AS13335" and c["ip"] is None and c["avg"] is None


def test_hosts_and_mtr_commands():
    assert st.parse_host("1.1.1.1") == {"host": "1.1.1.1", "probe": "icmp"}
    assert st.parse_host("tcp://example.com:443") == {"host": "example.com", "probe": "tcp", "port": 443}
    assert st.parse_host("tcp://[2606:4700::1111]:53")["host"] == "2606:4700::1111"
    assert st.parse_host("dns://9.9.9.9/example.org") == {"host": "9.9.9.9", "probe": "dns", "lookup": "example.org"}
    for bad in (dict(host="-oops"), dict(host="h", probe="tcp", port=None), dict(host="h", probe="tcp", port=70000),
                dict(host="h", probe="dns", lookup="a b"), dict(host="h", probe="curl")):
        try:
            target("x", **bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    st.ASN_LOOKUP = True
    assert st.mtr_command(target("a", "1.1.1.1")) == ["mtr", "--json", "-n", "-c", "10", "-z", "1.1.1.1"]
    assert st.mtr_command(target("b", "h", probe="tcp", port=443))[-4:] == ["-T", "-P", "443", "h"]
    cmd = st.mtr_command(target("c", "9.9.9.9", probe="dns", lookup="example.org"))
    assert cmd[-4:] == ["-T", "-P", "53", "9.9.9.9"]


def test_route_segments():
    A = [hop(1, "a"), hop(2, "b"), hop(3, "c")]
    A_silent = [hop(1, "a"), hop(2, None, 100), hop(3, "c"), hop(4, None, 100)]   # silent mid + trailing hop
    B = [hop(1, "a"), hop(2, "x"), hop(3, "c")]
    segs, known = st.route_segments([(ts, st.path_key(h)) for ts, h in ((0, A), (300, A_silent), (600, B), (900, A))])
    assert [s["route"] for s in segs] == [0, 1, 0]           # silent hops are not a change; A comes back as A
    assert [(s["from"], s["to"], s["end"]) for s in segs] == [(0, 300, 600), (600, 600, 900), (900, 900, 1200)]
    assert known == [["a", "b", "c"], ["a", "x", "c"]]
    assert not st.same_path(["a", "b"], ["a", "b", "c"])     # different hop count = different route
    assert st.split_path(st.path_key(A_silent)) == st.path_of(A_silent) == ["a", None, "c"]
    assert st.split_path(st.path_key([hop(1, None, 100)])) == []


def test_loss_origin():
    assert st.loss_origin([hop(1, "a"), hop(2, "b", 50), hop(3, "c")]) is None    # rate-limiting
    real = [hop(1, "a"), hop(2, "b", 40), hop(3, "c"), hop(4, "d", 10), hop(5, None, 100), hop(6, "e", 10)]
    assert st.loss_origin(real) == 4                         # persists to the end, silent hop skipped


def test_diff_hops():
    prev = [hop(1, "a"), hop(2, "b"), hop(3, "c")]
    cur = [hop(1, "a"), hop(2, "x"), hop(3, None, 100), hop(4, "d")]
    assert [r["state"] for r in st.diff_hops(prev, cur)] == ["same", "changed", "unknown", "added"]
    assert [r["state"] for r in st.diff_hops(cur, prev)][-1] == "removed"
    assert {r["state"] for r in st.diff_hops(None, cur)} == {None}


def test_status_thresholds_and_bucketize():
    now = 10_000
    assert st.status_of(now, None, None, None, None) == "stale"
    assert st.status_of(now, now, None, 100.0, 20) == "down"
    assert st.status_of(now, now, 20, 25.0, 20) == "crit"
    assert st.status_of(now, now, 41, 0.0, 20) == "warn"     # 41 > 20 * 1.5 + 10
    assert st.status_of(now, now, 39, 0.0, 20) == "ok"
    strict = {"loss_warn": 1.0, "loss_crit": 5.0, "latency_warn": 30.0}
    assert st.status_of(now, now, 20, 5.0, 20, strict) == "crit"
    assert st.status_of(now, now, 31, 0.0, 30, strict) == "warn"   # above its own latency limit
    assert st.status_of(now, now, 20, 10.0, 20, {"loss_warn": 15.0}) == "ok"
    rows = [(0, 10.0, 0.0, 1.0, json.dumps([9.0, 10.0, 11.0])), (300, 20.0, 50.0, None, json.dumps([20.0]))]
    (pt,) = st.bucketize(rows, 600)
    assert pt[0] == 0 and pt[1] == 10.5 and pt[2] == 25.0 and pt[3] == 1.0 and len(pt[4]) == st.PINGS


def test_load_targets():
    with tempfile.TemporaryDirectory() as d:
        ok, bad = Path(d, "ok.ini"), Path(d, "bad.ini")
        ok.write_text("[Internet]\nCloudflare DNS = 1.1.1.1  # comment\nShop = tcp://shop.example:443\n"
                      "[Serviços]\nResolver = dns://9.9.9.9/example.org\n", encoding="utf-8")
        bad.write_text("[x]\nevil = -f/etc/passwd\n", encoding="utf-8")
        t = st.load_targets(ok)
        assert [x["id"] for x in t] == ["internet-cloudflare-dns", "internet-shop", "servicos-resolver"]
        assert (t[0]["probe"], t[1]["probe"], t[1]["port"], t[2]["lookup"]) == ("icmp", "tcp", 443, "example.org")
        assert t[0]["slaves"] is None and t[0]["master"]
        try:
            st.load_targets(bad)
        except SystemExit:
            pass
        else:
            raise AssertionError("option-like host accepted")


# ---------- SmokePing ----------

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
url = http://office.lan:8100

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
lookup = example.org
+ TCPPing
port = 443
+ Curl
"""
SMOKEPING_TARGETS = """\
*** Targets ***
probe = FPing
menu = Top
title = Network

+ Internet
menu = Internet
title = The internet
loss_warn = 10

++ Cloudflare
menu = Cloudflare DNS
host = 1.1.1.1
latency_warn = 40

++ Fast
probe = FPingFast
host = 8.8.8.8

++ Resolver
probe = DNS
host = 9.9.9.9

++ Shop
probe = TCPPing
host = shop.example
port = 8443

++ Page
probe = Curl
host = example.org

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


def test_smokeping_config():
    with tempfile.TemporaryDirectory() as d:
        cfg = st.load_config(args(smokeping=smokeping_dir(d)))
        t = {x["id"]: x for x in cfg["targets"]}
        assert list(t) == ["internet-cloudflare", "internet-fast", "internet-resolver", "internet-shop",
                           "remote-vps", "remote-vps-deep"], list(t)               # no Curl, no multi-host
        c = t["internet-cloudflare"]
        assert (c["group"], c["name"], c["probe"]) == ("Internet", "Cloudflare DNS", "icmp")
        assert (c["loss_warn"], c["latency_warn"], c["loss_crit"]) == (10.0, 40.0, None)   # inherited, own, default
        assert c["slaves"] == [] and c["master"]
        assert t["internet-fast"]["probe"] == "icmp"                             # FPingFast is an FPing
        assert (t["internet-resolver"]["probe"], t["internet-resolver"]["lookup"]) == ("dns", "example.org")
        assert (t["internet-shop"]["probe"], t["internet-shop"]["port"]) == ("tcp", 8443)   # the target's port wins
        assert t["remote-vps"]["name"] == "VPS in Frankfurt" and not t["remote-vps"]["master"]
        assert t["remote-vps"]["slaves"] == ["porto"]
        assert t["remote-vps-deep"]["group"] == "Remote / VPS in Frankfurt"
        assert t["remote-vps-deep"]["slaves"] == ["porto", "office"] and not t["remote-vps-deep"]["master"]
        assert cfg["agents"] == {"porto": {"token": "short", "url": None},
                                 "office": {"token": "a-long-enough-office-secret", "url": "http://office.lan:8100"}}
        assert (cfg["step"], cfg["pings"]) == (300, 10)
        assert len(cfg["files"]) == 4                                         # config, Probes, Targets, secrets
        cfg = st.load_config(args(smokeping=Path(d, "config"), agents="porto=0123456789abcdefXYZ"))
        assert cfg["agents"]["porto"]["token"] == "0123456789abcdefXYZ"        # AGENTS wins over the secrets file
        sources = ["home", "porto", "office"]
        assert st.probers(t["internet-cloudflare"], sources) == ["home"]
        assert st.probers(t["remote-vps-deep"], sources) == ["porto", "office"]
        assert st.probers({"id": "x"}, sources) == sources                   # targets.ini: everyone probes everything


def test_smokeping_from_another_container():
    """linuxserver/smokeping: a folder of split files, @include and secrets as absolute /config/... paths."""
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "target").mkdir()
        Path(d, "Probes").write_text("*** Probes ***\n+ FPing\nbinary = /usr/sbin/fping\n", encoding="utf-8")
        Path(d, "Slaves").write_text("*** Slaves ***\nsecrets = /config/smokeping_secrets\n+porto\n", encoding="utf-8")
        Path(d, "smokeping_secrets").write_text("porto:" + TOKEN + "\n", encoding="utf-8")
        Path(d, "Targets").write_text("*** Targets ***\nprobe = FPing\nmenu = Top\ntitle = Top\n"
                                      "@include /config/target/dns.conf\n@include /config/target/gone.conf\n",
                                      encoding="utf-8")
        Path(d, "target", "dns.conf").write_text("+ DNS\nmenu = DNS\n++ Cloudflare\nhost = 1.1.1.1\n", encoding="utf-8")
        Path(d, "Alerts").write_text("*** Alerts ***\nto = root@localhost\n", encoding="utf-8")
        for path in (Path(d), Path(d, "Targets")):
            cfg = st.load_config(args(smokeping=path))
            assert [t["id"] for t in cfg["targets"]] == ["dns-cloudflare"], cfg["targets"]
        cfg = st.load_config(args(smokeping=Path(d)))      # the folder: Probes, Slaves and secrets come along
        assert cfg["agents"] == {"porto": {"token": TOKEN, "url": None}}
        Path(d, "config").write_text("@include Probes\n@include Slaves\n@include Targets\n", encoding="utf-8")
        assert st.load_config(args(smokeping=Path(d)))["agents"] == {"porto": {"token": TOKEN, "url": None}}
        try:
            st.load_config(args(smokeping=Path(d, "nothing")))
        except SystemExit as e:
            assert "cannot read" in str(e)
        else:
            raise AssertionError("a missing main file must stop the start")


def test_bare_targets_file_and_reload():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "Targets")
        f.write_text("probe = FPing\n+ LAN\n++ Router\nhost = 192.168.1.1\n", encoding="utf-8")
        a = args(smokeping=f)
        st.apply_config(a, st.load_config(a))
        assert [t["id"] for t in st.Handler.targets] == ["lan-router"] and st.Handler.sources == ["home"]
        f.write_text("+ LAN\n++ Router\nhost = 192.168.1.1\n++ NAS\nhost = 192.168.1.20\n", encoding="utf-8")
        os.utime(f, (1000, 1000))                                             # a different mtime, whatever the clock
        st.maybe_reload(a)
        assert [t["id"] for t in st.Handler.targets] == ["lan-router", "lan-nas"]
        f.write_text("+ LAN\n++ Router\nhost = -oops\n++ Bad\nhost = /x\n", encoding="utf-8")
        os.utime(f, (2000, 2000))
        st.maybe_reload(a)                                                    # bad hosts are skipped, not fatal
        assert [t["id"] for t in st.Handler.targets] == []
        f.write_text("*** Database ***\nstep = 5\n", encoding="utf-8")
        os.utime(f, (3000, 3000))
        st.maybe_reload(a)                                                    # invalid: the last good config stays
        assert st.STEP == 300


def test_parse_agents():
    assert st.parse_agents("porto=0123456789abcdef, office=fedcba9876543210@http://office:8100", "local") == {
        "porto": {"token": "0123456789abcdef", "url": None},
        "office": {"token": "fedcba9876543210", "url": "http://office:8100"}}
    assert st.parse_agents("", "local") == {}
    for spec in ("porto=short", "Porto=0123456789abcdef", "local=0123456789abcdef", "porto",
                 "porto=0123456789abcdef@ftp://x"):
        try:
            st.parse_agents(spec, "local")
        except SystemExit:
            continue
        raise AssertionError(spec)


# ---------- RRD import ----------

def test_rrd_fetch_parsing():
    text = ("                          uptime               loss             median              ping1              ping2\n"
            "\n"
            "1792400100: 1.0000000000e+03 0.0000000000e+00 1.2000000000e-02 1.1000000000e-02 1.3000000000e-02\n"
            "1792400400: -nan 2.0000000000e+00 -nan -nan -nan\n"
            "1792400700: -nan -nan -nan -nan -nan\n")
    names, data = st.parse_rrd_fetch(text)
    assert names == ["uptime", "loss", "median", "ping1", "ping2"] and len(data) == 3
    rows = st.rrd_rows("home", "lan-router", names, data, 300)
    assert rows[0] == ("home", "lan-router", 1792399800, 12.0, 0.0, None, "[11.0, 13.0]")
    assert rows[1][3:5] == (None, 100.0) and len(rows) == 2                  # all lost; the unknown row is dropped


# ---------- storage ----------

def test_trace_detail_compares_previous_route():
    A = [hop(1, "a", asn="AS1"), hop(2, "b")]
    B = [hop(1, "a", asn="AS1"), hop(2, "x", asn="AS2")]
    with tempfile.TemporaryDirectory() as d:
        db = Path(d, "t.db")
        st.init_db(db, "local")
        st.store(db, [], [("local", "t", ts, json.dumps(h), st.path_key(h)) for ts, h in ((0, A), (300, A), (600, B), (900, B))], 900)
        with st.db_open(db) as c:
            assert sorted(r[0] for r in c.execute("SELECT asn FROM asn WHERE name IS NULL")) == ["AS1", "AS2"]
            c.execute("UPDATE asn SET name='ONE - First Net' WHERE asn='AS1'")
        with st.db_open(db) as c:
            r = st.trace_detail(c, "local", "t", None, "route")
            assert (r["cur"]["ts"], r["cur"]["label"], r["prev"]["ts"], r["prev"]["label"]) == (900, "B", 300, "A")
            assert [x["state"] for x in r["rows"]] == ["same", "changed"]
            assert r["asn_names"] == {"AS1": "ONE - First Net", "AS2": None}
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


def test_upgrade_from_0_5_indexes_routes_and_rounds():
    with tempfile.TemporaryDirectory() as d:
        db = Path(d, "old.db")
        with st.db_open(db) as c:   # the 0.2 to 0.5 schema: no path table, no rounds table
            c.execute("CREATE TABLE ping (source TEXT, target TEXT, ts INTEGER, median REAL, loss REAL, jitter REAL,"
                      " rtts TEXT, PRIMARY KEY (source, target, ts)) WITHOUT ROWID")
            c.execute("CREATE TABLE trace (source TEXT, target TEXT, ts INTEGER, hops TEXT,"
                      " PRIMARY KEY (source, target, ts)) WITHOUT ROWID")
            c.execute("INSERT INTO ping VALUES ('local', 't', 300, 10.0, 0.0, 1.0, '[10.0]')")
            c.execute("INSERT INTO trace VALUES ('local', 't', 300, ?)", (json.dumps([hop(1, "a"), hop(2, None, 100), hop(3, "c")]),))
        st.init_db(db, "local")
        st.store(db, *st.round_rows("local", 600, {"t": [10.0]}, {"t": [hop(1, "a"), hop(2, "b"), hop(3, "c")]}), 600)
        st.fill_paths(db, [("local", "t"), ("local", "gone")])
        st.fill_paths(db, [("local", "t")])          # nothing left to do
        with st.db_open(db) as c:
            assert st.load_paths(c, "local", "t") == [(300, "a,,c"), (600, "a,b,c")]
            assert st.last_rounds(c) == {"local": 600}
            assert [s["route"] for s in st.route_segments(st.load_paths(c, "local", "t"))[0]] == [0]   # silent hop
        st.store(db, *st.round_rows("local", 600 + 31 * 86400, {"t": [10.0]}, {}), 600 + 31 * 86400)
        with st.db_open(db) as c:                    # a month later: the old rows are gone, target by target
            assert c.execute("SELECT COUNT(*) FROM trace").fetchone()[0] == 0
            assert c.execute("SELECT COUNT(*) FROM path").fetchone()[0] == 0


def test_clean_round():
    now = 1_000_000
    good = {"ts": now - 7, "pings": {"t": [1.5, None]},
            "traces": {"t": [{"ttl": 1, "ip": "10.0.0.1", "asn": "AS64496", "loss": 0, "avg": 1.2, "extra": "dropped"},
                             {"ttl": 2, "ip": None, "loss": 100}]}}
    ts, pings, traces = st.clean_round(good, {"t"}, now)
    assert ts == (now - 7) // st.STEP * st.STEP and pings == {"t": [1.5, None]}
    assert traces["t"][0] == {"ttl": 1, "ip": "10.0.0.1", "asn": "AS64496", "loss": 0.0, "avg": 1.2, "best": None,
                              "wrst": None, "sd": None}
    assert st.clean_round({"ts": now, "pings": None, "traces": {}}, {"t"}, now)[1] is None   # fping failed there
    bad = [
        {"ts": now, "pings": {"unknown": [1.0]}},                       # target the server does not give that agent
        {"ts": now, "pings": {"t": [float("nan")]}},
        {"ts": now, "pings": {"t": ["1"]}},
        {"ts": True, "pings": {}},
        {"ts": now - 40 * 86400},                                       # older than the retention
        {"ts": now, "traces": {"t": [{"ttl": 1, "ip": "1.1.1.1; rm -rf /", "loss": 0}]}},
        {"ts": now, "traces": {"t": [{"ttl": 1, "ip": "1.1.1.1", "asn": "<script>", "loss": 0}]}},
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
    assert st.agent_targets([{"id": "ok", "host": "1.1.1.1", "probe": "icmp", "port": None, "lookup": None},
                             {"id": "bad", "host": "-x", "probe": "icmp"}, "junk"]) == [
        {"id": "ok", "host": "1.1.1.1", "probe": "icmp", "port": None, "lookup": None}]


# ---------- probes over loopback ----------

def test_tcp_and_dns_probes():
    st.PINGS = 2
    try:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        threading.Thread(target=lambda: [listener.accept()[0].close() for _ in range(2)], daemon=True).start()
        got = st.tcp_ping(target("w", "127.0.0.1", probe="tcp", port=port))
        assert len(got) == 2 and all(v is not None and v < 1000 for v in got), got
        listener.close()

        dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # a resolver that answers one TXT record
        dns.bind(("127.0.0.1", 0))

        def answer():
            for _ in range(3):
                q, peer = dns.recvfrom(512)
                qend = 12 + q[12:].index(b"\0") + 5
                txt = b"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
                ans = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(txt) + 1) + bytes([len(txt)]) + txt
                dns.sendto(q[:2] + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0) + q[12:qend] + ans, peer)
        threading.Thread(target=answer, daemon=True).start()
        server = dns.getsockname()

        orig = socket.getaddrinfo
        socket.getaddrinfo = lambda h, p, **kw: orig(h, server[1] if p == 53 else p, **kw)   # port 53 -> our port
        try:
            got = st.dns_ping(target("r", "127.0.0.1", probe="dns", lookup="example.org"))
            assert len(got) == 2 and all(v is not None for v in got), got
            assert st.dns_txt("AS13335.asn.cymru.com", "127.0.0.1")[0].endswith("Cloudflare, Inc., US")
        finally:
            socket.getaddrinfo = orig
            dns.close()
    finally:
        st.PINGS = st.DEFAULT_PINGS


# ---------- the server over HTTP ----------

def server_with(d, **handler):
    db = Path(d, "s.db")
    st.init_db(db, "local")
    st.Handler.db = db
    st.Handler.sources = ["local", "porto", "office"]
    st.Handler.targets = [target("t"), target("u", "10.0.0.8", slaves=["office"])]
    st.Handler.agents = {"porto": {"token": TOKEN, "url": None}, "office": {"token": "office-" + TOKEN, "url": None}}
    for k, v in handler.items():
        setattr(st.Handler, k, v)
    return (db, *serve(st.Handler))


def test_agent_push_end_to_end():
    with tempfile.TemporaryDirectory() as d:
        db, srv, url = server_with(d)
        try:
            got = call(url + "/api/agent/targets")
            assert [t["id"] for t in got["targets"]] == ["t"] and got["pings"] == st.PINGS   # not office's "u"
            assert got["targets"][0] == {"id": "t", "host": "10.0.0.9", "probe": "icmp", "port": None, "lookup": None}
            now = int(time.time())
            call(url + "/api/agent/push", {"ts": now, "pings": {"t": [5.0] * 20},
                                           "traces": {"t": [{"ttl": 1, "ip": "10.0.0.9", "loss": 0, "avg": 5.0}]}})
            ov = call(url + "/api/overview?src=porto")
            assert [t["id"] for t in ov["targets"]] == ["t"]                  # porto does not probe "u"
            assert ov["targets"][0]["status"] == "ok" and ov["targets"][0]["by_source"] == {"local": "stale", "porto": "ok", "office": "stale"}
            assert [s["name"] for s in ov["sources"]] == ["local", "porto", "office"] and ov["auth"] is False
            expect_http(401, lambda: call(url + "/api/agent/targets", token="wrong-token-xxxxxx"))
            expect_http(400, lambda: call(url + "/api/agent/push", {"ts": now, "pings": {"u": [1.0]}}))
            expect_http(400, lambda: call(url + "/api/overview?src=nowhere"))
        finally:
            srv.shutdown()
            srv.server_close()


def test_sign_in_and_metrics():
    with tempfile.TemporaryDirectory() as d:
        db, srv, url = server_with(d)
        st.PASSWORD, st.METRICS_TOKEN = "correct horse", "metrics-" + TOKEN
        st.Handler.metrics_cache = (0, None, "")
        try:
            now = int(time.time())
            st.store(db, *st.round_rows("local", now // 300 * 300, {"t": [10.0, 12.0, None, 11.0]}, {}), now)
            expect_http(401, lambda: call(url + "/api/overview"))
            page = urllib.request.urlopen(url + "/", timeout=5)                 # redirected to the sign-in page
            assert page.url.endswith("/login") and "Password" in page.read().decode()
            e = expect_http(401, lambda: call(url + "/login", form="password=wrong"))
            assert "Wrong password" in e.read().decode()

            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw):
                    return None
            try:
                urllib.request.build_opener(NoRedirect).open(url + "/login", data=b"password=correct+horse", timeout=5)
            except urllib.error.HTTPError as e:
                assert e.code == 303
                cookie = e.headers["Set-Cookie"].split(";")[0]
                assert "HttpOnly" in e.headers["Set-Cookie"] and "SameSite=Strict" in e.headers["Set-Cookie"]
            ov = call(url + "/api/overview", cookie=cookie)
            assert ov["auth"] is True and ov["targets"][0]["median"] == 11.0
            forged = "smoketrace=" + str(int(time.time()) + 999) + ".00"
            expect_http(401, lambda: call(url + "/api/overview", cookie=forged))

            expect_http(401, lambda: call(url + "/metrics", token="wrong"))
            text = call(url + "/metrics", token=st.METRICS_TOKEN)
            assert 'smoketrace_median_seconds{target="t",name="T",group="g",host="10.0.0.9",probe="icmp",source="local"} 0.011' in text
            assert 'smoketrace_loss_ratio{target="t",name="T",group="g",host="10.0.0.9",probe="icmp",source="local"} 0.25' in text
            assert 'smoketrace_status{target="t",name="T",group="g",host="10.0.0.9",probe="icmp",source="porto"} 4' in text
            assert "# TYPE smoketrace_route_changes_24h gauge" in text
        finally:
            st.PASSWORD = st.METRICS_TOKEN = None
            srv.shutdown()
            srv.server_close()


def test_agent_with_the_servers_agents_line_instead_of_token():
    seen, saved = {}, (st.run_agent, st.shutil.which, sys.argv)
    st.run_agent = lambda server, token, *_: seen.update(server=server, token=token)
    st.shutil.which = lambda b: "/usr/bin/" + b
    try:
        sys.argv = ["smoketrace.py", "--agent", "https://s.example/", "--agents", "fs-opo=" + TOKEN, "--name", "fs-opo", "--token", ""]
        st.main()
        assert seen == {"server": "https://s.example", "token": TOKEN}      # the agent's own entry in AGENTS
        sys.argv = ["smoketrace.py", "--agent", "https://s.example", "--agents", "", "--token", ""]
        try:
            st.main()
            raise AssertionError("an agent without a token must not start")
        except SystemExit as e:
            assert "TOKEN" in str(e) and "AGENTS" in str(e)
    finally:
        st.run_agent, st.shutil.which, sys.argv = saved


def test_version_matches_the_changelog():
    top = next(line for line in (Path(st.__file__).parent / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
               if line.startswith("## ["))
    assert top.startswith(f"## [{st.VERSION}]"), (top, st.VERSION)


def test_targets_edited_on_the_page():
    with tempfile.TemporaryDirectory() as d:
        ini = Path(d, "targets.ini")
        ini.write_text("[Internet]\nCloudflare = 1.1.1.1\nShop = tcp://203.0.113.20:443\n", encoding="utf-8")
        a = args(targets=ini)
        cfg = st.load_config(a)
        assert cfg["source"] == "ini" and [t["id"] for t in cfg["targets"]] == ["internet-cloudflare", "internet-shop"]
        st.apply_config(a, cfg)
        # the list functions: a rename keeps the id (and so the history); a new target never reuses one
        new = st.edit_targets(cfg["targets"], "save", {"id": "internet-cloudflare", "group": "DNS", "name": "Cloudflare 1",
                                                      "address": "1.0.0.1", "loss_warn": 5})
        assert new[0]["id"] == "internet-cloudflare" and new[0]["group"] == "DNS" and new[0]["loss_warn"] == 5.0
        new = st.edit_targets(new, "save", {"group": "Internet", "name": "Cloudflare", "address": "dns://1.1.1.1/example.org"})
        assert new[-1]["id"] == "internet-cloudflare-2" and new[-1]["probe"] == "dns"
        for bad, field in (({"group": "", "name": "x", "address": "1.1.1.1"}, "group"),
                           ({"group": "g", "name": "x", "address": "-oops"}, "address"),
                           ({"group": "DNS", "name": "Cloudflare 1", "address": "9.9.9.9"}, "name"),
                           ({"group": "g", "name": "x", "address": "1.1.1.1", "loss_warn": 150}, "loss_warn")):
            try:
                st.edit_targets(new, "save", bad)
                raise AssertionError(bad)
            except ValueError as e:
                assert str(e).startswith(field + ":"), e
        assert [t["id"] for t in st.edit_targets(new, "delete", {"id": "internet-shop"})] == ["internet-cloudflare", "internet-cloudflare-2"]
        # over HTTP: only signed in, only JSON; the first edit moves the list to targets.json, which then wins
        db = Path(d, "s.db")
        st.init_db(db, "home")
        st.Handler.db = db
        srv, url = serve(st.Handler)
        try:
            st.PASSWORD = None
            assert call(url + "/api/targets")["editable"] is False                      # no password: read-only
            expect_http(403, lambda: call(url + "/api/targets", {"op": "delete", "id": "internet-shop"}))
            st.PASSWORD = "correct horse"
            cookie = "smoketrace=" + st.session_value(int(time.time()) + 3600)
            expect_http(401, lambda: call(url + "/api/targets", {"op": "delete", "id": "internet-shop"}))
            req = urllib.request.Request(url + "/api/targets", data=b'{"op":"delete","id":"internet-shop"}',
                                         headers={"Cookie": cookie, "Content-Type": "text/plain"})
            expect_http(403, lambda: urllib.request.urlopen(req, timeout=5))             # a cross-site form cannot send JSON

            def post(body):
                req = urllib.request.Request(url + "/api/targets", data=json.dumps(body).encode(),
                                             headers={"Cookie": cookie, "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    return json.load(r)
            out = post({"op": "save", "group": "Internet", "name": "Quad9", "address": "9.9.9.9"})
            assert out["source"] == "page" and [t["name"] for t in out["targets"]] == ["Cloudflare", "Shop", "Quad9"]
            assert Path(d, "targets.json").exists() and [t["name"] for t in st.Handler.targets] == ["Cloudflare", "Shop", "Quad9"]
            e = expect_http(400, lambda: post({"op": "save", "group": "Internet", "name": "Bad", "address": "not a host!"}))
            assert json.loads(e.read())["field"] == "address"
            ini.write_text("[Other]\nX = 10.0.0.1\n", encoding="utf-8")                   # targets.ini no longer counts
            assert [t["name"] for t in st.load_config(a)["targets"]] == ["Cloudflare", "Shop", "Quad9"]
        finally:
            st.PASSWORD = None
            srv.shutdown()
            srv.server_close()


def test_pull_round_trip():
    """The pull agent's HTTP side: targets in, rounds out, acknowledged rounds dropped."""
    with tempfile.TemporaryDirectory() as d:
        db, srv, url = server_with(d)
        srv.shutdown()
        srv.server_close()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        ticks = []
        orig = st.every_round
        st.every_round = lambda fn: ticks.append(fn)     # keep the agent's round function, do not loop
        try:
            threading.Thread(target=st.run_listener,
                             args=(f"127.0.0.1:{port}", "pull-" + TOKEN,
                                   lambda targets, ts: {t["id"]: [7.0] * 20 for t in targets},
                                   lambda t, ts: [hop(1, "10.0.0.9")]), daemon=True).start()
            for _ in range(50):
                if ticks:
                    break
                time.sleep(0.05)
            time.sleep(0.3)
            agent = {"token": "pull-" + TOKEN, "url": f"http://127.0.0.1:{port}"}
            st.Handler.agents["office"] = agent
            st.pull_agent(db, "office", agent)                 # the agent learns its targets ("t" and "u")
            now = int(time.time()) // 300 * 300
            ticks[0](now)                                      # one round on the agent
            st.pull_agent(db, "office", agent)                 # the server takes it and acknowledges it
            with st.db_open(db) as c:
                rows = c.execute("SELECT source, target, ts, median FROM ping ORDER BY target").fetchall()
            assert rows == [("office", "t", now, 7.0), ("office", "u", now, 7.0)], rows
            assert st.PULL_ACK["office"] == now
            st.pull_agent(db, "office", agent)                 # acknowledged: nothing comes twice
            with st.db_open(db) as c:
                assert c.execute("SELECT COUNT(*) FROM ping").fetchone()[0] == 2
        finally:
            st.every_round = orig
            st.PULL_ACK.clear()


# ---------- alerts ----------

def test_alerts():
    got = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append((self.path, dict(self.headers), self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):
            pass

    sink, base = serve(Sink)
    with tempfile.TemporaryDirectory() as d:
        db, srv, url = server_with(d)
        st.Handler.targets = [target("t")]
        st.Handler.sources = ["local", "porto"]
        alerts = st.Alerter(base + "/discord", base + "/ntfy", base + "/hook")
        st.PUBLIC_URL = "https://st.example"
        A = [hop(1, "10.0.0.1"), hop(2, "198.51.100.1", asn="AS64497"), hop(3, "10.0.0.9")]
        B = [hop(1, "10.0.0.1"), hop(2, "198.51.100.9", 20, asn="AS64498"), hop(3, "10.0.0.9", 20)]
        try:
            now = int(time.time()) // 300 * 300 - 600

            def rnd(i, rtts, hops):
                ts = now + i * 300
                st.store(db, *st.round_rows("local", ts, {"t": rtts}, {"t": hops}), ts)
                alerts.check(db, "local")

            ok, lossy = [10.0] * 20, [10.0] * 15 + [None] * 5
            rnd(0, ok, A)          # first look: remembered, nothing sent
            rnd(1, lossy, B)       # one round of crit and a new route: not yet
            assert not got
            rnd(2, lossy, B)       # second round: both confirmed
            for _ in range(50):
                if len(got) >= 6:
                    break
                time.sleep(0.05)
            assert len(got) == 6, [g[0] for g in got]          # 2 events x 3 channels
            hooks = [json.loads(g[2]) for g in got if g[0] == "/hook"]
            status = next(h for h in hooks if h["kind"] == "status")
            route = next(h for h in hooks if h["kind"] == "route")
            assert status["level"] == "crit" and status["previous"] == "ok" and status["title"] == "T is critical"
            assert any("Real loss starts at hop 2 (198.51.100.9, AS64498" in line for line in status["lines"]), status
            assert "Seen from porto: no data" in status["lines"] and status["url"] == "https://st.example/#/t/t"
            assert route["title"] == "Route to T changed" and "AS path: AS64497  →  AS64498" in route["lines"]
            discord = next(json.loads(g[2]) for g in got if g[0] == "/discord")
            assert discord["embeds"][0]["color"] in (0xEC835A, 0x2A78D6)
            ntfy = next(g for g in got if g[0] == "/ntfy")
            assert ntfy[1]["Title"].startswith("=?UTF-8?B?") and ntfy[1]["Priority"] in ("4", "3")
        finally:
            st.PUBLIC_URL = None
            for s in (sink, srv):
                s.shutdown()
                s.server_close()


# ---------- the dashboard ----------

def test_board_minis_compare_and_gzip():
    import gzip
    with tempfile.TemporaryDirectory() as d:
        db = Path(d, "b.db")
        st.init_db(db, "local")
        t0 = int(time.time())
        targets = [st.make_target(st.slug(f"{g}-{n}"), g, n, **st.parse_host(h)) for g, n, h, _ in st.DEMO_TARGETS
                   if g in ("Services", "Sites / Braga", "Sites / Lisbon")]
        for name, remote in (("local", False), ("porto", True)):
            ping, trace = st.demo_probes(t0, remote)
            st.seed_demo(db, name, targets, ping, trace, t0, days=1)
        with st.db_open(db) as c:
            b = st.board(c, ["local", "porto"], "local", targets, 86400, t0)
        assert b["cells"] == len(b["targets"][0]["sev"]) == len(b["targets"][0]["med"]) >= 96
        by = {x["id"]: x for x in b["targets"]}
        assert by["services-vps-frankfurt"]["status"] == "down" and "3" in by["services-vps-frankfurt"]["sev"][-4:]
        assert by["sites-braga-braga-01"]["status"] in ("warn", "crit")
        braga = next(c for c in b["clusters"] if c["hop"]["ip"].startswith("100.70."))
        assert len(braga["targets"]) == 9 and braga["hop"]["why"] == "loss"      # one hop behind nine problems
        assert b["local"] is None                                              # porto sees the VPS down too
        assert any(e["kind"] == "status" and e["target"] == "services-vps-frankfurt" and e["to"] == "down" for e in b["events"])
        assert by["sites-braga-braga-01"]["by_source"]["porto"] == "ok"        # porto reaches Braga another way
        st.Handler.db, st.Handler.targets, st.Handler.sources, st.Handler.agents = db, targets, ["local", "porto"], {}
        srv, url = serve(st.Handler)
        try:
            req = urllib.request.Request(url + "/api/board?range=21600", headers={"Accept-Encoding": "gzip"})
            with urllib.request.urlopen(req, timeout=10) as r:
                assert r.headers["Content-Encoding"] == "gzip"
                assert json.loads(gzip.decompress(r.read()))["cells"] in (72, 73)
            minis = call(url + "/api/minis?range=86400&ids=sites-braga-braga-01,nope")
            assert list(minis) == ["sites-braga-braga-01"] and 60 <= len(minis["sites-braga-braga-01"]) <= 80
            cmp = call(url + "/api/compare?id=sites-braga-braga-01&range=86400")
            assert [s["name"] for s in cmp["sources"]] == ["local", "porto"]
            with urllib.request.urlopen(url + "/fonts/archivo.woff2", timeout=5) as r:
                assert r.headers["Content-Type"] == "font/woff2" and "immutable" in r.headers["Cache-Control"]
        finally:
            srv.shutdown()
            srv.server_close()
            st.BOARD_CACHE.clear()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok")
