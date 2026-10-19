#!/usr/bin/env python3
"""smoketrace: SmokePing-style latency (fping) plus mtr traceroutes per target, one stdlib-only process.

  python3 smoketrace.py                      real probes, needs fping + mtr on PATH
  python3 smoketrace.py --demo               synthetic data, any OS, no probes
"""
import argparse
import bisect
import configparser
import json
import math
import random
import re
import shutil
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
STEP = 300                  # seconds per round (SmokePing default)
PINGS = 20                  # pings per round (SmokePing default)
MTR_CYCLES = 10
RETENTION_DAYS = 30         # ponytail: raw rows, no RRD consolidation; ~1 KB per trace, fine for tens of targets
LOSS_WARN, LOSS_CRIT = 5, 20            # % lost in the last round (1 of 20 pings = 5 %)
LAT_FACTOR, LAT_MARGIN = 1.5, 10.0      # warn when median > 24 h baseline * 1.5 + 10 ms
MAX_POINTS = 600            # chart points per request; longer ranges are bucketed
RANGES = (3 * 3600, 86400, 7 * 86400, RETENTION_DAYS * 86400)
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]*")   # no leading "-": a host must never parse as a probe option


def log(msg):
    print(time.strftime("%F %T"), msg, file=sys.stderr, flush=True)


# ---------- targets ----------

def slug(s):
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()   # "Serviços" -> "servicos"
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def load_targets(path):
    """INI file: [Group] sections, one `Name = host` per line."""
    cp = configparser.ConfigParser(delimiters=("=",), inline_comment_prefixes=("#", ";"), interpolation=None)
    cp.optionxform = str
    if not cp.read(path, encoding="utf-8"):
        raise SystemExit(f"sem ficheiro de alvos: {path}")
    targets, seen = [], set()
    for group in cp.sections():
        for name, host in cp[group].items():
            host, tid = host.strip(), slug(f"{group}-{name}")
            if not HOST_RE.fullmatch(host):
                raise SystemExit(f"{path}: host inválido para {name!r}: {host!r}")
            if tid in seen:
                raise SystemExit(f"{path}: alvo repetido: {group}/{name}")
            seen.add(tid)
            targets.append({"id": tid, "group": group, "name": name, "host": host})
    return targets


# ---------- probes ----------

def parse_fping(text):
    """`fping -C` stderr -> {host: [rtt_ms or None, ...]}; other stderr lines are ignored."""
    out = {}
    for line in text.splitlines():
        host, sep, rest = line.partition(" : ")
        if not sep:
            continue
        try:
            out[host.strip()] = [None if v == "-" else float(v) for v in rest.split()]
        except ValueError:
            continue
    return out


def fping(hosts, _ts):
    # Same flags as SmokePing's FPing probe; one fping call covers every target.
    r = subprocess.run(["fping", "-C", str(PINGS), "-q", "-B1", "-r1", "-i10", *sorted(set(hosts))],
                       capture_output=True, text=True, timeout=PINGS * 3 + 30)
    return parse_fping(r.stderr)   # exit code 1/2 just means some host was unreachable


def parse_mtr(text):
    """`mtr --json` -> [{ttl, ip, loss, avg, best, wrst, sd}]; silent hops ("???") get ip None."""
    hops = []
    for h in json.loads(text)["report"]["hubs"]:
        ip = None if h["host"] == "???" else h["host"]
        loss = float(h["Loss%"])
        live = ip is not None and loss < 100
        hops.append({"ttl": int(h["count"]), "ip": ip, "loss": loss,
                     **{k: round(float(h[src]), 3) if live else None
                        for k, src in (("avg", "Avg"), ("best", "Best"), ("wrst", "Wrst"), ("sd", "StDev"))}})
    return hops


def mtr(host, _ts):
    # ponytail: mtr JSON keeps one IP per TTL; ECMP shows up as route flaps (A/B/A), add paris-traceroute if that hurts
    r = subprocess.run(["mtr", "--json", "-n", "-c", str(MTR_CYCLES), host],
                       capture_output=True, text=True, timeout=MTR_CYCLES * 4 + 30)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"mtr exit {r.returncode}")
    return parse_mtr(r.stdout)


def summarize(rtts):
    """-> (median, loss %, jitter, sorted replies). Jitter = mean |delta| between consecutive replies."""
    seq = [r for r in rtts if r is not None]
    loss = 100.0 * (len(rtts) - len(seq)) / len(rtts) if rtts else 100.0
    med = statistics.median(seq) if seq else None
    jit = statistics.fmean(abs(a - b) for a, b in zip(seq, seq[1:])) if len(seq) > 1 else None
    return med, loss, jit, sorted(seq)


# ---------- route logic ----------

def path_of(hops):
    """IP per TTL; silent hops are None; trailing silent hops are dropped."""
    p = [h["ip"] for h in sorted(hops, key=lambda h: h["ttl"])]
    while p and p[-1] is None:
        p.pop()
    return p


def same_path(a, b):
    """Same route = same IP at every TTL; a silent hop matches anything (ICMP-silent routers come and go)."""
    return len(a) == len(b) and all(x == y or x is None or y is None for x, y in zip(a, b))


def route_segments(traces):
    """[(ts, hops)] sorted -> (segments, known paths). Each segment: {route, from, to, end}."""
    known, segs = [], []
    for ts, hops in traces:
        p = path_of(hops)
        if segs and same_path(known[segs[-1]["route"]], p):
            i = segs[-1]["route"]
        else:
            i = next((k for k, q in enumerate(known) if same_path(q, p)), None)
            if i is None:
                known.append(p)
                i = len(known) - 1
            segs.append({"route": i, "from": ts, "to": ts})
        known[i] = [a if a is not None else b for a, b in zip(known[i], p)]
        segs[-1]["to"] = ts
    for a, b in zip(segs, segs[1:]):
        a["end"] = b["from"]
    if segs:
        segs[-1]["end"] = segs[-1]["to"] + STEP
    return segs, known


def label(i):
    return chr(65 + i) if i < 26 else f"R{i + 1}"


def loss_origin(hops, min_loss=1.0):
    """TTL where loss starts and persists to the last answering hop, else None.
    Loss on an earlier hop that does not carry on is ICMP rate-limiting, not real loss."""
    origin = None
    for h in sorted(hops, key=lambda h: h["ttl"], reverse=True):
        if h["ip"] is None:
            continue
        if h["loss"] < min_loss:
            break
        origin = h["ttl"]
    return origin


def diff_hops(prev, cur):
    """Align two traces by TTL. state: same | changed | added | removed | unknown (one side silent)."""
    a = {h["ttl"]: h for h in prev or []}
    b = {h["ttl"]: h for h in cur or []}
    rows = []
    for ttl in range(1, max([*a, *b, 0]) + 1):
        pa, pb = a.get(ttl), b.get(ttl)
        if prev is None:
            state = None
        elif pa is None:
            state = "added"
        elif pb is None:
            state = "removed"
        elif pa["ip"] == pb["ip"]:
            state = "same"
        elif pa["ip"] is None or pb["ip"] is None:
            state = "unknown"
        else:
            state = "changed"
        rows.append({"ttl": ttl, "state": state, "prev": pa, "cur": pb})
    return rows


def status_of(now, last_ts, median, loss, baseline):
    if last_ts is None or now - last_ts > 3 * STEP:
        return "stale"
    if loss >= 100:
        return "down"
    if loss >= LOSS_CRIT:
        return "crit"
    if loss >= LOSS_WARN or (median is not None and baseline and median > baseline * LAT_FACTOR + LAT_MARGIN):
        return "warn"
    return "ok"


def bucketize(rows, bucket):
    """rows (ts, median, loss, jitter, rtts_json) -> [[ts, median, loss, jitter, smoke]]; smoke = sorted replies."""
    r2 = lambda v: None if v is None else round(v, 2)
    if bucket <= STEP:
        return [[ts, r2(med), loss, r2(jit), json.loads(rtts)] for ts, med, loss, jit, rtts in rows]
    groups = {}
    for row in rows:
        groups.setdefault(row[0] // bucket * bucket, []).append(row)
    out = []
    for ts, g in groups.items():
        allr = sorted(v for row in g for v in json.loads(row[4]))
        n = len(allr)
        smoke = [allr[round(i * (n - 1) / (PINGS - 1))] for i in range(PINGS)] if n else []
        jits = [row[3] for row in g if row[3] is not None]
        out.append([ts, r2(statistics.median(allr)) if n else None, round(statistics.fmean(row[2] for row in g), 1),
                    r2(statistics.fmean(jits)) if jits else None, smoke])
    return out


# ---------- storage ----------

@contextmanager
def db_open(path):
    db = sqlite3.connect(path, timeout=30)
    try:
        with db:
            yield db
    finally:
        db.close()


def init_db(path):
    with db_open(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS ping (target TEXT, ts INTEGER, median REAL, loss REAL, jitter REAL,"
                   " rtts TEXT, PRIMARY KEY (target, ts)) WITHOUT ROWID")
        db.execute("CREATE TABLE IF NOT EXISTS trace (target TEXT, ts INTEGER, hops TEXT,"
                   " PRIMARY KEY (target, ts)) WITHOUT ROWID")


def round_rows(targets, ts, pings, traces):
    rp, rt = [], []
    for t in targets:
        if pings is not None:
            med, loss, jit, ok = summarize(pings.get(t["host"]) or [None] * PINGS)
            rp.append((t["id"], ts, med, loss, jit, json.dumps(ok)))
        if traces.get(t["id"]):
            rt.append((t["id"], ts, json.dumps(traces[t["id"]], separators=(",", ":"))))
    return rp, rt


def store(path, rp, rt, now):
    cut = now - RETENTION_DAYS * 86400
    with db_open(path) as db:
        db.executemany("INSERT OR REPLACE INTO ping VALUES (?,?,?,?,?,?)", rp)
        db.executemany("INSERT OR REPLACE INTO trace VALUES (?,?,?)", rt)
        db.execute("DELETE FROM ping WHERE ts < ?", (cut,))
        db.execute("DELETE FROM trace WHERE ts < ?", (cut,))


def run_round(path, targets, ts, ping_fn, trace_fn):
    """fping and the mtr runs go out together, so latency and route describe the same minutes."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {t["id"]: pool.submit(trace_fn, t["host"], ts) for t in targets}
        try:
            pings = ping_fn([t["host"] for t in targets], ts)
        except Exception as e:      # collector failure: leave a gap, never fake 100 % loss
            log(f"fping falhou: {e}")
            pings = None
        traces = {}
        for tid, f in futs.items():
            try:
                traces[tid] = f.result()
            except Exception as e:
                log(f"mtr {tid} falhou: {e}")
    store(path, *round_rows(targets, ts, pings, traces), ts)


def collector(path, targets, ping_fn, trace_fn):
    while True:
        ts = int(time.time()) // STEP * STEP
        try:
            run_round(path, targets, ts, ping_fn, trace_fn)
        except Exception as e:
            log(f"ronda {ts} falhou: {e}")
        time.sleep(max(1.0, ts + STEP - time.time()))


# ---------- queries ----------

def load_traces(db, tid, since=0):
    return [(ts, json.loads(h)) for ts, h in
            db.execute("SELECT ts, hops FROM trace WHERE target=? AND ts>=? ORDER BY ts", (tid, since))]


def summary(db, t, now):
    rows = db.execute("SELECT ts, median, loss, jitter FROM ping WHERE target=? AND ts>=? ORDER BY ts",
                      (t["id"], now - 86400)).fetchall()
    segs, _ = route_segments(load_traces(db, t["id"], now - 86400))
    last_ts, med, loss, jit = rows[-1] if rows else (None, None, None, None)
    meds = [r[1] for r in rows if r[1] is not None]
    base = statistics.median(meds) if meds else None
    return {**t, "status": status_of(now, last_ts, med, loss, base), "last_ts": last_ts,
            "median": med, "loss": loss, "jitter": jit, "baseline": base,
            "route_changes": max(0, len(segs) - 1), "last_change": segs[-1]["from"] if len(segs) > 1 else None,
            "spark": [[ts, None if m is None else round(m, 2), l] for ts, m, l, _ in rows]}


def target_detail(db, t, rng, now):
    since = now - rng
    bucket = STEP * max(1, math.ceil(rng / MAX_POINTS / STEP))
    rows = db.execute("SELECT ts, median, loss, jitter, rtts FROM ping WHERE target=? AND ts>=? ORDER BY ts",
                      (t["id"], since)).fetchall()
    segs, known = route_segments(load_traces(db, t["id"]))   # whole history: route letters stay stable across ranges
    vis = [{**s, "label": label(s["route"]), "hops": len(known[s["route"]]), "change": k > 0 and s["from"] >= since}
           for k, s in enumerate(segs) if s["end"] > since]
    s = {k: v for k, v in summary(db, t, now).items() if k != "spark"}
    return {"target": s, "from": since, "to": now, "bucket": bucket, "points": bucketize(rows, bucket),
            "segments": vis, "loss_warn": LOSS_WARN, "loss_crit": LOSS_CRIT, "pings": PINGS}


def trace_detail(db, tid, ts, vs):
    """Trace at/just before ts (latest if None) vs the last trace of the previous route, or the previous round."""
    traces = load_traces(db, tid)   # ponytail: full scan per click, ~ms for 30 d; index route changes if it gets slow
    if not traces:
        return {"cur": None}
    segs, _ = route_segments(traces)
    tss = [x for x, _ in traces]
    i = len(tss) - 1 if ts is None else max(0, bisect.bisect_right(tss, ts) - 1)
    seg_at = lambda when: max((k for k, s in enumerate(segs) if s["from"] <= when), default=0)
    k = seg_at(tss[i])
    j, fallback = i - 1, False
    if vs == "route":
        if k > 0:
            j = bisect.bisect_left(tss, segs[k - 1]["to"])
        else:
            fallback = True

    def side(n):
        if n < 0:
            return None
        when, hops = traces[n]
        r = segs[seg_at(when)]["route"]
        return {"ts": when, "hops": hops, "route": r, "label": label(r), "origin": loss_origin(hops)}

    cur, prev = side(i), side(j)
    return {"cur": cur, "prev": prev, "vs": vs, "fallback": fallback,
            "rows": diff_hops(prev and prev["hops"], cur["hops"])}


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    db = None
    targets = []

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        now = int(time.time())
        try:
            if u.path in ("/", "/index.html"):
                return self.send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            t = next((x for x in self.targets if x["id"] == q.get("id")), None)
            with db_open(self.db) as db:
                if u.path == "/api/overview":
                    return self.json({"now": now, "step": STEP, "targets": [summary(db, x, now) for x in self.targets]})
                if u.path == "/api/target" and t:
                    rng = int(q.get("range", 86400))
                    return self.json(target_detail(db, t, min(max(rng, 3600), RANGES[-1]), now))
                if u.path == "/api/trace" and t:
                    ts = int(q["ts"]) if q.get("ts") else None
                    return self.json(trace_detail(db, t["id"], ts, "round" if q.get("vs") == "round" else "route"))
            self.send(404, b'{"error":"not found"}', "application/json")
        except ValueError:
            self.send(400, b'{"error":"bad request"}', "application/json")

    def json(self, obj):
        self.send(200, json.dumps(obj, separators=(",", ":")).encode(), "application/json")

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


# ---------- demo ----------

DEMO_TARGETS = [   # (group, name, host, scenario)
    ("LAN", "Router", "192.168.1.1", "lan"),
    ("Internet", "Cloudflare DNS", "1.1.1.1", "reroute"),   # path change + latency step + loss starting on the new path
    ("Internet", "Google DNS", "8.8.8.8", "flap"),          # path alternating in the last 3 h
    ("Internet", "Quad9", "9.9.9.9", "ratelimit"),          # loss on a mid hop only, plus one real-loss hour
    ("Internet", "Wikipedia", "185.15.59.224", "ok"),
    ("Serviços", "VPS Frankfurt", "203.0.113.10", "down"),  # dead for the last 40 min
]


def demo_probes(t0):
    """Synthetic rounds, deterministic per (host, ts) so seeded history and live rounds agree."""
    scen = {h: (i, s) for i, (_, _, h, s) in enumerate(DEMO_TARGETS)}

    def state(host, ts):
        i, s = scen[host]
        age, rnd = t0 - ts, random.Random(f"{host}/{ts}")
        hour = time.localtime(ts).tm_hour + time.localtime(ts).tm_min / 60
        base = 0.4 if s == "lan" else 6.0 + 9 * i
        extra = 0.0 if s == "lan" else 3 * max(0.0, math.sin((hour - 13) / 12 * math.pi))   # evening congestion
        route, loss, sd, down = 0, 0.0005, base * 0.05 + 0.15, False
        if s == "reroute" and (4 * 3600 <= age < 6 * 3600 or 72 * 3600 <= age < 74 * 3600):
            route, extra, loss, sd = 1, extra + 18, 0.10, sd * 3
        if s == "flap" and age < 3 * 3600:
            route = ts // (STEP * 4) % 2
            extra += 3 * route
        if s == "ratelimit" and 9 * 3600 <= age < 10 * 3600:
            loss = 0.15
        if s == "down" and age < 40 * 60:
            down = True
        if rnd.random() < 0.03:
            sd *= 6
        return rnd, i, s, base + extra, loss, sd, route, down

    def path(host, i, s, route):
        if s == "lan":
            return [host]
        isp = ["192.168.1.1", "100.64.0.1", None, "198.51.100.1"]
        mid = ([f"198.51.100.{20 + i}", f"203.0.113.{100 + i}"] if route == 0 else
               [f"198.51.100.{120 + i}", f"198.51.100.{140 + i}", f"203.0.113.{160 + i}"])
        return isp + mid + [host]

    def ping(hosts, ts):
        out = {}
        for h in hosts:
            rnd, _, _, lat, loss, sd, _, down = state(h, ts)
            out[h] = [None if down or rnd.random() < loss else round(lat + abs(rnd.gauss(0, sd)), 3)
                      for _ in range(PINGS)]
        return out

    def trace(host, ts):
        rnd, i, s, lat, loss, sd, route, down = state(host, ts)
        p = path(host, i, s, route)
        hops = []
        for k, ip in enumerate(p, 1):
            hl = 0.0
            if s == "ratelimit" and k == 2:
                hl = rnd.choice([20.0, 30.0, 40.0, 50.0])
            elif s == "ratelimit" and loss > 0.1 and k >= 5:
                hl = rnd.choice([10.0, 20.0])
            elif s == "reroute" and route == 1 and k >= 5:
                hl = rnd.choice([0.0, 10.0, 10.0, 20.0])
            if down and k >= 5:
                ip = None
            if ip is None:
                hl = 100.0
            avg = 0.4 if k == 1 else lat * (0.2 + 0.8 * k / len(p)) + abs(rnd.gauss(0, sd))
            live = ip is not None
            hops.append({"ttl": k, "ip": ip, "loss": hl,
                         "avg": round(avg, 3) if live else None,
                         "best": round(max(0.1, avg - abs(rnd.gauss(0, sd))), 3) if live else None,
                         "wrst": round(avg + abs(rnd.gauss(0, sd)) * 3, 3) if live else None,
                         "sd": round(sd * 0.8, 3) if live else None})
        return hops

    return ping, trace


def seed_demo(path, targets, ping, trace, t0, days=7):
    rp, rt = [], []
    end = t0 // STEP * STEP
    for ts in range(end - days * 86400, end, STEP):
        a, b = round_rows(targets, ts, ping([t["host"] for t in targets], ts),
                          {t["id"]: trace(t["host"], ts) for t in targets})
        rp += a
        rt += b
    store(path, rp, rt, end)


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="SmokePing-style latency + mtr traceroutes")
    ap.add_argument("--targets", type=Path, default=HERE / "targets.ini")
    ap.add_argument("--db", type=Path)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--demo", action="store_true", help="synthetic data, no fping/mtr needed")
    a = ap.parse_args()

    if a.demo:
        targets = [{"id": slug(f"{g}-{n}"), "group": g, "name": n, "host": h} for g, n, h, _ in DEMO_TARGETS]
        db = a.db or HERE / "demo.db"
        for suffix in ("", "-wal", "-shm"):
            Path(f"{db}{suffix}").unlink(missing_ok=True)
        t0 = int(time.time())
        ping_fn, trace_fn = demo_probes(t0)
        init_db(db)
        seed_demo(db, targets, ping_fn, trace_fn, t0)
    else:
        missing = [b for b in ("fping", "mtr") if not shutil.which(b)]
        if missing:
            raise SystemExit(f"falta {', '.join(missing)} no PATH (Debian: apt install fping mtr-tiny)")
        targets = load_targets(a.targets)
        db = a.db or HERE / "smoketrace.db"
        ping_fn, trace_fn = fping, mtr
        init_db(db)

    threading.Thread(target=collector, args=(db, targets, ping_fn, trace_fn), daemon=True).start()
    Handler.db, Handler.targets = db, targets
    log(f"smoketrace: {len(targets)} alvos, http://{a.bind}:{a.port}")
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
