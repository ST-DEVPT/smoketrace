#!/usr/bin/env python3
"""smoketrace: SmokePing-style latency plus an mtr traceroute every round, per target, in one stdlib-only process.

  python3 smoketrace.py                                 server: probes, stores, alerts, serves the dashboard
  python3 smoketrace.py --agent https://server:8099 --token T
                                                        agent that pushes its rounds to the server
  python3 smoketrace.py --listen 0.0.0.0:8100 --token T
                                                        agent the server pulls from (when it cannot reach the server)
  python3 smoketrace.py --import-rrd /var/lib/smokeping --smokeping /etc/smokeping/config
                                                        one-off: SmokePing's RRD history into the database
  python3 smoketrace.py --demo                          synthetic data, any OS, no probes

Every flag also reads an environment variable; README.md lists them.
"""
import argparse
import base64
import bisect
import configparser
import hashlib
import hmac
import json
import math
import os
import random
import re
import shutil
import socket
import sqlite3
import statistics
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
STEP = DEFAULT_STEP = 300   # seconds per round (SmokePing default); SmokePing's *** Database *** can change it
PINGS = DEFAULT_PINGS = 20  # pings per round (SmokePing default); likewise
MTR_CYCLES = 10
RETENTION_DAYS = 30         # ponytail: raw rows, no RRD consolidation; ~1 KB per trace, fine for tens of targets
LOSS_WARN, LOSS_CRIT = 5.0, 20.0        # % lost in the last round (1 of 20 pings = 5 %); per target in SmokePing's config
LAT_FACTOR, LAT_MARGIN = 1.5, 10.0      # warn when median > 24 h baseline * 1.5 + 10 ms
MAX_POINTS = 600            # chart points per request; longer ranges are bucketed
RANGES = (3 * 3600, 86400, 7 * 86400, RETENTION_DAYS * 86400)
AGENT_BACKLOG = 288         # rounds an agent keeps while the server is unreachable (one day)
PULL_BATCH = 24             # rounds per pull; the server pulls again while an agent has more
MAX_PUSH = 1 << 20          # bytes per pushed round
ALERT_ROUNDS = 2            # a new status or route must hold this many rounds before it is alerted
SESSION_DAYS = 30
PROBES = ("icmp", "tcp", "dns")
STATUS_CODE = {"ok": 0, "warn": 1, "crit": 2, "down": 3, "stale": 4}
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]*")   # no leading "-": a host must never parse as a probe option
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,199}")
LOOKUP_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}")
IP_RE = re.compile(r"[0-9A-Fa-f.:]{2,45}")
ASN_RE = re.compile(r"AS\d{1,10}")

# set by main() from the environment
PASSWORD = METRICS_TOKEN = PUBLIC_URL = None
ASN_LOOKUP = True


def log(msg):
    print(time.strftime("%F %T"), msg, file=sys.stderr, flush=True)


# ---------- targets ----------

def slug(s):
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()   # "Serviços" -> "servicos"
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def make_target(tid, group, name, host, probe="icmp", port=None, lookup=None, slaves=None, master=True,
                loss_warn=None, loss_crit=None, latency_warn=None):
    """slaves None: every agent probes it; master: the server's own probe does too. Thresholds None: the defaults."""
    t = {"id": tid, "group": group, "name": name, "host": host, "probe": probe, "port": port, "lookup": lookup,
         "slaves": slaves, "master": master, "loss_warn": loss_warn, "loss_crit": loss_crit, "latency_warn": latency_warn}
    check_target(t)
    return t


def check_target(t):
    """Everything that reaches a probe's command line or socket is checked here, on the server and on agents."""
    if not ID_RE.fullmatch(str(t.get("id"))):
        raise ValueError(f"bad id {t.get('id')!r}")
    if not isinstance(t.get("host"), str) or not HOST_RE.fullmatch(t["host"]):
        raise ValueError(f"invalid host {t.get('host')!r}")
    if t.get("probe") not in PROBES:
        raise ValueError(f"unknown probe {t.get('probe')!r}")
    if t["probe"] == "tcp" and not (isinstance(t.get("port"), int) and 1 <= t["port"] <= 65535):
        raise ValueError(f"bad TCP port {t.get('port')!r}")
    if t["probe"] == "dns" and not (isinstance(t.get("lookup"), str) and LOOKUP_RE.fullmatch(t["lookup"])):
        raise ValueError(f"bad DNS lookup {t.get('lookup')!r}")
    return t


def parse_host(value):
    """`host`, `tcp://host:port` or `dns://server/name` -> probe fields."""
    v = value.strip()
    if v.startswith("tcp://"):
        host, _, port = v[6:].rpartition(":")
        return {"host": host.strip("[]"), "probe": "tcp", "port": int(port) if port.isdigit() else None}
    if v.startswith("dns://"):
        host, _, name = v[6:].partition("/")
        return {"host": host, "probe": "dns", "lookup": name or "example.com"}
    return {"host": v, "probe": "icmp"}


def load_targets(path):
    """INI file: [Group] sections, one `Name = host` per line (or tcp://host:port, dns://server/name)."""
    cp = configparser.ConfigParser(delimiters=("=",), inline_comment_prefixes=("#", ";"), interpolation=None)
    cp.optionxform = str
    if not cp.read(path, encoding="utf-8"):
        raise SystemExit(f"no targets file: {path}")
    targets, seen = [], set()
    for group in cp.sections():
        for name, value in cp[group].items():
            tid = slug(f"{group}-{name}")
            try:
                t = make_target(tid, group, name, **parse_host(value))
            except ValueError as e:
                raise SystemExit(f"{path}: {group}/{name}: {e}")
            if tid in seen:
                raise SystemExit(f"{path}: duplicate target: {group}/{name}")
            seen.add(tid)
            targets.append(t)
    return targets


def parse_agents(spec, local):
    """"porto=token,office=token@http://office:8100" -> {name: {token, url}}; a url means the server pulls."""
    agents = {}
    for item in filter(None, (s.strip() for s in spec.split(","))):
        name, sep, rest = item.partition("=")
        token, _, url = rest.partition("@")
        if not sep or not NAME_RE.fullmatch(name) or name == local:
            raise SystemExit(f"AGENTS: {name!r} must be a lowercase name (a-z, 0-9, -) other than {local!r}")
        if len(token) < 16:
            raise SystemExit(f"AGENTS: the token for {name!r} must be at least 16 characters")
        if url and not url.startswith(("http://", "https://")):
            raise SystemExit(f"AGENTS: the address of {name!r} must start with http:// or https://")
        agents[name] = {"token": token, "url": url or None}
    return agents


# ---------- SmokePing's config ----------

SECTION_RE = re.compile(r"\*\*\*\s*(\w+)\s*\*\*\*")
NODE_RE = re.compile(r"(\++)\s*(\S+)")
PROBE_KINDS = {"FPing": "icmp", "FPing6": "icmp", "TCPPing": "tcp", "DNS": "dns"}
INHERITED = ("probe", "slaves", "nomasterpoll", "port", "lookup", "loss_warn", "loss_crit", "latency_warn")


SECTION_FILES = ("General", "Database", "Probes", "Slaves", "Targets")   # split layouts (Debian, linuxserver)


def locate(path, base):
    """A path from SmokePing's config, found here. Paths are often absolute for the machine or container SmokePing
    ran in (/etc/smokeping/..., /config/...); when one is not here, try it under the folder the config is in,
    dropping leading parts: /config/target/dns.conf -> <base>/target/dns.conf."""
    rooted = str(path).startswith(("/", "\\"))           # absolute for a Linux SmokePing, wherever we run
    path = Path(path)
    if not (path.is_absolute() or rooted):
        return base / path
    if path.exists():
        return path
    parts = path.parts[1:]
    for i in range(len(parts)):
        candidate = base.joinpath(*parts[i:])
        if candidate.exists():
            return candidate
    return path


def smokeping_main(path):
    """SMOKEPING_CONFIG may be the main file or the folder: its `config` file, or the split files themselves."""
    path = Path(path)
    if not path.is_dir():
        return path, None
    if (path / "config").is_file():
        return path / "config", None
    found = [f for f in SECTION_FILES if (path / f).is_file()]
    if "Targets" not in found:
        raise SystemExit(f"{path}: no `config` file and no `Targets` file in this folder")
    return None, [path / f for f in found]


def read_smokeping(path, files, depth=0, base=None):
    """The config's lines with every @include expanded; `files` collects each file read (for reloads)."""
    if depth > 10:
        raise SystemExit(f"{path}: @include nested too deep")
    path = Path(path)
    base = base or path.parent
    files.append(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        if depth == 0:
            raise SystemExit(f"cannot read {path}: {e}")
        log(f"@include {path} skipped: {e.strerror or e}")      # one missing include must not stop the rest
        return []
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("@include"):
            lines += read_smokeping(locate(s[len("@include"):].strip(), base), files, depth + 1, base)
        else:
            lines.append(s)
    return lines


def read_smokeping_config(path, files):
    """Lines of the whole config: from its main file, or from a folder of split section files."""
    main, parts = smokeping_main(path)
    if main:
        return read_smokeping(main, files), main.parent
    base = parts[0].parent
    return [line for f in parts for line in read_smokeping(f, files, base=base)], base


def parse_smokeping(lines):
    """-> {section: (attributes before the first node, [(level, name, attributes)])}.
    A file with no *** Section *** header is a bare Targets file."""
    secs, cur = {}, None
    for s in lines:
        if not s or s.startswith("#"):
            continue
        m = SECTION_RE.fullmatch(s)
        if m:
            cur = secs.setdefault(m.group(1), ({}, []))
            continue
        if cur is None:
            cur = secs.setdefault("Targets", ({}, []))
        m = NODE_RE.fullmatch(s)
        if m:
            cur[1].append((len(m.group(1)), m.group(2), {}))
            continue
        key, sep, value = s.partition("=")
        if sep:
            (cur[1][-1][2] if cur[1] else cur[0])[key.strip()] = value.strip()
    return secs


def smokeping_targets(secs):
    """Targets with a host and a supported probe; groups from the + / ++ tree; probe settings inherited."""
    probes, parent = {}, None   # probe name -> (kind of probe, its attributes)
    for level, name, attrs in secs.get("Probes", ({}, []))[1]:
        if level == 1:
            parent = name
            probes[name] = (name, attrs)
        elif parent:          # ++FPingFast under +FPing is an FPing, with FPing's settings unless it sets its own
            probes[name] = (parent, {**probes[parent][1], **attrs})
    root, nodes = secs.get("Targets", ({}, []))
    stack = [(0, [], [], {"probe": "FPing", **{k: root[k] for k in INHERITED if k in root}})]
    targets, skipped, seen = [], [], set()
    for level, name, attrs in nodes:
        while stack[-1][0] >= level:
            stack.pop()
        _, path, labels, inherit = stack[-1]
        path, labels = path + [name], labels + [attrs.get("menu") or attrs.get("title") or name]
        inherit = {**inherit, **{k: attrs[k] for k in INHERITED if k in attrs}}
        stack.append((level, path, labels, inherit))
        host = attrs.get("host")
        if not host:
            continue
        where = "/" + "/".join(path)
        kind_name, pattrs = probes.get(inherit["probe"], (inherit["probe"], {}))
        kind = PROBE_KINDS.get(kind_name)
        if host.startswith("/"):
            skipped.append(f"{where} (multi-host graph)")
            continue
        if not kind:
            skipped.append(f"{where} (probe {inherit['probe']})")
            continue
        tid = slug("-".join(path))
        try:
            num = lambda k: None if inherit.get(k) is None else float(inherit[k])
            port = inherit.get("port") or pattrs.get("port") or "80"
            t = make_target(tid, " / ".join(labels[:-1]) or "Targets", labels[-1], host, probe=kind,
                            port=int(port) if kind == "tcp" else None,
                            lookup=(inherit.get("lookup") or pattrs.get("lookup") or "example.com") if kind == "dns" else None,
                            slaves=inherit.get("slaves", "").split(),
                            master=inherit.get("nomasterpoll", "no").lower() not in ("yes", "true", "1"),
                            loss_warn=num("loss_warn"), loss_crit=num("loss_crit"), latency_warn=num("latency_warn"))
        except ValueError as e:
            skipped.append(f"{where} ({e})")
            continue
        if tid in seen:
            skipped.append(f"{where} (duplicate)")
            continue
        seen.add(tid)
        targets.append(t)
    if skipped:
        log(f"not probed: {', '.join(skipped)}")
    return targets


def smokeping_agents(secs, base, files):
    """*** Slaves *** names with their secrets from the `secrets` file (name:secret per line); `url` = pull mode."""
    root, nodes = secs.get("Slaves", ({}, []))
    slaves = [(n, attrs) for level, n, attrs in nodes if level == 1]
    if not slaves:
        return {}
    path = locate(root.get("secrets", "smokeping_secrets"), base)
    files.append(path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        log(f"cannot read the slaves' secrets ({e}): set AGENTS instead")
        return {}
    secrets = dict(line.strip().split(":", 1) for line in lines if ":" in line and not line.lstrip().startswith("#"))
    agents = {}
    for n, attrs in slaves:
        if not NAME_RE.fullmatch(n):
            log(f"slave {n!r} ignored: agent names are lowercase letters, digits and -")
        elif not secrets.get(n, "").strip():
            log(f"slave {n!r} ignored: no secret for it in {path}")
        else:
            agents[n] = {"token": secrets[n].strip(), "url": attrs.get("url") or None}
            if len(agents[n]["token"]) < 16:
                log(f"slave {n!r}: its secret is short ({len(agents[n]['token'])} characters); a longer one is safer")
    return agents


def load_config(a):
    """-> {targets, agents, step, pings, files}, from SmokePing's config or targets.ini, plus AGENTS."""
    files, step, pings, agents = [], DEFAULT_STEP, DEFAULT_PINGS, {}
    if a.smokeping:
        lines, base = read_smokeping_config(a.smokeping, files)
        secs = parse_smokeping(lines)
        targets = smokeping_targets(secs)
        agents = smokeping_agents(secs, base, files)
        db = secs.get("Database", ({}, []))[0]
        try:
            step = int(db.get("step", DEFAULT_STEP))
            pings = int(db.get("pings", DEFAULT_PINGS))
        except ValueError:
            raise SystemExit("*** Database ***: step and pings must be whole numbers")
        if not (60 <= step <= 3600 and 1 <= pings <= 100):
            raise SystemExit("*** Database ***: step must be 60-3600 s and pings 1-100")
    else:
        if not a.targets.exists() and (HERE / "targets.ini").exists():
            shutil.copy(HERE / "targets.ini", a.targets)
            log(f"wrote an example targets file to {a.targets}: put your targets in it")
        targets = load_targets(a.targets)
        files.append(a.targets)
    agents.update(parse_agents(a.agents, a.name))      # AGENTS adds to (or overrides) SmokePing's slaves
    agents.pop(a.name, None)
    return {"targets": targets, "agents": agents, "step": step, "pings": pings, "files": files}


def stamp(files):
    return tuple(f.stat().st_mtime_ns if f.exists() else None for f in files)


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


def fping(hosts):
    # Same flags as SmokePing's FPing probe; one fping call covers every ICMP target.
    r = subprocess.run(["fping", "-C", str(PINGS), "-q", "-B1", "-r1", "-i10", *sorted(set(hosts))],
                       capture_output=True, text=True, timeout=PINGS * 3 + 30)
    return parse_fping(r.stderr)   # exit code 1/2 just means some host was unreachable


def spaced(n, fn):
    """n samples of fn(), one per second like fping -C; a failure is None."""
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            fn()
            out.append(round((time.perf_counter() - t0) * 1000, 3))
        except OSError:
            out.append(None)
        time.sleep(max(0.0, 1 - (time.perf_counter() - t0)))
    return out


def tcp_ping(t):
    """Time to open a TCP connection, like SmokePing's TCPPing; the name is resolved once, outside the timing."""
    try:
        fam, _, _, _, addr = socket.getaddrinfo(t["host"], t["port"], type=socket.SOCK_STREAM)[0]
    except OSError:
        return [None] * PINGS

    def connect():
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect(addr)
    return spaced(PINGS, connect)


def dns_query(server, name, qtype=1, timeout=2.0):
    """One query over UDP -> the response; raises OSError on timeout. Any answer counts, even NXDOMAIN."""
    qid = random.randrange(65536)
    q = (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
         + b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\0"
         + struct.pack(">HH", qtype, 1))
    fam, _, _, _, addr = socket.getaddrinfo(server, 53, type=socket.SOCK_DGRAM)[0]
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, addr)
        while True:
            data, _ = s.recvfrom(4096)
            if data[:2] == q[:2]:
                return data


def dns_ping(t):
    """Time to an answer from a DNS server, like SmokePing's DNS probe."""
    return spaced(PINGS, lambda: dns_query(t["host"], t["lookup"]))


def real_ping(targets, _ts):
    """{target id: rtts}: one fping for every ICMP target, TCP connects and DNS queries in threads."""
    icmp = [t for t in targets if t["probe"] == "icmp"]
    out = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {t["id"]: pool.submit(tcp_ping if t["probe"] == "tcp" else dns_ping, t)
                for t in targets if t["probe"] != "icmp"}
        if icmp:
            by_host = fping([t["host"] for t in icmp])
            out.update({t["id"]: by_host.get(t["host"]) or [None] * PINGS for t in icmp})
        for tid, f in futs.items():
            out[tid] = f.result()
    return out


def parse_mtr(text):
    """`mtr --json` -> [{ttl, ip, asn, loss, avg, best, wrst, sd}]; silent hops ("???") get ip None."""
    hops = []
    for h in json.loads(text)["report"]["hubs"]:
        ip = None if h["host"] == "???" else h["host"]
        loss = float(h["Loss%"])
        live = ip is not None and loss < 100
        asn = str(h.get("ASN", ""))
        hops.append({"ttl": int(h["count"]), "ip": ip, "asn": asn if ASN_RE.fullmatch(asn) else None, "loss": loss,
                     **{k: round(float(h[src]), 3) if live else None
                        for k, src in (("avg", "Avg"), ("best", "Best"), ("wrst", "Wrst"), ("sd", "StDev"))}})
    return hops


def mtr_command(t):
    cmd = ["mtr", "--json", "-n", "-c", str(MTR_CYCLES)]
    if ASN_LOOKUP:
        cmd.append("-z")                     # the AS of every hop (asks origin.asn.cymru.com over DNS)
    if t["probe"] == "tcp":
        cmd += ["-T", "-P", str(t["port"])]  # the same port the latency is measured on
    elif t["probe"] == "dns":
        # TCP to port 53: a UDP probe gets no answer from a DNS server (the port is open, the payload is not
        # a query), so the trace would end in silence; every DNS server must answer on TCP 53 too (RFC 7766)
        cmd += ["-T", "-P", "53"]
    return cmd + [t["host"]]


def mtr(t, _ts):
    # ponytail: mtr cannot pin a flow (its --localport gets no UDP answers back); ECMP shows as routes taking turns
    r = subprocess.run(mtr_command(t), capture_output=True, text=True, timeout=MTR_CYCLES * 4 + 60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"mtr exit {r.returncode}")
    hops = parse_mtr(r.stdout)
    if not hops:
        raise RuntimeError("mtr answered with no hops")
    return hops


def summarize(rtts):
    """-> (median, loss %, jitter, sorted replies). Jitter = mean |delta| between consecutive replies."""
    seq = [r for r in rtts if r is not None]
    loss = 100.0 * (len(rtts) - len(seq)) / len(rtts) if rtts else 100.0
    med = statistics.median(seq) if seq else None
    jit = statistics.fmean(abs(a - b) for a, b in zip(seq, seq[1:])) if len(seq) > 1 else None
    return med, loss, jit, sorted(seq)


def probe_round(targets, ts, ping_fn, trace_fn):
    """Latency and traceroutes go out together, so both describe the same minutes.
    -> ({target id: rtts} or None when the latency probe itself failed, {target id: hops})"""
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {t["id"]: pool.submit(trace_fn, t, ts) for t in targets}
        try:
            pings = ping_fn(targets, ts) if targets else {}
        except Exception as e:      # collector failure: leave a gap, never fake 100 % loss
            log(f"latency probe failed: {e}")
            pings = None
        traces = {}
        for tid, f in futs.items():
            try:
                traces[tid] = f.result()
            except Exception as e:
                log(f"mtr {tid} failed: {e}")
    return pings, traces


# ---------- AS names ----------

def skip_name(data, i):
    while True:
        n = data[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def dns_txt(name, server):
    """TXT records of `name`, asked of `server`."""
    data = dns_query(server, name, qtype=16, timeout=3)
    qd, an = struct.unpack(">HH", data[4:8])
    i = 12
    for _ in range(qd):
        i = skip_name(data, i) + 4
    out = []
    for _ in range(an):
        i = skip_name(data, i)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if rtype == 16:
            j, end = i, i + rdlen
            while j < end:
                out.append(data[j + 1:j + 1 + data[j]].decode("utf-8", "replace"))
                j += 1 + data[j]
        i += rdlen
    return out


def resolver():
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            parts = line.split()
            if len(parts) > 1 and parts[0] == "nameserver":
                return parts[1]
    except OSError:
        pass
    return "1.1.1.1"


def asn_namer(path):
    """Fill in the names of AS numbers seen in traces: "AS13335" -> "CLOUDFLARENET - Cloudflare, Inc., US"."""
    while True:
        try:
            with db_open(path) as db:
                todo = [r[0] for r in db.execute(
                    "SELECT asn FROM asn WHERE name IS NULL OR (name = '' AND ts < ?) LIMIT 50", (time.time() - 86400,))]
            for asn in todo:
                try:
                    txt = dns_txt(f"{asn}.asn.cymru.com", resolver())
                    name = txt[0].split("|")[-1].strip() if txt else ""
                except (OSError, IndexError, struct.error):
                    name = ""
                with db_open(path) as db:
                    db.execute("UPDATE asn SET name=?, ts=? WHERE asn=?", (name, int(time.time()), asn))
        except Exception as e:
            log(f"AS names: {e}")
        time.sleep(60)


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


def threshold(t, key, default):
    v = (t or {}).get(key)
    return default if v is None else v


def status_of(now, last_ts, median, loss, baseline, t=None):
    if last_ts is None or now - last_ts > 3 * STEP:
        return "stale"
    if loss >= 100:
        return "down"
    if loss >= threshold(t, "loss_crit", LOSS_CRIT):
        return "crit"
    lat = threshold(t, "latency_warn", None)
    if (loss >= threshold(t, "loss_warn", LOSS_WARN)
            or (median is not None and lat is not None and median > lat)
            or (median is not None and baseline and median > baseline * LAT_FACTOR + LAT_MARGIN)):
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


# ---------- agents: what a round from an agent may contain ----------

def _num(v, lo, hi, required=False):
    if v is None and not required:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise ValueError(f"bad number {v!r}")
    return float(v)


def _int(v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ValueError(f"bad integer {v!r}")
    return v


def clean_round(p, ids, now):
    """Validate an agent's round and rebuild it from known fields only. -> (ts, pings or None, traces)."""
    if not isinstance(p, dict):
        raise ValueError("round must be an object")
    ts = _int(p.get("ts"), now - RETENTION_DAYS * 86400 + 1, now + STEP) // STEP * STEP
    pings = None
    if p.get("pings") is not None:
        if not isinstance(p["pings"], dict):
            raise ValueError("pings must be an object")
        pings = {}
        for tid, rtts in p["pings"].items():
            if tid not in ids or not isinstance(rtts, list) or not 0 < len(rtts) <= 100:
                raise ValueError(f"bad pings for {tid!r}")
            pings[tid] = [_num(v, 0, 60000) for v in rtts]
    traces = {}
    if not isinstance(p.get("traces") or {}, dict):
        raise ValueError("traces must be an object")
    for tid, hops in (p.get("traces") or {}).items():
        if tid not in ids or not isinstance(hops, list) or len(hops) > 64:
            raise ValueError(f"bad trace for {tid!r}")
        out = []
        for h in hops:
            ip = h.get("ip") if isinstance(h, dict) else ""
            asn = h.get("asn")
            if ip is not None and not (isinstance(ip, str) and IP_RE.fullmatch(ip)):
                raise ValueError(f"bad hop in {tid!r}")
            if asn is not None and not (isinstance(asn, str) and ASN_RE.fullmatch(asn)):
                raise ValueError(f"bad AS in {tid!r}")
            out.append({"ttl": _int(h.get("ttl"), 1, 64), "ip": ip, "asn": asn, "loss": _num(h.get("loss"), 0, 100, True),
                        **{k: _num(h.get(k), 0, 60000) for k in ("avg", "best", "wrst", "sd")}})
        traces[tid] = out
    return ts, pings, traces


def agent_view(t):
    """What an agent needs to know about a target."""
    return {k: t[k] for k in ("id", "host", "probe", "port", "lookup")}


def agent_targets(got):
    """An agent re-checks every target it is given before it reaches a probe."""
    out = []
    for t in got:
        try:
            out.append(check_target(dict(t)))
        except (ValueError, TypeError, AttributeError) as e:
            log(f"target ignored: {e}")
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


def init_db(path, source):
    with db_open(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        old = [r[1] for r in db.execute("PRAGMA table_info(ping)")]
        if old and "source" not in old:      # 0.1 schema: one probe, no source column; it becomes this one
            db.execute("ALTER TABLE ping RENAME TO ping_v1")
            db.execute("ALTER TABLE trace RENAME TO trace_v1")
        db.execute("CREATE TABLE IF NOT EXISTS ping (source TEXT, target TEXT, ts INTEGER, median REAL, loss REAL,"
                   " jitter REAL, rtts TEXT, PRIMARY KEY (source, target, ts)) WITHOUT ROWID")
        db.execute("CREATE TABLE IF NOT EXISTS trace (source TEXT, target TEXT, ts INTEGER, hops TEXT,"
                   " PRIMARY KEY (source, target, ts)) WITHOUT ROWID")
        db.execute("CREATE TABLE IF NOT EXISTS asn (asn TEXT PRIMARY KEY, name TEXT, ts INTEGER) WITHOUT ROWID")
        if old and "source" not in old:
            db.execute("INSERT INTO ping SELECT ?, * FROM ping_v1", (source,))
            db.execute("INSERT INTO trace SELECT ?, * FROM trace_v1", (source,))
            db.execute("DROP TABLE ping_v1")
            db.execute("DROP TABLE trace_v1")
            log(f"database upgraded: existing data now belongs to {source!r}")


def round_rows(source, ts, pings, traces):
    rp = []
    for tid, rtts in (pings or {}).items():
        med, loss, jit, ok = summarize(rtts)
        rp.append((source, tid, ts, med, loss, jit, json.dumps(ok)))
    rt = [(source, tid, ts, json.dumps(h, separators=(",", ":"))) for tid, h in traces.items() if h]
    return rp, rt


def store(path, rp, rt, now):
    cut = now - RETENTION_DAYS * 86400
    asns = {h["asn"] for row in rt for h in json.loads(row[3]) if h.get("asn")}
    with db_open(path) as db:
        db.executemany("INSERT OR REPLACE INTO ping VALUES (?,?,?,?,?,?,?)", rp)
        db.executemany("INSERT OR REPLACE INTO trace VALUES (?,?,?,?)", rt)
        db.executemany("INSERT OR IGNORE INTO asn VALUES (?, NULL, 0)", [(a,) for a in asns])
        db.execute("DELETE FROM ping WHERE ts < ?", (cut,))
        db.execute("DELETE FROM trace WHERE ts < ?", (cut,))


def every_round(fn):
    while True:
        ts = int(time.time()) // STEP * STEP
        try:
            fn(ts)
        except Exception as e:
            log(f"round {ts} failed: {e}")
        time.sleep(max(1.0, ts + STEP - time.time()))


def collector(path, source, targets_fn, ping_fn, trace_fn, before=lambda: None, after=lambda ts: None):
    def one(ts):
        before()
        store(path, *round_rows(source, ts, *probe_round(targets_fn(), ts, ping_fn, trace_fn)), ts)
        after(ts)
    every_round(one)


# ---------- remote agents ----------

def run_agent(server, token, ping_fn, trace_fn):
    """Push mode: probe from here, push each round to the server; keep rounds while it is unreachable."""
    def call(path, body=None):
        req = urllib.request.Request(server + path, data=body and json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "User-Agent": "smoketrace-agent"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    backlog = deque(maxlen=AGENT_BACKLOG)   # ponytail: in memory, lost on restart; a file if that ever matters
    targets = []

    def one(ts):
        nonlocal targets
        global STEP, PINGS
        try:
            got = call("/api/agent/targets")
            targets = agent_targets(got["targets"])
            STEP, PINGS = _int(got["step"], 60, 3600), _int(got["pings"], 1, 100)   # the primary decides
        except Exception as e:
            log(f"cannot fetch targets from {server}: {e}" + (" (using the last list)" if targets else ""))
        if targets:
            pings, traces = probe_round(targets, ts, ping_fn, trace_fn)
            backlog.append({"ts": ts, "pings": pings, "traces": traces})
        while backlog:
            try:
                call("/api/agent/push", backlog[0])
            except Exception as e:
                log(f"push to {server} failed, {len(backlog)} round(s) kept: {e}")
                break
            backlog.popleft()

    log(f"smoketrace agent: pushing to {server}")
    every_round(one)


def run_listener(listen, token, ping_fn, trace_fn):
    """Pull mode: the server comes to us each round with our targets and takes the rounds we have."""
    host, _, port = listen.rpartition(":")
    state = {"targets": [], "backlog": deque(maxlen=AGENT_BACKLOG)}
    lock = threading.Lock()

    class Pull(BaseHTTPRequestHandler):
        def do_GET(self):
            self.reply(200, b"ok") if self.path == "/livez" else self.reply(404, b"not found")

        def do_POST(self):
            global STEP, PINGS
            given = self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
            if self.path != "/api/agent/pull" or not hmac.compare_digest(given, token.encode()):
                return self.reply(401, b'{"error":"bad token"}')
            try:
                size = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(size, MAX_PUSH)))
                with lock:
                    state["targets"] = agent_targets(body["targets"])
                    STEP, PINGS = _int(body["step"], 60, 3600), _int(body["pings"], 1, 100)
                    ack = _int(body.get("ack") or 0, 0, 2 ** 40)
                    while state["backlog"] and state["backlog"][0]["ts"] <= ack:
                        state["backlog"].popleft()      # the server has these: drop them only now
                    rounds = list(state["backlog"])[:PULL_BATCH]
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                return self.reply(400, json.dumps({"error": str(e)}).encode())
            self.reply(200, json.dumps({"rounds": rounds}, separators=(",", ":")).encode())

        def reply(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    def one(ts):
        with lock:
            targets = list(state["targets"])
        if targets:
            pings, traces = probe_round(targets, ts, ping_fn, trace_fn)
            with lock:
                state["backlog"].append({"ts": ts, "pings": pings, "traces": traces})

    threading.Thread(target=every_round, args=(one,), daemon=True).start()
    log(f"smoketrace agent: waiting for the server on {listen}")
    ThreadingHTTPServer((host or "0.0.0.0", int(port)), Pull).serve_forever()


PULL_ACK = {}


def pull_agent(path, name, agent):
    """Ask a pull-mode agent for its rounds (with its targets and our step and pings), store them, acknowledge."""
    ack = PULL_ACK.get(name, 0)
    for _ in range(AGENT_BACKLOG // PULL_BATCH + 1):
        mine = targets_for(name)
        body = {"step": STEP, "pings": PINGS, "ack": ack, "targets": [agent_view(t) for t in mine]}
        req = urllib.request.Request(agent["url"].rstrip("/") + "/api/agent/pull", data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {agent['token']}",
                                              "Content-Type": "application/json", "User-Agent": "smoketrace"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                rounds = json.load(r)["rounds"]
        except Exception as e:
            log(f"cannot pull from {name} ({agent['url']}): {e}")
            return
        now, ids = int(time.time()), {t["id"] for t in mine}
        for r in rounds if isinstance(rounds, list) else []:
            try:
                ts, pings, traces = clean_round(r, ids, now)
                store(path, *round_rows(name, ts, pings, traces), now)
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                log(f"rejected a round from {name}: {e}")
            if isinstance(r, dict) and isinstance(r.get("ts"), int):
                ack = max(ack, r["ts"])
        PULL_ACK[name] = ack
        if rounds:
            ALERTS.check(path, name)
        if len(rounds) < PULL_BATCH:
            return


# ---------- queries ----------

def load_traces(db, src, tid, since=0):
    return [(ts, json.loads(h)) for ts, h in db.execute(
        "SELECT ts, hops FROM trace WHERE source=? AND target=? AND ts>=? ORDER BY ts", (src, tid, since))]


def last_trace(db, src, tid):
    row = db.execute("SELECT hops FROM trace WHERE source=? AND target=? ORDER BY ts DESC LIMIT 1", (src, tid)).fetchone()
    return json.loads(row[0]) if row else []


def summary(db, src, t, now, full=True):
    rows = db.execute("SELECT ts, median, loss, jitter FROM ping WHERE source=? AND target=? AND ts>=? ORDER BY ts",
                      (src, t["id"], now - 86400)).fetchall()
    last_ts, med, loss, jit = rows[-1] if rows else (None, None, None, None)
    meds = [r[1] for r in rows if r[1] is not None]
    base = statistics.median(meds) if meds else None
    out = {**t, "status": status_of(now, last_ts, med, loss, base, t), "last_ts": last_ts,
           "median": med, "loss": loss, "jitter": jit, "baseline": base}
    if full:
        segs, _ = route_segments(load_traces(db, src, t["id"], now - 86400))
        out.update(route_changes=max(0, len(segs) - 1), last_change=segs[-1]["from"] if len(segs) > 1 else None,
                   spark=[[ts, None if m is None else round(m, 2), l] for ts, m, l, _ in rows])
    return out


def probers(t, sources):
    """The sources that probe a target: the server's own (unless nomasterpoll), then the agents it lists."""
    return ([sources[0]] if t.get("master", True) else []) + [
        s for s in sources[1:] if t.get("slaves") is None or s in t["slaves"]]


def targets_for(name):
    return [t for t in Handler.targets if name in probers(t, Handler.sources)]


def overview(db, sources, src, targets, now):
    last = dict(db.execute("SELECT source, MAX(ts) FROM ping GROUP BY source"))
    rows = []
    for t in targets:
        who = probers(t, sources)
        if src not in who:
            continue
        row = summary(db, src, t, now)
        if len(sources) > 1:
            row["by_source"] = {s: summary(db, s, t, now, full=False)["status"] for s in who}
        rows.append(row)
    return {"now": now, "step": STEP, "source": src, "targets": rows, "auth": bool(PASSWORD),
            "sources": [{"name": s, "last_ts": last.get(s)} for s in sources]}


def target_detail(db, src, t, rng, now):
    since = now - rng
    bucket = STEP * max(1, math.ceil(rng / MAX_POINTS / STEP))
    rows = db.execute("SELECT ts, median, loss, jitter, rtts FROM ping WHERE source=? AND target=? AND ts>=? ORDER BY ts",
                      (src, t["id"], since)).fetchall()
    segs, known = route_segments(load_traces(db, src, t["id"]))   # whole history: route letters stay stable
    vis = [{**s, "label": label(s["route"]), "hops": len(known[s["route"]]), "change": k > 0 and s["from"] >= since}
           for k, s in enumerate(segs) if s["end"] > since]
    return {"target": summary(db, src, t, now, full=False), "source": src, "from": since, "to": now,
            "bucket": bucket, "points": bucketize(rows, bucket), "segments": vis, "step": STEP,
            "loss_warn": threshold(t, "loss_warn", LOSS_WARN), "loss_crit": threshold(t, "loss_crit", LOSS_CRIT),
            "pings": PINGS}


def trace_detail(db, src, tid, ts, vs):
    """Trace at/just before ts (latest if None) vs the last trace of the previous route, or the previous round."""
    traces = load_traces(db, src, tid)   # ponytail: full scan per click, ~ms for 30 d; index route changes if slow
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
    asns = sorted({h.get("asn") for s in (cur, prev) if s for h in s["hops"] if h.get("asn")})
    names = dict(db.execute(f"SELECT asn, name FROM asn WHERE asn IN ({','.join('?' * len(asns))})", asns)) if asns else {}
    return {"cur": cur, "prev": prev, "vs": vs, "fallback": fallback, "asn_names": names,
            "rows": diff_hops(prev and prev["hops"], cur["hops"])}


def metrics(db, sources, targets, now):
    """Prometheus text format: one series per target and source."""
    def lab(**kv):
        return ",".join(f'{k}="{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34)).replace(chr(10), " ")}"'
                        for k, v in kv.items())
    series = {
        "median_seconds": ("gauge", "Median round-trip time of the last round"),
        "loss_ratio": ("gauge", "Share of pings lost in the last round, 0 to 1"),
        "jitter_seconds": ("gauge", "Mean difference between consecutive replies in the last round"),
        "status": ("gauge", "0 ok, 1 warning, 2 critical, 3 down, 4 no data"),
        "route_changes_24h": ("gauge", "Route changes over the last 24 hours"),
        "last_round_timestamp_seconds": ("gauge", "When the last round was taken"),
    }
    values = {k: [] for k in series}
    for t in targets:
        for src in probers(t, sources):
            s = summary(db, src, t, now)
            l = lab(target=t["id"], name=t["name"], group=t["group"], host=t["host"], probe=t["probe"], source=src)
            for key, v in (("median_seconds", s["median"] and s["median"] / 1000),
                           ("loss_ratio", s["loss"] is not None and s["loss"] / 100),
                           ("jitter_seconds", s["jitter"] and s["jitter"] / 1000),
                           ("status", STATUS_CODE[s["status"]]), ("route_changes_24h", s["route_changes"]),
                           ("last_round_timestamp_seconds", s["last_ts"])):
                if v is not None and v is not False:
                    values[key].append(f"smoketrace_{key}{{{l}}} {float(v):g}")
    out = []
    for key, (kind, help_) in series.items():
        out += [f"# HELP smoketrace_{key} {help_}", f"# TYPE smoketrace_{key} {kind}", *values[key]]
    return "\n".join(out) + "\n"


# ---------- alerts ----------

LEVEL = {"down": (0xD03B3B, 5, "rotating_light"), "crit": (0xEC835A, 4, "warning"), "warn": (0xFAB219, 3, "warning"),
         "ok": (0x0CA30C, 3, "white_check_mark"), "route": (0x2A78D6, 3, "twisted_rightwards_arrows"),
         "silent": (0x898781, 4, "zzz")}
WORDS = {"ok": "OK", "warn": "warning", "crit": "critical", "down": "down", "stale": "no data"}


class Alerter:
    """Status and route changes, held for ALERT_ROUNDS rounds before they are sent: Discord, ntfy, any webhook."""

    def __init__(self, discord=None, ntfy=None, webhook=None, routes=True):
        self.discord, self.ntfy, self.webhook, self.routes = discord, ntfy, webhook, routes
        self.state, self.silent, self.lock = {}, {}, threading.Lock()

    def enabled(self):
        return bool(self.discord or self.ntfy or self.webhook)

    def check(self, path, src):
        """After a round from `src` is stored: every target it probes."""
        if not self.enabled():
            return
        now = int(time.time())
        with self.lock, db_open(path) as db:
            for t in Handler.targets:
                if src in probers(t, Handler.sources):
                    self.one(db, src, t, now)

    def one(self, db, src, t, now):
        s = summary(db, src, t, now, full=False)
        hops = last_trace(db, src, t["id"])
        key = (src, t["id"])
        k = self.state.get(key)
        if k is None:       # first look after a start: remember, do not alert
            self.state[key] = {"status": s["status"], "pend": None, "n": 0, "hops": hops, "phops": None, "pn": 0}
            return
        st = s["status"]
        if st != "stale":   # a silent source is one alert for the source, not one per target
            if st == k["status"]:
                k["pend"], k["n"] = None, 0
            else:
                k["n"] = k["n"] + 1 if k["pend"] == st else 1
                k["pend"] = st
                if k["n"] >= ALERT_ROUNDS:
                    old, k["status"], k["pend"], k["n"] = k["status"], st, None, 0
                    self.send(self.status_event(db, src, t, s, old, hops, now))
        p = path_of(hops)
        if not path_of(k["hops"]):          # no route known yet: this one is the reference
            k["hops"] = hops
        elif self.routes and p:
            if same_path(path_of(k["hops"]), p):
                k["phops"], k["pn"] = None, 0
            else:
                same_new = k["phops"] is not None and same_path(path_of(k["phops"]), p)
                k["pn"], k["phops"] = (k["pn"] + 1 if same_new else 1), hops
                if k["pn"] >= ALERT_ROUNDS:
                    old, k["hops"], k["phops"], k["pn"] = k["hops"], hops, None, 0
                    self.send(self.route_event(db, src, t, old, hops))

    def sources(self, path, now):
        """Agents that stopped (or started again) sending rounds."""
        if not self.enabled():
            return
        with db_open(path) as db:
            last = dict(db.execute("SELECT source, MAX(ts) FROM ping GROUP BY source"))
        for name in Handler.sources[1:]:
            quiet = last.get(name) is None or now - last[name] > 3 * STEP
            was = self.silent.setdefault(name, quiet)
            if quiet != was:
                self.silent[name] = quiet
                self.send({"kind": "source", "level": "silent" if quiet else "ok", "source": name, "target": None,
                           "title": f"Agent {name} stopped sending rounds" if quiet else f"Agent {name} is back",
                           "lines": [f"Last round {datetime.fromtimestamp(last[name]).strftime('%d/%m %H:%M')}"]
                                    if last.get(name) else [], "url": PUBLIC_URL})

    def hop_text(self, db, h):
        name = h.get("asn") and (db.execute("SELECT name FROM asn WHERE asn=?", (h["asn"],)).fetchone() or [None])[0]
        asn = f", {h['asn']}{' ' + name.split(' - ')[-1] if name else ''}" if h.get("asn") else ""
        return f"hop {h['ttl']} ({h['ip'] or '???'}{asn})"

    def status_event(self, db, src, t, s, old, hops, now):
        title = f"{t['name']} is {WORDS[s['status']]}" if s["status"] != "ok" else f"{t['name']} is OK again"
        lines = [f"Median {s['median']:.1f} ms · loss {s['loss']:.0f} %" if s["median"] is not None
                 else f"Loss {s['loss']:.0f} %", f"Was {WORDS[old]}"]
        origin = loss_origin(hops)
        if origin is not None and s["status"] != "ok":
            lines.append("Real loss starts at " + self.hop_text(db, next(h for h in hops if h["ttl"] == origin)))
        answered = [h for h in hops if h["ip"]]
        if hops and not hops[-1]["ip"] and answered:
            lines.append("The traceroute stops after " + self.hop_text(db, answered[-1]))
        for other in probers(t, Handler.sources):
            if other != src:
                lines.append(f"Seen from {other}: {WORDS[summary(db, other, t, now, full=False)['status']]}")
        return {"kind": "status", "level": s["status"], "previous": old, "source": src, "target": t["id"],
                "title": title, "lines": lines, "url": PUBLIC_URL and f"{PUBLIC_URL}/#/t/{t['id']}"}

    def route_event(self, db, src, t, old, hops):
        lines = []
        for r in diff_hops(old, hops):
            if r["state"] in ("changed", "added", "removed"):
                a, b = r["prev"], r["cur"]
                lines.append(f"{self.hop_text(db, b or a)}: {(a or {}).get('ip') or '—'} → {(b or {}).get('ip') or '—'}")
        old_as = [h["asn"] for h in old if h.get("asn")]
        new_as = [h["asn"] for h in hops if h.get("asn")]
        if old_as and new_as and list(dict.fromkeys(old_as)) != list(dict.fromkeys(new_as)):
            lines.append(f"AS path: {' › '.join(dict.fromkeys(old_as))}  →  {' › '.join(dict.fromkeys(new_as))}")
        return {"kind": "route", "level": "route", "source": src, "target": t["id"],
                "title": f"Route to {t['name']} changed", "lines": lines[:8],
                "url": PUBLIC_URL and f"{PUBLIC_URL}/#/t/{t['id']}"}

    def send(self, ev):
        ev = {**ev, "ts": int(time.time())}
        log(f"alert: {ev['title']} (from {ev['source']})")
        threading.Thread(target=self.deliver, args=(ev,), daemon=True).start()

    def deliver(self, ev):
        for name in ("discord", "ntfy", "webhook"):
            if getattr(self, name):
                try:
                    getattr(self, "to_" + name)(ev)
                except Exception as e:
                    log(f"alert to {name} failed: {e}")

    @staticmethod
    def post(url, data, headers):
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "smoketrace", **headers})
        urllib.request.urlopen(req, timeout=10).close()

    def to_discord(self, ev):
        color = LEVEL[ev["level"]][0]
        embed = {"title": ev["title"], "description": "\n".join(ev["lines"]), "color": color,
                 "footer": {"text": f"smoketrace · seen from {ev['source']}"},
                 "timestamp": datetime.fromtimestamp(ev["ts"], timezone.utc).isoformat()}
        if ev.get("url"):
            embed["url"] = ev["url"]
        self.post(self.discord, json.dumps({"username": "smoketrace", "embeds": [embed]}).encode(),
                  {"Content-Type": "application/json"})

    def to_ntfy(self, ev):
        _, prio, tag = LEVEL[ev["level"]]
        title = f"{ev['title']} (from {ev['source']})"
        headers = {"Title": "=?UTF-8?B?" + base64.b64encode(title.encode()).decode() + "?=",
                   "Priority": str(prio), "Tags": tag}
        if ev.get("url"):
            headers["Click"] = ev["url"]
        self.post(self.ntfy, "\n".join(ev["lines"]).encode(), headers)

    def to_webhook(self, ev):
        self.post(self.webhook, json.dumps(ev).encode(), {"Content-Type": "application/json"})


ALERTS = Alerter()


# ---------- sign-in ----------

def session_value(expiry):
    sig = hmac.new(PASSWORD.encode(), str(expiry).encode(), hashlib.sha256).hexdigest()
    return f"{expiry}.{sig}"


def signed_in(cookie_header):
    if not PASSWORD:
        return True
    try:
        morsel = SimpleCookie(cookie_header or "").get("smoketrace")
    except Exception:       # http.cookies.CookieError on a malformed header
        return False
    expiry = morsel.value.partition(".")[0] if morsel else ""
    return expiry.isdigit() and int(expiry) > time.time() and hmac.compare_digest(session_value(int(expiry)), morsel.value)


LOGIN_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>smoketrace · sign in</title>
<style>
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink-2:#52514e;--border:rgba(11,11,11,.12);--focus:#2a78d6;--bad:#d03b3b}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink-2:#c3c2b7;--border:rgba(255,255,255,.12);--focus:#3987e5}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
form{width:min(340px,100%);background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px 24px}
.brand{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:650;margin-bottom:20px}.brand span{color:var(--ink-2);font-weight:450}
label{display:block;font-size:12px;color:var(--ink-2);margin-bottom:6px}
input{width:100%;height:38px;padding:0 12px;border:1px solid var(--border);border-radius:8px;background:var(--page);color:var(--ink);font:inherit}
button{margin-top:14px;width:100%;height:38px;border:0;border-radius:8px;background:var(--ink);color:var(--surface);font:inherit;font-weight:600;cursor:pointer}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}.err{color:var(--bad);font-size:13px;margin:10px 0 0}
</style></head><body><form method="post" action="/login">
<div class="brand"><svg width="20" height="20" viewBox="0 0 18 18" aria-hidden="true"><path d="M1 12c2.5 0 2.5-6 5-6s2.5 8 5 8 2.5-10 5-10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><div>smoke<span>trace</span></div></div>
<label for="p" id="l">Password</label><input id="p" name="password" type="password" autocomplete="current-password" autofocus required>
<button id="b">Sign in</button>%ERROR%</form>
<script>if((localStorage.getItem("lang")||navigator.language||"").slice(0,2)==="pt"){document.getElementById("l").textContent="Palavra-passe";document.getElementById("b").textContent="Entrar";const e=document.querySelector(".err");if(e)e.textContent="Palavra-passe errada."}</script>
</body></html>"""


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    db = None
    targets = []
    sources = ["local"]     # this probe first, then the agents
    agents = {}             # name -> {token, url}
    metrics_cache = (0, "")

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        now = int(time.time())
        try:
            if u.path == "/livez":
                return self.send(200, b"ok", "text/plain")
            if u.path == "/login":
                return self.send(200, LOGIN_PAGE.replace("%ERROR%", "").encode(), "text/html; charset=utf-8")
            if u.path == "/logout":
                return self.redirect("/login", "smoketrace=; Max-Age=0; Path=/")
            if u.path == "/metrics":
                return self.metrics(now)
            if u.path == "/api/agent/targets":
                name = self.agent()
                if not name:
                    return self.send(401, b'{"error":"bad token"}', "application/json")
                return self.json({"step": STEP, "pings": PINGS, "targets": [agent_view(t) for t in targets_for(name)]})
            if not signed_in(self.headers.get("Cookie")):
                if u.path.startswith("/api/"):
                    return self.send(401, b'{"error":"sign in"}', "application/json")
                return self.redirect("/login")
            if u.path in ("/", "/index.html"):
                return self.send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            src = q.get("src") or self.sources[0]
            if src not in self.sources:
                raise ValueError(src)
            t = next((x for x in self.targets if x["id"] == q.get("id")), None)
            with db_open(self.db) as db:
                if u.path == "/api/overview":
                    return self.json(overview(db, self.sources, src, self.targets, now))
                if u.path == "/api/target" and t:
                    rng = int(q.get("range", 86400))
                    return self.json(target_detail(db, src, t, min(max(rng, 3600), RANGES[-1]), now))
                if u.path == "/api/trace" and t:
                    ts = int(q["ts"]) if q.get("ts") else None
                    return self.json(trace_detail(db, src, t["id"], ts, "round" if q.get("vs") == "round" else "route"))
            self.send(404, b'{"error":"not found"}', "application/json")
        except ValueError:
            self.send(400, b'{"error":"bad request"}', "application/json")

    def do_POST(self):
        path = urlparse(self.path).path
        size = int(self.headers.get("Content-Length") or 0)
        if not 0 < size <= MAX_PUSH:
            return self.send(413, b'{"error":"too large"}', "application/json")
        body = self.rfile.read(size)
        if path == "/login" and PASSWORD:
            given = parse_qs(body.decode("utf-8", "replace")).get("password", [""])[0]
            if hmac.compare_digest(given.encode(), PASSWORD.encode()):
                expiry = int(time.time()) + SESSION_DAYS * 86400
                secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
                return self.redirect("/", f"smoketrace={session_value(expiry)}; Max-Age={SESSION_DAYS * 86400};"
                                          f" Path=/; HttpOnly; SameSite=Strict{secure}")
            time.sleep(1)       # slows down guessing
            page = LOGIN_PAGE.replace("%ERROR%", '<p class="err" role="alert">Wrong password.</p>')
            return self.send(401, page.encode(), "text/html; charset=utf-8")
        if path != "/api/agent/push":
            return self.send(404, b'{"error":"not found"}', "application/json")
        name = self.agent()
        if not name:
            return self.send(401, b'{"error":"bad token"}', "application/json")
        now = int(time.time())
        try:
            ts, pings, traces = clean_round(json.loads(body), {t["id"] for t in targets_for(name)}, now)
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            log(f"rejected a round from {name}: {e}")
            return self.send(400, b'{"error":"bad round"}', "application/json")
        store(self.db, *round_rows(name, ts, pings, traces), now)
        ALERTS.check(self.db, name)
        self.json({"ok": True})

    def metrics(self, now):
        if METRICS_TOKEN or PASSWORD:
            given = self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
            if not METRICS_TOKEN or not hmac.compare_digest(given, METRICS_TOKEN.encode()):
                return self.send(401, b"set METRICS_TOKEN and send it as a bearer token\n", "text/plain")
        at, text = Handler.metrics_cache
        if now - at >= 30:
            with db_open(self.db) as db:
                text = metrics(db, self.sources, self.targets, now)
            Handler.metrics_cache = (now, text)
        self.send(200, text.encode(), "text/plain; version=0.0.4")

    def agent(self):
        """The agent whose token this request carries, or None."""
        given = self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
        return next((n for n, a in self.agents.items() if given and hmac.compare_digest(given, a["token"].encode())), None)

    def redirect(self, where, cookie=None):
        self.send_response(303)
        self.send_header("Location", where)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def json(self, obj):
        self.send(200, json.dumps(obj, separators=(",", ":")).encode(), "application/json")

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


# ---------- importing SmokePing's RRD history ----------

def parse_rrd_fetch(text):
    """`rrdtool fetch` output -> (data source names, [(ts, {name: value or None})])."""
    names, rows = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        if not names:
            names = line.split()
            continue
        ts, sep, vals = line.partition(":")
        if not sep:
            continue
        vs = []
        for v in vals.split():
            try:
                f = float(v)
                vs.append(None if math.isnan(f) else f)
            except ValueError:
                vs.append(None)
        rows.append((int(ts), dict(zip(names, vs))))
    return names, rows


def rrd_rows(source, tid, names, data, res):
    """SmokePing's RRD rows (seconds; `loss` in lost pings; ping1..pingN sorted) -> our ping rows."""
    pings = sorted((n for n in names if re.fullmatch(r"ping\d+", n)), key=lambda n: int(n[4:]))
    out = []
    for ts, v in data:
        if v.get("loss") is None and v.get("median") is None:
            continue
        rtts = sorted(round(v[n] * 1000, 3) for n in pings if v.get(n) is not None)
        loss = 100.0 * v["loss"] / len(pings) if v.get("loss") is not None and pings else (0.0 if rtts else 100.0)
        med = round(v["median"] * 1000, 3) if v.get("median") is not None else None
        start = (ts - res) // STEP * STEP           # rrdtool stamps the end of each interval
        out.append((source, tid, start, med, round(min(loss, 100.0), 1), None, json.dumps(rtts)))
    return out


def import_rrd(a):
    """One-off: every <datadir>/<path>/<Target>[~slave].rrd into the database, up to RETENTION_DAYS back."""
    if not shutil.which("rrdtool"):
        raise SystemExit("rrdtool not found: run this on the SmokePing machine (it has rrdtool), or install it")
    root = Path(a.import_rrd)
    known = {t["id"] for t in load_config(a)["targets"]} if a.smokeping else None
    db = a.db or HERE / "smoketrace.db"
    init_db(db, a.name)
    now = int(time.time())
    done = skipped = 0
    for f in sorted(root.rglob("*.rrd")):
        parts = list(f.relative_to(root).with_suffix("").parts)
        name, _, slave = parts[-1].partition("~")
        tid, src = slug("-".join([*parts[:-1], name])), slave or a.name
        if known is not None and tid not in known:
            skipped += 1
            continue
        rows = []
        for start, end, res in ((now - RETENTION_DAYS * 86400, now - 3 * 86400, 3600), (now - 3 * 86400, now, STEP)):
            r = subprocess.run(["rrdtool", "fetch", str(f), "AVERAGE", "-s", str(start), "-e", str(end), "-r", str(res)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                log(f"{f}: {r.stderr.strip()}")
                continue
            names, data = parse_rrd_fetch(r.stdout)
            step = data[1][0] - data[0][0] if len(data) > 1 else res
            rows += rrd_rows(src, tid, names, data, step)
        with db_open(db) as c:
            c.executemany("INSERT OR IGNORE INTO ping VALUES (?,?,?,?,?,?,?)", rows)   # smoketrace's own rounds win
        done += 1
        log(f"{f.relative_to(root)}: {len(rows)} rounds as {tid} from {src}")
    log(f"imported {done} RRD files" + (f", skipped {skipped} with no target in the config" if skipped else ""))


# ---------- demo ----------

DEMO_TARGETS = [   # (group, name, host, scenario)
    ("LAN", "Router", "192.168.1.1", "lan"),
    ("Internet", "Cloudflare DNS", "1.1.1.1", "reroute"),   # path change + latency step + loss starting on the new path
    ("Internet", "Google DNS", "8.8.8.8", "flap"),          # path alternating in the last 3 h
    ("Internet", "Quad9", "9.9.9.9", "ratelimit"),          # loss on a mid hop only, plus one real-loss hour
    ("Internet", "Wikipedia", "185.15.59.224", "ok"),
    ("Services", "Shop (HTTPS)", "tcp://203.0.113.20:443", "ok"),
    ("Services", "VPS Frankfurt", "203.0.113.10", "down"),  # dead for the last 40 min, seen from everywhere
]
DEMO_AGENT = "porto"   # a second vantage point: same targets, its own ISP, none of the local route trouble
DEMO_AS = {"AS64496": "HOMENET - Home ISP, PT", "AS64497": "TRANSIT-ONE - Transit One, EU",
           "AS64498": "TRANSIT-TWO - Transit Two, EU", "AS64499": "DESTNET - Destination Networks, EU",
           "AS64500": "PORTONET - Porto ISP, PT"}


def demo_probes(t0, remote=False):
    """Synthetic rounds, deterministic per (host, ts) so seeded history and live rounds agree."""
    scen = {parse_host(h)["host"]: (i, s) for i, (_, _, h, s) in enumerate(DEMO_TARGETS)}

    def state(host, ts):
        i, s = scen[host]
        if remote:
            s = {"reroute": "ok", "flap": "ok", "lan": "ok"}.get(s, s)
        age, rnd = t0 - ts, random.Random(f"{host}/{ts}/{remote}")
        hour = time.localtime(ts).tm_hour + time.localtime(ts).tm_min / 60
        base = 0.4 if s == "lan" else 6.0 + 7 * i + (4 if remote else 0)
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
            return [(host, None)]
        isp = ([("10.20.0.1", None), ("100.72.0.1", "AS64500"), ("198.51.100.200", "AS64500")] if remote else
               [("192.168.1.1", None), ("100.64.0.1", "AS64496"), (None, None), ("198.51.100.1", "AS64496")])
        mid = ([(f"198.51.100.{20 + i}", "AS64497"), (f"203.0.113.{100 + i}", "AS64497")] if route == 0 else
               [(f"198.51.100.{120 + i}", "AS64498"), (f"198.51.100.{140 + i}", "AS64498"),
                (f"203.0.113.{160 + i}", "AS64498")])
        return isp + mid + [(host, "AS64499")]

    def ping(targets, ts):
        out = {}
        for t in targets:
            rnd, _, _, lat, loss, sd, _, down = state(t["host"], ts)
            out[t["id"]] = [None if down or rnd.random() < loss else round(lat + abs(rnd.gauss(0, sd)), 3)
                            for _ in range(PINGS)]
        return out

    def trace(t, ts):
        rnd, i, s, lat, loss, sd, route, down = state(t["host"], ts)
        p = path(t["host"], i, s, route)
        hops = []
        for k, (ip, asn) in enumerate(p, 1):
            hl = 0.0
            if s == "ratelimit" and k == 2:
                hl = rnd.choice([20.0, 30.0, 40.0, 50.0])
            elif s == "ratelimit" and loss > 0.1 and k >= 5:
                hl = rnd.choice([10.0, 20.0])
            elif s == "reroute" and route == 1 and k >= 5:
                hl = rnd.choice([0.0, 10.0, 10.0, 20.0])
            if down and k >= 5:
                ip, asn = None, None
            if ip is None:
                hl = 100.0
            avg = 0.4 if k == 1 else lat * (0.2 + 0.8 * k / len(p)) + abs(rnd.gauss(0, sd))
            live = ip is not None
            hops.append({"ttl": k, "ip": ip, "asn": asn, "loss": hl,
                         "avg": round(avg, 3) if live else None,
                         "best": round(max(0.1, avg - abs(rnd.gauss(0, sd))), 3) if live else None,
                         "wrst": round(avg + abs(rnd.gauss(0, sd)) * 3, 3) if live else None,
                         "sd": round(sd * 0.8, 3) if live else None})
        return hops

    return ping, trace


def seed_demo(path, source, targets, ping, trace, t0, days=7):
    rp, rt = [], []
    end = t0 // STEP * STEP
    for ts in range(end - days * 86400, end, STEP):
        a, b = round_rows(source, ts, ping(targets, ts), {t["id"]: trace(t, ts) for t in targets})
        rp += a
        rt += b
    store(path, rp, rt, end)
    with db_open(path) as db:
        db.executemany("INSERT OR REPLACE INTO asn VALUES (?, ?, 0)", DEMO_AS.items())


# ---------- main ----------

CONFIG = {"stamp": None, "files": []}


def apply_config(a, cfg):
    global STEP, PINGS
    STEP, PINGS = cfg["step"], cfg["pings"]
    Handler.targets, Handler.agents, Handler.sources = cfg["targets"], cfg["agents"], [a.name, *cfg["agents"]]
    CONFIG.update(files=cfg["files"], stamp=stamp(cfg["files"]))


def maybe_reload(a):
    """Re-read the config when any file it came from changed; a broken edit keeps the last good config."""
    if stamp(CONFIG["files"]) == CONFIG["stamp"]:
        return
    try:
        cfg = load_config(a)
    except SystemExit as e:
        CONFIG["stamp"] = stamp(CONFIG["files"])     # do not retry the same broken edit every round
        log(f"config not reloaded, keeping the last one: {e}")
        return
    apply_config(a, cfg)
    log(f"config reloaded: {len(cfg['targets'])} targets, agents {', '.join(cfg['agents']) or 'none'}")


def after_round(db, a):
    """The server's own round is stored: alerts, then the agents the server pulls from."""
    def run(ts):
        ALERTS.check(db, a.name)
        ALERTS.sources(db, int(time.time()))
        for name, agent in Handler.agents.items():
            if agent.get("url"):
                threading.Thread(target=pull_agent, args=(db, name, agent), daemon=True).start()
    return run


def main():
    global PASSWORD, METRICS_TOKEN, PUBLIC_URL, ASN_LOOKUP, LOSS_WARN, LOSS_CRIT, ALERTS
    env = os.environ.get
    ap = argparse.ArgumentParser(description="SmokePing-style latency + mtr traceroutes")
    ap.add_argument("--targets", type=Path, default=Path(env("TARGETS", HERE / "targets.ini")))
    ap.add_argument("--smokeping", type=Path, default=env("SMOKEPING_CONFIG"),
                    help="read targets, slaves (as agents), step and pings from SmokePing's config instead")
    ap.add_argument("--db", type=Path, default=env("DB"))
    ap.add_argument("--bind", default=env("BIND", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(env("PORT", "8099")))
    ap.add_argument("--name", default=env("NAME", "local"), help="what the dashboard calls this probe")
    ap.add_argument("--agents", default=env("AGENTS", ""),
                    help="agents: name=token (they push) or name=token@http://agent:8100 (the server pulls)")
    ap.add_argument("--agent", metavar="SERVER_URL", default=env("SERVER"), help="run as an agent pushing to SERVER_URL")
    ap.add_argument("--listen", metavar="HOST:PORT", default=env("LISTEN"), help="run as an agent the server pulls from")
    ap.add_argument("--token", default=env("TOKEN"), help="this agent's token (as the server knows it)")
    ap.add_argument("--import-rrd", metavar="DATADIR", default=env("IMPORT_RRD"), help="import SmokePing's RRD files")
    ap.add_argument("--demo", action="store_true", default=env("DEMO") == "1", help="synthetic data, no probes")
    a = ap.parse_args()

    PASSWORD, METRICS_TOKEN = env("PASSWORD") or None, env("METRICS_TOKEN") or None
    PUBLIC_URL = (env("PUBLIC_URL") or "").rstrip("/") or None
    ASN_LOOKUP = env("ASN", "1") != "0"
    LOSS_WARN, LOSS_CRIT = float(env("LOSS_WARN", LOSS_WARN)), float(env("LOSS_CRIT", LOSS_CRIT))
    ALERTS = Alerter(env("DISCORD_WEBHOOK"), env("NTFY_URL"), env("WEBHOOK_URL"), routes=env("ALERT_ROUTES", "1") != "0")
    if a.import_rrd:
        return import_rrd(a)
    if not a.demo:
        missing = [b for b in ("fping", "mtr") if not shutil.which(b)]
        if missing:
            raise SystemExit(f"{', '.join(missing)} not found (Debian: apt install fping mtr-tiny)")
    if a.agent or a.listen:
        if not a.token:
            raise SystemExit("an agent needs --token (TOKEN)")
        if a.listen:
            return run_listener(a.listen, a.token, real_ping, mtr)
        return run_agent(a.agent.rstrip("/"), a.token, real_ping, mtr)

    if not NAME_RE.fullmatch(a.name):
        raise SystemExit(f"--name {a.name!r}: lowercase letters, digits and -")
    if a.demo:
        targets = [make_target(slug(f"{g}-{n}"), g, n, **parse_host(h)) for g, n, h, _ in DEMO_TARGETS]
        db = a.db or HERE / "demo.db"
        for suffix in ("", "-wal", "-shm"):
            Path(f"{db}{suffix}").unlink(missing_ok=True)
        t0 = int(time.time())
        init_db(db, a.name)
        probes = {a.name: demo_probes(t0), DEMO_AGENT: demo_probes(t0, remote=True)}
        Handler.db, Handler.targets, Handler.sources, Handler.agents = db, targets, list(probes), {}
        for name, (ping_fn, trace_fn) in probes.items():
            seed_demo(db, name, targets, ping_fn, trace_fn, t0)
            after = lambda ts, name=name: ALERTS.check(db, name)
            threading.Thread(target=collector, args=(db, name, lambda: targets, ping_fn, trace_fn),
                             kwargs={"after": after}, daemon=True).start()
    else:
        db = a.db or HERE / "smoketrace.db"
        init_db(db, a.name)
        apply_config(a, load_config(a))
        master = lambda: [t for t in Handler.targets if t["master"]]
        threading.Thread(target=collector, args=(db, a.name, master, real_ping, mtr, lambda: maybe_reload(a),
                                                 after_round(db, a)), daemon=True).start()
        if ASN_LOOKUP:
            threading.Thread(target=asn_namer, args=(db,), daemon=True).start()
        Handler.db = db

    extras = [x for x, on in (("sign-in", PASSWORD), ("alerts", ALERTS.enabled()), ("metrics token", METRICS_TOKEN)) if on]
    log(f"smoketrace: {len(Handler.targets)} targets, sources {', '.join(Handler.sources)}"
        f"{', ' + ', '.join(extras) if extras else ''}, http://{a.bind}:{a.port}")
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
