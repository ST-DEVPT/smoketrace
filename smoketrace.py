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
import gzip
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
import signal
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
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

VERSION = "0.12.0"           # the top of CHANGELOG.md says the same; a test checks
HERE = Path(__file__).resolve().parent
STEP = DEFAULT_STEP = 300   # seconds per round (SmokePing default); SmokePing's *** Database *** can change it
PINGS = DEFAULT_PINGS = 20  # pings per round (SmokePing default); likewise
MTR_CYCLES = 10
TRACE_PARALLEL = 16         # mtr at once at most: each raw socket sees every ICMP reply of the others (CPU ~ n²)
TRACE_STEP = None           # seconds between two traceroutes of a target (TRACE_STEP); None: every round
STEP_ENV = None             # STEP from the environment: wins over SmokePing's *** Database *** step
RETENTION_DAYS = 30         # ponytail: raw rows, no RRD consolidation; ~1 KB per trace, a few GB at 500 targets
LOSS_WARN, LOSS_CRIT = 10.0, 20.0       # % lost in the last round: 2 of 20 pings warn, 4 are critical; per target too
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
HOST_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*")   # no leading "-": a host must never parse as a probe option
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")   # site names: as written, case kept
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


def duration(value, name):
    """`180`, `180s`, `3m` or `1h` -> seconds; SystemExit names the variable when it is not one."""
    m = re.fullmatch(r"\s*(\d+)\s*([smh]?)\s*", str(value).lower())
    if not m:
        raise SystemExit(f"{name}={value!r}: seconds, or a number with s, m or h (180, 3m, 1h)")
    return int(m[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[m[2]]


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


def address(t):
    """A target's address as it is written: host, tcp://host:port or dns://server/name."""
    if t["probe"] == "tcp":
        return f"tcp://{'[' + t['host'] + ']' if ':' in t['host'] else t['host']}:{t['port']}"
    return f"dns://{t['host']}/{t['lookup']}" if t["probe"] == "dns" else t["host"]


EDITABLE = ("group", "name", "address", "slaves", "master", "loss_warn", "loss_crit", "latency_warn")


def target_from(d, tid):
    """A target from the page's fields (or a targets.json entry); ValueError names the field that is wrong."""
    group, name = str(d.get("group") or "").strip(), str(d.get("name") or "").strip()
    if not group or len(group) > 120 or any(c in group for c in "[]\n\r"):
        raise ValueError("group: a name without [ ] or line breaks, up to 120 characters")
    if not name or len(name) > 120 or any(c in name for c in "=\n\r"):
        raise ValueError("name: a name without = or line breaks, up to 120 characters")
    slaves = d.get("slaves")
    if slaves is not None and not (isinstance(slaves, list) and all(isinstance(x, str) and NAME_RE.fullmatch(x) for x in slaves)):
        raise ValueError("slaves: a list of agent names")
    limits = {}
    for k in ("loss_warn", "loss_crit", "latency_warn"):
        v = d.get(k)
        if v in (None, ""):
            limits[k] = None
        elif isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= (100 if k != "latency_warn" else 60000):
            limits[k] = float(v)
        else:
            raise ValueError(f"{k}: a number" + (" from 0 to 100" if k != "latency_warn" else " of ms"))
    try:
        return make_target(tid, group, name, **parse_host(str(d.get("address") or "")), slaves=slaves,
                           master=d.get("master", True) is not False, **limits)
    except ValueError as e:
        raise ValueError(f"address: {e}")


def load_json_targets(path):
    """targets.json, the list the page edits: {"targets": [{id, group, name, address, ...}], "agents": [...]}.
    -> (targets, the agents it already knew, or None when it predates that list)"""
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
        targets = [target_from(d, d["id"]) for d in body["targets"]]
        known = body.get("agents")
        if known is not None and not (isinstance(known, list) and all(isinstance(x, str) for x in known)):
            raise ValueError("agents: a list of agent names")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise SystemExit(f"{path}: {e}")
    if len({t["id"] for t in targets}) != len(targets):
        raise SystemExit(f"{path}: two targets share an id")
    return targets, known


def save_json_targets(path, targets, agents=()):
    """Written whole and swapped in, so a reader never sees half a file. `agents`: the agents it has seen, so one
    added later is told apart from one taken off a target on purpose."""
    body = {"targets": [{"id": t["id"], **{k: (address(t) if k == "address" else t[k]) for k in EDITABLE}} for t in targets],
            "agents": sorted(set(agents))}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(body, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def edit_targets(targets, op, d):
    """-> the new list. Ids stay with their targets through renames and moves, so their history stays too."""
    out = list(targets)
    i = next((k for k, t in enumerate(out) if t["id"] == d.get("id")), None)
    if op == "delete":
        if i is None:
            raise ValueError("id: no such target")
        del out[i]
        return out
    if op != "save":
        raise ValueError("op: save or delete")
    if d.get("id") and i is None:
        raise ValueError("id: no such target")
    tid = out[i]["id"] if i is not None else slug(f"{d.get('group')}-{d.get('name')}")
    taken = {t["id"] for k, t in enumerate(out) if k != i}
    base, n = tid, 2
    while tid in taken:                    # a new target never takes an old one's id (nor its history)
        tid, n = f"{base}-{n}", n + 1
    t = target_from(d, tid)
    if any((x["group"], x["name"]) == (t["group"], t["name"]) for k, x in enumerate(out) if k != i):
        raise ValueError("name: this group already has a target with that name")
    if i is None:
        out.append(t)
    else:
        out[i] = t
    return out


def parse_agents(spec, local):
    """"porto=token,office=token@http://office:8100" -> {name: {token, url}}; a url means the server pulls."""
    agents = {}
    for item in filter(None, (s.strip() for s in spec.split(","))):
        name, sep, rest = item.partition("=")
        token, _, url = rest.partition("@")
        if not sep or not NAME_RE.fullmatch(name) or name == local:
            raise SystemExit(f"AGENTS: {name!r} must be a name of letters, digits, _ and - other than {local!r}")
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
            log(f"slave {n!r} ignored: agent names are letters, digits, _ and -")
        elif not secrets.get(n, "").strip():
            log(f"slave {n!r} ignored: no secret for it in {path}")
        else:
            agents[n] = {"token": secrets[n].strip(), "url": attrs.get("url") or None}
            if len(agents[n]["token"]) < 16:
                log(f"slave {n!r}: its secret is short ({len(agents[n]['token'])} characters); a longer one is safer")
    return agents


def add_new_agents(targets, agents, known):
    """An agent the targets do not know yet probes all of them: it is added to every target that lists its agents
    (a target with no list is probed by every agent already). `known`: the agents seen before, or None for the
    ones some target names. -> the new agents, if a target had to take them"""
    if known is None:
        known = {n for t in targets for n in t["slaves"] or ()}
    new, listed = [n for n in agents if n not in known], [t for t in targets if t["slaves"] is not None]
    for t in listed if new else ():
        t["slaves"] = t["slaves"] + [n for n in new if n not in t["slaves"]]
    return new if listed else []


def load_config(a):
    """-> {targets, agents, step, pings, files}, from SmokePing's config or targets.ini, plus AGENTS."""
    files, step, pings, agents = [], DEFAULT_STEP, DEFAULT_PINGS, {}
    edited = a.targets.with_suffix(".json")       # once targets are edited on the page, they live here
    if a.smokeping:
        lines, base = read_smokeping_config(a.smokeping, files)
        secs = parse_smokeping(lines)
        targets = None if edited.exists() else smokeping_targets(secs)   # its slaves, step and pings still count
        agents = smokeping_agents(secs, base, files)
        db = secs.get("Database", ({}, []))[0]
        try:
            step = int(db.get("step", DEFAULT_STEP))
            pings = int(db.get("pings", DEFAULT_PINGS))
        except ValueError:
            raise SystemExit("*** Database ***: step and pings must be whole numbers")
        if not (60 <= step <= 3600 and 1 <= pings <= 100):
            raise SystemExit("*** Database ***: step must be 60-3600 s and pings 1-100")
    elif not edited.exists():
        if not a.targets.exists() and (HERE / "targets.ini").exists():
            shutil.copy(HERE / "targets.ini", a.targets)
            log(f"wrote an example targets file to {a.targets}: put your targets in it")
        targets = load_targets(a.targets)
        files.append(a.targets)
    source, known = "smokeping" if a.smokeping else "ini", None
    if edited.exists():
        (targets, known), source = load_json_targets(edited), "page"
        files.append(edited)
    agents.update(parse_agents(a.agents, a.name))      # AGENTS adds to (or overrides) SmokePing's slaves
    agents.pop(a.name, None)
    new = add_new_agents(targets, agents, set(known) if known is not None else None)
    if new:
        log(f"new agent{'s' if len(new) > 1 else ''} {', '.join(new)}: probing all {len(targets)} targets")
    if source == "page" and (new or known is None):    # remember them, so unticking one later sticks
        try:
            save_json_targets(edited, targets, {*(known or ()), *agents})
        except OSError as e:
            log(f"cannot write {edited}: {e}")
    return {"targets": targets, "agents": agents, "step": STEP_ENV or step, "pings": pings, "files": files,
            "source": source, "edited": edited}


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


def run(cmd, timeout):
    """subprocess.run in a process group of its own: a timeout kills the whole group, so mtr's helpers
    (mtr-packet, the child that looks up AS numbers) go with it instead of piling up until no process or thread
    can start. Every process is waited for here; tini, PID 1 in the image, reaps whatever escapes."""
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True) as p:
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL) if hasattr(os, "killpg") else p.kill()   # Windows: no groups
            except ProcessLookupError:
                pass
            p.communicate()
            raise
    return subprocess.CompletedProcess(cmd, p.returncode, out, err)


def fping_timeout(n_hosts):
    """-i10 spaces every packet 10 ms apart across all hosts, so a round needs at least hosts*pings*10ms."""
    return min(max(PINGS * 3 + 30, n_hosts * PINGS * 0.015 + 30), max(STEP - 10, PINGS * 3 + 30))


def fping(hosts):
    # Same flags as SmokePing's FPing probe; one fping call covers every ICMP target.
    hosts = sorted(set(hosts))
    r = run(["fping", "-C", str(PINGS), "-q", "-B1", "-r1", "-i10", *hosts], fping_timeout(len(hosts)))
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
    r = run(mtr_command(t), MTR_CYCLES * 4 + 60)
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


def trace_workers(n_traces):
    """mtr runs at least MTR_CYCLES seconds (one cycle a second, more for silent hops): enough of them in
    parallel that the round's traces fit in two thirds of the step, from 4 up to TRACE_PARALLEL at once."""
    return min(TRACE_PARALLEL, max(4, math.ceil(n_traces * (MTR_CYCLES + 5) / (STEP * 2 / 3))))


def trace_capacity():
    """Traces that fit in one round with TRACE_PARALLEL mtr at once."""
    return max(1, int(TRACE_PARALLEL * (STEP * 2 / 3) // (MTR_CYCLES + 5)))


def trace_rounds():
    """Rounds between two traceroutes of a target that TRACE_STEP asks for (1: every round)."""
    return max(1, round(TRACE_STEP / STEP)) if TRACE_STEP else 1


def trace_plan(targets, ts, lossy=()):
    """The targets traced this round: all of them when they fit and TRACE_STEP asks for no fewer, else each in
    turn every k rounds, plus (in the room left) those that started losing packets in the last round, where a
    traceroute says the most."""
    room = trace_capacity()
    k = max(trace_rounds(), math.ceil(len(targets) / max(1, room * 3 // 4)) if len(targets) > room else 1)
    if k == 1:
        return targets
    ordered = sorted(targets, key=lambda t: t["id"])
    plan = ordered[ts // STEP % k::k]
    ids = {t["id"] for t in plan}
    return plan + [t for t in ordered if t["id"] in lossy and t["id"] not in ids][:room - len(plan)]


def lost(pings):
    """Targets that lost at least one ping this round."""
    return {tid for tid, rtts in (pings or {}).items() if None in rtts}


class Lossy:
    """The targets that started losing pings last round: traced the next one out of turn. One that loses pings
    every round (a router that rate-limits ICMP) is traced when it starts, then in its turn like the rest."""
    def __init__(self):
        self.before, self.fresh = set(), set()

    def update(self, pings):
        now = lost(pings)
        self.fresh, self.before = now - self.before, now


def probe_round(targets, ts, ping_fn, trace_fn, lossy=()):
    """Latency and traceroutes go out together, so both describe the same minutes; with many targets only
    some are traced each round (trace_plan). -> ({target id: rtts} or None when the latency probe itself
    failed, {target id: hops})"""
    traced = trace_plan(targets, ts, lossy)
    with ThreadPoolExecutor(max_workers=trace_workers(len(traced))) as pool:
        futs = {t["id"]: pool.submit(trace_fn, t, ts) for t in traced}
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


def path_key(hops):
    """The route stored next to a trace, 'ip,ip,,ip': comparing routes then needs no JSON."""
    return ",".join(ip or "" for ip in path_of(hops))


def split_path(key):
    return [ip or None for ip in key.split(",")] if key else []


def same_path(a, b):
    """Same route = same IP at every TTL; a silent hop matches anything (ICMP-silent routers come and go)."""
    return len(a) == len(b) and all(x == y or x is None or y is None for x, y in zip(a, b))


def route_segments(traces):
    """[(ts, path key)] sorted -> (segments, known paths). Each segment: {route, from, to, end}."""
    known, segs, last = [], [], None
    for ts, key in traces:
        if key != last:         # most rounds repeat the last path: only a different one is looked at
            p, last = split_path(key), key
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


def status_fn(t, baseline):
    """(median, loss) -> status of one round of one target; its limits are looked up once, not per round."""
    crit, warn = threshold(t, "loss_crit", LOSS_CRIT), threshold(t, "loss_warn", LOSS_WARN)
    lat = threshold(t, "latency_warn", None)
    slow = baseline * LAT_FACTOR + LAT_MARGIN if baseline else None

    def status(median, loss):
        if loss >= 100:
            return "down"
        if loss >= crit:
            return "crit"
        if loss >= warn or median is not None and (lat is not None and median > lat or slow is not None and median > slow):
            return "warn"
        return "ok"
    return status


def status_of(now, last_ts, median, loss, baseline, t=None):
    if last_ts is None or now - last_ts > 3 * STEP:
        return "stale"
    return status_fn(t, baseline)(median, loss)


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
        # each trace's route as 'ip,ip,,ip', apart from its hops: route history reads ~30 bytes a row, not ~1 KB
        db.execute("CREATE TABLE IF NOT EXISTS path (source TEXT, target TEXT, ts INTEGER, path TEXT,"
                   " PRIMARY KEY (source, target, ts)) WITHOUT ROWID")
        db.execute("CREATE TABLE IF NOT EXISTS asn (asn TEXT PRIMARY KEY, name TEXT, ts INTEGER) WITHOUT ROWID")
        # one row per stored round: "when did each source last report" without scanning every ping
        db.execute("CREATE TABLE IF NOT EXISTS rounds (source TEXT, ts INTEGER, PRIMARY KEY (source, ts)) WITHOUT ROWID")
        if old and "source" not in old:
            db.execute("INSERT INTO ping SELECT ?, * FROM ping_v1", (source,))
            db.execute("INSERT INTO trace (source, target, ts, hops) SELECT ?, * FROM trace_v1", (source,))
            db.execute("DROP TABLE ping_v1")
            db.execute("DROP TABLE trace_v1")
            log(f"database upgraded: existing data now belongs to {source!r}")
        if not db.execute("SELECT 1 FROM rounds LIMIT 1").fetchone():
            db.execute("INSERT OR IGNORE INTO rounds SELECT DISTINCT source, ts FROM ping")


def fill_paths(path, pairs):
    """Traces stored before 0.6 have no row in `path`: add them, a (source, target) at a time, in the background."""
    n = 0
    for src, tid in pairs:
        with db_open(path) as db:
            first = db.execute("SELECT MIN(ts) FROM path WHERE source=? AND target=?", (src, tid)).fetchone()[0]
            rows = db.execute("SELECT ts, hops FROM trace WHERE source=? AND target=? AND ts<?",
                              (src, tid, 2 ** 62 if first is None else first)).fetchall()
            db.executemany("INSERT OR IGNORE INTO path VALUES (?,?,?,?)",
                           [(src, tid, ts, path_key(json.loads(h))) for ts, h in rows])
        n += len(rows)
    if n:
        log(f"{n} older traces indexed by route")


def round_rows(source, ts, pings, traces):
    rp = []
    for tid, rtts in (pings or {}).items():
        med, loss, jit, ok = summarize(rtts)
        rp.append((source, tid, ts, med, loss, jit, json.dumps(ok)))
    rt = [(source, tid, ts, json.dumps(h, separators=(",", ":")), path_key(h)) for tid, h in traces.items() if h]
    return rp, rt


PRUNED = {"day": None}


def store(path, rp, rt, now):
    cut = now - RETENTION_DAYS * 86400
    asns = {h["asn"] for row in rt for h in json.loads(row[3]) if h.get("asn")}
    pairs = [(s, t, cut) for s, t in {r[:2] for r in rp} | {r[:2] for r in rt}]
    with db_open(path) as db:
        db.executemany("INSERT OR REPLACE INTO ping VALUES (?,?,?,?,?,?,?)", rp)
        db.executemany("INSERT OR REPLACE INTO trace (source, target, ts, hops) VALUES (?,?,?,?)", [r[:4] for r in rt])
        db.executemany("INSERT OR REPLACE INTO path VALUES (?,?,?,?)", [(*r[:3], r[4]) for r in rt])
        db.executemany("INSERT OR IGNORE INTO asn VALUES (?, NULL, 0)", [(a,) for a in asns])
        db.executemany("INSERT OR IGNORE INTO rounds VALUES (?, ?)", {(r[0], r[2]) for r in rp})
        # old rows go along the primary key, target by target: a delete on ts alone reads the whole table
        db.executemany("DELETE FROM ping WHERE source=? AND target=? AND ts<?", pairs)
        db.executemany("DELETE FROM trace WHERE source=? AND target=? AND ts<?", pairs)
        db.executemany("DELETE FROM path WHERE source=? AND target=? AND ts<?", pairs)
        db.execute("DELETE FROM rounds WHERE ts<?", (cut,))
        if PRUNED["day"] != now // 86400:      # targets no longer in the config: once a day, the slow way
            PRUNED["day"] = now // 86400
            db.execute("DELETE FROM ping WHERE ts<?", (cut,))
            db.execute("DELETE FROM trace WHERE ts<?", (cut,))
            db.execute("DELETE FROM path WHERE ts<?", (cut,))


def every_round(fn):
    while True:
        ts = int(time.time()) // STEP * STEP
        try:
            fn(ts)
        except Exception as e:
            log(f"round {ts} failed: {e}")
        if time.time() - ts > STEP:
            log(f"round {ts} took {time.time() - ts:.0f} s, longer than the {STEP} s step")
        time.sleep(max(1.0, ts + STEP - time.time()))


def collector(path, source, targets_fn, ping_fn, trace_fn, before=lambda: None, after=lambda ts: None):
    lossy = Lossy()

    def one(ts):
        before()
        pings, traces = probe_round(targets_fn(), ts, ping_fn, trace_fn, lossy.fresh)
        lossy.update(pings)
        store(path, *round_rows(source, ts, pings, traces), ts)
        after(ts)
    every_round(one)


# ---------- remote agents ----------

def steps():
    """What the server tells its agents about timing: they probe on its clock."""
    return {"step": STEP, "pings": PINGS, "trace_step": TRACE_STEP}


def take_steps(got):
    """An agent takes the server's step, pings and TRACE_STEP (a server older than TRACE_STEP sends none)."""
    global STEP, PINGS, TRACE_STEP
    STEP, PINGS = _int(got["step"], 60, 3600), _int(got["pings"], 1, 100)
    TRACE_STEP = _int(got["trace_step"], 60, 86400) if got.get("trace_step") else None


def run_agent(server, token, ping_fn, trace_fn):
    """Push mode: probe from here, push each round to the server; keep rounds while it is unreachable."""
    def call(path, body=None):
        req = urllib.request.Request(server + path, data=body and json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "User-Agent": "smoketrace-agent"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    backlog = deque(maxlen=AGENT_BACKLOG)   # ponytail: in memory, lost on restart; a file if that ever matters
    targets, lossy = [], Lossy()

    def one(ts):
        nonlocal targets
        try:
            got = call("/api/agent/targets")
            targets = agent_targets(got["targets"])
            take_steps(got)                 # the primary decides
        except Exception as e:
            log(f"cannot fetch targets from {server}: {e}" + (" (using the last list)" if targets else ""))
        if targets:
            pings, traces = probe_round(targets, ts, ping_fn, trace_fn, lossy.fresh)
            lossy.update(pings)
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
    state = {"targets": [], "backlog": deque(maxlen=AGENT_BACKLOG), "lossy": Lossy()}
    lock = threading.Lock()

    class Pull(BaseHTTPRequestHandler):
        def do_GET(self):
            self.reply(200, b"ok") if self.path == "/livez" else self.reply(404, b"not found")

        def do_POST(self):
            given = self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
            if self.path != "/api/agent/pull" or not hmac.compare_digest(given, token.encode()):
                return self.reply(401, b'{"error":"bad token"}')
            try:
                size = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(size, MAX_PUSH)))
                with lock:
                    state["targets"] = agent_targets(body["targets"])
                    take_steps(body)
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
            pings, traces = probe_round(targets, ts, ping_fn, trace_fn, state["lossy"].fresh)
            state["lossy"].update(pings)
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
        body = {**steps(), "ack": ack, "targets": [agent_view(t) for t in mine]}
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

def load_paths(db, src, tid, since=0):
    """[(ts, path key)] of one target's traces, oldest first."""
    return db.execute("SELECT ts, path FROM path WHERE source=? AND target=? AND ts>=? ORDER BY ts", (src, tid, since)).fetchall()


def hops_at(db, src, tid, ts):
    return json.loads(db.execute("SELECT hops FROM trace WHERE source=? AND target=? AND ts=?", (src, tid, ts)).fetchone()[0])


def last_rounds(db):
    """{source: ts of its last stored round}"""
    return dict(db.execute("SELECT source, MAX(ts) FROM rounds GROUP BY source"))


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
        segs, _ = route_segments(load_paths(db, src, t["id"], now - 86400))
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
    last = last_rounds(db)
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


def editable_why():
    """Why the page cannot edit the targets, or None when it can."""
    if CONFIG["source"] == "demo":
        return "demo"
    return None if PASSWORD else "password"     # anyone who can open the page could change what the server probes


def target_detail(db, src, t, rng, now):
    since = now - rng
    bucket = STEP * max(1, math.ceil(rng / MAX_POINTS / STEP))
    rows = db.execute("SELECT ts, median, loss, jitter, rtts FROM ping WHERE source=? AND target=? AND ts>=? ORDER BY ts",
                      (src, t["id"], since)).fetchall()
    segs, known = route_segments(load_paths(db, src, t["id"]))    # whole history: route letters stay stable
    vis = [{**s, "label": label(s["route"]), "hops": len(known[s["route"]]), "change": k > 0 and s["from"] >= since}
           for k, s in enumerate(segs) if s["end"] > since]
    events = target_events(db, src, t, since, now)[:100]
    return {"target": summary(db, src, t, now, full=False), "source": src, "from": since, "to": now, "events": events,
            "bucket": bucket, "points": bucketize(rows, bucket), "segments": vis, "step": STEP,
            "loss_warn": threshold(t, "loss_warn", LOSS_WARN), "loss_crit": threshold(t, "loss_crit", LOSS_CRIT),
            "pings": PINGS}


def trace_detail(db, src, tid, ts, vs):
    """Trace at/just before ts (latest if None) vs the last trace of the previous route, or the previous round."""
    paths = load_paths(db, src, tid)
    if not paths:
        return {"cur": None}
    segs, _ = route_segments(paths)
    tss = [x for x, _ in paths]
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
        when, hops = tss[n], hops_at(db, src, tid, tss[n])
        r = segs[seg_at(when)]["route"]
        return {"ts": when, "hops": hops, "route": r, "label": label(r), "origin": loss_origin(hops)}

    cur, prev = side(i), side(j)
    asns = sorted({h.get("asn") for s in (cur, prev) if s for h in s["hops"] if h.get("asn")})
    names = dict(db.execute(f"SELECT asn, name FROM asn WHERE asn IN ({','.join('?' * len(asns))})", asns)) if asns else {}
    return {"cur": cur, "prev": prev, "vs": vs, "fallback": fallback, "asn_names": names,
            "rows": diff_hops(prev and prev["hops"], cur["hops"])}


# ---------- the dashboard ----------

SEVERITY = {"ok": 0, "warn": 1, "crit": 2, "down": 3}
BOARD_BUCKET = {6 * 3600: 300, 86400: 900, 7 * 86400: 7200}      # heatmap cell per range: 72, 96, 84 cells
BOARD_CACHE = {}            # (source or "all", range) -> (computed at, data version, board, its JSON)
EDIT_LOCK = threading.Lock()
BOARD_LOCKS = {}


def status_events(points):
    """Status changes in [(ts, status)], held ALERT_ROUNDS rounds like the alerts: [(ts, from, to)]."""
    out, cur, pend, n, first = [], None, None, 0, None
    for ts, st in points:
        if cur is None:
            cur = st
        elif st == cur:
            pend, n = None, 0
        else:
            if st == pend:
                n += 1
            else:
                pend, n, first = st, 1, ts
            if n >= ALERT_ROUNDS:
                out.append((first, cur, st))
                cur, pend, n = st, None, 0
    return out


def hop_info(db, hops):
    """The hop to blame: where real loss starts, else the last that answers when the trace ends in silence."""
    origin = loss_origin(hops)
    answered = [h for h in hops if h["ip"]]
    if origin is not None:
        h, why = next(h for h in hops if h["ttl"] == origin), "loss"
    elif hops and not hops[-1]["ip"] and answered:
        h, why = answered[-1], "stops"
    else:
        return None
    name = h.get("asn") and (db.execute("SELECT name FROM asn WHERE asn=?", (h["asn"],)).fetchone() or [None])[0]
    return {"why": why, "ttl": h["ttl"], "ip": h["ip"], "asn": h.get("asn"), "as_name": name}


def target_events(db, src, t, since, now, rows=None, segs=None, baseline=None, stats=None):
    """Status and route changes of one target as one source saw them, newest first."""
    if rows is None:
        rows = db.execute("SELECT ts, median, loss, jitter, rtts FROM ping WHERE source=? AND target=? AND ts>=? "
                          "ORDER BY ts", (src, t["id"], since)).fetchall()
    if segs is None:
        segs, _ = route_segments(load_paths(db, src, t["id"], since))
    if stats is None:
        if baseline is None:
            meds = [r[1] for r in rows if r[1] is not None]
            baseline = statistics.median(meds) if meds else None
        status = status_fn(t, baseline)
        stats = [status(r[1], r[2]) for r in rows]
    ev = [{"ts": ts, "kind": "status", "target": t["id"], "source": src, "from": a, "to": b}
          for ts, a, b in status_events(zip((r[0] for r in rows), stats))]
    ev += [{"ts": s["from"], "kind": "route", "target": t["id"], "source": src, "from": label(segs[k - 1]["route"]),
            "to": label(s["route"])} for k, s in enumerate(segs) if k > 0]
    return sorted(ev, key=lambda e: -e["ts"])


def status_now(rows, now, t):
    """(status, last_ts, median, loss, jitter, baseline) from rows (ts, median, loss, jitter, ...) covering 24 h."""
    day = [r for r in rows if r[0] >= now - 86400]
    meds = [r[1] for r in day if r[1] is not None]
    base = statistics.median(meds) if meds else None
    last_ts, med, loss, jit = day[-1][:4] if day else (None, None, None, None)
    return status_of(now, last_ts, med, loss, base, t), last_ts, med, loss, jit, base


def board(db, sources, src, targets, rng, now):
    """Everything the dashboard shows in one compact answer: per target its state now and one heatmap row
    (severity per cell as a string, medians, worst loss, cells where the route changed), the problems and
    the hop they share, and the timeline."""
    width = BOARD_BUCKET.get(rng, 900)
    start = (now - rng) // width * width
    nb = math.ceil((now - start) / width)
    out, events, problems, fleet = [], [], [], [[] for _ in range(nb)]
    q = "SELECT ts, median, loss, jitter FROM ping WHERE source=? AND target=? AND ts>=? ORDER BY ts"
    for t in targets:
        who = probers(t, sources)
        if src not in who:
            continue
        rows = db.execute(q, (src, t["id"], min(start, now - 86400))).fetchall()
        st, last_ts, med, loss, jit, base = status_now(rows, now, t)
        rows = [r for r in rows if r[0] >= start]
        status = status_fn(t, base)
        stats = [status(m, l) for _, m, l, _ in rows]
        sev, cmed, closs = [-1] * nb, [[] for _ in range(nb)], [0.0] * nb
        for (ts, m, l, _), s in zip(rows, stats):
            i = min(nb - 1, (ts - start) // width)
            v = SEVERITY[s]
            if v > sev[i]:
                sev[i] = v
            if l > closs[i]:
                closs[i] = l
            if m is not None:
                cmed[i].append(m)
        segs, _ = route_segments(load_paths(db, src, t["id"], start))
        changes = [sg["from"] for k, sg in enumerate(segs) if k > 0]
        meds = []
        for i, c in enumerate(cmed):
            v = round(statistics.median(c), 1) if c else None
            meds.append(v)
            if v is not None:
                fleet[i].append(v)
        evs = target_events(db, src, t, start, now, rows, segs, base, stats)
        events += evs
        by = None
        if len(sources) > 1:
            by = {x: (st if x == src else status_now(db.execute(q, (x, t["id"], now - 86400)).fetchall(), now, t)[0])
                  for x in who}
        out.append({"id": t["id"], "name": t["name"], "group": t["group"], "host": t["host"], "probe": t["probe"],
                    "port": t["port"], "lookup": t["lookup"], "status": st, "last_ts": last_ts, "median": med,
                    "loss": loss, "jitter": jit, "baseline": base, "route_changes": len(changes),
                    "last_change": changes[-1] if changes else None, "by_source": by,
                    "sev": "".join("." if v < 0 else str(v) for v in sev), "med": meds,
                    "cl": [round(v) for v in closs],
                    "rc": sorted({min(nb - 1, (ts - start) // width) for ts in changes})})
        if st != "ok":
            since = next((e["ts"] for e in evs if e["kind"] == "status" and e["to"] == st), None)
            problems.append({"id": t["id"], "status": st, "since": since,
                             "hop": hop_info(db, last_trace(db, src, t["id"])) if segs and st != "stale" else None,
                             "elsewhere": {k: v for k, v in (by or {}).items() if k != src}})
    clusters = clusters_of(problems)
    local = None
    hurt = [pr for pr in problems if pr["status"] != "stale"]
    if len(sources) > 1 and out and len(hurt) >= 2 and len(hurt) / len(out) >= 0.5:
        if all(pr["elsewhere"] and all(v == "ok" for v in pr["elsewhere"].values()) for pr in hurt):
            local = src               # broken from here only: the problem is near this vantage point
    agent_ev = []
    for name in sources:
        tss = [r[0] for r in db.execute("SELECT ts FROM rounds WHERE source=? AND ts>=? ORDER BY ts", (name, start))]
        for a, b in zip(tss, tss[1:]):
            if b - a > 3 * STEP:
                agent_ev += [{"ts": a + STEP, "kind": "quiet", "source": name}, {"ts": b, "kind": "back", "source": name}]
    last = last_rounds(db)
    events = sorted(events + agent_ev, key=lambda e: -e["ts"])[:500]
    nets = site_networks(db, sources, targets)
    return {"now": now, "step": STEP, "trace_step": trace_rounds() * STEP, "editable": editable_why() is None,
            "source": src, "range": rng, "start": start, "width": width, "cells": nb,
            "auth": bool(PASSWORD), "version": VERSION, "targets": out,
            "sources": [{"name": x, "last_ts": last.get(x), **nets.get(x, {})} for x in sources],
            "fleet": [round(statistics.median(f), 1) if f else None for f in fleet],
            "problems": problems, "clusters": clusters, "local": local, "events": events,
            "loss_warn": LOSS_WARN, "loss_crit": LOSS_CRIT}


def clusters_of(problems):
    """Problems whose traceroutes point at the same hop, most targets first."""
    points = {}
    for pr in problems:
        if pr["hop"] and pr["hop"]["ip"]:
            points.setdefault(pr["hop"]["ip"], []).append(pr)
    return sorted(({"hop": prs[0]["hop"], "targets": [x["id"] for x in prs]}
                   for prs in points.values() if len(prs) > 1), key=lambda c: -len(c["targets"]))


ALL = "all"     # the board of every site at once
REFRESHING = set()
WATCHED = {}            # (source or "all", range) -> when a viewer last asked for it
WATCH_FOR = 600         # boards asked for in the last 10 minutes are kept warm; the rest wait for a viewer


def refresh_board(src, rng):
    """Recompute one board in the background, once at a time; the old one is served meanwhile."""
    key = (src, rng)
    if key in REFRESHING:
        return
    REFRESHING.add(key)

    def run():
        try:
            with db_open(Handler.db) as db:
                Handler.fresh_board(db, src, rng, int(time.time()))
        except Exception as e:
            log(f"board {src} {rng}: {e}")
        finally:
            REFRESHING.discard(key)
    threading.Thread(target=run, daemon=True).start()


def warm_boards(now=None):
    """After a round: bring the boards someone is watching up to date before they ask again. Only those: a week of
    every site costs seconds of CPU, and nobody should pay that every round for a view opened once yesterday."""
    now = now or time.time()
    for key, at in list(WATCHED.items()):
        if now - at <= WATCH_FOR:
            refresh_board(*key)
        else:
            WATCHED.pop(key, None)
            BOARD_CACHE.pop(key, None)


def site_networks(db, sources, targets):
    """Where each site is, from its own traceroutes: the network of the first hop that has an AS number (its
    provider), with the operator and the country from that AS's name. Nothing is asked of any outside service."""
    out = {}
    for s in sources:
        seen = Counter()
        for t in [t for t in targets if s in probers(t, sources)][:12]:
            row = db.execute("SELECT hops FROM trace WHERE source=? AND target=? ORDER BY ts DESC LIMIT 1", (s, t["id"])).fetchone()
            hop = next((h for h in json.loads(row[0]) if h.get("asn")), None) if row else None
            if hop:
                seen[hop["asn"]] += 1
        if not seen:
            continue
        asn = seen.most_common(1)[0][0]
        name = (db.execute("SELECT name FROM asn WHERE asn=?", (asn,)).fetchone() or [None])[0] or ""
        m = re.fullmatch(r"(?:.* - )?(.*?)(?:, ([A-Z]{2}))?", name)
        out[s] = {"asn": asn, "as_name": m.group(1) or None, "cc": m.group(2)}
    return out


def merge_boards(boards):
    """The board of every site at once. Per target: the worst status among the sites that probe it, with that
    site's figures (so the numbers explain the colour) in `src`; per heatmap cell the worst severity and loss of
    any site; route changes from all of them. Problems and events say which site saw them."""
    order = {b["source"]: i for i, b in enumerate(boards)}
    seen = {}
    for b in boards:
        for x in b["targets"]:
            seen.setdefault(x["id"], []).append((b["source"], x))
    worst = lambda sx: (sx[1]["status"] != "stale", SEVERITY.get(sx[1]["status"], 0), -order[sx[0]])
    cellmax = lambda strs: "".join(max(cs) for cs in zip(*strs))     # "." (no data) < "0" < "3": the worst wins
    targets, rep = [], {}
    for tid, xs in seen.items():
        src, x = max(xs, key=worst)
        rep[tid] = src
        changes = [y["last_change"] for _, y in xs if y["last_change"]]
        targets.append({**x, "src": src, "sev": cellmax([y["sev"] for _, y in xs]),
                        "cl": [max(c) for c in zip(*(y["cl"] for _, y in xs))],
                        "rc": sorted({i for _, y in xs for i in y["rc"]}),
                        "route_changes": sum(y["route_changes"] for _, y in xs),
                        "last_change": max(changes) if changes else None})
    problems = [{**pr, "source": b["source"]} for b in boards for pr in b["problems"] if rep.get(pr["id"]) == b["source"]]
    events = [e if e.get("source") else {**e, "source": b["source"]}
              for k, b in enumerate(boards) for e in b["events"] if k == 0 or e["kind"] not in ("quiet", "back")]
    nb = boards[0]["cells"]
    fleet = [[x["med"][i] for x in targets if x["med"][i] is not None] for i in range(nb)]
    local = [b["local"] for b in boards if b["local"]]
    return {**boards[0], "source": ALL, "targets": targets, "problems": problems, "clusters": clusters_of(problems),
            "local": ", ".join(local) or None, "events": sorted(events, key=lambda e: -e["ts"])[:500],
            "fleet": [round(statistics.median(f), 1) if f else None for f in fleet]}


def minis(db, src, ids, targets, rng, now):
    """Small charts for the cards on screen: ~72 points of [ts, median, p10, p90, loss] per target."""
    width = STEP * max(1, math.ceil(rng / 72 / STEP))
    out = {}
    for t in targets:
        if t["id"] in ids:
            rows = db.execute("SELECT ts, median, loss, jitter, rtts FROM ping WHERE source=? AND target=? AND ts>=? "
                              "ORDER BY ts", (src, t["id"], now - rng)).fetchall()
            out[t["id"]] = [[p[0], p[1], p[4][len(p[4]) // 10] if p[4] else None,
                             p[4][-1 - len(p[4]) // 10] if p[4] else None, p[2]] for p in bucketize(rows, width)]
    return out


def compare(db, sources, t, rng, now):
    """The target's median and loss as every source that probes it saw them, on one time axis."""
    since = now - rng
    bucket = STEP * max(1, math.ceil(rng / MAX_POINTS / STEP))
    out = []
    for src in probers(t, sources):
        rows = db.execute("SELECT ts, median, loss, jitter, rtts FROM ping WHERE source=? AND target=? AND ts>=? "
                          "ORDER BY ts", (src, t["id"], since)).fetchall()
        out.append({"name": src, "points": [[p[0], p[1], p[2]] for p in bucketize(rows, bucket)]})
    return {"from": since, "to": now, "bucket": bucket, "sources": out}



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
        row = db.execute("SELECT ts, hops FROM trace WHERE source=? AND target=? ORDER BY ts DESC LIMIT 1",
                         (src, t["id"])).fetchone()
        tts, hops = (row[0], json.loads(row[1])) if row else (None, [])
        key = (src, t["id"])
        k = self.state.get(key)
        if k is None:       # first look after a start: remember, do not alert
            self.state[key] = {"status": s["status"], "pend": None, "n": 0, "hops": hops, "phops": None, "pn": 0,
                               "tts": tts}
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
        if tts == k["tts"]:                 # not traced this round (many targets take turns): nothing new
            return
        k["tts"] = tts
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
            last = last_rounds(db)
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


FONTS = {"/fonts/archivo.woff2": "archivo.woff2", "/fonts/plex-mono-400.woff2": "plex-mono-400.woff2",
         "/fonts/plex-mono-500.woff2": "plex-mono-500.woff2"}


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
@font-face{font-family:"Archivo";src:url(/fonts/archivo.woff2) format("woff2");font-weight:100 900;font-stretch:62% 125%}
@font-face{font-family:"Plex Mono";src:url(/fonts/plex-mono-400.woff2) format("woff2");font-weight:400}
:root{color-scheme:dark;--bg:#111110;--panel:#171716;--ink:#ebe9e4;--ink-2:#aaa79f;--ink-3:#8f8c84;--line-2:#3a3834;--brand:#ff6a33;--bad:#f0524a}
:root[data-theme=light]{color-scheme:light;--bg:#f2f0eb;--panel:#faf9f6;--ink:#171717;--ink-2:#4f4d48;--ink-3:#6b6860;--line-2:#c7c2b6;--brand:#c2410c;--bad:#c0301c}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:40px 16px;background:var(--bg);color:var(--ink);
font:14px/1.45 "Archivo","Helvetica Neue",Helvetica,sans-serif;-webkit-font-smoothing:antialiased}
form{width:100%;max-width:360px}
.mark{display:flex;align-items:center;gap:10px;margin-bottom:40px;font-weight:650;font-size:15px}.mark svg{color:var(--brand)}
h1{margin:0 0 6px;font-size:34px;line-height:1.05;font-weight:450;font-stretch:78%;letter-spacing:-.01em}
p{margin:0 0 28px;color:var(--ink-3)}
label{display:block;margin-bottom:6px;font-size:13px;color:var(--ink-2)}
input{width:100%;padding:11px 12px;border:1px solid var(--line-2);border-radius:7px;background:var(--panel);color:var(--ink);font:15px "Plex Mono",ui-monospace,monospace}
input:focus{border-color:var(--ink);outline:none}
button{width:100%;margin-top:22px;padding:11px;border:1px solid var(--ink);border-radius:7px;background:var(--ink);color:var(--bg);font:600 14px "Archivo",sans-serif;cursor:pointer}
:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
.err{min-height:20px;margin:12px 0 0;font-size:13px;color:var(--bad)}
</style><script>try{document.documentElement.dataset.theme=localStorage.getItem("theme")||(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark")}catch{}</script>
</head><body><form method="post" action="/login">
<div class="mark"><svg width="22" height="22" viewBox="0 0 18 18" aria-hidden="true"><path d="M1 12c2.5 0 2.5-6 5-6s2.5 8 5 8 2.5-10 5-10" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>smoketrace</div>
<h1 id="h">Sign in</h1><p id="s">Use the password set in PASSWORD.</p>
<label for="p" id="l">Password</label><input id="p" name="password" type="password" autocomplete="current-password" autofocus required>
<button id="b">Sign in</button>%ERROR%</form>
<script>if((localStorage.getItem("lang")||navigator.language||"").slice(0,2)==="pt"){const T={h:"Entrar",s:"Use a palavra-passe definida em PASSWORD.",l:"Palavra-passe",b:"Entrar"};
for(const k in T)document.getElementById(k).textContent=T[k];const e=document.querySelector(".err");if(e)e.textContent="Palavra-passe errada."}</script>
</body></html>"""


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    db = None
    targets = []
    sources = ["local"]     # this probe first, then the agents
    agents = {}             # name -> {token, url}
    metrics_cache = (0, None, "")

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        now = int(time.time())
        try:
            if u.path == "/livez":
                return self.send(200, b"ok", "text/plain")
            if u.path in FONTS:     # served before sign-in: the sign-in page uses them too
                return self.send(200, (HERE / "fonts" / FONTS[u.path]).read_bytes(), "font/woff2", cache=True)
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
                return self.json({**steps(), "targets": [agent_view(t) for t in targets_for(name)]})
            if not signed_in(self.headers.get("Cookie")):
                if u.path.startswith("/api/"):
                    return self.send(401, b'{"error":"sign in"}', "application/json")
                return self.redirect("/login")
            if u.path in ("/", "/index.html"):
                return self.send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            src = q.get("src") or (ALL if u.path == "/api/board" and len(self.sources) > 1 else self.sources[0])
            if src == ALL and u.path != "/api/board":
                src = self.sources[0]           # one site's figures; the page asks for the right one
            if src not in self.sources and src != ALL:
                raise ValueError(src)
            t = next((x for x in self.targets if x["id"] == q.get("id")), None)
            with db_open(self.db) as db:
                if u.path == "/api/targets":
                    return self.json(self.target_list())
                if u.path == "/api/overview":
                    return self.json(overview(db, self.sources, src, self.targets, now))
                if u.path == "/api/board":
                    rng = int(q.get("range", 86400))
                    rng = rng if rng in BOARD_BUCKET else 86400
                    return self.send(200, self.board(db, src, rng, now)[1], "application/json")
                if u.path == "/api/minis":
                    rng = int(q.get("range", 86400))
                    ids = set(q.get("ids", "").split(",")[:150])
                    return self.json(minis(db, src, ids, self.targets, min(max(rng, 3600), RANGES[-1]), now))
                if u.path == "/api/compare" and t:
                    rng = int(q.get("range", 86400))
                    return self.json(compare(db, self.sources, t, min(max(rng, 3600), RANGES[-1]), now))
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
        if path == "/api/targets":
            return self.edit_targets(body)
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

    @classmethod
    def fresh_board(cls, db, src, rng, now):
        """-> (board, its JSON) as of now, computed once per round however many ask; "all" merges every site's."""
        key = (src, rng)
        with BOARD_LOCKS.setdefault(key, threading.Lock()):     # many viewers, one computation
            at, ver, data, body = BOARD_CACHE.get(key, (0, None, None, None))
            version = last_rounds(db)
            if data is None or ver != version or now - at >= STEP:     # none yet, a new round, or time moved
                data = (merge_boards([cls.fresh_board(db, s, rng, now)[0] for s in cls.sources]) if src == ALL
                        else board(db, cls.sources, src, cls.targets, rng, now))
                body = json.dumps(data, separators=(",", ":")).encode()
                BOARD_CACHE[key] = (now, version, data, body)
        return data, body

    def board(self, db, src, rng, now):
        """What a viewer gets: the last board at once, and a newer one computed behind it when a round has landed.
        Only the very first board of a range makes anyone wait (a week of every site took 15 s on 555 targets)."""
        WATCHED[(src, rng)] = time.time()
        at, ver, data, body = BOARD_CACHE.get((src, rng), (0, None, None, None))
        if data is None:
            return self.fresh_board(db, src, rng, now)
        if ver != last_rounds(db) or now - at >= STEP:
            refresh_board(src, rng)
        return data, body

    def target_list(self):
        why = editable_why()
        return {"source": CONFIG["source"], "file": str(CONFIG["edited"] or ""), "editable": why is None, "why": why,
                "sources": self.sources, "targets": [{"id": t["id"], **{k: (address(t) if k == "address" else t[k])
                                                                      for k in EDITABLE}, "probe": t["probe"]}
                                                     for t in self.targets]}

    def edit_targets(self, body):
        """The page's edits: signed in, JSON only (a cross-site form cannot send it), written to targets.json."""
        if not signed_in(self.headers.get("Cookie")):
            return self.send(401, b'{"error":"sign in"}', "application/json")
        if not self.target_list()["editable"] or "application/json" not in self.headers.get("Content-Type", ""):
            return self.send(403, b'{"error":"editing is off"}', "application/json")
        try:
            d = json.loads(body)
            with EDIT_LOCK:
                new = edit_targets(self.targets, d.get("op"), d)
                save_json_targets(CONFIG["edited"], new, self.agents)
                apply_config(CONFIG["args"], load_config(CONFIG["args"]))
        except (ValueError, AttributeError, TypeError) as e:
            field, _, msg = str(e).partition(": ")
            if field not in (*EDITABLE, "id", "op"):
                field, msg = None, str(e)
            return self.send(400, json.dumps({"error": msg or field, "field": field if msg else None}).encode(),
                             "application/json")
        except (SystemExit, OSError) as e:     # a list that no longer loads, or a folder it cannot write to
            return self.send(500, json.dumps({"error": str(e)}).encode(), "application/json")
        log(f"targets edited on the page: {d.get('op')} {d.get('id') or d.get('name')}")
        self.json({"ok": True, **self.target_list()})

    def metrics(self, now):
        if METRICS_TOKEN or PASSWORD:
            given = self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
            if not METRICS_TOKEN or not hmac.compare_digest(given, METRICS_TOKEN.encode()):
                return self.send(401, b"set METRICS_TOKEN and send it as a bearer token\n", "text/plain")
        at, ver, text = Handler.metrics_cache
        with db_open(self.db) as db:
            if ver != (version := last_rounds(db)) or now - at >= STEP:     # once per round, however often scraped
                text = metrics(db, self.sources, self.targets, now)
                Handler.metrics_cache = (now, version, text)
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

    def send(self, code, body, ctype, cache=False):
        zipped = len(body) > 1400 and "gzip" in self.headers.get("Accept-Encoding", "") and not ctype.startswith("font/")
        if zipped:
            body = gzip.compress(body, 5)
        self.send_response(code)
        if zipped:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "public, max-age=604800, immutable" if cache else "no-store")
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
# ...and a fleet of sites in nested groups, so the dashboard has something to organise: a regional backbone
# hop losing packets for every Braga site (one cause, many targets), a slow site, a dead one, a flapping one
DEMO_SITES = [("Sites / Lisbon", 14), ("Sites / Porto", 12), ("Sites / Braga", 9), ("Cloud / AWS eu-west-1", 8),
              ("Cloud / Azure westeurope", 5)]
DEMO_SPECIAL = {("Sites / Lisbon", 7): "down", ("Sites / Porto", 3): "slow", ("Cloud / AWS eu-west-1", 2): "flap"}
for gi, (group, n) in enumerate(DEMO_SITES):
    for j in range(1, n + 1):
        scenario = "cluster" if group == "Sites / Braga" else DEMO_SPECIAL.get((group, j), "site")
        DEMO_TARGETS.append((group, f"{group.split(' / ')[-1].split()[0]} {j:02d}", f"10.{40 + gi}.{j}.1", scenario))
DEMO_AGENT = "porto"   # a second vantage point: same targets, its own ISP, none of the local route trouble
DEMO_AS = {"AS64496": "HOMENET - Home ISP, PT", "AS64497": "TRANSIT-ONE - Transit One, EU",
           "AS64498": "TRANSIT-TWO - Transit Two, EU", "AS64499": "DESTNET - Destination Networks, EU",
           "AS64500": "PORTONET - Porto ISP, PT", "AS64501": "BACKBONE - Regional Backbone, PT",
           "AS64502": "SITES - Branch Network, PT"}


def demo_probes(t0, remote=False):
    """Synthetic rounds, deterministic per (host, ts) so seeded history and live rounds agree."""
    scen = {parse_host(h)["host"]: (i, s) for i, (_, _, h, s) in enumerate(DEMO_TARGETS)}

    def state(host, ts):
        i, s = scen[host]
        if remote:
            s = {"reroute": "ok", "flap": "ok", "lan": "ok", "slow": "site"}.get(s, s)
        age, rnd = t0 - ts, random.Random(f"{host}/{ts}/{remote}")
        hour = time.localtime(ts).tm_hour + time.localtime(ts).tm_min / 60
        base = 0.4 if s == "lan" else 6.0 + 7 * (i % 9) + (4 if remote else 0)
        extra = 0.0 if s == "lan" else 3 * max(0.0, math.sin((hour - 13) / 12 * math.pi))   # evening congestion
        route, loss, sd, down = 0, 0.0003, base * 0.05 + 0.15, False
        if s == "reroute" and (4 * 3600 <= age < 6 * 3600 or 72 * 3600 <= age < 74 * 3600):
            route, extra, loss, sd = 1, extra + 18, 0.10, sd * 3
        if s == "flap" and age < 3 * 3600:
            route = ts // (STEP * 4) % 2
            extra += 3 * route
        if s == "ratelimit" and 9 * 3600 <= age < 10 * 3600:
            loss = 0.15
        if s == "down" and age < 40 * 60:
            down = True
        if s == "cluster" and age < 50 * 60 and not remote:    # the Braga backbone hop drops a quarter; porto goes round it
            loss, sd = 0.25, sd * 2
        if s == "slow" and age < 2 * 3600:                     # a congested site link: +30 ms, still answering
            extra, sd = extra + 30, sd * 4
        if rnd.random() < 0.03:
            sd *= 6
        return rnd, i, s, base + extra, loss, sd, route, down

    def path(host, i, s, route):
        if s == "lan":
            return [(host, None)]
        isp = ([("10.20.0.1", None), ("100.72.0.1", "AS64500"), ("198.51.100.200", "AS64500")] if remote else
               [("192.168.1.1", None), ("100.64.0.1", "AS64496"), (None, None), ("198.51.100.1", "AS64496")])
        if s in ("site", "cluster", "slow") or host.startswith("10.4"):
            region = host.split(".")[1]
            alt = route and s == "flap"
            return isp + [(f"100.70.{region}.{2 if alt else 1}", "AS64501"), (host, "AS64502")]
        mid = ([(f"198.51.100.{20 + i}", "AS64497"), (f"203.0.113.{100 + i}", "AS64497")] if route == 0 else
               [(f"198.51.100.{120 + i}", "AS64498"), (f"198.51.100.{140 + i}", "AS64498"),
                (f"203.0.113.{160 + i}", "AS64498")])
        return isp + mid + [(host, "AS64499")]

    def ping(targets, ts):
        out = {}
        for t in targets:
            rnd, _, s, lat, loss, sd, _, down = state(t["host"], ts)
            if s == "cluster" and loss > 0.2:   # 3 to 8 of 20 lost every round, so all nine show, not most of them
                lost = set(rnd.sample(range(PINGS), min(PINGS, rnd.choice([3, 4, 5, 6, 7, 8]))))
                out[t["id"]] = [None if k in lost else round(lat + abs(rnd.gauss(0, sd)), 3) for k in range(PINGS)]
                continue
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
            elif s == "cluster" and loss > 0.2 and k >= len(p) - 1:
                hl = rnd.choice([20.0, 30.0])
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

CONFIG = {"stamp": None, "files": [], "source": "demo", "edited": None, "args": None}


def apply_config(a, cfg):
    global STEP, PINGS
    STEP, PINGS = cfg["step"], cfg["pings"]
    Handler.targets, Handler.agents, Handler.sources = cfg["targets"], cfg["agents"], [a.name, *cfg["agents"]]
    CONFIG.update(files=cfg["files"], stamp=stamp(cfg["files"]), source=cfg["source"], edited=cfg["edited"], args=a)
    BOARD_CACHE.clear()


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
        warm_boards()
        ALERTS.check(db, a.name)
        ALERTS.sources(db, int(time.time()))
        for name, agent in Handler.agents.items():
            if agent.get("url"):
                threading.Thread(target=pull_agent, args=(db, name, agent), daemon=True).start()
    return run


def main():
    global PASSWORD, METRICS_TOKEN, PUBLIC_URL, ASN_LOOKUP, LOSS_WARN, LOSS_CRIT, ALERTS, TRACE_PARALLEL, STEP_ENV, TRACE_STEP, STEP
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
    TRACE_PARALLEL = _int(int(env("TRACE_PARALLEL", TRACE_PARALLEL)), 1, 64)
    if env("STEP"):
        STEP_ENV = duration(env("STEP"), "STEP")
        if not 60 <= STEP_ENV <= 3600:
            raise SystemExit(f"STEP={env('STEP')}: from 60 s to 1 h")
    if env("TRACE_STEP"):
        TRACE_STEP = duration(env("TRACE_STEP"), "TRACE_STEP")
        if not 60 <= TRACE_STEP <= 86400:
            raise SystemExit(f"TRACE_STEP={env('TRACE_STEP')}: from 60 s to 24 h")
    ALERTS = Alerter(env("DISCORD_WEBHOOK"), env("NTFY_URL"), env("WEBHOOK_URL"), routes=env("ALERT_ROUTES", "1") != "0")
    if a.import_rrd:
        return import_rrd(a)
    if not a.demo:
        missing = [b for b in ("fping", "mtr") if not shutil.which(b)]
        if missing:
            raise SystemExit(f"{', '.join(missing)} not found (Debian: apt install fping mtr-tiny)")
    if a.agent or a.listen:
        if not a.token and a.agents:     # the server's AGENTS line pasted on the agent: its token is in there
            mine = parse_agents(a.agents, "")
            pick = mine.get(a.name) or (next(iter(mine.values())) if len(mine) == 1 else None)
            if pick:
                a.token = pick["token"]
                log("using the token from AGENTS; on an agent it goes in TOKEN (AGENTS is the server's list)")
        if not a.token:
            raise SystemExit("an agent needs its token in TOKEN: the same token the server lists for it in AGENTS "
                             "(name=token); AGENTS itself belongs on the server")
        if a.listen:
            return run_listener(a.listen, a.token, real_ping, mtr)
        return run_agent(a.agent.rstrip("/"), a.token, real_ping, mtr)

    if not NAME_RE.fullmatch(a.name):
        raise SystemExit(f"--name {a.name!r}: letters, digits, _ and -")
    if a.demo:
        STEP = STEP_ENV or STEP
        targets = [make_target(slug(f"{g}-{n}"), g, n, **parse_host(h)) for g, n, h, _ in DEMO_TARGETS]
        db = a.db or HERE / "demo.db"
        for suffix in ("", "-wal", "-shm"):
            Path(f"{db}{suffix}").unlink(missing_ok=True)
        t0 = int(time.time())
        init_db(db, a.name)
        probes = {a.name: demo_probes(t0), DEMO_AGENT: demo_probes(t0, remote=True)}
        Handler.db, Handler.targets, Handler.sources, Handler.agents = db, targets, list(probes), {}
        core = [t for t in targets if not t["group"].startswith(("Sites", "Cloud"))]
        fleet = [t for t in targets if t not in core]
        for name, (ping_fn, trace_fn) in probes.items():
            seed_demo(db, name, core, ping_fn, trace_fn, t0)
            seed_demo(db, name, fleet, ping_fn, trace_fn, t0, days=2)     # a faster start; the week is for the core
            after = lambda ts, name=name: (warm_boards(), ALERTS.check(db, name))
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
        threading.Thread(target=fill_paths, args=(db, [(s, t["id"]) for s in Handler.sources for t in Handler.targets]),
                         daemon=True).start()
        Handler.db = db

    extras = [x for x, on in (("sign-in", PASSWORD), ("alerts", ALERTS.enabled()), ("metrics token", METRICS_TOKEN)) if on]
    timing = f"pings every {STEP} s" + (f", traces every {trace_rounds() * STEP} s" if trace_rounds() > 1 else "")
    log(f"smoketrace {VERSION}: {len(Handler.targets)} targets, sources {', '.join(Handler.sources)}, {timing}"
        f"{', ' + ', '.join(extras) if extras else ''}, http://{a.bind}:{a.port}")
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
