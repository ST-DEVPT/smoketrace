<p align="center">
  <img src="docs/icon.svg" width="76" height="76" alt="">
</p>

<h1 align="center">smoketrace</h1>

<p align="center">
  <b>SmokePing, with the route behind every spike.</b><br>
  Latency, jitter and packet loss for every target, and an mtr traceroute taken in the same minutes,
  so a latency step and the route change that caused it sit on one screen.
</p>

<p align="center">
  <a href="https://github.com/ST-DEVPT/smoketrace/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ST-DEVPT/smoketrace/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/ST-DEVPT/smoketrace/releases"><img alt="Release" src="https://img.shields.io/github/v/release/ST-DEVPT/smoketrace?color=2a78d6"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%E2%80%933.14-3b7a39">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-none-3b7a39">
  <a href="https://github.com/ST-DEVPT/smoketrace/pkgs/container/smoketrace"><img alt="Image" src="https://img.shields.io/badge/ghcr.io-amd64%20%7C%20arm64-2c6b8a"></a>
  <img alt="Probes: fping and mtr" src="https://img.shields.io/badge/probes-fping%20%2B%20mtr-2c6b8a">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-4f4d48"></a>
</p>

<p align="center">
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#remote-agents">Remote agents</a> ·
  <a href="#reading-the-screen">Reading the screen</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#limits">Limits</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/overview-light.jpg">
    <img alt="The overview: every target with its status, latency, jitter, loss, the last 24 hours and its route changes" src="docs/overview.jpg">
  </picture>
</p>

## Why

SmokePing tells you *that* the latency to a target jumped at 05:10. It does not tell you *why*. The usual
answer is an `mtr` in cron writing text files, then lining up timestamps by hand, at night, while reading mtr
the way it is easiest to read wrong: a router that rate-limits ICMP looks like 50 % loss.

smoketrace runs `fping` and `mtr` together, every five minutes, for every target. It keeps both, draws the
route under the latency on the same time axis, and reads the traceroute for you: which hops changed, where
real loss starts, and which "loss" is only a router saying no to ICMP.

## What SmokePing alone does not show

| | SmokePing + `mtr` in cron | smoketrace |
| --- | --- | --- |
| Latency steps up at 05:10 | The step | The step, a line at 05:10 where the route changed, and the hops that changed |
| 50 % loss on hop 4 of an mtr | Looks like an outage | Tagged **rate-limit**: it does not carry on to the destination |
| Where real loss starts | Read the mtr by eye | **Real loss starts here** on the first hop where it lasts to the end |
| Two paths taking turns | Invisible | Every path gets a letter; the route strip shows A B A B |
| The target stops answering | A red graph | Plus the last hop that still answers |
| Is it them or is it us? | Slaves: a Perl install and a shared secret per site | An agent container per site; every target shows how each site sees it |
| Running it | Perl, RRDtool, a web server, its own config language | One container, or one Python file with no dependencies |

## At a glance

<p align="center"><img alt="A target's page: a latency step, the loss under it, and route B in the route strip" src="docs/detail.jpg"></p>

<table>
  <tr>
    <td valign="top" width="68%">
      <img alt="The traceroute on route B against route A: three hops changed, one new, real loss from hop 5" src="docs/trace.jpg"><br><br>
      <img alt="Two paths taking turns over three hours, route B costing 3 ms, with the tooltip open" src="docs/flap.jpg">
    </td>
    <td valign="top" align="center">
      <img alt="A target's page on a phone" src="docs/phone.jpg" width="280">
    </td>
  </tr>
</table>

- **Every target on one screen**: status by shape and label (OK, warning, critical, down, no data), median,
  jitter, loss, a 24-hour sparkline on a shared time axis and the route changes. Grouped, worst first,
  filtered by a click on a status, searched with <kbd>/</kbd>.
- **SmokePing's smoke**: the 20 pings of every round drawn as nested bands around the median, so the spread
  and the outliers show, not only an average.
- **Route and latency on one time axis**: a route strip under the chart, and a line at every change, in the
  new route's colour, through latency and loss.
- **Click any moment** for that round's traceroute, against the previous route or the previous round, hop by
  hop: changed, new, gone, silent, and how much slower.
- **Reads mtr for you**: loss that stops at one hop is rate-limiting; loss that starts at a hop and reaches the
  destination is real, and is marked where it starts.
- **Several vantage points**: agents at other sites probe the same targets and push their rounds; switch the
  dashboard between them, and see at a glance whether a target is down from everywhere or from one place.
- **Made to be left alone**: one Python file, the standard library only, SQLite, 30 days kept; a multi-arch
  image with only `NET_RAW`, a read-only root and no-new-privileges.
- **English and Portuguese, dark and light, desktop and phone**, the keyboard on the chart
  (<kbd>←</kbd> <kbd>→</kbd> <kbd>Enter</kbd>), and a table of every point.

## Quick start

### Docker

```bash
mkdir smoketrace && cd smoketrace
curl -O https://raw.githubusercontent.com/ST-DEVPT/smoketrace/main/docker-compose.yml
docker compose up -d
```

The first start writes an example `data/targets.ini`. Put your targets in it (the folder belongs to root, as
the container does: use `sudo`), then `docker compose restart`. Open `http://<docker-host>:8099`; the first
round lands within five minutes. To update: `docker compose pull && docker compose up -d`.

The compose file uses the host's network, so traceroutes start at your real gateway and not at Docker's
bridge, and it gives the container `NET_RAW` and nothing else.

> [!WARNING]
> There is no login, and the server listens on every interface: keep it on a trusted network, or behind a
> reverse proxy with authentication. See [SECURITY.md](SECURITY.md).

### Try the demo

```bash
docker run --rm -p 8099:8099 -e DEMO=1 ghcr.io/st-devpt/smoketrace:latest
```

Or without Docker, on any OS: `python3 smoketrace.py --demo`. The demo seeds a week of six targets seen from
two places: a route change with loss on the new path (Cloudflare DNS), two paths taking turns (Google DNS), a
router that rate-limits ICMP plus an hour of real loss (Quad9), and a server that just went down for everyone.

### Without Docker (Debian, Ubuntu)

```bash
sudo apt install python3 fping mtr-tiny
sudo git clone https://github.com/ST-DEVPT/smoketrace /opt/smoketrace
sudo install -D -m 644 /opt/smoketrace/targets.ini /etc/smoketrace/targets.ini   # then put your targets in it
sudo cp /opt/smoketrace/smoketrace.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now smoketrace
```

## Remote agents

An agent is the same image started with a server address and a token. It fetches the targets from the server,
probes them from where it runs, and pushes every round. It needs no port and no storage: only an outgoing
connection to the server. If the server is unreachable, it keeps up to a day of rounds and sends them later.

**1. On the server**, give each agent a name and a long random token (`openssl rand -hex 24`) in
`docker-compose.yml`, then `docker compose up -d`:

```yaml
    environment:
      NAME: home
      AGENTS: porto=4f1c…a9e2,office=b7d0…13c5
```

**2. At each site**, run [`docker-compose.agent.yml`](docker-compose.agent.yml) with that site's token:

```yaml
    environment:
      SERVER: http://smoketrace.lan:8099
      TOKEN: 4f1c…a9e2
```

**3. In the dashboard**, *Seen from* switches between `home`, `porto` and `office`, and the overview shows how
each of them sees every target: down from everywhere is the target; down from one place is the path from there.

Over the internet, put the server behind HTTPS (a reverse proxy) or reach it through a VPN such as WireGuard:
the token travels with every round.

## Configuration

`targets.ini`: one `[Group]` per section, one `Name = host` per line.

```ini
[LAN]
Router = 192.168.1.1

[Internet]
Cloudflare DNS = 1.1.1.1
Google DNS = 8.8.8.8
```

Every option is an environment variable and a flag:

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `TARGETS` | `--targets` | `/data/targets.ini` in the image | the file above |
| `DB` | `--db` | `/data/smoketrace.db` in the image | the SQLite database |
| `BIND` | `--bind` | `0.0.0.0` in the image, else `127.0.0.1` | address to listen on |
| `PORT` | `--port` | `8099` | |
| `NAME` | `--name` | `local` | what the dashboard calls the server's own probe |
| `AGENTS` | `--agents` | none | agents allowed to push: `name=token,name=token` |
| `SERVER` | `--agent` | none | run as an agent pushing to this server |
| `TOKEN` | `--token` | none | the agent's token |
| `DEMO` | `--demo` | off | `1`: synthetic data, no probes |

The rest are constants at the top of [`smoketrace.py`](smoketrace.py), set to SmokePing's defaults:

| Constant | Default | |
| --- | --- | --- |
| `STEP` | 300 s | one round every five minutes |
| `PINGS` | 20 | pings per target per round |
| `MTR_CYCLES` | 10 | probes per hop per round |
| `RETENTION_DAYS` | 30 | |
| `LOSS_WARN`, `LOSS_CRIT` | 5 %, 20 % | one lost ping of 20 is 5 % |
| `LAT_FACTOR`, `LAT_MARGIN` | 1.5, 10 ms | warning when the median is above the 24 h baseline × 1.5 + 10 ms |

## Reading the screen

The chart is three bands on one time axis:

- **Latency**: the line is the median of each round; the grey smoke behind it is its 20 pings, darker towards
  the middle. A thin, flat band is a healthy link, tall smoke is jitter, a lone whisker is one slow reply.
- **Loss**: the bar height is the share lost in that round; amber under 20 %, red from 20 %.
- **Route**: one letter per path (A, B, C…), kept for the target's whole history, so A coming back is still A.
  A line in the new route's colour marks each change across all three bands.

Click any moment (or <kbd>←</kbd> <kbd>→</kbd> and <kbd>Enter</kbd>) for its traceroute, against the
**previous route** (the default) or the **previous round**:

<p align="center"><img alt="Quad9 in its hour of loss: loss on hop 2 tagged rate-limit, loss from hop 5 to the end tagged real loss" src="docs/loss.jpg"></p>

- **rate-limit**: loss on a hop that does not carry on to the destination. That router answers ICMP slowly or
  not at all; the packets going through it are fine.
- **real loss starts here**: the first hop from which the loss lasts to the last hop that answers. The problem
  is that hop, or the link into it.
- `???` is a hop that never answers ICMP. That is normal, and it never counts as a route change.
- When the destination stops answering, the page says which hop answered last.

## How it works

```mermaid
flowchart LR
  T["targets.ini"] --> R{{"every 5 minutes"}}
  R --> F["fping -C 20<br>every target, one call"]
  R --> M["mtr --json -c 10<br>one per target, in parallel"]
  F --> DB[("SQLite<br>30 days")]
  M --> DB
  AG["Agents at other sites<br>same probes, same minutes"] -- "push, one round at a time" --> DB
  T -. "targets" .-> AG
  DB --> A["JSON API"] --> U["Dashboard"]
```

- **One round, one window.** fping and the mtr runs start together, so the latency and the route describe the
  same minutes.
- **fping** runs with SmokePing's own flags (`-C 20 -q -B1 -r1 -i10`). Each round keeps the median, the loss,
  the jitter (the mean difference between consecutive replies) and the 20 sorted replies for the smoke.
- **The same route** means the same IP at every TTL. A silent hop matches anything, so routers that skip ICMP
  now and then do not fake a change.
- **Rows, not RRD.** Raw rounds stay in SQLite for 30 days; longer chart ranges are bucketed as they are read
  (600 points at most), so the smoke of a 30-day view is still the real spread.
- **Every source is kept apart.** The server's own probe and each agent have their own rows, routes and route
  letters; an agent's round is checked field by field before it is stored.
- **Status** comes from the last round: down at 100 % loss, critical from 20 %, warning from 5 % or when the
  median runs well above its 24-hour baseline, no data after three missed rounds.

### API

| Endpoint | Returns |
| --- | --- |
| `GET /api/overview?src=…` | every target as one source sees it, plus each source's status for it |
| `GET /api/target?id=…&range=86400&src=…` | points `[ts, median, loss, jitter, smoke]`, route segments, thresholds |
| `GET /api/agent/targets`, `POST /api/agent/push` | for agents only, with `Authorization: Bearer <token>` |
| `GET /api/trace?id=…&ts=…&vs=route&src=…` | the traceroute at `ts` (the latest without it), the one it is compared with (`vs=route` or `round`) and the hop-by-hop diff |

## Limits

- No alerts yet; the overview, the tab title and the favicon carry the worst state.
- mtr's JSON keeps one IP per hop, so ECMP (several equal-cost paths) shows as routes taking turns.
  paris-traceroute would pin the flow.
- No login (see the warning above); agents authenticate with their token.

## Development

```bash
python3 test_smoketrace.py      # parsers, route logic, diff, status: no network
python3 smoketrace.py --demo    # the dashboard against a week of synthetic data
python3 docs/screenshots.py     # regenerates the images in docs/ (needs Playwright)
```

CI runs the tests on Python 3.10 to 3.14, the demo end to end, a real round of fping and mtr against the
runner itself, and the image as shipped: a server and an agent, each with only `NET_RAW`, probing for real.

<p align="center"><sub>Made in Portugal 🇵🇹 by <a href="https://github.com/ST-DEVPT">ST-DEVPT</a> · tools for the homelab, built to be left alone.</sub></p>
