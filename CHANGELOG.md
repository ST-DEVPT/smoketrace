# Changelog

Versions follow [semantic versioning](https://semver.org).

## [0.4.1] - 2026-10-19

- **Many targets**: fping's timeout grows with the number of ICMP targets (at `-i10` every packet waits 10 ms,
  so 640 hosts at 20 pings need over two minutes) and stays below the step; before, any config past ~300 hosts
  hit a fixed 90 s timeout and every round came back as 100% loss.

## [0.4.0] - 2026-10-19

- **Alerts** on Discord, ntfy or any webhook, when a target's status or its route changes and holds for two
  rounds, when it recovers, and when an agent stops or starts sending rounds. Each alert says what you would look
  up first: the median and loss, the hop where real loss starts (with its AS), where the traceroute stops, the
  AS path before and after, what the other sites see, and a link to the target (`PUBLIC_URL`).
- **TCP and DNS probes**: `tcp://host:port` times a TCP connection (for hosts that drop ICMP) and traces over
  that port; `dns://server/name` times a DNS server's answer and traces over TCP 53. SmokePing's `TCPPing`
  (`port`) and `DNS` (`lookup`) targets are now probed too.
- **AS and operator of every hop** (mtr `-z`, names from Team Cymru, looked up once and kept), in the traceroute
  table, an "AS path changed" note and the alerts. `ASN=0` turns it off.
- **Prometheus**: `/metrics` with median, loss, jitter, status, route changes and the last round, per target and
  source (`METRICS_TOKEN`); `docs/grafana.json` is a dashboard to import.
- **Sign-in**: `PASSWORD` protects the dashboard and its API with a signed, HttpOnly session cookie.
- **Agents the server pulls from**: `LISTEN` on the agent and `name=token@http://agent:8100` in `AGENTS` (or
  `url =` under a SmokePing slave), for sites the server can reach but that cannot reach the server.
  Rounds are dropped from the agent only once the server has acknowledged them.
- **SmokePing's history**: `--import-rrd` copies up to 30 days from SmokePing's RRD files (master and slaves).
- **Per-target limits**: `loss_warn`, `loss_crit` and `latency_warn` in SmokePing's config, inherited down the
  tree; `LOSS_WARN` and `LOSS_CRIT` for the defaults.
- **SmokePing's config from another container**: `SMOKEPING_CONFIG` may be a folder (a `config` file, or the split
  files of Debian and linuxserver/smokeping); absolute paths such as `@include /config/target/dns.conf` are found
  in the mounted folder; an include that cannot be found is logged and skipped instead of stopping the start.
- Imported hourly history draws as a continuous line; the image runs Python 3.14.

## [0.3.0] - 2026-10-19

- **Reads SmokePing's config**: point `SMOKEPING_CONFIG` at it and smoketrace takes the targets from
  `*** Targets ***` (the `+`/`++` tree becomes the groups, `menu` or `title` the names), follows `@include`,
  inherits `probe`, `slaves` and `nomasterpoll` the way SmokePing does, and uses `step` and `pings` from
  `*** Database ***`. Targets on a probe other than FPing (DNS, Curl, TCPPing…) and multi-host graphs are listed
  in the log and left out.
- **SmokePing's slaves are the agents**: the names in `*** Slaves ***` with their secrets from the `secrets` file.
  Start an agent with the slave's secret as its `TOKEN`; it probes only the targets whose `slaves` name it, with
  the primary's step and pings. `nomasterpoll = yes` leaves a target to the agents. `AGENTS` still works and
  wins over the secrets file.
- **Config changes without a restart**: the primary re-reads its config (every included file and the secrets)
  when one changes, before the next round, and the agents follow on their next round. A broken edit is logged
  and the last good config stays.
- The overview lists, for each source, only the targets it probes.

## [0.2.0] - 2026-10-19

- **Docker**: a multi-arch image (`ghcr.io/st-devpt/smoketrace`, amd64 and arm64) and a compose file. The
  container gets `NET_RAW` and nothing else, a read-only root and no-new-privileges, and uses the host's network
  so traceroutes start at your real gateway. The first start writes an example `data/targets.ini`.
- **Remote agents**: the same image, started with `SERVER` and `TOKEN`, probes the server's targets from another
  site and pushes every round; while the server is unreachable it keeps up to a day of rounds. The server lists
  its agents in `AGENTS` (`name=token`), checks every pushed round field by field, and keeps each source apart.
- **Seen from**: the dashboard switches between the server's own probe and each agent, and the overview shows
  how every source sees every target, so "down for everyone" and "down from one site" look different.
- **English and Portuguese**: the dashboard follows the browser's language, with a switch in the header;
  messages, files and the demo are in English.
- Every option can be set with an environment variable (`TARGETS`, `DB`, `BIND`, `PORT`, `NAME`, `AGENTS`,
  `SERVER`, `TOKEN`, `DEMO`).
- Databases from 0.1.0 are upgraded on start: their data becomes the server's own source (`NAME`).

## [0.1.0] - 2026-10-19

First release.

- **Latency the SmokePing way**: 20 pings to every target every five minutes with fping, with SmokePing's own
  flags; the median, the loss, the jitter, and the smoke of all 20 replies.
- **A traceroute every round**: an mtr to every target, in the same minutes as the pings, so the route and the
  latency always describe the same window.
- **Route changes on the chart**: every path gets a letter for the target's whole history; a route strip under
  the chart and a line at every change, through latency and loss.
- **Traceroute diff**: click any moment for its traceroute against the previous route or the previous round,
  hop by hop, with the latency difference and the destination's.
- **Rate-limit or real loss**: loss that stops at a hop is tagged rate-limit; loss that lasts to the
  destination is marked where it starts; a target that stops answering says which hop answered last.
- **Overview**: every target with its status by shape and label, latency, jitter, loss, a 24-hour sparkline and
  its route changes; filters, search, dark and light, phone.
- **Demo mode** with a week of synthetic data, and a hardened systemd unit.
