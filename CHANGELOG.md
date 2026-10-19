# Changelog

Versions follow [semantic versioning](https://semver.org).

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
