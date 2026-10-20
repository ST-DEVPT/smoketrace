# Changelog

Versions follow [semantic versioning](https://semver.org).

## [0.8.0] - 2026-10-21

- **Edit targets on the page.** A *Targets* page lists every target by group, and with `PASSWORD` set you can add,
  change and remove them: group, name, address (`host`, `tcp://host:port`, `dns://server/name`), which sites probe
  it, and its own loss and latency limits. A bad field is pointed out where it is. A renamed or moved target keeps
  its id, so its history stays. Changes are probed from the next round and reach the agents on theirs.
  The page keeps the list in `targets.json` next to `targets.ini`; the first change copies the current targets
  there (from `targets.ini`, or from SmokePing's config with their agents and limits; SmokePing's agents, round
  length and pings still apply). Without `PASSWORD` the page is read-only.
- **The version** is shown in the corner of the page, linked to its release notes, and in the start-up log.
- **Simpler documentation**: install in three steps, a remote site in three steps, every option in one place
  (also commented in `docker-compose.yml` and `docker-compose.agent.yml`), and the common problems with their
  fixes. SmokePing and the inner workings moved to `docs/`.
- **Agents**: with the server's `AGENTS` line pasted on an agent instead of `TOKEN`, the agent takes its token
  from it and says so in the log; with no token at all, the error says where the token comes from.
- The systemd unit keeps its targets in `/var/lib/smoketrace`, where the page can write them.

## [0.7.0] - 2026-10-21

**Navigation fixed.** Moving around quickly could show the wrong data:

- A slow answer could paint over a newer one: a week-long overview arriving after you had gone back to 24 hours
  (the 24 h button pressed, a week of data shown), a target's 30 days after you had picked 3 hours, an earlier
  traceroute after a later click, a background refresh switching the source back. Each kind of request is now
  numbered and only the newest is shown.
- Back from a target returns to the overview where you left it: the page, the heatmap and the table scroll.
  <kbd>Esc</kbd> and the *Overview* link go back the same way instead of adding a history entry.
- The moment whose traceroute you picked is in the address (`#/t/<id>?at=<time>`): reload, back and forward and a
  shared link show that moment, and changing `at=` on the same target loads it.
- `test_ui.py` checks all of this in a real browser, with slowed answers; CI runs it.

**The look, reworked** (using the guidance of the *impeccable*, *taste*, *ui-ux-pro-max* and *no-ai-slop* skills):

- The line under the title states the finding for what you are looking at ("12 of 55 targets need attention. 9 of
  them lose packets at 100.70.42.1 (Regional Backbone)") with the link that shows only those; a target's page
  says what is true about it now ("Losing 30 % of pings for 49 min. Real loss starts at hop 5 …").
- One strip of counts is also the status filter; the separate status chips are gone, and zeros print in grey.
- What is fine is grey and only trouble has colour, in the heatmap, the table and the icons; no data is a dash,
  not a cell.
- The traceroute draws both routes as transit lines beside the hops: one line where they share a router, two
  where they part, a red station where real loss starts. The "before" column shows only when the hops differ, and
  the table fits its column on a laptop and on a phone.
- The median is the one line in colour on the chart; app-sized type (32 px title, 32 px figures); drawn icons
  instead of text arrows and triangles; themed selection and scrollbars; a refresh button next to "Updated";
  loading shows the layout with grey bars; losing the connection is a quiet notice that says how old the figures
  are, not a red band.
- Copy rewritten to say the fact first, without colon reveals or closing aphorisms.

## [0.6.0] - 2026-10-20

Hundreds of targets, measured on 555 with a week of history:

- **Less CPU for traceroutes.** At most 16 mtr run at once (`TRACE_PARALLEL`, was up to 64): each one's raw
  socket receives every ICMP reply of all the others, so their CPU grew with the square of how many ran
  together. When the targets do not all fit in a round, each is traced in turn every few rounds, and a target
  that lost packets is traced the next round as well. Route-change alerts count new traces only.
- **The dashboard is computed once per round**, not every 20 seconds per viewer, and so is `/metrics` however
  often it is scraped. Computing it is faster too: 24 hours went from 7 s to 0.6 s, a week from 26 s to 2.5 s,
  `/metrics` from 4.6 s to 0.7 s. Routes are kept in a narrow table of their own, so reading a week of routes no
  longer reads (and parses) every traceroute.
- **Storing a round** went from 1.8 s to under 0.3 s: old rows are removed target by target along the
  primary key, and the full sweep for removed targets runs once a day.
- **The table view** adds rows as they scroll into view (it took ~300 ms to draw 555 rows on every refresh),
  and a refresh keeps the table's scroll position.
- **Fixed**: a view choice saved by an older version (`view` in the browser's storage) drew the heatmap of the
  group shown before instead of the current one. Saved choices are now checked.
- Upgrading adds two tables; traces already stored get their route in the background after the start (about
  half a minute per million traces).

## [0.5.0] - 2026-10-20

- **A dashboard for many targets.** The overview is organised by your groups (SmokePing's tree or the sections of
  `targets.ini`), shown as a tree on the left with counts; picking a group scopes the whole page to it.
- **Readouts** for what is in view: how many are OK, down and degraded, the median latency with its trend, the
  worst loss and the route changes. Down, degraded, worst loss and route changes are filters.
- **Filters that stack**: status, probe, "route changed" and a search over names, groups and addresses (`/`),
  with sorting by severity, latency, loss, jitter, how far above usual, or route changes. They live in the URL,
  so a filtered view can be shared or bookmarked.
- **Three views of the same list**: a heatmap (one row per target, coloured by status, latency against the
  target's usual, or loss; groups fold into one row; hover for the numbers, click for that moment's traceroute),
  a sortable table with a history strip, and cards with a small chart each.
- **Needs attention**: every problem with how long it has lasted, the hop where loss starts or where the trace
  stops, and what the other sites see. Targets that lose packets at the same hop are grouped first ("one cause
  is likelier than many"), and problems seen from one site only point at that site.
- **A timeline** of status changes, route changes and agents going quiet; each entry opens that moment.
- Each target's page adds its own events and, with several sites, their medians on the same chart
  (*Compare sites*).
- A new look, shared with rack-fan-control: warm greys, Archivo and IBM Plex Mono (bundled, no outside
  requests), dark and light following the system; the sign-in page matches.
- `/api/board`, `/api/minis` and `/api/compare` serve the dashboard; answers over 1.4 KB are gzip-compressed.
- `LOSS_WARN` defaults to 10 % (two of 20 pings) instead of 5 %, so a single lost ping no longer warns.
- The demo has a fleet of 55 targets across sites and clouds, with a shared-hop outage to find.

## [0.4.2] - 2026-10-19

- **Traceroutes for many targets**: the number of mtr running at once grows with the targets (8 up to 64) so
  every trace of a round fits in the step; with 8, 555 targets took about 15 minutes a round and nothing was
  stored until it ended.

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
