# Moving from SmokePing

smoketrace reads SmokePing's config as it is: no conversion, and SmokePing can keep running beside it until you
are happy. Mount the folder the config lives in and point `SMOKEPING_CONFIG` at it in `docker-compose.yml`:

```yaml
    volumes:
      - ./data:/data
      - /etc/smokeping:/etc/smokeping:ro     # SmokePing in a container (linuxserver/smokeping)? Its config folder,
                                             # e.g. /DATA/smokeping/config:/etc/smokeping:ro
    environment:
      SMOKEPING_CONFIG: /etc/smokeping
```

The folder can hold one main `config` file (with `@include`s) or the split files that Debian and the
linuxserver/smokeping image use (`Probes`, `Slaves`, `Database`, `Targets`…). Paths inside the config are often
absolute for the machine or container SmokePing ran in, such as `@include /config/target/dns.conf` or
`secrets = /config/smokeping_secrets`: when such a path is not there, smoketrace looks for it in the mounted folder
(`/etc/smokeping/target/dns.conf`). An include that cannot be found is logged and skipped; the rest of the config
still loads.

The secrets file is often readable by SmokePing's user only. The container runs as root without
`CAP_DAC_OVERRIDE`, so if the log says it cannot read the secrets, make the file readable to root
(`sudo chown root smokeping_secrets`) or give the agents' tokens in `AGENTS` instead.

## What is read

| SmokePing | smoketrace |
| --- | --- |
| `*** Targets ***`, the `+` / `++` / `+++` tree | the targets; the tree becomes the groups, `menu` (or `title`) the names |
| `@include` | followed, relative to the including file |
| `FPing`, `FPing6`, `TCPPing` (`port`), `DNS` (`lookup`) and their subprobes | probed as ICMP, TCP and DNS; other probes (Curl, SSH…) and multi-host graphs are listed in the log and left out |
| `*** Slaves ***` and its `secrets` file | the agents: a slave's name, with its secret as the agent's `TOKEN`; `url = http://…` under a slave makes the server fetch from it |
| `slaves = porto office` | which agents probe the target (inherited, as in SmokePing) |
| `nomasterpoll = yes` | the server leaves the target to its agents |
| `step`, `pings` in `*** Database ***` | the round length and the pings per round, for the server and every agent |
| `loss_warn`, `loss_crit` (in %), `latency_warn` (in ms) | smoketrace's own per-target limits, inherited down the tree |
| `*** Alerts ***`, `*** Presentation ***` | not used: [alerts](../README.md#alerts) are smoketrace's own |

The server re-reads the config (every included file and the secrets) when one of them changes, before its next
round; the agents get the new list on theirs. A broken edit is logged and the last good config stays.

## Editing on the page

The first time you add, change or remove a target on the Targets page, smoketrace copies SmokePing's targets (with
their agents and limits, and the same ids, so the history stays) to `/data/targets.json` and reads its targets from
there from then on. SmokePing's slaves, secrets, round length and pings still apply. To go back to SmokePing's
targets, delete `/data/targets.json`.

## Bring the history along

SmokePing keeps its history in RRD files; one command copies up to 30 days of it (median, loss and the spread of
every round, for the master and every slave) into smoketrace's database. It needs `rrdtool`, which every SmokePing
machine has, so the simplest is a throw-away container on that machine, once, before you start smoketrace for the
first time:

```bash
docker run --rm -v /var/lib/smokeping:/rrd:ro -v /etc/smokeping:/etc/smokeping:ro -v "$PWD/data:/data" \
  --entrypoint sh ghcr.io/st-devpt/smoketrace:latest -c "apk add -q rrdtool && \
  python smoketrace.py --import-rrd /rrd --smokeping /etc/smokeping --name home"
```

With the linuxserver/smokeping image, its data folder holds the RRD files: `-v /DATA/smokeping/data:/rrd:ro` and
`-v /DATA/smokeping/config:/etc/smokeping:ro`.

`--name` is the name the server's own probe will have (`NAME`); slave files (`Target~porto.rrd`) go to that
agent. Rounds older than three days come in hourly, as SmokePing stored them. Then stop SmokePing and its slaves.
