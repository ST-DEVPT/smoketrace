# Security

smoketrace has no login. Anyone who can reach its port sees your targets, their addresses, the routes to them
and their history. Nobody can change anything through it: the API only reads.

- It listens on `127.0.0.1` unless told otherwise; the systemd unit uses `--bind 0.0.0.0` for the LAN. Keep it
  on a trusted network, or put it behind a reverse proxy with authentication.
- The systemd unit runs it as a dynamic, unprivileged user with one capability, `CAP_NET_RAW`, which fping and
  mtr need for ICMP.
- Targets come only from `targets.ini`, and a host that could be read as a command-line option is refused.

## Reporting a vulnerability

Please use [private vulnerability reporting](https://github.com/ST-DEVPT/smoketrace/security/advisories/new)
rather than a public issue.
