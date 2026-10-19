# Security

smoketrace has no login. Anyone who can reach its port sees your targets, their addresses, the routes to them
and their history. The dashboard and its API only read; the only thing that writes is an agent's push, and
that needs the agent's token.

- The image listens on every interface (`BIND=0.0.0.0`); outside Docker it listens on `127.0.0.1` unless told
  otherwise. Keep it on a trusted network, or put it behind a reverse proxy with authentication.
- The container runs with one capability, `NET_RAW` (what fping and mtr need for ICMP), a read-only root and
  no-new-privileges. The systemd unit runs it as a dynamic, unprivileged user with the same single capability.
- **Agents** authenticate with a token, compared in constant time: at least 16 characters in `AGENTS`; secrets
  taken from SmokePing's secrets file are accepted as they are, with a warning in the log when shorter. Every pushed
  round is rebuilt from known fields only: targets the server has, numbers in range, hop addresses that are IP
  addresses. The token travels with every round, so over the internet put the server behind HTTPS or a VPN.
- Targets come only from `targets.ini`, and a host that could be read as a command-line option is refused.

## Reporting a vulnerability

Please use [private vulnerability reporting](https://github.com/ST-DEVPT/smoketrace/security/advisories/new)
rather than a public issue.
