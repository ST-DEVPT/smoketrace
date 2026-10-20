# Security

Without `PASSWORD`, anyone who can reach its port sees your targets, their addresses, the routes to them and
their history. With it, the dashboard and its API need a sign-in: a session cookie signed with the password
(HMAC-SHA256), HttpOnly, SameSite=Strict, Secure behind an HTTPS proxy that sets `X-Forwarded-Proto`, valid for 30
days; changing the password ends every session, and a wrong password costs a second. `/metrics` then needs
`METRICS_TOKEN`. Two things write: an agent's round, which needs the agent's token, and the Targets page.

- The image listens on every interface (`BIND=0.0.0.0`); outside Docker it listens on `127.0.0.1` unless told
  otherwise. Keep it on a trusted network, or put it behind a reverse proxy with authentication.
- The container runs with one capability, `NET_RAW` (what fping and mtr need for ICMP), a read-only root and
  no-new-privileges. The systemd unit runs it as a dynamic, unprivileged user with the same single capability.
- **Agents** authenticate with a token, compared in constant time: at least 16 characters in `AGENTS`; secrets
  taken from SmokePing's secrets file are accepted as they are, with a warning in the log when shorter. Every pushed
  round is rebuilt from known fields only: targets the server has, numbers in range, hop addresses that are IP
  addresses. The token travels with every round, so over the internet put the server behind HTTPS or a VPN.
- **The Targets page** edits targets only when `PASSWORD` is set and you are signed in; without a password it is
  read-only, since anyone who opens the page could otherwise change what the server probes. An edit must be sent
  as `application/json`, which a form on another site cannot send, on top of the SameSite=Strict cookie. Every
  field is checked as a target from a file is, and the list is written whole and swapped in.
- A host that could be read as a command-line option is refused, wherever the target comes from (the page,
  `targets.ini`, SmokePing's config, or the server's list as an agent receives it).

## Reporting a vulnerability

Please use [private vulnerability reporting](https://github.com/ST-DEVPT/smoketrace/security/advisories/new)
rather than a public issue.
