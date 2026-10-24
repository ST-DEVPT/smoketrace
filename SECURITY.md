# Security

Without `PASSWORD`, anyone who can reach its port sees your targets, their addresses, the routes to them and
their history. With it, the dashboard and its API need a sign-in: a session cookie signed with the password
(HMAC-SHA256), HttpOnly, SameSite=Strict, Secure behind an HTTPS proxy that sets `X-Forwarded-Proto`, valid for 30
days; changing the password ends every session. A wrong password costs a second, and any sign-in in the second
after one is answered 429 without being checked, so guesses go one a second however many are sent at once (in
a flood of guesses you may have to try again). `/metrics` then needs `METRICS_TOKEN`. Three things write: an
agent's round, which needs the agent's token, the Targets page and the Sites page.

- The image listens on every interface (`BIND=0.0.0.0`); outside Docker it listens on `127.0.0.1` unless told
  otherwise. Keep it on a trusted network, or put it behind a reverse proxy with authentication.
- The container runs with one capability, `NET_RAW` (what fping and mtr need for ICMP), a read-only root and
  no-new-privileges. The systemd unit runs it as a dynamic, unprivileged user with the same single capability.
- **Agents** authenticate with a token, compared in constant time: at least 16 characters in `AGENTS`; secrets
  taken from SmokePing's secrets file are accepted as they are, with a warning in the log when shorter. Every pushed
  round is rebuilt from known fields only: targets the server has, numbers in range, hop addresses that are IP
  addresses. The token travels with every round, so over the internet put the server behind HTTPS or a VPN.
- **The Targets and Sites pages** edit only when `PASSWORD` is set and you are signed in; without a password it is
  read-only, since anyone who opens the page could otherwise change what the server probes. An edit must be sent
  as `application/json`, which a form on another site cannot send, on top of the SameSite=Strict cookie. Every
  field is checked as a target from a file is, and the list is written whole and swapped in.
- **Outside services**: each site asks Google's name servers for its own public address once an hour (one DNS
  question), and AS numbers, their names and the site's network come from Team Cymru over DNS. `ASN=0` turns
  all of it off. Nothing else leaves the server except what you configure (alerts, agents).
- **MariaDB**: its password can stay out of the address, in `DB_PASSWORD`. The image installs one package,
  PyMySQL, pinned by hash in `requirements.txt`, as the base image is pinned by digest.
- A host that could be read as a command-line option is refused, wherever the target comes from (the page,
  `targets.ini`, SmokePing's config, or the server's list as an agent receives it).

## Reporting a vulnerability

Please use [private vulnerability reporting](https://github.com/ST-DEVPT/smoketrace/security/advisories/new)
rather than a public issue.
