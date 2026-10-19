# Changelog

Versions follow [semantic versioning](https://semver.org).

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
