# Security Model

This repo ships guardrails for AI coding agents. This file writes down the threat it
addresses, the layers around it, and what is in scope, so you can point the agent (and
future-you) at the rules instead of trusting memory.

## Threat

**Indirect prompt injection acting on the agent's credentials.** An AI agent that can read
web pages and run commands inherits your environment: cloud profiles, tokens, kubeconfigs,
SSH keys. A malicious instruction hidden in a page the agent reads can try to make it exfiltrate
data using those credentials.

The dangerous ingredient is not the *reading*. It is **privilege plus an egress channel**: the
agent acting on injected text with real access and a way to send data out.

## Layers (defense in depth)

No single control is enough. Each layer fails differently, which is the point.

1. **Least privilege.** Run the agent read-only by default; elevate only for the task that
   needs it. The highest-impact control, and not something this repo can do for you.
2. **Pre-execution guardrails.** The hooks here: block secret-read-plus-egress, encoded
   payloads piped to the network, and data sent to non-allowlisted hosts.
3. **Web-read gating.** Fetching pages from non-allowlisted domains requires confirmation.
4. **Human-in-the-loop.** Keep a human confirming anything mutating or destructive.
5. **Network egress controls.** An egress firewall, IDS/IPS, and reputation or Geo-IP
   filtering catch traffic the host-level hooks never inspect.
6. **Audit trail.** Blocks are logged locally; pair that with cloud-side audit for forensics.

## What the hooks cover

- Reading a secret or credential file and sending it over the network in one command.
- `base64`/`gzip`/`xxd` piped into `curl`/`wget`/`Invoke-WebRequest`.
- `POST`/`PUT` of data to a host outside the allowlist.
- `WebFetch` to a domain outside the allowlist (asks for confirmation).

## What they do NOT cover

- Exfiltration over an *allowed* host (a gist, a paste service, a CI artifact).
- DNS exfiltration, or data smuggled through an MCP tool the hook never sees.
- A slow trickle that stays under any single command. These are heuristics, not a sandbox.
- They are no substitute for least privilege (layer 1).

## Reporting

Found a bypass, a false block, or a missed pattern? Please open an issue with a minimal
repro (a sample hook payload is ideal). Responsible disclosure is appreciated for anything
that materially weakens the guardrails.
