# ShieldNet Secure Edge

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![CI](https://github.com/kennguy3n/secure-edge/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/secure-edge/actions/workflows/ci.yml)
[![Coverage: agent/internal/dlp ≥ 80%](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)](./.github/workflows/ci.yml)

**Open-source, privacy-first AI Data Loss Prevention for desktop.**

A cross-platform agent (Windows, macOS, Linux) that blocks unauthorized AI
tools at the DNS layer and inspects content sent to approved AI tools through
a layered, on-device DLP pipeline. Content reaches the pipeline through a
Chrome / Firefox / Safari companion extension or, for non-browser traffic,
an optional local MITM proxy that decrypts only Tier-2 domains and tunnels
everything else opaquely. The agent runs as a minimal system-tray app, costs
negligible CPU and memory, and **records nothing about user access** — only
running aggregate counters.

## Privacy invariant

Secure Edge persists three things, and nothing else:

- **Policy configuration** — which categories are allowed, inspected, or blocked.
- **Anonymous aggregate counters** — `dns_queries_total`, `dns_blocks_total`,
  `dlp_scans_total`, `dlp_blocks_total`, `tamper_detections_total`. Integers only;
  no per-event timestamps.
- **Rule files** — domain lists and DLP patterns.

No domain names, URLs, IP addresses, user identifiers, or per-event timestamps
ever reach disk. Block notifications render in real time and are discarded.
[`store/privacy_test.go`](./agent/internal/store/privacy_test.go) sweeps every
text column in the SQLite database and asserts these values cannot reach disk.

## Policy tiers

| Tier | Action       | Mechanism                                            |
|------|--------------|------------------------------------------------------|
| 1    | Allow        | Pass-through, no inspection                          |
| 2    | Allow + DLP  | Forwarded, inspected by the layered DLP pipeline     |
| 3    | Block (AI)   | DNS resolver returns NXDOMAIN                        |
| 4    | Block (other)| DNS resolver returns NXDOMAIN                        |

## Quick start

```bash
git clone https://github.com/kennguy3n/secure-edge.git
cd secure-edge/agent
make build
./secure-edge-agent --config ../config.yaml      # or omit --config for defaults

# In a second shell, run the tray app:
cd ../electron
npm install && npm run build && npm start
```

Binding `127.0.0.1:53` on Linux / macOS requires `sudo` or the
`cap_net_bind_service` capability; pick a higher-numbered `dns_listen`
(e.g. `127.0.0.1:5353`) in `config.yaml` for unprivileged development.

A minimal `config.yaml`:

```yaml
upstream_dns: "8.8.8.8:53"
dns_listen:   "127.0.0.1:5353"
api_listen:   "127.0.0.1:8080"
db_path:      "secure-edge.db"
rule_paths:
  - rules/ai_chat_blocked.txt
  - rules/ai_code_blocked.txt
  - rules/ai_allowed.txt
  - rules/ai_chat_dlp.txt
  - rules/phishing.txt
  - rules/social.txt
  - rules/news.txt
dlp_patterns:   rules/dlp_patterns.json
dlp_exclusions: rules/dlp_exclusions.json
```

Reference presets (`config.personal.example.yaml`,
`config.team.example.yaml`, `config.managed.example.yaml`) live at the repo
root. Configuration reference:
[docs/admin-guide.md](./docs/admin-guide.md) (operator guide) and
[`agent/internal/config/config.go`](./agent/internal/config/config.go)
(struct tags, defaults, validation).

Leaving `dlp_patterns` blank disables the DLP pipeline and `/api/dlp/*` returns
`503`. Likewise, leaving `rule_update_url` blank returns `503` from
`/api/rules/*`. The DNS and policy paths keep working independently.

## Project layout

```
secure-edge/
├── agent/                     # Go backend, single static binary
│   ├── cmd/                   # main agent + signing tools
│   └── internal/              # api, config, dlp, dns, heartbeat,
│                              # policy, profile, proxy, rules, stats,
│                              # store, tamper, updater
├── electron/                  # System-tray app (Electron + React)
├── extension/                 # Chrome / Firefox / Safari companion (Manifest V3)
├── rules/                     # Bundled domain lists + DLP patterns
├── docs/                      # Operator + contributor documentation
├── scripts/                   # Platform install + DNS + proxy scripts
└── .github/                   # Issue / PR templates, CI, release workflow
```

## API

Local HTTP API on `127.0.0.1:8080` (configurable). All endpoints accept only
loopback callers and an `Origin` allowlist; control-path endpoints additionally
require a Bearer capability token when `api_token_required: true`.

| Method   | Path                              | Description                                                                                                |
|----------|-----------------------------------|------------------------------------------------------------------------------------------------------------|
| GET      | `/api/status`                     | Uptime, version, Go runtime stats, DLP pattern count, rule-file basenames                                  |
| GET/PUT  | `/api/policies`, `/api/policies/:category` | List or set the action for a category (`allow`, `allow_with_dlp`, `deny`)                          |
| GET/POST | `/api/stats`, `/api/stats/reset`  | Read aggregate counters or reset them to zero                                                              |
| GET      | `/api/stats/export`               | Counter snapshot as an attachment envelope                                                                 |
| POST     | `/api/dlp/scan`                   | Scan `{content}` through the pipeline; returns `{blocked, pattern_name, score}`. In-memory, never persisted |
| GET/PUT  | `/api/dlp/config`                 | Read or update DLP scoring weights and per-severity thresholds                                             |
| GET/POST | `/api/rules/status`, `/api/rules/update` | Inspect or force a rule-manifest check                                                              |
| GET/POST/DELETE | `/api/rules/override`, `/api/rules/override/:domain` | Admin allow/block override store                                              |
| POST     | `/api/proxy/enable`, `/api/proxy/disable` | Start or stop the local MITM proxy (`{remove_ca: true}` removes the per-device CA on disable)      |
| GET      | `/api/proxy/status`               | `{running, ca_installed, listen_addr, dlp_scans_total, dlp_blocks_total}`                                  |
| GET      | `/api/profile`                    | Current enterprise profile, or 404                                                                         |
| POST     | `/api/profile/import`             | Import a profile from `{url}` or `{profile}` body; locks local edits when `managed=true`                   |
| GET      | `/api/tamper/status`              | `{dns_ok, proxy_ok, last_check, detections_total}`                                                         |
| GET/POST | `/api/agent/update-check`, `/api/agent/update` | Manifest check / staged self-update (SHA-256 + Ed25519 verified)                              |
| GET      | `/api/config/enforcement-mode`    | Effective enforcement mode (`personal`, `team`, `managed`) and whether overrides are locked                |
| GET      | `/api/config/risky-extensions`    | Effective risky-file-extension blocklist (baked-in default or operator override)                           |

DLP endpoints return `503` when `dlp_patterns` is unset; rule endpoints return
`503` when `rule_update_url` is blank; proxy endpoints return `503` when the
proxy controller is not configured.

## Extension transport

The extension prefers Native Messaging and falls back to HTTP; see
[ARCHITECTURE.md](./ARCHITECTURE.md#companion-extension) for transport
details and enforcement caveats.

## Enterprise features

Optional features for managed deployments. Each honours the same privacy
invariant as the base agent.

- **Signed configuration profiles.** JSON profile sources (`profile_path`,
  `profile_url`) are verified against `profile_public_key`; `managed=true`
  profiles lock the policy and DLP APIs and the tray UI.
- **Tamper detection.** Background DNS / proxy probes bump
  `tamper_detections_total` only on transitions and surface an ephemeral
  tray balloon — no per-event log on disk.
- **Optional heartbeat.** `heartbeat_url` posts exactly
  `{agent_version, os_type, os_arch, aggregate_counters}`, asserted by
  `agent/internal/heartbeat/heartbeat_test.go`.
- **Admin overrides.** Drop `allow.txt` / `block.txt` /
  `dlp_patterns_override.json` / `dlp_exclusions_override.json` into
  `rules/local/` to add company-specific rules without touching the
  bundled files; the tray exposes equivalent UI.

## Security posture

The agent ships with three enforcement presets (personal, team, managed)
and a layered security model. See
[ARCHITECTURE.md § Security posture](./ARCHITECTURE.md#security-posture)
for the enforcement matrix, extension-vs-proxy boundary analysis, and DLP
accuracy methodology.

## Testing

```bash
cd agent && make test      # go test -race ./...
cd agent && make lint      # go vet ./...

cd ../electron  && npm run typecheck
cd ../extension && npm install && npm run typecheck && npm test
```

The DLP package has a `_test.go` per pipeline component (`classifier`,
`ahocorasick`, `regex`, `hotword`, `entropy`, `exclusion`, `scorer`,
`threshold`) plus a `pipeline_test.go` integration test that exercises real
AWS keys with hotword context (block), the AWS docs example key
`AKIAIOSFODNN7EXAMPLE` (exclude), benign prose (allow), empty content, and
large payloads embedding a real-looking key.

Performance benchmarks for the DLP pipeline, DNS resolver, and stats counter
live in `*_bench_test.go` files; see [BENCHMARKS.md](./BENCHMARKS.md).

## DLP coverage

812 patterns across 22 categories. See
[SECURITY_RULES.md](./SECURITY_RULES.md) for the full per-pattern
reference.

## Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) — components, DB schema, API, integration points, security posture
- [SECURITY.md](./SECURITY.md) — vulnerability disclosure + release-artefact verification recipe
- [SECURITY_RULES.md](./SECURITY_RULES.md) — per-pattern reference table
- [CONTRIBUTING.md](./CONTRIBUTING.md) — development setup, PR process, coding standards
- [AGENTS.md](./AGENTS.md) — AI usage policy
- [CHANGELOG.md](./CHANGELOG.md) — release-by-release summary
- [BENCHMARKS.md](./BENCHMARKS.md) — DLP, DNS, and stats benchmarks
- [docs/admin-guide.md](./docs/admin-guide.md) — installation, configuration, profiles, MDM
- [docs/user-guide.md](./docs/user-guide.md) — tray icon, false-positive reporting, privacy summary
- [docs/rule-contribution-guide.md](./docs/rule-contribution-guide.md) — how to add domains and categories
- [docs/dlp-pattern-authoring-guide.md](./docs/dlp-pattern-authoring-guide.md) — DLP schema, scoring, hotwords, entropy, exclusions

## License

MIT — see [LICENSE](./LICENSE).
