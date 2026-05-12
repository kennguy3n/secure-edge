# ShieldNet Secure Edge

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Build](https://img.shields.io/badge/build-pending-lightgrey)](#)

**Open-source, privacy-first AI Data Leakage Prevention for desktop.**

Secure Edge is a cross-platform desktop agent (Windows, macOS, Linux) that blocks unauthorized
AI tools at the DNS level and (in later phases) inspects content sent to approved AI tools via
a layered on-device DLP pipeline. It runs as a minimal system-tray app, consumes negligible
CPU and memory, and **logs nothing** about user access — only running aggregate counters.

## Privacy First

The agent stores only:

- **Policy configuration** — which categories are allowed, inspected, or blocked
- **Anonymous aggregate counters** — `dns_queries_total`, `dns_blocks_total`,
  `dlp_scans_total`, `dlp_blocks_total` (integers only, no per-event timestamps)
- **Rule files** — domain lists and DLP patterns

No domain names, URLs, IP addresses, user identifiers, or per-event timestamps are ever written
to disk. DLP block notifications are shown in real time and discarded. The
[`store/privacy_test.go`](./agent/internal/store/privacy_test.go) test sweeps every text column
in the SQLite database and asserts none of those values reach disk.

## Policy Tiers

| Tier | Action | Mechanism |
|------|--------|-----------|
| 1 | Allow | Pass-through, no inspection |
| 2 | Allow + DLP | Forwarded, inspected by the layered DLP pipeline (Phase 2) |
| 3 | Block (AI) | DNS resolver returns NXDOMAIN |
| 4 | Block (Other) | DNS resolver returns NXDOMAIN |

## Quick Start

```bash
git clone https://github.com/kennguy3n/secure-edge.git
cd secure-edge

# Build and run the Go agent (DNS listener + local API on 127.0.0.1:8080).
cd agent
make build
./secure-edge-agent --config ../config.yaml      # or omit --config for defaults

# In a second shell, install and run the Electron tray app.
cd electron
npm install
npm run build
npm start
```

Binding `127.0.0.1:53` on Linux/macOS requires `sudo` or the `cap_net_bind_service` capability;
pick a higher-numbered `dns_listen` (e.g. `127.0.0.1:5353`) in `config.yaml` for unprivileged
development.

Example `config.yaml`:

```yaml
upstream_dns: "8.8.8.8:53"
dns_listen: "127.0.0.1:5353"
api_listen: "127.0.0.1:8080"
db_path: "secure-edge.db"
stats_flush_interval: 60s
rule_paths:
  - rules/ai_chat_blocked.txt
  - rules/ai_code_blocked.txt
  - rules/ai_allowed.txt
  - rules/ai_chat_dlp.txt
  - rules/phishing.txt
  - rules/social.txt
```

## Project Structure

```
secure-edge/
├── README.md            PROPOSAL.md  ARCHITECTURE.md  PHASES.md  PROGRESS.md  LICENSE
├── agent/                            # Go backend (single static binary)
│   ├── cmd/agent/main.go
│   ├── internal/
│   │   ├── api/                      # HTTP API server + handlers
│   │   ├── config/                   # YAML configuration loader
│   │   ├── dns/                      # Embedded DNS resolver (miekg/dns)
│   │   ├── policy/                   # Policy engine
│   │   ├── rules/                    # Rule-file parser + lookup index
│   │   ├── stats/                    # Anonymous aggregate counters
│   │   └── store/                    # SQLite (modernc.org/sqlite, WAL)
│   ├── go.mod / go.sum
│   └── Makefile                      # build / test / lint targets
├── electron/                         # System-tray app (Electron + React)
│   ├── main.ts                       # Tray icon, health polling, BrowserWindow
│   ├── preload.ts                    # Secure contextBridge
│   ├── src/
│   │   ├── pages/{Settings,Status}.tsx
│   │   ├── components/{CategoryToggle,StatsCard}.tsx
│   │   └── api/agent.ts              # HTTP client for the Go agent
│   ├── package.json
│   └── electron-builder.yml
└── rules/                            # Bundled domain lists (community-editable)
    ├── ai_chat_blocked.txt
    ├── ai_chat_dlp.txt
    ├── ai_code_blocked.txt
    ├── ai_allowed.txt
    ├── phishing.txt
    └── social.txt
```

## API

Local HTTP API on `127.0.0.1:8080` (configurable):

| Method | Path                       | Description |
|--------|----------------------------|-------------|
| GET    | `/api/status`              | Agent status + uptime + version |
| GET    | `/api/policies`            | List `[category, action]` rows |
| PUT    | `/api/policies/:category`  | Update an action; triggers policy reload |
| GET    | `/api/stats`               | Aggregate counters (integers only) |
| POST   | `/api/stats/reset`         | Reset all counters to zero |

`action` is one of `allow`, `allow_with_dlp`, `deny`.

## Testing

```bash
cd agent
make test                 # runs `go test -race ./...`
make lint                 # runs `go vet ./...`

cd ../electron
npm run typecheck         # TypeScript strict mode against renderer + main
```

## Documentation

- [PROPOSAL.md](./PROPOSAL.md) — scope, privacy model, layered DLP overview
- [ARCHITECTURE.md](./ARCHITECTURE.md) — components, DB schema, API, integration
- [PHASES.md](./PHASES.md) — phased implementation plan
- [PROGRESS.md](./PROGRESS.md) — per-item progress tracker

## Contributing

Contributions are welcome under the MIT license. Good first contributions:

- **Rule lists** — add domains (one per line, leading `.` for "include subdomains") to
  `rules/*.txt`.
- **DLP patterns / exclusions** (Phase 2) — `rules/dlp_patterns.json`,
  `rules/dlp_exclusions.json`.
- **Bug reports** — please use GitHub Issues.

Please run `make test` and `make lint` in `agent/` before submitting Go changes, and
`npm run typecheck` in `electron/` before submitting renderer changes.

## License

[MIT](./LICENSE)
