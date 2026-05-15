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
everything else opaquely.

The agent runs as a minimal system-tray app, costs negligible CPU and memory,
and **records nothing about user access** — only running aggregate counters.

## Privacy invariant

The agent persists three things, and nothing else:

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
root. Every tunable config key is documented in
[docs/admin-guide.md](./docs/admin-guide.md).

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

The companion extension prefers Chrome Native Messaging (no CORS, survives
air-gapped networks) and falls back to HTTP to `127.0.0.1:8080` when the
native host is unavailable. Install the host manifest with
`extension/native-messaging/install.sh` (macOS / Linux) or `install.ps1`
(Windows). Safari Web Extensions have no Native Messaging, so the Safari
port uses the HTTP fallback exclusively; the agent's CORS allowlist accepts
`chrome-extension://`, `moz-extension://`, and `safari-web-extension://`
origins.

> **Enforcement boundary.** The browser extension provides best-effort DLP
> coaching for interactive AI tool usage — it patches `fetch` /
> `XMLHttpRequest` in the page's MAIN world and signals intent over
> `window.postMessage`, which the page itself can observe and ignore. Treat
> the extension as a usability layer, not a hard enforcement boundary. For
> hard enforcement, enable the local MITM proxy (`POST /api/proxy/enable`)
> so Tier-2 traffic is decrypted and inspected outside the page's reach, or
> deploy managed browser policies (Chrome Enterprise `URLBlocklist`,
> `ManagedConfigurationPerOrigin`, or Firefox enterprise policies) to
> restrict which AI domains the browser can reach in the first place.

## Enterprise features

Optional features for managed deployments. Each honours the same privacy
invariant as the base agent.

- **Signed configuration profiles.** Set `profile_path` or `profile_url` in
  `config.yaml`; the JSON profile (`name`, `version`, `managed`, `categories`,
  `dlp`, `signature`) is verified against `profile_public_key` and applied on
  startup. When `managed=true`, `PUT /api/policies/:category` and
  `PUT /api/dlp/config` return `403` and the Electron settings UI disables
  every input.
- **Tamper detection.** A background goroutine (default 60s) checks that OS
  DNS still points at the agent and, when the MITM proxy is enabled, that
  the system proxy still points at `127.0.0.1:8443`. Transitions bump
  `tamper_detections_total`; the tray surfaces an ephemeral balloon. No
  per-event log on disk.
- **Optional heartbeat.** Set `heartbeat_url` to enable. Payload is exactly
  `{agent_version, os_type, os_arch, aggregate_counters}`. Tests in
  `agent/internal/heartbeat/heartbeat_test.go` assert this on the JSON
  wire format.
- **Admin overrides.** Drop files into `rules/local/` (`allow.txt`,
  `block.txt`, `dlp_patterns_override.json`, `dlp_exclusions_override.json`)
  to add company-specific rules without touching the bundled files. The
  Electron settings page exposes an allow / block UI backed by
  `POST /api/rules/override` and DLP threshold sliders backed by
  `PUT /api/dlp/config`.

## Security posture

### Enforcement modes

The agent ships with three enforcement presets. The decision is
driven by `enforcement_mode` in `config.yaml`; the secure-defaults
validator (`ValidateEnforcementRequirements` in
`agent/internal/config/config.go`) refuses to start `team` or
`managed` unless every required control is configured.

| Mode       | Default auth                        | MAC mismatch     | Agent unavailable | Oversize body | Profiles         | Target                       |
|------------|-------------------------------------|------------------|-------------------|----------------|------------------|------------------------------|
| `personal` | None (permissive)                   | Warn & fall open | Fall open silent  | Fall open      | Unsigned ok      | Individual developer         |
| `team`     | Bearer token + extension pinning    | Warn & fall open | Warn toast        | Fall open      | Unsigned ok      | Small team pilots            |
| `managed`  | Bearer + pinning + bridge HMAC + signed profiles + signed rules | **Block** | **Block**  | **Block**      | **Signed required** | MDM-deployed enterprise |

`team` and `managed` modes **refuse to start** unless every required
control is configured. This is not optional — a misconfigured
managed install fails at boot with a human-readable error naming
the missing field (see `config_test.go` for the full matrix of
rejected shapes).

In `managed`, the extension matches the agent's fail-closed posture:
a missing or mismatched Native Messaging response MAC discards the
result and routes the upload through `policyForUnavailable("managed")
=== "block"`. The same path catches `ReadableStream` fetch bodies
(which `bodyValueToTextAsync` cannot tee safely) and any scan
timeout. In `personal` and `team` those failure modes preserve the
legacy fall-open / warn-and-allow posture so the privacy-first
defaults are unchanged.

### Extension vs. proxy enforcement boundary

The browser extension is a **coaching layer** for honest-user DLP.
It catches paste / drop / submit / fetch / XHR in the patched
content-script bridge and surfaces a block toast in the page. It
cannot prevent:

- A hostile page that runs JS before the extension's
  `document_start` injection point and bypasses the patched
  `fetch` / `XHR` entirely.
- A compromised or removed extension (the agent has no way to
  cryptographically attest the extension is the one it pinned).
- A non-browser client (a CLI tool, a packaged Electron app, a
  Python script) that talks directly to the AI provider's API.
- A page that exfiltrates via a side channel the extension does not
  hook (WebSockets after `Sec-WebSocket-Key`, `navigator.sendBeacon`
  bodies that arrive on a different event loop tick, server-sent
  events, etc.).

For hard enforcement, deploy:

- The local MITM proxy (`proxy_enabled: true`) so every Tier-2 host's
  TLS is terminated locally and the DLP pipeline sees the cleartext
  request body before it leaves the box.
- Managed browser policies — Chrome `URLBlocklist` /
  `URLAllowlist`, Firefox `policies.json`, Edge group-policy
  equivalents — so the user cannot uninstall the extension or
  override its allowlist.
- OS-level egress controls (WFP filters on Windows, Network
  Extension content filters on macOS, nftables / iptables on Linux)
  that block direct connections to Tier-2 hostnames bypassing the
  MITM proxy.

The full boundary analysis lives in
[docs/admin-guide.md §8](./docs/admin-guide.md). The agent's CA
private key for the MITM proxy is mode-checked on every load:
group / world bits on the key file fail the proxy boot with a
human-readable error (see
[`agent/internal/proxy/ca.go`](./agent/internal/proxy/ca.go)).

### DLP accuracy methodology

812 patterns across 22 categories (the full breakdown is in the
[DLP coverage](#dlp-coverage) section below). Accuracy is enforced
by three CI-gated layers, each pinned in `agent/internal/dlp/`:

| Layer        | Corpus size | Budget                                                       | Source                                                                 |
|--------------|-------------|--------------------------------------------------------------|------------------------------------------------------------------------|
| Smoke        | 50          | FP rate < 10 %, FN rate < 5 %                                | [`accuracy_smoke_test.go`](./agent/internal/dlp/accuracy_smoke_test.go)        |
| Large        | 5 000+      | FP rate < 5 %, FN rate < 3 %, per-category FN < 10 %         | [`accuracy_large_test.go`](./agent/internal/dlp/accuracy_large_test.go)        |
| Regression   | full corpus | per-category recall must not drop > 2 pp; FP must not rise > 1 pp vs the committed baseline | [`accuracy_regression_test.go`](./agent/internal/dlp/accuracy_regression_test.go) |

The smoke test runs on every `go test` (no tag); large and
regression runs are gated behind `-tags=large` so the default
developer workflow stays fast. CI runs all three.

The corpus is fully synthetic — no real secrets are committed.
True-positive samples are generated by a deterministic generator;
true-negatives are realistic benign content (code, logs, docs,
docstrings) chosen to trip naive regex patterns but contain no
secret the agent should block. Composition and contribution rules
live in
[`agent/internal/dlp/testdata/corpus/README.md`](./agent/internal/dlp/testdata/corpus/README.md).

### HTTP surface hardening

Every HTTP listener the agent owns runs with a full timeout tuple
(`ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`)
plus a 16 KiB `MaxHeaderBytes` so a slowloris or a malicious
header buffer cannot pin a listener thread. Control endpoints that
take JSON bodies are wrapped in `http.MaxBytesReader(64 KiB)` and
return `413 Request Entity Too Large` on overflow — the agent will
not buffer megabytes of attacker-controlled JSON. The control API
exception list (4 MiB for `/api/dlp/scan`, 1 MiB for
`/api/profile/import`) is enumerated in
[`agent/internal/api/handlers.go`](./agent/internal/api/handlers.go).

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

812 patterns across 22 categories (counted from `rules/dlp_patterns.json`):

| Category             | Patterns | Examples                                                                                                                                  |
|----------------------|---------:|-------------------------------------------------------------------------------------------------------------------------------------------|
| `cloud`              | 462      | AWS, GCP, Azure, IBM, Alibaba, Oracle, DigitalOcean / Linode / Vultr / Hetzner / OVH / Scaleway / regional clouds, monitoring & VPN PATs  |
| `code_secret`        | 60       | GitHub / GitLab / Bitbucket PATs, .pypirc tokens, Rails master.key, Laravel APP\_KEY, Terraform / Ansible / Chef / Puppet / Docker / K8s   |
| `credential`         | 37       | shell `export` literals, JDBC URLs, env-file passwords, Salt / Helm / sealed-secret literals                                              |
| `phi`                | 35       | FHIR / SMART-on-FHIR tokens, Epic / Cerner credentials, HL7 v2 PID/OBX/ORC, DICOM tags, NPI, DEA, MBI, MRN, ICD-10 / ICD-9 / CPT / HCPCS / LOINC / SNOMED / DSM-5, NDC, CLIA |
| `database_registry`  | 34       | Postgres / MongoDB URIs, Docker / npm tokens, registry credentials                                                                        |
| `pii_eu`             | 30       | GDPR — IBAN, DE Personalausweis / Steueridentifikationsnummer, FR INSEE/NIR / SIREN / SIRET, IT Codice Fiscale, ES DNI/NIE, NL BSN, BE Rijksregister, PL PESEL, PT NIF, SE Personnummer, FI HETU, GR AFM, HU TAJ, EU VAT |
| `financial`          | 20       | Stripe (whsec\_, rk\_), Plaid, Dwolla, Adyen, Wise, GoCardless, PayPal, Square, Coinbase, Razorpay                                          |
| `pii_sea`            | 20       | Singapore NRIC/FIN, Malaysia MyKad, Thai NID, Philippines SSS/TIN/UMID, Indonesia NIK/NPWP, Vietnam CCCD/MST, Japan My Number / Passport, Korea RRN / Biz Reg, Taiwan NID, China Resident ID / Passport, India Aadhaar / PAN, Hong Kong HKID |
| `mobile_desktop`     | 17       | Apple App Store Connect, Google Play, code-signing, iOS Info.plist, Android local.properties                                              |
| `pii_gcc`            | 15       | UAE Emirates ID / TRN / IBAN, Saudi National ID (Iqama) / IBAN, Qatar QID, Bahrain CPR, Kuwait Civil ID, Oman Civil Number, GCC VAT IDs   |
| `ai_ml`              | 13       | OpenAI, Anthropic, Google AI, Replicate, HuggingFace                                                                                      |
| `package_manager`    | 12       | npm, PyPI, Maven, NuGet, RubyGems                                                                                                         |
| `ci_cd`              | 8        | CircleCI, TeamCity, Bitrise, Buildkite                                                                                                    |
| `messaging`          | 8        | Slack, Twilio, SendGrid, Discord, Mailgun, Zoom JWT, Microsoft Teams, Vonage, MessageBird                                                 |
| `auth`               | 8        | OIDC ID tokens, OAuth refresh tokens, JWT secrets, SAML assertions, Auth0, Okta, Stripe Connect, Twilio Authy                             |
| `infra_secret`       | 7        | Terraform, Vault, Pulumi                                                                                                                  |
| `pii_uk`             | 5        | UK NINO, NHS Number, UK Passport, UK Driver's Licence, UK UTR                                                                             |
| `pii_ccpa`           | 5        | California Driver's Licence / State ID / Medi-Cal Beneficiary ID / Vehicle Plate / CDTFA Sales Tax Permit                                 |
| `payments`           | 5        | Stripe, Square, PayPal, Braintree                                                                                                         |
| `pii`                | 4        | US SSN, credit cards, emails, phones                                                                                                      |
| `pii_switzerland`    | 4        | Swiss AHV / AVS, Swiss IBAN, Swiss UID (CHE-…), Swiss Passport                                                                            |
| `iac`                | 3        | Atlas, Spacelift, Env0                                                                                                                    |

See [SECURITY_RULES.md](./SECURITY_RULES.md) for the per-pattern table
(name, severity, prefix, hotword requirement).

## Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) — components, DB schema, API, integration points
- [SECURITY.md](./SECURITY.md) — vulnerability disclosure + release-artefact verification recipe
- [SECURITY_RULES.md](./SECURITY_RULES.md) — per-pattern reference table
- [CONTRIBUTING.md](./CONTRIBUTING.md) — development setup, PR process, coding standards
- [CHANGELOG.md](./CHANGELOG.md) — release-by-release summary
- [BENCHMARKS.md](./BENCHMARKS.md) — DLP, DNS, and stats benchmarks
- [docs/admin-guide.md](./docs/admin-guide.md) — installation, configuration, profiles, MDM
- [docs/user-guide.md](./docs/user-guide.md) — tray icon, false-positive reporting, privacy summary
- [docs/rule-contribution-guide.md](./docs/rule-contribution-guide.md) — how to add domains and categories
- [docs/dlp-pattern-authoring-guide.md](./docs/dlp-pattern-authoring-guide.md) — DLP schema, scoring, hotwords, entropy, exclusions

## License

MIT — see [LICENSE](./LICENSE).
