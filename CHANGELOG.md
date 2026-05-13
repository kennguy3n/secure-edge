# Changelog

All notable changes to Secure Edge are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches `1.0.0`. Until then the pre-release version (`0.x`)
may introduce breaking changes between feature releases.

## [Unreleased]

### Added — Phase 6: Hardening, Ecosystem Expansion & Community

- Expanded the DLP pattern library by ~30 patterns across Terraform,
  container registries, secret managers, OAuth2/OIDC, IaC vault
  strings, and package-manager ecosystems.
- Adaptive scanning for large payloads, pattern category grouping,
  short-lived LRU scan cache, and concurrent regex evaluation for
  payloads over 10 KiB.
- Browser extension: drag-and-drop interception, dynamic content
  script registration so Tier-2 host updates take effect without an
  extension reload, an options page, and opt-in clipboard scanning.
- Platform hardening: agent self-update via GitHub Releases
  (SHA-256 + Ed25519 verification), graceful shutdown that waits for
  in-flight scans, runtime metadata in `/api/status`, and a
  configurable token-bucket rate limiter on `/api/dlp/scan`.
- Electron tray UI: dark mode tuned for WCAG 2.1 AA contrast, a
  read-only Rules page, a first-run setup wizard, and an in-memory
  recent-blocks list.
- Testing & quality: end-to-end DNS test, Go native fuzzing for the
  DLP pipeline, a Playwright-based extension integration harness,
  and a CI coverage gate that fails when the DLP package drops
  below 80%.
- Community files: `CONTRIBUTING.md`, this changelog, `SECURITY.md`,
  GitHub issue/PR templates.

## [0.5.0] — 2026-05-13 — Phase 5

### Added

- Enterprise profile distribution with policy lockdown, signed
  profile manifests, and an /api/profile endpoint.
- Tamper detection comparing the running DNS / proxy configuration
  against the agent's expected state and surfacing a hash-mismatch
  signal.
- Optional aggregate heartbeat (`heartbeat_url`) that POSTs only
  agent version + OS metadata + anonymous counters. No content,
  domains, or IPs are ever included.
- Admin allow/block override store backed by SQLite with a CRUD API
  under `/api/rules/override`.
- Expanded DLP pattern library (~95 new patterns) across Java,
  Rust, frontend frameworks, desktop publishing, AI/ML APIs, iOS,
  and others. See `docs/accessibility.md` and `BENCHMARKS.md` for
  the audit trail.

### Changed

- DLP pattern severity scoring is now data-driven via the
  `score_weight` field, allowing low-confidence ecosystems to score
  lower without removing them.
- Status page surfaces tamper detection state and enterprise profile
  lockdown.

### Fixed

- Aho-Corasick automaton switched to `MatchThreadSafe()` so the
  worker-pool path no longer drops hits under concurrent access.
- Several accessibility regressions in the Electron tray: tablist
  arrow-key navigation, visible focus rings, and labelled form
  controls. See `docs/accessibility.md`.

## [0.4.0] — 2026-05-12 — Phase 4

### Added

- Local MITM proxy with on-demand CA generation, system-trust
  installer scripts for macOS, Linux, and Windows, and a pinning
  bypass list for apps that break under MITM.
- Per-host classification — Tier-1 hosts route DNS only, Tier-2
  hosts route through the proxy with DLP enabled.
- Electron Proxy page for enabling/disabling the proxy, installing
  the CA, and toggling system proxy configuration.
- Safari extension build (`manifest.safari.json`) and Firefox
  build (`manifest.firefox.json`) alongside the existing Chrome
  Manifest V3.

## [0.3.0] — 2026-05-12 — Phase 3

### Added

- Rule auto-updater that polls a manifest URL and atomically swaps
  bundled rule files when a newer version is available.
- Multi-platform installers: a Homebrew tap, a Debian `.deb`, a
  Windows MSI, and a portable archive.
- CI workflow (`.github/workflows/ci.yml`) that runs the Go test
  suite, Electron typecheck, and extension typecheck on every push.

## [0.2.0] — 2026-05-12 — Phase 2

### Added

- DLP pipeline: Aho-Corasick prefix scanner → regex validator →
  hotword proximity check → entropy gate → exclusion filter →
  threshold engine.
- Browser extension (Chrome Manifest V3) that intercepts paste and
  form-submit events on configured AI tool hosts and routes them
  through `/api/dlp/scan`.
- Bundled DLP rule files (`rules/dlp_patterns.json`,
  `rules/dlp_exclusions.json`) with ~70 starter patterns.
- Native messaging bridge between the extension and the local
  agent for hosts where the loopback HTTP API is unreachable.

## [0.1.0] — 2026-05-12 — Phase 1

### Added

- Initial public release.
- Go agent: DNS resolver with policy engine, bundled rules, SQLite
  store for stats and config, local HTTP API on
  `127.0.0.1:8080`.
- Electron tray app with Status and Settings pages.
- Bundled domain blocklists for malware, phishing, tracking, and
  ads.
- Platform integration scripts for setting system DNS to the
  agent.
