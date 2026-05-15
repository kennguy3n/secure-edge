# Changelog

All notable changes to ShieldNet Secure Edge are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches `1.0.0`. Until then the pre-release version (`0.x`)
may introduce breaking changes between feature releases.

## [Unreleased]

### Added

- Browser-extension ID pinning for the agent's control-plane
  endpoints via the new `allowed_extension_ids` config key.
- Per-install API capability token. The agent issues a
  32-byte hex token at `api_token_path` and hands it to the
  browser extension over Native Messaging; the Electron tray
  reads it from the same path. Enforcement is staged
  (`api_token_required` toggles between warn-only and reject).
- HMAC-authenticated Native Messaging bridge keyed by the
  per-install API token. The `bridge_mac_required` knob
  mirrors `api_token_required` for staged rollout, and the
  agent rejects rolled-back request ids or duplicate `hello`
  frames on the same connection.
- File-upload DLP scanning. The MAIN-world fetch / XHR hook
  reads Blob, File, ArrayBuffer, and ArrayBufferView bodies
  and walks FormData entries, and a new
  `file-upload-interceptor` content script blocks risky
  uploads from `<input type="file">` and file drops before
  any content leaves the page.
- Risky-file-extension blocklist. The upload interceptor
  blocks a baked-in 34-entry executable / installer /
  script / disk-image / Java-archive set before any read,
  with a new `risky_file_extensions` config key and
  `GET /api/config/risky-extensions` endpoint so operators
  can override the default.
- Clipboard-paste file scanning. The `paste-interceptor`
  reads `clipboardData.files` and `items[].getAsFile()`,
  applies the same risky-extension guard and DLP scan as
  uploads, and suppresses the gesture synchronously on a
  blocking verdict.
- Signed enterprise configuration profiles. Profiles carry an
  Ed25519 `signature` field, the disk / URL / inline-import
  paths share one `profile.Verifier`, and a companion
  `agent/cmd/sign-enterprise-profile` CLI mirrors the rule-
  manifest signer.
- Release-artefact hardening: every release publishes a
  `SHA256SUMS` manifest, Sigstore keyless signatures
  (`.sig` + `.pem`) under the workflow's GitHub OIDC identity,
  CycloneDX 1.6 SBOMs for the Go agent / Electron tray /
  browser extension, and a SLSA Build Level 3 provenance
  attestation. `SECURITY.md` carries the verification recipe.
- Three reference config presets at the repo root:
  `config.personal.example.yaml`,
  `config.team.example.yaml`, and
  `config.managed.example.yaml`, plus an admin-guide section
  recommending a personal → team → managed graduation path.
- Managed-deployment (MDM) admin guide. New section in
  `docs/admin-guide.md` covers per-organisation bundle
  generation, Chrome Enterprise managed policies, and
  per-platform walkthroughs for JAMF Pro, Microsoft Intune,
  and VMware Workspace ONE.
- Explicit screenshot / image DLP limitation called out in
  `docs/admin-guide.md` and the `paste-interceptor` header.
  The DLP scanner is text-only; binary payloads are decoded
  as best-effort UTF-8 and OCR / image classification are
  out of scope.
- Adversarial test coverage for the MAIN ↔ ISO postMessage
  relay and additional paste-interceptor posture rows
  (oversize in team mode, agent-unavailable across
  personal / team / managed, `items[]`-only screenshot paste).
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

### Changed

- `paste-interceptor.ts` now shares the `MAX_SCAN_BYTES`
  constant with the other interceptors, and the constant is
  pinned across the isolated and MAIN worlds by a parity
  test.
- `drag-interceptor.ts` cedes file drops to
  `file-upload-interceptor.ts` so OS file managers that
  attach a `text/plain` path alongside the `File` cannot
  trick `drag-interceptor` into resuming a stale path string
  while the file is being blocked.

### Fixed

- Cross-compilation: `agent/internal/tamper/proxy_check.go`
  now dispatches per platform via build-tagged
  `proxy_{darwin,windows,other}.go` files instead of a
  `switch runtime.GOOS` against per-platform stubs, so the
  agent cross-builds cleanly for darwin and windows targets.
- Electron-builder Linux `.deb` packaging now picks up
  `homepage` + `author{name,email}` from `package.json`,
  and the dotless `artifactName` in `electron-builder.yml`
  survives GitHub's release-upload filename normalisation.
- Windows MSI build now uses native WiX v4+
  `<Files Include="…">` and is pinned to the WiX dotnet
  tool v5.0.2.
- The release `SHA256SUMS` pipeline uses NUL-separated piping
  so artefacts whose names contain spaces hash correctly.

## [0.5.0] — 2026-05-13

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

## [0.4.0] — 2026-05-12

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

## [0.3.0] — 2026-05-12

### Added

- Rule auto-updater that polls a manifest URL and atomically swaps
  bundled rule files when a newer version is available.
- Multi-platform installers: a Homebrew tap, a Debian `.deb`, a
  Windows MSI, and a portable archive.
- CI workflow (`.github/workflows/ci.yml`) that runs the Go test
  suite, Electron typecheck, and extension typecheck on every push.

## [0.2.0] — 2026-05-12

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

## [0.1.0] — 2026-05-12

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
