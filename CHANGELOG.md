# Secure Edge — Changelog

All notable changes to Secure Edge are recorded in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches `1.0.0`. Until then, the `0.x` series may introduce breaking
changes between feature releases — breaking entries are flagged explicitly.

## [Unreleased]

### Added

- **Optional ML-augmented DLP detection layer** (`agent/internal/dlp/ml/`):
  strictly-additive pre-filter and borderline-score disambiguator that
  never overrides high-confidence deterministic decisions. Ships behind
  the `onnx` build tag with pinned ONNX Runtime + multilingual MiniLM
  artefacts; the default CGO-free build is unchanged. See
  [INSTALL_ML.md](./INSTALL_ML.md).
- **DLP coverage expanded to 812 patterns across 22 categories** (W1: 376 → 718;
  W4: 718 → 812 with GDPR / Switzerland / UK / GCC / Southeast-East-Asia /
  HIPAA-adjacent PHI / CCPA detectors). See [SECURITY_RULES.md](./SECURITY_RULES.md).
- **DLP classifier-scoped patterns**: optional `content_types` field on
  patterns restricts which classifier verdicts (`code` / `structured` /
  `credentials` / `natural`) a pattern may fire on, so language-specific
  shapes cannot fire on prose. Documented in
  [docs/dlp-pattern-authoring-guide.md](./docs/dlp-pattern-authoring-guide.md).
- **Capability tokens and extension pinning**: per-install bearer token
  at `api_token_path` plus an `allowed_extension_ids` CORS allowlist.
- **HMAC-authenticated Native Messaging bridge** keyed by the per-install
  API token, with strict-monotonic request ids and `bridge_mac_required`
  to stage enforcement.
- **File-upload and clipboard-file DLP** across `<input type=file>`,
  drag-drop, paste, and patched `fetch` / XHR bodies, plus a configurable
  34-entry risky-extension blocklist that fires before any file read.
- **Signed enterprise profiles** (Ed25519 over `profile.CanonicalForSigning`),
  with a shared verifier across the disk / URL / inline-import paths and
  a CLI signer (`agent/cmd/sign-enterprise-profile`).
- **Release-artefact hardening**: `SHA256SUMS`, Sigstore keyless
  signatures, CycloneDX 1.6 SBOMs for the agent / tray / extension, and
  SLSA Build Level 3 provenance attestations. Verification recipe in
  [SECURITY.md](./SECURITY.md).
- **Reference configuration presets** (`config.personal.example.yaml`,
  `config.team.example.yaml`, `config.managed.example.yaml`) and a
  personal → team → managed graduation path in
  [docs/admin-guide.md](./docs/admin-guide.md).
- **MDM deployment guide** covering Chrome Enterprise managed policies
  and JAMF Pro, Microsoft Intune, and VMware Workspace ONE walkthroughs.
- **Hardening sweep**: versioned SQLite migrations, transactional
  profile apply, atomic counter flush, fail-closed managed-mode boot,
  the team/managed secure-defaults validator, store-level input
  validation, path-stripping `/api/status`, and DNS-pinned
  `http.Transport` for profile-URL fetches.

### Changed

- **Breaking (managed mode):** `enforcement_mode: managed` now requires
  `profile_path` or `profile_url` at boot; previously a managed install
  could start with only the store's seeded defaults.
- **Breaking (team & managed):** secure-defaults validator rejects
  configs missing `allowed_extension_ids`, `api_token_path`, or
  `api_token_required: true`; `managed` additionally requires
  `bridge_mac_required: true`, `profile_public_key`, and
  `rule_update_public_key`.
- **HTTP surface hardening**: full timeout tuple
  (`ReadHeaderTimeout` / `ReadTimeout` / `WriteTimeout` /
  `IdleTimeout` / `MaxHeaderBytes`) on the control API and proxy
  listeners; JSON control endpoints capped at 64 KiB via
  `http.MaxBytesReader`; `/api/dlp/scan` (4 MiB) and
  `/api/profile/import` (1 MiB) keep higher caps.
- **CA private-key permission check on every load**: the proxy refuses
  to read a key whose POSIX mode bits include group / world access
  (no-op on Windows where ACLs apply).
- **Browser extension fails closed in managed mode** on Native
  Messaging MAC mismatch, oversize body, or scan-null; `personal` and
  `team` preserve the legacy warn-and-resolve posture.
- **Content scripts inject into every frame** across the Chrome,
  Firefox, and Safari manifests so DLP coverage extends to same-origin
  iframes.
- **Packaged `config.yaml` self-identifies as the personal preset** and
  points operators at the team / managed example configs.
- **README gained a `Security posture` cross-reference**; the canonical
  enforcement matrix, extension-vs-proxy boundary analysis, DLP
  accuracy methodology, and HTTP hardening tuple now live in
  [ARCHITECTURE.md](./ARCHITECTURE.md#security-posture).

### Fixed

- Custom rule categories from `cfg.rule_paths` are accepted again after
  the hardening sweep's closed-set allowlist; `Store.RegisterCategories`
  picks them up at boot.
- `ErrInvalidCategory` and `ErrInvalidDLPConfig` now surface as HTTP 400
  instead of 500.
- Cross-compilation cleans up for darwin and windows via build-tagged
  `proxy_{darwin,windows,other}.go` files.
- Electron-builder Linux `.deb` packaging and Windows MSI build (WiX
  v4+, pinned to dotnet tool `v5.0.2`).
- Release `SHA256SUMS` pipeline now handles artefact names containing
  spaces via NUL-separated piping.
- Long-IO control handlers (`POST /api/rules/update`,
  `POST /api/agent/update`, `POST /api/profile/import`) drop the
  control-API `WriteTimeout` per request so signed-manifest, binary,
  and profile fetches do not race the global 10 s cap.
- No-body control endpoints cap their post-response keep-alive body
  drain at 64 KiB so a hostile peer cannot ship megabytes at endpoints
  that take no body.

## [0.5.0] — 2026-05-13

### Added

- Enterprise profile distribution with policy lockdown, signed profile
  manifests, and a `/api/profile` endpoint.
- Tamper detection comparing the running DNS / proxy configuration
  against the agent's expected state and surfacing a hash-mismatch
  signal.
- Optional aggregate heartbeat (`heartbeat_url`) that POSTs only
  `{agent_version, os_type, os_arch, aggregate_counters}`. No content,
  domains, or IPs are ever included.
- Admin allow/block override store backed by SQLite with a CRUD API
  under `/api/rules/override`.
- ~95 additional DLP patterns across Java, Rust, frontend frameworks,
  desktop publishing, AI/ML APIs, and iOS ecosystems.

### Changed

- DLP severity scoring is now data-driven via per-pattern
  `score_weight`, so low-confidence ecosystems can score lower without
  being removed.
- The Status page surfaces tamper-detection state and enterprise-profile
  lockdown.

### Fixed

- Aho-Corasick automaton switched to `MatchThreadSafe()`, so the
  worker-pool path no longer drops hits under concurrent access.

## [0.4.0] — 2026-05-12

### Added

- Local MITM proxy with on-demand CA generation, system-trust installer
  scripts for macOS, Linux, and Windows, and a pinning bypass list for
  apps that break under MITM.
- Per-host classification — Tier-1 hosts route DNS only, Tier-2 hosts
  route through the proxy with DLP enabled.
- Electron Proxy page for enabling / disabling the proxy, installing
  the CA, and toggling system proxy configuration.
- Safari build (`manifest.safari.json`) and Firefox build
  (`manifest.firefox.json`) alongside the existing Chrome Manifest V3.

## [0.3.0] — 2026-05-12

### Added

- Rule auto-updater that polls a manifest URL and atomically swaps
  bundled rule files when a newer version is available.
- Multi-platform installers: a Homebrew tap, a Debian `.deb`, a Windows
  MSI, and a portable archive.
- CI workflow that runs the Go test suite plus Electron and extension
  typechecks on every push.

## [0.2.0] — 2026-05-12

### Added

- DLP pipeline: classifier → Aho-Corasick → regex → hotword proximity
  → entropy gate → exclusion filter → threshold engine.
- Browser extension (Chrome Manifest V3) that intercepts paste and
  form-submit events on configured AI hosts and routes them through
  `/api/dlp/scan`.
- Bundled DLP rule files (`rules/dlp_patterns.json`,
  `rules/dlp_exclusions.json`) with ~70 starter patterns.
- Native Messaging bridge between the extension and the local agent
  for hosts where the loopback HTTP API is unreachable.

## [0.1.0] — 2026-05-12

### Added

- Initial public release.
- Go agent: DNS resolver with policy engine, bundled rules, SQLite
  store for stats and config, local HTTP API on `127.0.0.1:8080`.
- Electron tray app with Status and Settings pages.
- Bundled domain blocklists.
- Platform integration scripts for setting system DNS to the agent.
