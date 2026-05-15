# Changelog

All notable changes to ShieldNet Secure Edge are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches `1.0.0`. Until then the pre-release version (`0.x`)
may introduce breaking changes between feature releases.

## [Unreleased]

### Added — Phase 7: Security Posture

- **A1**: Pin browser-extension IDs accepted by the API control
  plane. New `allowed_extension_ids` config key restricts which
  `chrome-extension://` / `moz-extension://` /
  `safari-web-extension://` origins may drive state-changing
  endpoints. Empty list keeps the legacy "any non-empty ID"
  behaviour and logs a startup warning.
- **A2**: Per-install API capability token. The agent generates a
  32-byte hex token at `api_token_path` (mode 0600) on first
  start, hands it to the browser extension over a new Native
  Messaging `hello` handshake, and the Electron tray reads it
  from the same file. `api_token_required` toggles enforcement
  between staged (wrong tokens 401, missing header falls through)
  and full (missing header also 401).
- **A2 follow-up**: Added `api.DefaultAPITokenPath()` in the Go
  agent so the per-OS default matches the Electron tray's
  `DEFAULT_API_TOKEN_PATH` byte-for-byte (XDG / Application
  Support / APPDATA). The agent prints the resolved value as a
  startup hint when `api_token_path` is empty so operators see
  exactly what to drop into `config.yaml` to enable bearer-token
  auth without any further tray configuration. Clarified the
  `NativeMessagingOptions.APIToken` doc comment to match the
  actual hello-without-token behaviour (successful reply with the
  `api_token` field stripped, no protocol-level error).
- **C2 follow-up**: `paste-interceptor.ts` now reuses the shared
  `MAX_SCAN_BYTES` constant instead of its own local
  `MAX_PASTE_BYTES`. The two were already 1 MiB so this is not a
  behavioural change, but it removes the only remaining interceptor
  that could drift from the shared threshold a future PR might
  retune. Pinned `/api/config/enforcement-mode` in
  `TestCORS_AIPageOriginsAllowedOnReadEndpoints` so a future
  attempt to add the endpoint to `isControlPath` fails at CI
  rather than silently breaking the extension service-worker's
  auth-free poll.
- **B1**: File upload DLP scanning. The MAIN-world fetch / XHR
  hook now reads Blob, File, ArrayBuffer, and ArrayBufferView
  bodies asynchronously (up to `MAX_SCAN_BYTES`), and walks
  FormData File entries so file uploads are scanned alongside
  text fields. A new `file-upload-interceptor.ts` content script
  closes the remaining gap by snooping `<input type="file">`
  change events and file-drop events at capture phase. The
  interceptor suppresses the gesture SYNCHRONOUSLY before any
  await (`preventDefault` / `stopPropagation` /
  `stopImmediatePropagation` / clearing `input.value`) so the
  page's own handlers never see the file; the scan runs after to
  drive the toast UX. Clean scans do not resume the gesture
  (re-injecting a `File` into `input.files` / a drop target is
  not portable across browsers). ReadableStream bodies still
  fall open (no safe tee without rewriting `init.body`); the
  agent-unavailable + oversize policy hooks from C2 cover the
  fall-open path in managed mode.
- **B1 follow-up**: Review-pass tightening on the file-upload
  path. `drag-interceptor.ts` now short-circuits on
  `dataTransfer.files.length > 0` so it cedes file drops to
  `file-upload-interceptor.ts` cleanly — previously, OS file
  managers that attach a `text/plain` path string alongside the
  File could trick drag-interceptor into `resumeDrop`-ing a stale
  path string into the focused textarea while file-upload-interceptor
  was simultaneously blocking the file. `file-upload-interceptor`'s
  `onDrop` now also calls `stopImmediatePropagation` synchronously
  for parity with `onChange`'s same-phase suppression. Added a
  `MAX_SCAN_BYTES` parity test that fails CI if the constant ever
  drifts between `scan-client.ts` (isolated world) and
  `main-world-network.ts` (MAIN world). Tightened the JSDoc on
  `readFormDataText` to document `encodeURIComponent` inflation (up
  to 3× on special characters) — the raw read budget holds, the
  encoded output is caught downstream by the oversize policy hook.
  Clarified the `onChange` header comment to accurately describe
  what capture-phase `stopPropagation` / `stopImmediatePropagation`
  do and do not prevent (the only remaining race is a page's own
  document-level capture listener registered before our
  `document_start` injection; the network interceptor closes the
  exfil path in that case). Re-framed the `manifestBody` doc
  comment to make clear that drift between `Manifest` and
  `manifestBody` is enforced by the run-time
  `TestManifestBody_MirrorsManifestMinusSignature` reflection test,
  not by the compiler (the two structs are independent types).
- **D1a**: Release-artefact hardening (signing + supply-chain
  transparency). The `release.yml` workflow now publishes, alongside
  every release: a `SHA256SUMS` manifest of every artefact; per-
  artefact and SHA256SUMS-level Sigstore keyless signatures
  (`.sig` + `.pem`) issued under the workflow's GitHub OIDC
  identity (no maintainer-held private keys); CycloneDX 1.6 SBOMs
  for the Go agent, Electron tray, and browser extension; and a
  SLSA Build Level 3 provenance attestation via
  `actions/attest-build-provenance@v2`. `SECURITY.md` gains a new
  "Verifying a release" section with a copy-paste recipe covering
  `sha256sum -c`, `cosign verify-blob` (with `--certificate-
  identity-regexp` pinned to this repo's workflow on a `v*` tag),
  and `gh attestation verify`. Platform-native code signing
  (Apple Developer ID, Windows Authenticode, Linux GPG) remains
  deferred to D1b until the respective certificates are provisioned
  (`PHASES.md:156`).

  Adjacent release-pipeline fixes uncovered while validating the
  D1a signing workflow end-to-end (the first time `release.yml`
  ran on a tag push to completion): refactored
  `agent/internal/tamper/proxy_check.go` from a `switch
  runtime.GOOS` against per-platform stubs into a per-platform
  dispatch (`proxyCheckImpl` in each `proxy_{darwin,windows,other}.go`
  under its own build tag) so the agent cross-compiles cleanly for
  darwin and windows targets; added `homepage` + `author{name,email}`
  to `electron/package.json` for electron-builder Linux `.deb`
  packaging; set `directories.output: dist-electron` and a dotless
  `artifactName` in `electron/electron-builder.yml` so installer
  filenames survive GitHub's release-upload "spaces→dots"
  normalisation; replaced WiX v3 `heat dir` with the native v4+
  `<Files Include="…">` element in `scripts/windows/secure-edge.wxs`
  and pinned the WiX dotnet tool to v5.0.2 (the last release before
  v6's Open Source Maintenance Fee EULA gate); and switched the
  `SHA256SUMS` pipeline to NUL-separated piping so artefacts whose
  names contain spaces hash correctly.
- **C1**: HMAC-authenticated Native Messaging bridge. Every non-
  `hello` frame on the extension ↔ agent Native Messaging
  connection now carries an HMAC-SHA256 MAC over `nonce ||
  direction_byte || id || kind || (content | blocked + token +
  error)`, keyed by the per-install API token issued in A2. The
  `hello` reply additionally surfaces a 16-byte `bridge_nonce`
  (TOFU bootstrap; the very reply that hands out the secret +
  nonce is intentionally unsigned). A new `bridge_mac_required`
  config knob mirrors `api_token_required`: false (default)
  emits a one-time stderr warning per connection and keeps
  serving scans for staged rollout, true rejects any
  mismatched / missing MAC with a `bridge MAC required` /
  `bridge MAC mismatch` error reply. The agent also enforces a
  strict-monotonic request id (`bridge id rollback` reply) and
  rejects a second `hello` on the same connection (`hello
  already issued`). A cross-language reference vector is pinned
  byte-for-byte in both `agent/internal/api/bridge_mac_test.go`
  and `extension/src/background/__tests__/bridge-mac.test.ts`
  so any drift in the HMAC input layout is caught on both sides.
- **D2**: Sign enterprise profiles with Ed25519. The
  `agent/internal/profile` package now carries a `Signature` field
  alongside a dedicated `profileBody` canonical-form struct (the
  same belt-and-suspenders pattern shipped for the A3 rule
  manifest in PR #20). `CanonicalForSigning` marshals through
  `profileBody`, which physically lacks a Signature field, so a
  future addition to `Profile` that forgets `omitempty` cannot
  silently change the bytes a previously-valid signature was
  computed over; a reflection test
  (`TestProfileBody_MirrorsProfileMinusSignature`) catches drift
  at every CI run. A new `profile.Verifier` enforces the
  operator's trust posture on every load: the disk-load
  (`LoadFromFile`), URL-fetch (`LoadFromURL`), and inline-import
  paths (`POST /api/profile/import` for both `{"url": …}` and
  `{"profile": {…}}` payloads) all route through the same
  verifier, so the three import surfaces share one posture. The
  staged rollout mirrors the rule-manifest verifier: when the new
  `profile_public_key` config key is absent the agent runs in
  warn-once mode (accepts unsigned profiles, logs a single line
  per process); when configured, the agent rejects unsigned /
  malformed / tampered / wrong-key-signed profiles before any
  policy is applied. A companion CLI
  (`agent/cmd/sign-enterprise-profile`) mirrors
  `sign-rule-manifest` so operators sign profile JSON with one
  command before distribution. An orphaned-key startup warning
  fires when `profile_public_key` is set but both `profile_path`
  and `profile_url` are empty (the key still applies to runtime
  `POST /api/profile/import`, but the warning surfaces the
  partial-rollout footgun the same way the rule-manifest variant
  did).
- **B2**: Block risky file extensions at the upload gesture. The
  `file-upload-interceptor` content script now matches every
  selected / dropped file's extension against a baked-in 34-entry
  blocklist (Windows / macOS / Linux executables, installers,
  scripts, disk images, Java archives; `.js` intentionally
  excluded) BEFORE any content is read or sent to the agent. The
  check runs in the same synchronous prelude as the existing
  suppression (`preventDefault` / `stopImmediatePropagation` /
  clearing `input.value`), so a blocked upload short-circuits the
  async content scan entirely — the filename and contents never
  leave the page for the B2 verdict. A risky-extension match
  always blocks, regardless of enforcement mode (`personal` /
  `team` / `managed` all see the same outcome); B2 is a policy
  lever to remove a class of file from the upload surface, not a
  fall-open ladder. Operators may override the baked-in list via
  a new `risky_file_extensions` config key on the agent, surfaced
  to the extension over a new `GET /api/config/risky-extensions`
  endpoint. The wire shape distinguishes three states: field
  absent (`{}`) means the extension uses its baked-in default;
  explicit empty array (`{"extensions": []}`) opts out of risky-
  extension blocking entirely; explicit list
  (`{"extensions": ["exe",...]}`) replaces the baked-in default
  verbatim. Entries are normalised on the agent side (trim,
  strip leading dot, lowercase, drop blanks). The extension
  service worker caches the override on cold start with a 5-min
  TTL and mirrors it into `chrome.storage.session` so a content
  script can fall back after a worker eviction. Toast: a new
  `risky-extension` `PolicyReason` variant surfaces `Secure Edge
  blocked this upload — .exe files are blocked by policy.`
- **C3**: Adversarial test table for the MAIN ↔ ISO postMessage
  bridge. New
  `extension/src/content/__tests__/network-interceptor.adversarial.test.ts`
  pins the bridge's threat-model boundary in 10 named rows:
  the `isScanRequest` type guard rejects mistyped / missing
  fields and accepts forward-compatible extra fields;
  `handleBridgeMessage` no-ops on guard-rejected shapes;
  `requestScan` ignores `scan-resp` messages with an unknown id;
  the relay does not respond to its own `scan-resp` echoed back
  as a `scan-req`; concurrent `handleBridgeMessage` calls keep
  their replies separate; a throwing scan collapses to a `null`
  verdict (no unhandled rejection); the relay forwards the
  content field byte-for-byte (no in-bridge sanitisation). Two
  rows pin the documented "cannot defend at the content-script
  layer" failure modes (well-formed page-forged `scan-req` runs
  the scan; matching-id forgery on `scan-resp` wins the race)
  with cross-references to the C1 HMAC bridge (extension ↔
  agent native messaging) and A2 bearer token (agent HTTP
  loopback) — the actual defences for those cells live on the
  next hop, not in the postMessage relay.
- **B3**: Clipboard-paste file scanning. The `paste-interceptor`
  content script now reads `clipboardData.files` AND
  `clipboardData.items[i].getAsFile()` for every paste gesture
  on a Tier-2 AI tool surface. The file path runs through the
  same risky-extension guard (B2 / PR #27) and DLP scan
  pipeline (B1 / PR #22) as `<input type=file>` uploads, with
  the same synchronous-first contract: `preventDefault()` and
  `stopPropagation()` fire BEFORE any `await`. The pre-B3
  text-paste behaviour is unchanged; the FILE path is a
  separate branch in `onPaste`. On a mixed text+file paste the
  FILE path wins (more-conservative rule); the text fragment is
  never forwarded to the agent. On a clean file verdict the
  gesture stays suppressed (no portable way to programmatically
  re-construct `DataTransfer.files` on the page side, matching
  the no-resume contract in `file-upload-interceptor`). Tests:
  new `paste-interceptor.test.ts` with 22 cases covering the
  helper exports plus 13 numbered rows for text-only / file-only
  / mixed / risky / oversize / agent-unavailable / null-data
  scenarios.
- **D4**: Managed-deployment (MDM) admin guide. New §10 in
  `docs/admin-guide.md` covers per-organisation bundle
  generation (signed `profile.json`, signed `manifest.json`,
  bearer token, agent binary, browser extension); Chrome
  Enterprise managed policies (`ExtensionInstallForcelist`,
  `ExtensionSettings`, `ManagedConfigurationPerOrigin`); and
  per-platform walkthroughs for JAMF Pro (macOS, Configuration
  Profile + Files & Processes + Restricted Software), Microsoft
  Intune (Windows, Win32 app + ADMX device-configuration
  policy), and VMware Workspace ONE (cross-platform, Files /
  Actions + Custom Settings). A "see also" line points to the
  Apple device-management docs for Kandji, Mosyle, and
  SimpleMDM (same payload shape, different upload mechanism).
  Closes with a six-row defence-in-depth checklist mapping
  every Phase 7 control (A2 bearer, C1 HMAC, A3 signed
  manifest, D2 signed profile, B2 risky-extension blocklist,
  browser policy) to where it lives in the bundle and how to
  verify it from the agent log or a single API probe.

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
