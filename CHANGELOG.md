# Changelog

All notable changes to ShieldNet Secure Edge are recorded in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches `1.0.0`. Until then, the `0.x` series may introduce breaking
changes between feature releases — breaking entries are flagged explicitly.

## [Unreleased]

### Added

- **DLP optional ML-augmented detection layer (Workstream 3).**
  Adds `agent/internal/dlp/ml/` — a strictly-additive ML layer that
  bolts onto the deterministic DLP pipeline. Two integration points:
  (1) a *pre-filter* that may skip regex validation when the embedder
  thinks content is benign **and** no Critical / High AC candidate is
  in flight, and (2) a *disambiguator* that nudges borderline scores
  (within `mlBorderlineWidth == 1` of the per-severity block
  threshold) by `±MLBoost`. High-confidence deterministic decisions
  are immune to the ML signal in both directions, so the
  deterministic pipeline retains veto power.

  Implementation:

  - Real `ONNXEmbedder` backed by `github.com/yalue/onnxruntime_go`
    + `github.com/sugarme/tokenizer` (SentencePiece + HuggingFace
    fast tokenizer JSON) lives behind the `onnx` build tag. The
    default build and CI use the in-tree `NullEmbedder` and remain
    CGO-free; `purego`/`dlopen` removes the CGO requirement even on
    the onnx-tagged build.
  - Default model is `paraphrase-multilingual-MiniLM-L12-v2`
    (multilingual, 50+ languages, 384-dim sentence embeddings,
    ~5–8 ms inference on commodity CPU). Artefacts load from
    `~/.shieldnet/models/model/` and are absent by default — the
    pipeline silently falls back to the fully-deterministic path
    when any artefact is missing.
  - `agent/internal/dlp/cmd/build_ml_artefacts` is an offline
    corpus tool that reads the existing TP / TN JSONL corpus,
    computes per-class L2-normalised centroids, fits a frozen
    Fisher / LDA-1d linear head from those centroids
    (`w = L2-normalise(TP - TN)`, `bias` centred at the midpoint
    of the per-class mean projections), and writes the
    `centroids.json` / `disambiguator.json` artefacts the layer
    consumes at runtime. The committed artefacts were produced
    from 500 TP / 500 TN samples; the cosine gap between the
    two class centroids is ≈0.50 (meaningful pre-filter signal),
    and the linear head separates the training corpus with 100%
    sign-accuracy on both classes (TP mean projection ≈ +0.47,
    TN mean projection ≈ -0.35, bias ≈ -0.058).
  - `scripts/fetch-ml-model.sh` + `scripts/fetch-onnxruntime.sh`
    drive a pinned, reproducible install. The model script defaults
    to the int8-quantised checkpoint (`onnx/model_qint8_avx512.onnx`,
    118 MB) and enforces the SHA-256 pins committed to
    `scripts/ml-model-manifest.txt`; the onnxruntime script pulls
    the official Microsoft CPU release tarball for the current
    OS/arch and enforces the pins committed to
    `scripts/onnxruntime-manifest.txt`. Both are reproducible from
    a clean clone — a tampered upstream artefact triggers a hard
    failure on download.
  - New top-level `INSTALL_ML.md` documents the end-to-end install
    on Linux, macOS, and Windows, including the privacy invariants,
    disk / memory footprint, and rollback procedure.
  - New `agent/Makefile` targets: `install-onnx-runtime`, `install-ml`,
    `build-onnx`, and a combined `install` that downloads both
    artefacts and builds the onnx-tagged binary in one step.
  - The model itself is intentionally NOT bundled in agent release
    artefacts to keep the binary small and the optional ML
    dependency clearly separable.
  - `config.Config` gains three opt-in fields: `dlp_ml_model_dir`,
    `dlp_ml_boost`, `dlp_ml_prefilter_threshold`. The agent's
    startup path constructs the Layer when `dlp_ml_boost > 0` and
    logs a single summary line describing whether the layer ended
    up ready.
  - `GET /api/dlp/config` now embeds an `ml` sub-object with
    `{boost, ready, build_tag_onnx}` so the Electron tray and the
    browser extension can observe whether the ML layer is live.
    `PUT /api/dlp/config` preserves `MLBoost` across writes so a
    tray slider change does NOT silently disable the ML
    augmentation until the next process restart.
  - Per-OS ONNX C++ shared-library bundling in `release.yml` and
    binary release-asset distribution of the model itself remain
    explicitly deferred to follow-up commits. The trained linear-
    head deferral is **closed**: the committed `disambiguator.json`
    is now a real LDA-1d head produced by `build_ml_artefacts`.

  Verification:

  - `make test`, `go vet`, and `go test -race -count=1 ./...` are
    green with and without `-tags=onnx`.
  - `TestDLPAccuracyLarge` / `TestDLPAccuracyRegression` are green
    with the layer absent — the W4 baseline is fully preserved
    bit-for-bit.
  - `go test -tags=onnx ./internal/dlp/ml/...` is green; with
    `SHIELDNET_ONNXRUNTIME_LIB` and `SHIELDNET_TEST_ONNX_MODEL_DIR`
    pointed at a real install, four integration tests prove the
    embedder produces L2-normalised 384-dim vectors, stable
    embeddings across repeated calls, discriminative cosine
    distances on semantically related vs. unrelated inputs, and
    graceful fallback when only one of the two artefacts is on
    disk.

- **DLP global-PII coverage expanded from 718 to 812 rules (Workstream 4).**
  Adds 94 jurisdiction-specific personal-data detectors across 7 themed
  batches covering GDPR (EU), Switzerland, the UK, the GCC / Middle
  East, Southeast / East Asia, HIPAA-adjacent PHI identifiers, and
  CCPA / California consumer identifiers:
  - **GDPR / EU (`pii_eu`, 30):** IBAN, EU VAT, DE Personalausweis /
    Steueridentifikationsnummer / Sozialversicherungsnummer, FR
    INSEE/NIR / SIREN / SIRET / CNI, IT Codice Fiscale / Partita IVA,
    ES DNI / NIE / CIF, NL BSN, BE Rijksregister, PL PESEL / NIP, PT
    NIF, SE Personnummer / Organisationsnummer, FI HETU, GR AFM, HU
    TAJ.
  - **Switzerland (`pii_switzerland`, 4):** AHV/AVS (756.xxxx.xxxx.xx),
    Swiss UID (CHE-xxx.xxx.xxx), Swiss Passport, Swiss New Old-Age
    Insurance Number (ZAS). Swiss IBANs (`CH..`) are covered by the
    `EU IBAN (SEPA)` pattern in `pii_eu`, which includes `CH` in its
    country-code alternation.
  - **United Kingdom (`pii_uk`, 5):** NINO, NHS Number, UK Passport,
    UK Driver's Licence, UK UTR.
  - **GCC / Middle East (`pii_gcc`, 15):** UAE Emirates ID (784-...),
    UAE TRN / IBAN, Saudi National ID (Iqama) / IBAN / VAT, Qatar
    QID, Bahrain CPR, Kuwait Civil ID, Oman Civil Number.
  - **Southeast / East Asia (`pii_sea`, 20):** Singapore NRIC/FIN,
    Malaysia MyKad, Thai National ID, Philippines SSS / TIN / UMID,
    Indonesia NIK / NPWP, Vietnam CCCD / MST, Japan My Number /
    Passport, South Korea RRN / Business Registration, Taiwan
    National ID, China Resident ID / Passport, India Aadhaar / PAN,
    Hong Kong HKID.
  - **HIPAA-adjacent PHI (`phi`, +15):** US CLIA Number; CPT, HCPCS
    Level II, LOINC, ICD-9-CM, and SNOMED CT bulk code lists; NDC
    11-digit drug code; DSM-5 diagnosis code; Medicare HICN (legacy);
    CMS Certification Number; Insurance Subscriber/Member ID;
    Patient DOB in clinical context; HL7 v2 OBX and ORC segments;
    DICOM (0010,0010) Patient Name Tag.
  - **CCPA / California (`pii_ccpa`, 5):** California Driver's
    Licence, California State ID, California Medi-Cal Beneficiary
    ID, California Vehicle License Plate, CDTFA Sales Tax Permit.
  Patterns whose ambient shape (9–13 digits with separators) collides
  with too many innocent strings are gated by `require_hotword: true`
  with multi-syllabic, locale-specific hotword phrases so the
  hotword AC scan stays selective. Bulk-detection medical-coding
  patterns use the `(?:CODE\b[\s,;|]+){N}CODE\b` form so a single
  5-digit number in isolation cannot fire. Three regex / generator
  defects discovered while wiring this in were fixed in the same
  branch: the Hong Kong HKID regex had a trailing `\b` that could
  never match after `)`; the EU VAT regex used `(?i)` and matched
  `deployment`; and the China Passport synthetic corpus phrase
  contained the substring `admin` which trips a generic dictionary
  exclusion. Final accuracy on the synthetic corpus
  (15 492 samples, 43 corpus categories): all category FN budgets
  green; full `go test -tags=large -count=1 -run 'TestDLPAccuracy(Large|Regression)' ./internal/dlp/` passes.
- **DLP pattern coverage expanded from 376 to 718 rules (Workstream 1).**
  Adds 342 new detectors across 17 themed batches: additional cloud
  providers (DigitalOcean / Linode / Vultr / Cloudflare / Hetzner /
  OVH / Scaleway / Backblaze / Wasabi), SaaS platform tokens
  (Salesforce / HubSpot / Zendesk / Intercom / Segment / Amplitude /
  Mixpanel / LaunchDarkly / Sentry / Datadog / New Relic / PagerDuty /
  ServiceNow / Jira / Confluence), crypto and blockchain
  (Infura / Alchemy / Moralis / ETH+SOL+BTC private keys), DNS/CDN
  signing keys, email/marketing platforms, social/media APIs,
  container/orchestration (Kubernetes / Helm / Docker Hub / Harbor /
  Rancher / ArgoCD), monitoring/logging (Grafana / Splunk HEC /
  Sumologic / Loki), networking/VPN (WireGuard / OpenVPN / Tailscale /
  Cloudflare Tunnel), IoT/edge, additional secret formats (TOTP/HOTP
  URIs, SAML, OAuth refresh tokens, X.509, SSH known\_hosts, GPG
  private keys), regional clouds (Yandex / Tencent / Baidu / Naver),
  developer tools (Vercel / Netlify / Heroku / Railway / Render /
  Supabase / Firebase / Planetscale / Neon / Turso / Clerk /
  Supertokens), communication platforms (Zoom JWT / Teams webhook /
  Webex / Vonage / MessageBird / Plivo / Bandwidth), language- and
  framework-specific code secrets (Python / Ruby / PHP / .NET /
  Java/Gradle/Maven / Go / Node / Terraform / Ansible / Chef / Puppet /
  Docker / Kubernetes / iOS / Android / shell), healthcare/HIPAA
  identifiers (FHIR / SMART-on-FHIR / Epic / Cerner / HL7 v2 / DICOM /
  NPI / DEA / MBI / NDC / MRN / ICD-10), and financial-services tokens
  (Plaid / Dwolla / Wise / Adyen / Mollie / GoCardless / additional
  Stripe / Square / PayPal / Coinbase / Razorpay / ACH literals).
  Final accuracy on the synthetic corpus (14 020 samples, 36
  corpus categories): precision 1.0000, recall 0.9993, F1 0.9996,
  fp\_rate 0.0000 (budget 0.05), fn\_rate 0.0007 (budget 0.03), all
  per-category FN budgets green. The committed regression baseline
  has been re-seeded so future PRs are gated against the post-W1
  accuracy state. Patterns whose ambient shape overlaps with benign
  text were tagged `require_hotword: true` to keep FP at zero.
- **DLP classifier-scoped patterns.** `Pattern` now accepts an optional
  `content_types` field (any subset of `code`, `structured`, `credentials`,
  `natural`) that restricts which `ClassifyContent` verdicts a pattern is
  allowed to fire on. The pipeline captures the classifier verdict and the
  AC filter step drops candidates whose pattern is scoped to a verdict the
  current content does not match — so language-specific shapes such as
  `String x = "..."` cannot fire on prose that happens to share the prefix.
  Patterns with no `content_types` continue to match every classification
  (backwards compatible). The loader rejects unknown verdicts (typos like
  `"Code"` or `"natual"`) at load time so a misspelled value cannot
  silently disable a pattern. The pipeline precomputes a
  `hasContentTypeFilter` flag at `Rebuild` time and skips `ClassifyContent`
  entirely when no loaded pattern uses the field, so installs that do not
  rely on classifier scoping pay zero per-scan classifier cost. Initial
  scoping is intentionally conservative: only `Source Code Imports`
  (`["code"]`, regex already requires ≥1 import/package line by
  construction) and `Kubernetes Secret YAML`
  (`["credentials", "structured"]`, already gated by `require_hotword:
  true`) are tagged in this PR — the JSON-paste-style patterns whose own
  regex captures enclosing JSON braces were left untagged to avoid the
  document-level-classifier FN edge case (a secret pasted inside a
  prose-dominant document would otherwise be dropped). Documented in
  [`docs/dlp-pattern-authoring-guide.md`](docs/dlp-pattern-authoring-guide.md).
- **Capability tokens and extension pinning.** Per-install API capability
  token issued at `api_token_path` (32-byte hex, mode `0600`), with
  `api_token_required` enforcing the `Authorization: Bearer` header on
  control endpoints. `allowed_extension_ids` restricts the agent's
  control-plane CORS allowlist to a fixed set of browser-extension IDs.
- **HMAC-authenticated Native Messaging bridge.** The bridge is keyed by the
  per-install API token; `bridge_mac_required` toggles enforcement, and the
  agent rejects rolled-back request IDs or duplicate `hello` frames on the
  same connection.
- **File-upload and clipboard-file DLP.** The MAIN-world `fetch` / XHR hook
  reads `Blob`, `File`, `ArrayBuffer`, and `ArrayBufferView` bodies and
  walks `FormData`; a new `file-upload-interceptor` content script blocks
  risky uploads from `<input type="file">` and file drops before any read,
  and `paste-interceptor` applies the same guard to clipboard files.
- **Risky-file-extension blocklist.** A baked-in 34-entry executable /
  installer / script / disk-image / Java-archive set blocks before any
  read; operators can override via `risky_file_extensions` and inspect
  the effective list via `GET /api/config/risky-extensions`.
- **Signed enterprise profiles.** Profiles carry an Ed25519 `signature`
  field verified against `profile_public_key`; the disk, URL, and
  inline-import paths share one `profile.Verifier`; and
  `agent/cmd/sign-enterprise-profile` mirrors the rule-manifest signer.
- **Release-artefact hardening.** Every release publishes a `SHA256SUMS`
  manifest, Sigstore keyless signatures (`.sig` + `.pem`) under the
  workflow's GitHub OIDC identity, CycloneDX 1.6 SBOMs for the agent /
  tray / extension, and a SLSA Build Level 3 provenance attestation. The
  verification recipe lives in [SECURITY.md](./SECURITY.md).
- **Reference configuration presets.** Three repo-root config files —
  `config.personal.example.yaml`, `config.team.example.yaml`,
  `config.managed.example.yaml` — and an admin-guide section that walks
  through a personal → team → managed graduation path.
- **MDM deployment guide.** New section in
  [docs/admin-guide.md](./docs/admin-guide.md) covers per-organisation
  bundle generation, Chrome Enterprise managed policies, and per-platform
  walkthroughs for JAMF Pro, Microsoft Intune, and VMware Workspace ONE.
- **Hardening sweep.** Versioned `PRAGMA user_version` migrations,
  transactional `Store.ApplyProfileTx` (validate-then-commit), atomic
  `Counter.Flush` / `Reset` serialisation, fail-closed managed-mode boot
  (`profile_path` or `profile_url` required), secure-defaults validator
  for `enforcement_mode: team | managed`, store-level input validation
  for category names and DLP weights, path-stripping `/api/status` (debug
  paths gated on control-Origin only), and DNS-pinned `http.Transport`
  for profile-URL fetches to close the DNS-rebinding TOCTOU window.

### Changed

- **Breaking (managed mode):** `enforcement_mode: managed` now requires
  `profile_path` **or** `profile_url` in `config.yaml`. Previously a
  managed install could boot with no profile source declared and run
  with only the store's seeded defaults — a downgrade window between
  agent start and the first push-via-API import. Operators who want the
  push-via-API model must now declare an initial source (e.g. point
  `profile_path` at a placeholder signed-empty profile shipped with the
  package). The `POST /api/profile/import` runtime path is unchanged.
- **Breaking (team & managed):** the new secure-defaults validator
  rejects configs that omit `allowed_extension_ids`, `api_token_path`,
  or `api_token_required: true`; `managed` additionally requires
  `bridge_mac_required: true`, a non-empty `profile_public_key`, and
  (added in this release) a non-empty `rule_update_public_key`.
  Whitespace-only values are treated as empty.
- **Local API and proxy HTTP servers set the full timeout tuple.** Both
  `agent/internal/api/server.go` and `agent/internal/proxy/proxy.go` now
  set `ReadTimeout` / `WriteTimeout` / `IdleTimeout` / `MaxHeaderBytes`
  on the underlying `*http.Server` so a slowloris or write-stall cannot
  hold a listener thread indefinitely. The control API uses 10 s / 10 s
  / 60 s / 16 KiB; the proxy uses 30 s / 30 s / 120 s / 16 KiB.
- **JSON control endpoints are capped at 64 KiB.** A new
  `decodeControlBody` helper in `agent/internal/api/handlers.go` wraps
  `r.Body` in `http.MaxBytesReader(maxControlBytes=64 KiB)` and returns
  `413 Request Entity Too Large` instead of buffering megabytes of
  attacker-controlled JSON. Wired into `PUT /api/policies/:category`,
  `PUT /api/dlp/config`, `POST /api/rules/override`, and
  `POST /api/proxy/disable`. `/api/dlp/scan` (4 MiB) and
  `/api/profile/import` (1 MiB) keep their existing higher caps.
- **CA private-key permission check on every load.** `loadCA()` in
  `agent/internal/proxy/ca.go` refuses to read a Root CA key whose
  POSIX mode bits include group / world access (mask `0o077`), and
  `NewCA()` re-stats after `writeCA()` to fail closed when a hostile
  umask or stale file leaks the key. The proxy controller's `Enable()`
  path re-checks on every call so a runtime `POST /api/proxy/enable`
  refuses to start if the key file was tampered with between calls.
  No-op on Windows where ACLs, not mode bits, are the access-control
  mechanism.
- **Browser extension fails closed on Native Messaging MAC mismatch in
  managed mode.** `extension/src/background/native-messaging.ts` now
  caches the agent's enforcement mode and, when a reply MAC is
  missing, mismatched, or unverifiable (compute error), discards the
  result in managed mode instead of resolving with it. The bridge's
  per-connection warn-once log is preserved; personal and team mode
  retain the pre-existing warn-and-resolve posture.
- **Content scripts now inject into every frame.** All three packaging
  manifests (`extension/manifest.json`, `manifest.firefox.json`,
  `manifest.safari.json`) flip `all_frames` from `false` to `true` on
  every `content_scripts` entry so Tier-2 AI surfaces that render
  their input inside same-origin iframes (e.g. embedded chat widgets,
  artefact / canvas views) stay covered by the DLP scanner. A new
  `manifest-all-frames.test.ts` pins the contract per manifest target.
- **Adversarial bridge test matrix.** New
  `extension/src/content/__tests__/adversarial.test.ts` consolidates
  the four documented bridge threat shapes in one file: page-forged
  `scan-resp` after the legitimate reply (first-reply-wins), pre-
  injection `fetch()` (documented limitation, deferred to the proxy +
  OS egress controls), oversize content in managed mode
  (`POLICY_PATTERN_OVERSIZE` block), and scan-null in managed mode
  (`POLICY_PATTERN_AGENT_UNAVAILABLE` block). Symmetric "must not
  block in personal mode" assertions guard against an over-eager
  promotion of the block branches.
- **Packaged `config.yaml` now self-identifies as the personal
  preset.** The header comment block at the top of `config.yaml`
  explicitly labels the file as `PERSONAL mode (development /
  individual use)`, enumerates the three enforcement presets
  (`personal` / `team` / `managed`) and what each one enforces,
  and points operators at `config.team.example.yaml` and
  `config.managed.example.yaml` for the harder postures. The file
  itself is unchanged on the value side — it remains the
  packaged out-of-the-box install.
- **`README.md` gained a "Security posture" section.** The new
  section consolidates the enforcement matrix (personal / team /
  managed posture per failure mode), the extension-vs-proxy
  enforcement boundary (what the extension cannot prevent and
  which OS / browser-policy / proxy control closes which gap),
  the three-layer DLP accuracy methodology (smoke / large /
  regression with their per-layer budgets and source files), and
  the HTTP surface hardening tuple now shared by the control API
  and the proxy listener. The DLP coverage table moved no rows;
  the new section sits between Enterprise features and Testing.
- `paste-interceptor.ts` shares the `MAX_SCAN_BYTES` constant with the
  other interceptors; a parity test pins the value across the isolated
  and MAIN worlds.
- `drag-interceptor.ts` cedes file drops to `file-upload-interceptor.ts`
  so OS file managers that attach a `text/plain` path alongside the
  `File` cannot trick `drag-interceptor` into resuming a stale path
  string while the file is being blocked.

### Fixed

- **Custom rule categories are accepted again.** The hardening sweep
  landed a closed-set category allowlist; the store now exposes
  `RegisterCategories([]string)` and the agent boot path registers every
  category derived from `cfg.rule_paths`, so a custom rule file under
  `rules/` (e.g. `gaming.txt` → `Gaming`) is once again addressable by
  `PUT /api/policies/:category` and accepted inside enterprise profiles
  without forcing operators to fork `store.knownCategories`.
- `ErrInvalidCategory` and `ErrInvalidDLPConfig` now surface as HTTP 400
  instead of 500 from `/api/policies` and `/api/dlp/config`.
- Cross-compilation: `agent/internal/tamper/proxy_check.go` dispatches
  per platform via build-tagged `proxy_{darwin,windows,other}.go`
  files instead of a `switch runtime.GOOS` against per-platform stubs,
  so the agent cross-builds cleanly for darwin and windows targets.
- Electron-builder Linux `.deb` packaging picks up `homepage` +
  `author{name,email}` from `package.json`; the dotless `artifactName`
  in `electron-builder.yml` survives GitHub's release-upload filename
  normalisation.
- Windows MSI build uses native WiX v4+ `<Files Include="…">` and is
  pinned to the WiX dotnet tool `v5.0.2`.
- The release `SHA256SUMS` pipeline uses NUL-separated piping so
  artefacts whose names contain spaces hash correctly.
- **Long-IO control handlers no longer hit `WriteTimeout`.** Three
  control endpoints do outbound HTTPS that can outlast the
  server-wide 10 s `http.Server.WriteTimeout` set on the control API
  (`agent/internal/api/server.go`): `POST /api/rules/update`
  (signed-manifest fetch), `POST /api/agent/update` (binary
  download), and `POST /api/profile/import` (profile URL fetch).
  Each now calls `http.NewResponseController(w).SetWriteDeadline(time.Time{})`
  via the new `allowLongWrite` helper at the top of the handler, so
  the write deadline is dropped only for these three endpoints while
  everything else still benefits from the global 10 s cap. Per-handler
  client timeouts (`RuleUpdater`, `AgentUpdater`, profile `http.Client`)
  continue to bound the wall-clock budget so removing the deadline does
  not open a hang vector. Pinned by `TestLongIOHandlers_DropWriteDeadline`
  in `handlers_test.go`.
- **No-body control endpoints bound their post-response drain.**
  `POST /api/proxy/enable`, `POST /api/rules/update`,
  `POST /api/stats/reset`, and `POST /api/agent/update` do not decode
  `r.Body`, but Go's `http.Server` drains the body after the handler
  returns to keep the keep-alive connection reusable. Without a cap a
  hostile peer could ship megabytes at endpoints that have no business
  taking a body. Each now calls the new `capControlBody` helper, which
  wraps `r.Body` in `http.MaxBytesReader(maxControlBytes)` so the drain
  returns `*http.MaxBytesError` once the 64 KiB cap is hit and the
  server closes the connection instead of reusing it. `capControlBody`
  runs immediately after the method check — *before* any nil-backend
  or profile-locked guard — so the cap is also in place on the
  503 / 403 early-return paths a hostile peer can reach without any
  agent-side configuration. Pinned by
  `TestNoBodyControlEndpoints_BodyIsCapped` and
  `TestNoBodyControlEndpoints_CapAppliedOnEarlyReturn` in
  `handlers_test.go`.

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
