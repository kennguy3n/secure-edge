# Admin Guide

This guide is for administrators who deploy ShieldNet Secure Edge across an
organization. End-user documentation lives in [user-guide.md](./user-guide.md).

## 1. Installation

Secure Edge ships as a single Go binary plus an Electron tray app. The Phase 4
release artifacts are produced by the `release.yml` GitHub Actions workflow and
attached to GitHub Releases. See [README.md](../README.md) for the per-platform
download/install commands.

| Platform | Install command |
| --- | --- |
| macOS (Apple Silicon) | `brew install --cask shieldnet-secure-edge` (planned) |
| macOS (Intel) | Download `secure-edge-darwin-amd64.tar.gz` and run `install.sh` |
| Linux (amd64) | `curl -fsSL https://shieldnet.io/install.sh | sh` |
| Linux (arm64) | Download `secure-edge-linux-arm64.tar.gz` and run `install.sh` |
| Windows | Run `secure-edge-setup.exe` (signed with the Authenticode cert; see Phase 6) |

All builds embed a build-time SHA-256 of `rules/manifest.json` so tamper
detection works even before the first rule update.

### 1.1 Verifying release artefacts before deploying

Every release ships with a `SHA256SUMS` manifest, a Sigstore keyless
signature over that manifest, per-artefact `.sig` / `.pem` files,
CycloneDX 1.5 SBOMs, and a SLSA build provenance attestation. Run the
verification recipe in [SECURITY.md](../SECURITY.md#verifying-a-release)
before pushing a build to managed endpoints — it confirms the artefact
was emitted by this repository's `Release` workflow on a `v*` tag and
has not been tampered with in transit. Platform-native code signing
(Apple Developer ID / Windows Authenticode / Linux GPG) is still
pending certificate provisioning (`PHASES.md`, "Code signing of release
artifacts"); the Sigstore chain is the authoritative trust path until
then.

## 2. Configuration (`config.yaml`)

The agent looks for `config.yaml` in the following locations, in order:

1. `$SECURE_EDGE_CONFIG` (env var, if set)
2. `$XDG_CONFIG_HOME/secure-edge/config.yaml`
3. `~/.config/secure-edge/config.yaml` (Linux/macOS) or
   `%APPDATA%\secure-edge\config.yaml` (Windows)
4. `/etc/secure-edge/config.yaml` (managed install)

Minimal example:

```yaml
upstream_dns:
  - 1.1.1.1
  - 9.9.9.9
listen_dns: 127.0.0.1:53053
listen_proxy: 127.0.0.1:8443
listen_api: 127.0.0.1:7878
rules_dir: ~/.local/share/secure-edge/rules
log_level: info
```

Full reference is in `agent/internal/config/config.go`.

### 2.0 Reference presets (start here, then customise)

Rather than editing the packaged `config.yaml` from scratch, operators
are expected to start from one of three reference presets that ship at
the repository root and copy it into the location §2 enumerates:

| Preset | File | Posture |
| --- | --- | --- |
| Personal | `config.personal.example.yaml` | Fall-open, individual developer use. No per-install token; no Native Messaging HMAC pinning; no profile signature pinning. Mirrors the packaged `config.yaml` defaults. |
| Team | `config.team.example.yaml` | Intermediate rollout. Per-install API token required; warn-toast on agent-unavailable; Native Messaging HMAC still lenient (warn-once log); unsigned profiles still accepted. |
| Managed | `config.managed.example.yaml` | Fail-closed end-state for MDM-deployed fleets. Every Phase 7 control surface enabled, every signed artefact verified, fail-closed on agent-unavailable gestures. |

Copy the appropriate file to the install location (e.g. `cp
config.managed.example.yaml /etc/secure-edge/config.yaml`) and fill in
the `<placeholder>` values from your signing host. The subsections
below document each individual knob in detail — the presets only
pre-select sensible groupings.

Do not deploy the managed preset to your full fleet without first
validating it on a single pilot endpoint (every signed surface
requires matching plumbing — an unsigned profile or a pre-C1
extension build on the wire will fail-closed under the managed
posture). The recommended sequence is personal → team → managed.
See §10.1 for the MDM deployment bundle and §3.1 / §4 / §2.1 for the
staged rollout posture under each signing surface.

### 2.1 Native Messaging bridge HMAC (`bridge_mac_required`)

Phase 7 added an HMAC-SHA256 message-authentication code to every
non-`hello` frame on the Native Messaging bridge that connects the
browser extension's service worker to the locally installed agent
binary (the program registered under `NativeMessagingHosts`).

The MAC is keyed by the per-install API token (the 32-byte hex value
under `api_token_path`, see A2). The agent mints a fresh 16-byte
nonce per connection and surfaces it on the (intentionally
unsigned) `hello` reply. The extension caches the nonce + token for
the lifetime of the port and includes the MAC on every subsequent
request; the agent verifies the MAC and signs its replies under the
same key.

Two knobs govern the behaviour:

```yaml
# Path to the per-install API token. Already documented under A2;
# the same file is reused as the HMAC key (no separate secret).
api_token_path: /var/lib/secure-edge/api-token

# Bridge MAC enforcement. Default is false (lenient) — the agent
# logs a one-time stderr warning per connection if a frame's MAC
# is missing or invalid but keeps serving scans. Flip to true once
# every extension build in your fleet is producing MACs.
bridge_mac_required: false
```

Recommended rollout sequence for a managed fleet:

1. Roll out the extension build that produces MACs to every
   endpoint. Leave `bridge_mac_required: false` on the agent.
2. Tail `journalctl --user -u secure-edge-agent` (Linux) /
   `~/Library/Logs/secure-edge/agent.log` (macOS) /
   `%LOCALAPPDATA%\secure-edge\agent.log` (Windows) for the
   one-time `agent: bridge MAC missing on Native Messaging request`
   warning. If you see it after the rollout completes, an
   endpoint is still on the pre-C1 extension build.
3. Once the warning stops appearing across your fleet, flip
   `bridge_mac_required: true`. Any subsequent missing or
   tampered MAC will be rejected with `bridge MAC required` /
   `bridge MAC mismatch` in the response, and the extension's
   scan will fall through to the HTTP fallback (which has its
   own bearer-token guard from A2).

The MAC check is automatically skipped when no `api_token_path` is
configured — without a shared secret there is nothing to verify
against, regardless of the `bridge_mac_required` knob's value. The
agent also enforces a strict-monotonic request id and rejects a
second `hello` on the same connection; both are unconditional and
not gated by `bridge_mac_required`.

### 2.2 Risky file extensions (`risky_file_extensions`)

Phase 7 (B2) added a policy lever that hard-blocks file uploads
whose extension is on a configurable risky list. The block is
evaluated **on the page**, inside the browser extension's
`file-upload-interceptor` content script, **before** any content is
read or sent to the agent — so the filename and contents never
leave the page for a B2 verdict.

The extension ships with a baked-in default list of 34 extensions
covering Windows / macOS / Linux executables, installers (`.msi`,
`.pkg`, `.deb`, `.rpm`), scripts (`.ps1`, `.vbs`, `.bat`, `.cmd`,
`.sh`, `.psm1`, `.psd1`, `.wsf`, `.wsh`, `.vbe`), disk images
(`.iso`, `.img`, `.vhd`, `.vhdx`, `.dmg`), Java archives (`.jar`,
`.class`), and a small set of platform binaries (`.app`, `.com`,
`.pif`, `.reg`, `.dll`, `.sys`, `.appx`, `.appxbundle`, `.msix`,
`.msp`, `.mst`). `.js` is **intentionally excluded** to avoid
breaking developer workflows; if your fleet requires it, add it
via the override below. Archive formats (`.zip`, `.7z`, `.rar`,
`.tar`, `.gz`) are also intentionally excluded — they are too
common for legitimate business use.

Operators override the baked-in list via a single config key:

```yaml
# Optional risky-extension override. Three states:
#   1) Omit the key entirely    → extension uses the baked-in 34-entry default.
#   2) Empty list `[]`          → opts out of B2 entirely (no extension is
#                                 blocked at this layer; content scan still runs).
#   3) Populated list           → replaces the baked-in default verbatim.
# Entries are case-insensitive; leading dots are stripped; blanks are dropped.
risky_file_extensions:
  - exe
  - scr
  - ps1
  - msi
```

The agent surfaces the resolved list (or its absence) to the
extension over `GET /api/config/risky-extensions`. The extension's
service worker caches the result for 5 minutes and mirrors it to
`chrome.storage.session` so content scripts can fall back after a
worker eviction without a re-fetch. The wire shape distinguishes
the three states above:

- `{}` (no `extensions` field) — extension uses the baked-in default
- `{"extensions": []}` — opt-out, no B2 blocking
- `{"extensions": ["exe", ...]}` — operator override

A risky-extension block fires **regardless of enforcement mode**.
B2 is a policy lever to remove a class of file from the upload
surface entirely; it does not fall open in `personal` or `team`
modes the way the content scan does. The toast reads
`Secure Edge blocked this upload — .exe files are blocked by
policy.` (with the matched extension substituted in).

## 3. Enterprise Profiles (managed mode)

Phase 5 added managed-mode profiles for enrolled fleets. A profile is a YAML
file with the same shape as `config.yaml` plus an `overrides` block. It is
loaded from `profile_path` or fetched from `profile_url` on agent start and on
every rule update.

```yaml
# profile.yaml
profile_id: acme-prod-2026q2
profile_version: 7
overrides:
  category_policies:
    "AI Chat (Unsanctioned)": deny
    "Code Hosting": allow_with_dlp
  thresholds:
    critical: 1
    high: 2
  managed: true   # disables local toggles in the tray UI
```

Set `profile_url: https://mdm.example.com/profiles/secure-edge.yaml` to fetch
the profile over HTTPS. Validation runs on every load — a malformed profile
falls back to the last good profile and logs a single line to the agent log
(no profile body is logged).

When `managed: true`, the Electron tray UI hides the category toggles and the
Settings page shows a read-only banner with the profile ID + version.

### 3.1 Signing enterprise profiles (`profile_public_key`, Phase 7 / D2)

The agent verifies an Ed25519 signature on every loaded profile when
`profile_public_key` is configured. The same verifier covers all three
import surfaces (`profile_path` on disk, `profile_url` over HTTPS, and
runtime `POST /api/profile/import` with either `{"url": …}` or
`{"profile": {…}}` shapes) so an attacker can't slip a tampered profile
through one path while signing the rest.

When `profile_public_key` is **absent**, the agent runs in a
backwards-compatible warn-once posture: unsigned profiles are accepted,
and a single line is logged per process so an operator who half-rolled
out the change sees a breadcrumb in their logs. When the key is
**configured**, unsigned, malformed, tampered, or wrong-key-signed
profiles are rejected before any policy is applied.

End-to-end signing example:

```bash
# 1. Generate an Ed25519 keypair once (keep the private key offline).
#    The CLI expects the Go crypto/ed25519 raw-private-key format
#    (64 bytes = 128 hex chars), which is seed || public. The
#    snippet below emits exactly that.
$ cat > /tmp/genkey.go <<'EOF'
package main
import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "os"
)
func main() {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { panic(err) }
    if err := os.WriteFile("ed25519-priv.hex",
        []byte(hex.EncodeToString(priv)), 0o600); err != nil { panic(err) }
    fmt.Println(hex.EncodeToString(pub))   // configure as profile_public_key
}
EOF
$ go run /tmp/genkey.go > ed25519-pub.hex
$ chmod 600 ed25519-priv.hex

# 2. Sign your profile JSON.
$ go run ./agent/cmd/sign-enterprise-profile \
    -in config/profile.json \
    -key ed25519-priv.hex
sign-enterprise-profile: signed config/profile.json (name=acme version=1.0.0)
  public key: <hex>
  configure the agent with `profile_public_key: "<hex>"`

# 3. Add the matching public key to config.yaml on every agent.
$ cat >> /etc/secure-edge/config.yaml <<EOF
profile_public_key: "$(cat ed25519-pub.hex)"
profile_path: "/etc/secure-edge/profile.json"
EOF

# 4. Restart the agent. It now verifies the on-disk profile, and any
#    runtime push through POST /api/profile/import, against the key.
```

Re-signing is necessary on every profile update. The CLI is idempotent —
running it again over an already-signed profile recomputes the signature
from the body (the `signature` field is excluded from the canonical
bytes by construction, so the round-trip is deterministic).

If you set `profile_public_key` but leave both `profile_path` and
`profile_url` empty, the agent prints a one-line orphan-key warning to
stderr at startup. The key is still useful in that configuration (runtime
`POST /api/profile/import` will verify against it), but the warning
surfaces the partial-rollout footgun.

## 4. Rule Updates

Two mechanisms:

- **Automatic**: the agent polls `manifest.json` at the configured
  `update_url` on the `update_interval` cadence (default 24h). Each entry in
  the manifest carries a SHA-256; the agent only swaps in a new rule file if
  the SHA-256 matches.
- **Manual**: `POST /api/rules/update` triggers an immediate fetch. The
  response is `{"updated":true,"version":"..."}` on success.

Both paths use the same loader, so they share the same tamper checks
(see §6).

## 5. Admin Overrides (`rules/local/`)

For per-host customization, place files under `rules_dir/local/`:

```
rules/local/
├── allow_domains.txt        # extra Tier 1 domains (one per line)
├── block_domains.txt        # extra Tier 3 domains
└── dlp_patterns_local.json  # extra DLP patterns (same schema as dlp_patterns.json)
```

Local rules are loaded after the shipped rules and override on a key-by-key
basis. Local rules are not signed and not in the manifest — they're meant for
per-host one-offs, not for fleet distribution.

## 6. Tamper Detection

On start and on every rule load, the agent recomputes the SHA-256 of every
shipped rule file and compares against `manifest.json`. A mismatch:

1. Refuses to load the modified file (the agent keeps running with the
   previous good copy).
2. Increments `tamper_detections_total` in the aggregate stats.
3. Surfaces a red tray icon and a `GET /api/status` field
   (`"tamper_state": "detected"`).

The integrity check ignores `rules/local/` so per-host overrides do not trip
the alarm.

## 7. Heartbeat

When `heartbeat_url` is set in `config.yaml` or the enterprise profile, the
agent posts a JSON heartbeat on a fixed interval (default 5 min):

```json
{
  "profile_id": "acme-prod-2026q2",
  "profile_version": 7,
  "agent_version": "0.5.0",
  "manifest_version": "rules-2026-05-13",
  "stats": {
    "dns_queries_total": 50321,
    "dns_blocks_total": 142,
    "dlp_scans_total": 8901,
    "dlp_blocks_total": 7,
    "tamper_detections_total": 0
  }
}
```

The heartbeat carries only aggregate counters — no domain names, no URLs, no
user identifiers. The receiving endpoint should reply 200 OK; non-200 responses
are retried with exponential backoff. See `agent/internal/heartbeat/`.

## 8. Enforcement Boundary: Extension vs. Proxy

ShieldNet Secure Edge has two on-device inspection paths and it is important
to understand exactly what each one guarantees before relying on one in a
deployment.

| Layer                  | Role                                  | Bypassable by the page?                                          |
| ---------------------- | ------------------------------------- | ---------------------------------------------------------------- |
| Browser extension      | DLP **coaching** (UX, real-time toast) | Yes — the page sees `window.postMessage` traffic and is in the same JS world as the bridge. |
| Local MITM proxy       | DLP **enforcement** (TLS termination on Tier-2 hosts) | No — runs outside the browser process and gates the network. |
| Managed browser policy | Hard domain blocklist / allowlist     | No — enforced by the browser before any page JS runs.            |

### Why the extension is coaching, not enforcement

The companion extension installs a MAIN-world content script that patches the
page's own `window.fetch` and `XMLHttpRequest.prototype.send`. To talk to the
isolated-world content script (which owns the agent connection), it uses
`window.postMessage`. The page's own JavaScript sits in the same MAIN world and
can:

- See every `secure-edge-bridge` message the MAIN-world script posts.
- Reply with a forged `secure-edge-iso` `scan-resp` `{ result: { blocked: false }}`.
- Replace `window.fetch` or `XMLHttpRequest.prototype.send` *after* our patch
  installs, restoring the original unpatched function.

The `BRIDGE_SOURCE` / `ISO_SOURCE` channel tags are best-effort identification
markers, not security tokens (see the inline comment in
`extension/src/content/main-world-network.ts`). A hostile or compromised page
trivially defeats them. The extension is therefore the right tool for *honest
user error* (someone pasting an API key into ChatGPT) but not for adversarial
or compromised pages.

### When to enable the proxy

Enable the local MITM proxy whenever any of the following are true:

- The threat model includes pages or web apps that may be hostile to the
  extension (compromised AI portals, browser extensions that fight ours,
  enterprise SSO-wrapped AI tools that load arbitrary third-party JS).
- You need enforcement coverage for non-browser traffic — desktop AI apps,
  IDE plugins (e.g. Copilot, Cursor) hitting Tier-2 endpoints, CLI tools, or
  any other process that bypasses the browser entirely.
- You require auditable "the network refused to forward this body" semantics
  rather than "the browser was asked nicely not to".

Start the proxy with `POST /api/proxy/enable`; the agent generates a local CA,
prompts the user to install it, and routes only Tier-2 hostnames through the
TLS termination path. All other hosts get an opaque CONNECT tunnel — the proxy
never sees their plaintext. See `agent/internal/proxy/proxy.go` for the policy
hook and `scripts/macos/configure-proxy.sh` / the Windows equivalent for the
system-proxy handoff.

### When to deploy managed browser policies

Managed browser policies (Chrome Enterprise `URLBlocklist` and friends, Firefox
`policies.json`, Edge GPO) are enforced by the browser itself before any page
script runs. Combine them with the proxy for defence in depth:

- Use `URLBlocklist` to keep blocked AI domains unreachable even if the user
  somehow disables the agent.
- Use `ManagedConfigurationPerOrigin` to push a hard deny / read-only mode on
  internal AI tools.

The agent does **not** distribute managed browser policies — that is the
endpoint management system's job. Document the policy bundle you deploy
alongside Secure Edge so future operators understand which layer enforces what.

### 8.1 Image / screenshot DLP is not in scope

The DLP scanner operates on **text content only**. The Aho-Corasick
prefix scan, the regex pass, the entropy / hotword scoring, and the
classifier head are all string-typed: the bytes a scanner receives
are decoded as best-effort UTF-8 before any pattern fires. That
decoder is the only way an image, screenshot, PDF, or other binary
payload enters the pipeline, and it does **not** extract meaningful
text from image pixels — a screenshot of an AWS access key is, to
the scanner, an unrelated string of mojibake.

This affects two surfaces specifically:

- **Clipboard screenshot paste** (`extension/src/content/paste-interceptor.ts`,
  Phase 7 / B3). The interceptor blocks the upload **gesture** by
  calling `preventDefault` / `stopPropagation` before any await,
  so a pasted screenshot never reaches the page's `paste`
  listeners. The agent then runs its UTF-8 decode + DLP scan on
  the file bytes; the resulting verdict is a coaching signal,
  not a content-aware verdict. **The bytes never reach the AI
  tool**, but Secure Edge cannot tell the operator whether the
  screenshot contained sensitive content.
- **Drag-and-drop / `<input type=file>` of image / PDF files**
  (`file-upload-interceptor.ts`, Phase 7 / B1). Same shape — the
  gesture is suppressed; the content scan is best-effort UTF-8.

What the scanner **does** cover for binary payloads:

- The risky-extension blocklist (§2.2). Filename-driven — a
  matching extension blocks the gesture before any content read,
  regardless of binary vs. text.
- The proxy enforcement boundary above. The MITM proxy refuses
  the body at the network layer; the content question is
  irrelevant because the network refused to forward it at all.

What the scanner does **not** support, and is not on the Phase 7
roadmap:

- OCR over screenshot pixels.
- Image-classification heads (e.g. a CNN that flags screenshots
  containing API-key-shaped layouts).
- PDF text extraction (a PDF is treated as the same best-effort
  UTF-8 decode as any other binary).

For managed deployments that need screenshot DLP coverage, the
recommended postures are:

1. **Block the gesture outright on Tier-2 AI tools.** A managed
   browser policy that disables clipboard image paste on the AI
   tool's origin (Chrome Enterprise
   [`DefaultClipboardSetting`](https://chromeenterprise.google/policies/#DefaultClipboardSetting)
   set to `BlockClipboard` on the AI tool's origin, or the
   equivalent in Edge / Firefox) makes screenshot paste
   unreachable before any extension content script gets to run.
2. **Layer in a complementary endpoint DLP product with OCR.**
   Secure Edge's threat model is honest-user DLP coaching for
   text payloads — a screenshot-OCR DLP product is a different
   surface and the two compose cleanly (the extension blocks the
   gesture for text-shape DLP; the endpoint product blocks the
   gesture for image-shape DLP).

The extension's B3 toast text intentionally does not claim that
the screenshot was scanned — it only signals that the paste was
suppressed. See the header comment in
`extension/src/content/paste-interceptor.ts` for the same caveat
in-source.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Tray icon is red | Tamper detected, or agent service is down | Check `GET /api/status`; reinstall the binary if SHA-256 mismatch persists. |
| DNS queries fail with NXDOMAIN for known-good domain | Domain is in an active blocklist | Add to `rules/local/allow_domains.txt`. |
| DLP false-positive blocks | Pattern fires on documentation/test value | File a `false_positive` issue on the GitHub repo; add a temporary exclusion in `rules/local/dlp_patterns_local.json`. |
| Profile not applied | `profile_url` returned non-200, or YAML invalid | Check the agent log for the single line emitted on profile load failure; the agent falls back to the last good profile. |
| High CPU | Likely DLP scanning very large clipboard pastes | The pipeline has a hard cap (`pipeline.maxScanBytes`) — confirm it's not been raised in a custom build. |

For deeper debugging, the agent supports `LOG_LEVEL=debug` to print per-step
pipeline timing (without logging scan content).

## 10. Managed Deployments (MDM)

This section pulls together every Phase 7 control surface — the
per-install bearer token (PR #18 / A2), the signed rule manifest
(PR #20 / A3), the signed enterprise profile (PR #28 / D2), and
the HMAC-authenticated Native Messaging bridge (PR #26 / C1) —
into one end-to-end walkthrough for deploying the agent + the
companion extension to a fleet of managed endpoints via a Mobile
Device Management (MDM) platform.

It is written for operators who have already validated the agent
+ extension on a single test endpoint by following sections
1–8, and are now wiring the same configuration into JAMF Pro
(macOS), Microsoft Intune (Windows), or VMware Workspace ONE
(cross-platform).

For Kandji, Mosyle, and SimpleMDM see the per-platform notes in
[Managed-deployment patterns by vendor](https://developer.apple.com/documentation/devicemanagement)
— the shape of the payload is the same as JAMF; only the upload
mechanism differs.

### 10.1 What to bundle

A deployment bundle is the minimum set of files an MDM-managed
endpoint needs to bring the agent up in **managed** mode with
every signed surface verified end-to-end. The bundle is **not**
ever published anywhere public — it is generated per organisation
on the operator's signing host and uploaded as an MDM payload.

| File | Where it lives on disk | Generated by | Signed? |
| --- | --- | --- | --- |
| `config.yaml` | macOS: `/Library/Application Support/secure-edge/`<br>Windows: `%ProgramData%\secure-edge\`<br>Linux: `/etc/secure-edge/` | Hand-authored from §2 | No (operator-controlled) |
| `profile.json` | Path that `config.yaml` references via `profile_path` | `sign-enterprise-profile` (§3.1) | Yes — Ed25519 |
| `manifest.json` + `rules/` | Path that `config.yaml` references via `rule_update_path` | `sign-rule-manifest` (§4) | Yes — Ed25519 |
| `api_token` | macOS / Linux: `/var/lib/secure-edge/api_token`<br>Windows: `%ProgramData%\secure-edge\api_token` | Generated per install during agent first-run (see §1) | n/a — secret |
| `secure-edge-agent` binary | macOS / Linux: `/usr/local/bin/` (or `/opt/secure-edge/bin/`)<br>Windows: `C:\Program Files\Secure Edge\` | GitHub Releases (verified per §1.1) | Yes — cosign + SLSA L3 |
| Extension `.crx` / `.xpi` | Managed via browser policy (see §10.2) | Chrome Web Store / signed `.crx` | Yes — Web Store key |

> **Privacy note.** Only the per-install `api_token` is a secret.
> Both Ed25519 public keys (`profile_public_key`,
> `rule_update_public_key`) are configuration values, not
> secrets — they verify signatures but cannot create them, so
> there is no harm in including them in an MDM payload that
> ships to thousands of endpoints. The matching private keys
> must never leave the operator's signing host.

#### Generating the per-install bundle (one-time, per organisation)

Generate two independent Ed25519 keypairs (one for profiles, one
for rule manifests) using the snippet shown in §3.1 — repeat it
twice, once writing to `keys/profile.ed25519.{priv,pub}.hex` and
once to `keys/rules.ed25519.{priv,pub}.hex`. Then sign each
artefact in place:

```sh
# On the operator signing host. Assumes §3.1's keygen snippet has
# been run twice to produce the two .priv / .pub.hex files below.

# 1. Authoritative org profile, signed by the profile key.
go run ./agent/cmd/sign-enterprise-profile \
    -in  ./profile.unsigned.json \
    -out ./profile.json \
    -key ./keys/profile.ed25519.priv.hex

# 2. Rule manifest, signed by the rules key. The CLI canonicalises
#    the manifest body (NOT the rules/ directory the manifest
#    references — those file hashes are already part of the body).
go run ./agent/cmd/sign-rule-manifest \
    -in  ./manifest.unsigned.json \
    -out ./manifest.json \
    -key ./keys/rules.ed25519.priv.hex

# 3. The matching public-key hex (32 bytes / 64 hex chars) is what
#    every managed endpoint receives via `config.yaml` (see fragment
#    below). It is NOT a secret — it can only verify signatures.
cat ./keys/profile.ed25519.pub.hex  # → e.g. "9b1ac8..."
cat ./keys/rules.ed25519.pub.hex    # → e.g. "5cf472..."
```

The matching `config.yaml` fragment the MDM ships to every
endpoint:

```yaml
enforcement_mode: managed

# Pinned signing keys — endpoints reject any profile / manifest
# that does not verify under these. Replace with the hex strings
# captured in step 5 above.
profile_public_key: "9b1ac8..."        # PR #28 / D2
rule_update_public_key: "5cf472..."    # PR #20 / A3

# Bearer token + HMAC posture (defence-in-depth on the
# extension ↔ agent hop).
api_token_required: true               # PR #18 / A2
bridge_mac_required: true              # PR #26 / C1

# Layout of the signed bundle on disk.
profile_path: "/Library/Application Support/secure-edge/profile.json"
rule_update_path: "/Library/Application Support/secure-edge/manifest.json"
api_token_path: "/var/lib/secure-edge/api_token"

# Risky-extension blocklist (PR #27 / B2). Omit to use the
# baked-in 34-entry default.
# risky_file_extensions: ["exe", "scr", "msi", ...]
```

### 10.2 Chrome Enterprise managed policies

The extension is force-installed via Chrome Enterprise managed
policies; the same JSON works for Edge for Business and any
Chromium-derived browser that honours
`HKLM\Software\Policies\Google\Chrome` (Windows) or
`/Library/Managed Preferences/com.google.Chrome.plist` (macOS).

```json
{
    "ExtensionInstallForcelist": [
        "<extension-id>;https://clients2.google.com/service/update2/crx"
    ],
    "ExtensionSettings": {
        "<extension-id>": {
            "installation_mode": "force_installed",
            "update_url": "https://clients2.google.com/service/update2/crx",
            "blocked_install_message": "Secure Edge is required by IT. Contact security@example.com if it is missing.",
            "runtime_blocked_hosts": [],
            "runtime_allowed_hosts": ["*://*/*"]
        }
    },
    "ManagedConfigurationPerOrigin": [
        {
            "origin": "chrome-extension://<extension-id>/",
            "configuration": {
                "agent_base": "http://127.0.0.1:8080",
                "enforcement_mode_hint": "managed"
            }
        }
    ]
}
```

- `ExtensionInstallForcelist` pins the exact extension ID — replace `<extension-id>` with the value shown on `chrome://extensions` after a manual install on a test endpoint.
- `runtime_allowed_hosts` defaults to every host because Secure Edge intercepts AI-tool surfaces by URL match. If your fleet only uses a known subset (e.g. just `chatgpt.com` and `claude.ai`), narrow this list to reduce the extension's exposure.
- `ManagedConfigurationPerOrigin` is **optional** — the extension reads the enforcement mode from the agent over loopback; the policy entry only matters for early-bootstrap before the agent first responds.

### 10.3 Per-platform recipes

The three subsections below are shape-only walkthroughs — they
show the payload layout for each platform but do not include
operator-specific values (paths, group names, signing identities).
Substitute your organisation's values when uploading the bundle.

#### 10.3.1 JAMF Pro (macOS)

JAMF deploys the bundle in three pieces: a **Configuration
Profile** for `config.yaml` and the two public keys, a
**Files & Processes** policy for the signed `profile.json` and
`manifest.json + rules/`, and a **Restricted Software** entry to
prevent users from uninstalling the agent.

1. **Configuration Profile** — *Computers → Configuration Profiles → New*.
   Add a **Custom Settings** payload with preference domain
   `com.shieldnet.secure-edge.config` and the plist below
   (one-to-one mapping of the `config.yaml` fields in §10.1):

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
      <dict>
        <key>enforcement_mode</key>
        <string>managed</string>
        <key>profile_public_key</key>
        <string>9b1ac8...</string>
        <key>rule_update_public_key</key>
        <string>5cf472...</string>
        <key>api_token_required</key>
        <true/>
        <key>bridge_mac_required</key>
        <true/>
        <key>profile_path</key>
        <string>/Library/Application Support/secure-edge/profile.json</string>
        <key>rule_update_path</key>
        <string>/Library/Application Support/secure-edge/manifest.json</string>
        <key>api_token_path</key>
        <string>/var/lib/secure-edge/api_token</string>
      </dict>
    </plist>
    ```

    The agent on macOS reads `config.yaml` from
    `/Library/Application Support/secure-edge/`; a postinstall
    script in step 2 translates the plist into the YAML the
    agent expects (or, equivalently, you can ship a static
    `config.yaml` as a payload file).

2. **Files & Processes policy** — *Computers → Policies → New*.
   Upload `profile.json`, `manifest.json`, and the entire
   `rules/` directory as a package payload. Target distribution
   points: `/Library/Application Support/secure-edge/`.
   Trigger: **Recurring Check-in** (default 30 min) and **At
   Login** for the first roll-out window.

3. **Restricted Software** — *Computers → Restricted Software*.
   Match on the agent binary path; action = **Restrict and Kill**.
   Pair with a JAMF Self Service entry so a user can request
   reinstall if the binary is removed in error.

#### 10.3.2 Microsoft Intune (Windows)

Intune deploys the bundle as a **Win32 app** plus an **ADMX-backed
device configuration policy**. The Win32 app installs the agent
binary, writes `config.yaml`, and drops the signed `profile.json`
and `manifest.json` into `%ProgramData%\secure-edge\`. The ADMX
policy pins the browser-side `ExtensionInstallForcelist`.

1. **Package the agent as a Win32 app.** Use the
   `IntuneWinAppUtil.exe` tool against a folder containing:

    ```
    secure-edge-windows-amd64.exe
    install.ps1
    profile.json
    manifest.json
    rules\
    ```

    `install.ps1` is a thin wrapper that:

    ```powershell
    # Halt on first error so a partial install never silently
    # leaves the endpoint in a half-configured state.
    $ErrorActionPreference = 'Stop'
    $PSNativeCommandUseErrorActionPreference = $true

    $installDir = "$env:ProgramFiles\Secure Edge"
    $dataDir = "$env:ProgramData\secure-edge"

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    Copy-Item secure-edge-windows-amd64.exe "$installDir\secure-edge-agent.exe"
    Copy-Item profile.json "$dataDir\"
    Copy-Item manifest.json "$dataDir\"
    Copy-Item -Recurse rules "$dataDir\rules"

    # The first-run bootstrap mints the api_token and writes
    # %ProgramData%\secure-edge\api_token. See §1.
    & "$installDir\secure-edge-agent.exe" --install-service
    ```

    Detection rule: file exists at
    `%ProgramFiles%\Secure Edge\secure-edge-agent.exe` AND
    `%ProgramData%\secure-edge\api_token`.

2. **Device configuration policy — ADMX.** Use the Chrome ADMX
   templates already installed in your Intune tenant.
   Configure:

    - `ExtensionInstallForcelist`: append
      `<extension-id>;https://clients2.google.com/service/update2/crx`.
    - `ExtensionSettings`: paste the JSON from §10.2 inline.

3. **Assignment scope.** Assign both the Win32 app and the ADMX
   policy to the same Azure AD group. Stage the rollout: assign
   to a 5 % pilot group with the lenient
   `bridge_mac_required: false` posture, watch the agent log
   for "bridge MAC verification failed" warnings for one week,
   then flip the policy to `bridge_mac_required: true` and
   expand the assignment.

#### 10.3.3 VMware Workspace ONE (cross-platform)

Workspace ONE uses one **Product** per platform target. The
cross-platform appeal is that the same `profile.json` /
`manifest.json` / public-key set ships to macOS, Windows, and
Linux endpoints with only the file-system layout changing.

1. **Files / Actions** payload — *Resources → Profiles & Baselines
   → Files / Actions*. Upload `profile.json`, `manifest.json`,
   and `rules/` as a single archive. Per-platform extraction
   path:

    | Platform | Extract to |
    | --- | --- |
    | macOS | `/Library/Application Support/secure-edge/` |
    | Windows | `%ProgramData%\secure-edge\` |
    | Linux | `/etc/secure-edge/` |

2. **Custom Settings** payload — per platform, ship the
   `config.yaml` from §10.1. Workspace ONE renders the YAML
   inline; no plist-to-YAML translation step is required.

3. **Sensors and compliance** — define a sensor that watches
   for the agent's heartbeat file (`/var/lib/secure-edge/heartbeat`
   or platform equivalent — see §7) and a compliance policy that
   flags any endpoint where the heartbeat has not updated in
   the last 24 h. This catches an agent that has been killed
   without the tray icon turning red.

> **Workspace ONE signature gotcha.** Workspace ONE re-archives
> uploaded payloads before deploying them. If you wrap the signed
> `profile.json` inside another archive layer, the on-disk
> filename still has to match what `config.yaml` references via
> `profile_path` — Workspace ONE will rename files inside an
> archive in some configurations. Verify with a single test
> endpoint before rolling out: the agent log emits one line on
> profile load failure with the absolute path it tried.

### 10.4 Defence-in-depth checklist

| Layer | Where it lives | Verified by |
| --- | --- | --- |
| Chrome browser policy | MDM-managed `ExtensionInstallForcelist` + `ExtensionSettings` | Browser admin console — extension cannot be removed by the user |
| Per-install bearer token (A2) | `api_token_path` on disk, `api_token_required: true` in `config.yaml` | `GET /api/status` returns 401 without `Authorization: Bearer …` (see §2.0) |
| Native-Messaging HMAC bridge (C1) | `bridge_mac_required: true` in `config.yaml` (reuses `api_token` as the HMAC key) | Agent stderr emits `bridge MAC verification failed` when an older extension talks to a strict-mode agent (§2.1) |
| Signed rule manifest (A3) | `rule_update_public_key` in `config.yaml`, `manifest.json` produced by `sign-rule-manifest` | Agent log emits one line on rule update; refuses to load any manifest that does not verify (§4) |
| Signed enterprise profile (D2) | `profile_public_key` in `config.yaml`, `profile.json` produced by `sign-enterprise-profile` | Agent log emits one line on profile load; refuses to load any unsigned profile when the key is configured (§3.1) |
| Risky-extension blocklist (B2) | Optional `risky_file_extensions` override in `config.yaml`; extension reads the baked-in 34-entry list otherwise | Extension surfaces the policy toast on `<input type=file>`, drag-drop, AND clipboard paste of any matched filename (§2.2) |

Each row is independently verifiable from the agent log or a
single API probe — the bundle is "deployed correctly" when every
row passes. A row failing in isolation does not break the others
(every defence is layered), but an operator running a fleet should
treat any persistent failure as a deployment regression and roll
back to the previous bundle.
