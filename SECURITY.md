# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in ShieldNet Secure Edge, please
report it privately so we can investigate and ship a fix before any
public disclosure.

**Contact:** open a draft GitHub security advisory at
<https://github.com/kennguy3n/secure-edge/security/advisories/new>.

If you can't use GitHub's security advisories, file a public issue
that says only "security report — please contact me" and we'll
respond with an alternate contact channel. **Do not include any
exploit details in a public issue.**

We aim to acknowledge new reports within **two business days** and
ship a fix within **30 days** of confirmation. Reports that affect
the privacy guarantees in [the threat model](#threat-model) — for
example, anything that causes scanned content, domain names, or
IP addresses to leak off-device — are treated as high-severity and
prioritised accordingly.

## Supported versions

Until ShieldNet Secure Edge reaches 1.0.0, only the latest minor release is
supported with security fixes. Older 0.x releases will not receive
back-ported patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Threat model

ShieldNet Secure Edge runs entirely on the user's device. The security
guarantees that we consider in-scope for this policy are:

1. **Privacy invariants** — the DLP pipeline must never persist
   scanned content, domain names, URLs, or IP addresses. The DNS
   resolver must never log queried names. Violations of this
   invariant are treated as **critical**, even if no remote code
   execution is involved.
2. **Local API confinement** — the local HTTP API on
   `127.0.0.1:8080` must reject requests from any non-loopback
   origin. Bypasses of the loopback check are **high-severity**.
3. **Self-update authenticity** — the agent's self-update path must
   reject release binaries whose SHA-256 or Ed25519 signature does
   not match the published manifest. Any path that lets an attacker
   inject a binary is **critical**.
4. **MITM proxy CA confinement** — the proxy's per-installation CA
   must be installed only in the user's trust store, must be
   removable via the GUI, and must not be re-used across
   installations. Issues here are **high-severity**.
5. **Native-messaging bridge integrity** — every non-`hello` frame
   on the extension ↔ agent Native Messaging connection is signed
   with HMAC-SHA256 (keyed by the per-install API token) over
   `nonce || direction_byte || id || kind || (content | blocked +
   token + error)`. The 16-byte nonce is minted per connection and
   surfaced in the intentionally unsigned (TOFU) `hello` reply.
   The agent enforces a strict-monotonic request id and rejects a
   second `hello` on the same connection. `bridge_mac_required`
   stages the rollout (`false`: warn, still serve; `true`: reject
   mismatched or missing MAC). Bypasses of MAC verification when
   `bridge_mac_required: true` are **high-severity**.
6. **Enterprise-profile authenticity** — enterprise profiles
   loaded from `profile_path`, fetched from `profile_url`, or
   imported through `POST /api/profile/import` carry an Ed25519
   signature over `profile.CanonicalForSigning` (which physically
   excludes the `signature` field via a dedicated body struct, so
   stripping or re-signing cannot produce a profile that verifies
   under a different operator's key). When `profile_public_key`
   is set, every loaded profile MUST verify against it; unsigned,
   tampered, or wrong-key-signed profiles are rejected before any
   policy is applied. With no key configured, the agent runs in a
   backwards-compatible warn-once posture. Bypasses of profile
   verification when `profile_public_key` is configured are
   **high-severity**.
7. **Risky-extension upload block** — the browser extension's
   `file-upload-interceptor` and `paste-interceptor` content
   scripts block uploads whose extension is on a policy-controlled
   risky list (default: 34 executable, installer, script,
   disk-image, and Java-archive extensions; `.js` intentionally
   excluded). The check runs synchronously before any content is
   read or sent to the agent, so neither filename nor contents
   leave the page when a match fires. All three entry points are
   guarded: `<input type=file>`, drag-drop, and clipboard paste
   (`clipboardData.files` and `clipboardData.items[].getAsFile()`).
   Operators may override the baked-in list via the agent's
   `risky_file_extensions` config key. Any bypass that lets a
   file with a listed extension reach the page's upload handler
   — or that leaks the filename or contents to the agent before
   the local check fires — is **medium-severity**.
8. **Clipboard-paste file scanning** — pasting a file (e.g. the
   user copied a file from their file manager, or pasted a
   screenshot from a clipboard tool) is handled by the same scan
   path as `<input type=file>` uploads. The paste interceptor
   reads `clipboardData.files` and
   `clipboardData.items[i].getAsFile()`, deduplicates, then
   honours the synchronous-first contract: `preventDefault()` and
   `stopPropagation()` fire **before** any `await`, the
   risky-extension guard from #7 runs first, and on a clean
   verdict the gesture is left suppressed (there is no portable
   way to programmatically reconstruct `DataTransfer.files` on
   the page side). On a mixed text-and-file paste the file path
   wins and the text fragment is never forwarded. Bypasses that
   let a clipboard-pasted file reach a Tier-2 page's upload
   handler without first passing the scan pipeline are
   **medium-severity**.

The following are explicitly **out of scope**:

- Vulnerabilities in upstream Go, Node.js, or Electron releases. We
  pick them up with our next dependency bump rather than filing
  duplicate advisories.
- Issues that require physical access to the device or root-level
  write access to the agent's binary directory.
- Denial-of-service attacks from the same loopback origin (a
  misbehaving local browser extension could overwhelm the agent;
  the documented mitigation is the rate limiter on
  `/api/dlp/scan`).
- Side-channel attacks against the local CPU.

## Responsible disclosure

If your report is valid and we ship a fix, we will credit you in
the release notes unless you ask us not to. Please do not publish
the details of the vulnerability before we publish the fix.

## Verifying a release

Every release published to
<https://github.com/kennguy3n/secure-edge/releases> ships with the
following artefacts you can use to verify integrity, authenticity,
and supply-chain provenance **before** running any installer:

| Artefact                          | Purpose                                                          |
| --------------------------------- | ---------------------------------------------------------------- |
| `SHA256SUMS`                      | SHA-256 of every other file in the release.                      |
| `SHA256SUMS.sig` / `.pem`         | Sigstore keyless signature + certificate over `SHA256SUMS`.      |
| `<artefact>.sig` / `.pem`         | Sigstore keyless signature + certificate over each artefact.     |
| `secure-edge-agent.cdx.json`      | CycloneDX SBOM for the Go agent (produced by syft).              |
| `secure-edge-electron.cdx.json`   | CycloneDX SBOM for the Electron tray app (produced by syft).     |
| `secure-edge-extension.cdx.json`  | CycloneDX SBOM for the browser extension (produced by syft).     |

In addition, each artefact has a SLSA Build Level 3 provenance
attestation stored in GitHub's [attestation store][gh-attest] and
verifiable with `gh attestation verify`.

Platform-native code signing (Apple Developer ID, Microsoft
Authenticode, Linux GPG package signatures) is **planned for a
future release**. Until those certificates are provisioned, the
Sigstore-based verification below is the authoritative trust
chain.

### One-shot verification recipe (Linux / macOS / WSL / git-bash)

```bash
# Required tools: gh (GitHub CLI), cosign >= 2.0, jq (optional, for SBOM inspection).
#   brew install gh cosign jq                     # macOS
#   sudo apt install gh jq && go install github.com/sigstore/cosign/v2/cmd/cosign@latest  # Debian/Ubuntu

TAG=v0.5.1   # adjust to the release you want to verify
REPO=kennguy3n/secure-edge

# 1) Download every asset from the release.
mkdir -p secure-edge-$TAG && cd secure-edge-$TAG
gh release download "$TAG" --repo "$REPO"

# 2) Verify integrity (offline). Should print "OK" for every line.
sha256sum -c SHA256SUMS

# 3) Verify SHA256SUMS authenticity. Queries the Rekor transparency log.
#    The --certificate-identity-regexp pins the signer to this repo's
#    release workflow on a v* tag; nothing else can produce a valid
#    signature for SHA256SUMS.
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp "^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/tags/v.+\$" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

# 4) Optional: verify a single artefact directly without going through SHA256SUMS.
cosign verify-blob \
  --certificate "secure-edge-agent-linux-amd64.pem" \
  --signature   "secure-edge-agent-linux-amd64.sig" \
  --certificate-identity-regexp "^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/tags/v.+\$" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  secure-edge-agent-linux-amd64

# 5) Verify SLSA build provenance (uses GitHub's attestation store).
gh attestation verify --owner kennguy3n secure-edge-agent-linux-amd64

# 6) Inspect SBOMs (optional).
jq '.metadata.component.name, (.components | length)' secure-edge-agent.cdx.json
```

If any of steps 2, 3, 4, or 5 fail, **do not run the installer**.
File a security advisory using the link at the top of this
document.

### What each verification step proves

- **Step 2 (`sha256sum -c`)** — bit-for-bit integrity of every
  artefact you downloaded against the published manifest. Catches
  corrupted downloads and tampered mirrors. Offline-only.
- **Step 3 (`cosign verify-blob SHA256SUMS`)** — proves the
  `SHA256SUMS` manifest itself was emitted by *this repository's*
  release workflow on a `v*` tag. The signing identity is a short-
  lived certificate issued by Sigstore's Fulcio CA, bound to the
  GitHub Actions OIDC subject for `kennguy3n/secure-edge`'s
  release workflow. The signature is recorded in the Rekor
  transparency log; you can independently verify it at
  <https://search.sigstore.dev>.
- **Step 4 (per-artefact `cosign verify-blob`)** — same proof
  as step 3 but for a single artefact, useful when you only
  download one file and don't want to fetch the entire release.
- **Step 5 (`gh attestation verify`)** — SLSA Build Level 3
  provenance: proves the artefact was built by GitHub-hosted
  runners from this repository's `Release` workflow, including
  the commit SHA, the workflow file path, and the runner image.
  Independent of cosign; uses GitHub's attestation API.

[gh-attest]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations
