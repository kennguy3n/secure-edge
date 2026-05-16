# Secure Edge Rule Contribution Guide

This guide explains how to add domains to the shipped ruleset. For DLP
pattern changes see
[dlp-pattern-authoring-guide.md](./dlp-pattern-authoring-guide.md).

## 1. Rule files at a glance

All rule files live under [`rules/`](../rules):

```
rules/
├── manifest.json         # signed inventory (version, per-file SHA-256)
├── ai_allowed.txt        # AI Allowed       (allow)
├── ai_chat_blocked.txt   # AI Chat Blocked  (deny)
├── ai_chat_dlp.txt       # AI Chat DLP      (allow_with_dlp / inspect)
├── ai_code_blocked.txt   # AI Code Blocked  (deny)
├── news.txt              # News             (allow)
├── phishing.txt          # Phishing         (deny)
├── social.txt            # Social           (allow)
├── dlp_patterns.json     # DLP regex / AC patterns
└── dlp_exclusions.json   # DLP false-positive exclusions
```

Domain list files are plain text. One domain per line. Comments start
with `#`. Lines may have a **leading dot** to match the domain and all
subdomains:

```
# block the entire deepseek.com tree
.deepseek.com
# block only the bare apex of evil.com
evil.com
```

Trailing whitespace, blank lines, and `#`-prefixed comments are ignored.

## 2. The three-state action model

Each category maps to one of three actions:

| Action | DNS layer | Proxy / extension layer |
| --- | --- | --- |
| `allow` | resolve | pass-through |
| `allow_with_dlp` (a.k.a. `inspect`) | resolve | DLP pipeline runs on body |
| `deny` | NXDOMAIN | n/a (blocked at DNS) |

Default actions are seeded in
[`agent/internal/store/store.go::seedDefaults`](../agent/internal/store/store.go).
Category names are derived from the rule-file basename at agent start
by `categoryFromPath` in
[`agent/cmd/agent/main.go`](../agent/cmd/agent/main.go) (e.g.
`ai_chat_blocked.txt` → `"AI Chat Blocked"`). Users or enterprise
profiles override the default via `category_policies` in `config.yaml`
or the profile.

## 3. Adding a domain

1. Pick the right list file from §1.
2. Add the domain in alphabetical order with a leading `.` if you want
   subdomain coverage.
3. Regenerate the SHA-256 for the file you edited and bump the
   manifest version:

   ```bash
   sha256sum rules/ai_chat_blocked.txt
   # then update the matching entry in rules/manifest.json and
   # bump manifest.json's "version" field
   ```

4. Open a PR. CI re-verifies every checksum in `manifest.json`.

## 4. Adding a category

1. Create the new `.txt` file under `rules/` (basename determines the
   category name — see `categoryFromPath`).
2. Add a SHA-256 entry under `manifest.json.files`.
3. Add a matching entry in
   [`agent/internal/store/store.go::seedDefaults`](../agent/internal/store/store.go)
   with the desired default action.
4. If the category needs DLP coverage too, follow
   [dlp-pattern-authoring-guide.md](./dlp-pattern-authoring-guide.md).

## 5. Testing locally

```bash
# unit tests cover loaders, AC, regex, hotword, entropy, exclusion,
# scoring, threshold, and pipeline integration
cd agent && make test

# manifest checksum integrity
cd agent && go test -run TestManifest ./internal/rules
```

The accuracy and integration tests in `agent/internal/dlp/` exercise
the full pattern set against the production `rules/*.json` — they flag
duplicate names, malformed regex, or missing required fields.

## 6. Submitting a PR

1. Branch from `main`. Use a descriptive branch name
   (`add-domain-foo`, `tighten-stripe-pattern`).
2. Keep PRs focused — one category or pattern family per PR.
3. Update [`CHANGELOG.md`](../CHANGELOG.md) if the change is
   user-visible (new category, behaviour change in scoring).
4. CI runs the full agent test suite, electron typecheck, and
   extension typecheck / build. PRs cannot land until CI is green.

## 7. Removing or relaxing a rule

The bar for **removing** a domain or **softening** a category is higher
than adding. Please include:

- A short rationale (e.g. *moved from deny to allow_with_dlp because
  the domain is now widely used for sanctioned dev workflows*).
- Any FP / FN evidence you have (issue links, support tickets).
- A test that demonstrates the new behaviour, where applicable.

Patterns we remove or relax leave a stub entry in
[`CHANGELOG.md`](../CHANGELOG.md) so operators know which version
stopped catching the old shape.
