# DLP Pattern Authoring Guide

This guide explains how to write a DLP pattern that lands in
[`rules/dlp_patterns.json`](../rules/dlp_patterns.json) and exclusions that
land in [`rules/dlp_exclusions.json`](../rules/dlp_exclusions.json).

For non-DLP rule changes (domains, categories) see
[rule-contribution-guide.md](./rule-contribution-guide.md).

## 1. Pipeline at a glance

The DLP pipeline runs seven steps per scan:

1. **Classifier** — returns one of `code`, `structured`, `credentials`,
   `natural`. The verdict is fed into the AC filter step (step 2) so
   patterns whose `content_types` does not include the verdict are
   dropped before regex validation.
2. **Aho-Corasick** — single-pass O(n) scan for all pattern prefixes.
3. **Regex revalidation** — runs the pattern's regex on a window around each
   AC hit; eliminates AC's false positives.
4. **Hotword proximity** — checks whether any of the pattern's `hotwords`
   appear within `hotword_window` bytes of the match.
5. **Entropy** — computes the Shannon entropy of `match.Value`. Values
   below `entropy_min` are penalised.
6. **Exclusion** — looks up dictionary and regex exclusions; the result is
   either *Hit* (subtracts `ExclusionPenalty`) or *SuppressEntirely*.
7. **Thresholding** — compares the aggregated score to the per-severity
   threshold (`critical=1`, `high=2`, `medium=3`, `low=4` by default).

Architecture details: [ARCHITECTURE.md](../ARCHITECTURE.md).

## 2. The pattern JSON schema

Every entry in `rules/dlp_patterns.json` is an object with these fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `name` | string | Human-readable label. Must be unique across the file. Shown in tray notifications. |
| `regex` | string | Go [RE2](https://github.com/google/re2/wiki/Syntax) regex. Compiled once at load. |
| `prefix` | string | Aho-Corasick prefix. **Lowercase**, **literal** (no metacharacters). Pick the longest invariant prefix of `regex` — e.g. `AKIA` for AWS keys, `sk-ant-api03-` for Anthropic. |
| `severity` | string | One of `critical`, `high`, `medium`, `low`. Drives the threshold check. |
| `score_weight` | int | Base score contribution. Conventionally `1` for single-shot patterns, `2` for patterns whose match is structurally narrow (e.g. typed UUID-shaped key IDs). |
| `hotwords` | []string | Words that, when present near the match, **boost** the score by `hotword_boost`. Lower-cased at evaluation. |
| `hotword_window` | int | How many bytes either side of the match to look for hotwords. Defaults to 200; widen for patterns that live deep inside config files. |
| `hotword_boost` | int | Score delta when at least one hotword fires. Conventionally `2`. |
| `require_hotword` | bool | When `true`, **no** block is issued unless at least one hotword matched. Use for patterns whose regex shape is shared with benign text (e.g. generic `password = "..."`). |
| `entropy_min` | float | Below this Shannon entropy the score is **penalised** by `EntropyPenalty`. Set `0` to disable the entropy gate. |
| `min_matches` | int | (optional) Require this many distinct matches in the same content before scoring; useful for low-signal regex like 16-digit credit card shapes. |
| `content_types` | []string | (optional) Restrict this pattern to one or more classifier verdicts: `"code"`, `"structured"`, `"credentials"`, `"natural"`. Empty / omitted means "match every classification" (backwards compatible). When non-empty, candidates produced from content whose `ClassifyContent` verdict is not in this list are dropped at the Aho-Corasick filter step before the regex pass. Use this to scope language-specific shapes (`String x = "..."`, `let x = "..."`) so they cannot fire on prose that happens to share the prefix. |

### Example: a high-signal cloud key

```json
{
  "name": "Anthropic API Key",
  "regex": "sk-ant-api03-[A-Za-z0-9_\\-]{80,}",
  "prefix": "sk-ant-api03-",
  "severity": "critical",
  "score_weight": 1,
  "hotwords": ["anthropic", "claude"],
  "hotword_window": 200,
  "hotword_boost": 2,
  "require_hotword": false,
  "entropy_min": 4.0
}
```

### Example: a low-signal generic shape

```json
{
  "name": "Java Password Literal",
  "regex": "(?i)String\\s+(?:password|passwd|pwd|secret|apiKey)\\s*=\\s*\\\"[^\\\"\\s]{8,}\\\"",
  "prefix": "String",
  "severity": "high",
  "score_weight": 1,
  "hotwords": ["java", "class", "import", "private", "public"],
  "hotword_window": 300,
  "hotword_boost": 2,
  "require_hotword": true,
  "entropy_min": 3.0
}
```

Note `require_hotword: true` — without it the regex would flag any `String x =
"abcdefgh"` literal in any text file.

## 3. Choosing a prefix

The Aho-Corasick pass is the hot path. It scans content in O(n) for **every
prefix in the rule set at once**. A good prefix is:

- **Literal** — no `[a-z]`, no `(?:foo|bar)`, no anchors. The AC trie can't
  represent them.
- **Lower-case** — the AC scan is case-insensitive only for the lowercase
  trie. Build your prefix in lowercase.
- **As long as possible while still always present in real matches**. For
  AWS keys, `AKIA` (4 chars) is the longest invariant. For Stripe live keys,
  `sk_live_` (8 chars). Longer prefixes → fewer false hits in the AC pass →
  fewer regex calls downstream.
- **Distinctive**. Don't use `api` or `key` as a prefix — every config file
  has those words. Use the actual token prefix.

If the regex genuinely has no invariant prefix (e.g. UUIDs), omit `prefix`.
The pattern will then run via the full-content fallback path, which is slower
but still correct.

## 4. When to use `require_hotword`

Set `require_hotword: true` whenever the regex alone is **ambiguous**.
Good candidates:

- Generic password assignments (`password = "..."`).
- Bare base64-shaped strings that could be JWT bodies, signatures, or
  unrelated content.
- 16/32-hex-char shapes (`[0-9a-f]{32}`) that also match commit SHAs and
  hashed identifiers.
- Patterns whose prefix is a common word (`secret`, `token`, `key`).

If `require_hotword` is set, populate `hotwords` with terms that always
appear in legitimate use of the secret — language keywords (`fn`, `class`,
`import`), config-file conventions (`spring.datasource`, `[registries]`), or
the platform name (`anthropic`, `auth0`, `clerk`).

## 5. Setting `entropy_min`

Shannon entropy of the matched string is a cheap "is this random?" check.

| Pattern shape | Recommended `entropy_min` |
| --- | --- |
| Long base62/base64 random strings | `4.0` — `4.5` |
| Hex strings | `3.0` — `3.5` |
| Short typed IDs (e.g. 10-char Apple Team ID) | `0` (disable) |
| Username / shape-only matches | `0` (disable) |
| Mixed alpha + URL chars | `3.0` |

When in doubt, leave `entropy_min: 0`. The hotword and exclusion machinery is
usually enough to keep FP rates within budget.

## 6. Writing an exclusion

Exclusions live in `rules/dlp_exclusions.json`. Two types:

### Dictionary exclusion

```json
{
  "applies_to": "AWS Access Key",
  "type": "dictionary",
  "words": ["AKIAIOSFODNN7EXAMPLE", "AKIA1234567890123456"],
  "match_type": "exact"
}
```

- `match_type: "exact"` — `match.Value` must equal one of `words`. Suppresses
  the match entirely.
- `match_type: "proximity"` (default) — any word appearing within `window`
  bytes of the match **subtracts** `ExclusionPenalty` from the score. Does
  not suppress entirely.

`applies_to` can be `"*"` to apply to every pattern.

### Regex exclusion

```json
{
  "applies_to": "Google API Key",
  "type": "regex",
  "pattern": "AIza[A-Za-z0-9_\\-]*(?:EXAMPL|TEST|DEMO|TUTORIAL|FAKE|DummyKey)",
  "suppress": true
}
```

When `suppress: true`, a regex hit on `match.Value` removes the match
entirely (same effect as an exact dictionary hit). Without `suppress`, the
regex hit subtracts `ExclusionPenalty`.

Use the suppressing form **only** when the regex unambiguously describes
docs-only content (e.g. tokens whose body contains literal `EXAMPLE`).

## 7. Scoring formula

For each `(pattern, match)` pair the pipeline computes:

```
score = pattern.score_weight
      + (hotword_present ? HotwordBoost : 0)
      + (entropy >= entropy_min ? EntropyBoost : EntropyPenalty)
      + (exclusion_hit ? ExclusionPenalty : 0)
      + (num_matches - 1) * MultiMatchBoost
```

Defaults (from `DefaultScoreWeights` in
[`agent/internal/dlp/types.go`](../agent/internal/dlp/types.go)):

```
HotwordBoost     = +2
EntropyBoost     = +1
EntropyPenalty   = -2
ExclusionPenalty = -3
MultiMatchBoost  = +1
```

A match blocks iff `score >= threshold(severity)`. Thresholds default to
`critical=1, high=2, medium=3, low=4` and are configurable at runtime via
`PUT /api/dlp/config`.

## 8. Testing your pattern locally

Add a test case to
[`agent/internal/dlp/patterns_extended_test.go`](../agent/internal/dlp/patterns_extended_test.go).
Pattern: 2+ true-positive cases, 1+ false-positive (benign content) case.

```go
{
    label: "My new pattern - happy path",
    content: "...real-looking secret...",
    allowedPatterns: []string{"My New Pattern"},
},
```

Run only your new case:

```bash
cd agent && go test -race -count=1 -v ./internal/dlp/ \
    -run 'TestExtendedPatterns_TruePositives/My_new_pattern'
```

Then run the smoke corpus to confirm the FP / FN budget is still met:

```bash
cd agent && go test -race -count=1 ./internal/dlp/ \
    -run TestDLPAccuracySmokeCorpus
```

The smoke test asserts **FP < 10 %** and **FN < 5 %**. The larger
5,000+-sample corpus and per-category regression check are gated
behind the `large` build tag — see
[SECURITY_RULES.md → Coverage notes](../SECURITY_RULES.md#coverage-notes).

## 9. Updating the manifest

After editing `dlp_patterns.json` or `dlp_exclusions.json`, regenerate the
SHA-256 entries in `rules/manifest.json`:

```bash
cd rules
python3 - <<'PY'
import hashlib, json, pathlib
m = json.loads(pathlib.Path("manifest.json").read_text())
for f in m["files"]:
    path = pathlib.Path(f["name"])
    if path.exists():
        f["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
pathlib.Path("manifest.json").write_text(json.dumps(m, indent=2) + "\n")
PY
```

Bump `manifest_version` if the changes are user-visible.
