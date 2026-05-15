## DLP accuracy corpus

This directory holds the synthetic test corpus used by the large-scale
DLP accuracy test, [`accuracy_large_test.go`](../../accuracy_large_test.go),
and the regression baseline test, [`accuracy_regression_test.go`](../../accuracy_regression_test.go).

All samples are synthetic. No real secrets are committed here. True-positive
samples are produced by a deterministic generator that emits format-valid
random values. True-negative samples are realistic benign content that might
trip naive regex patterns (token-shaped hex/base64 strings inside code,
logs, docs, etc.) but contain no secrets the agent should block.

### Layout

```
testdata/corpus/
├── true_positives/
│   ├── cloud_providers/        # AWS, Azure, GCP, Firebase, Google API keys
│   ├── cloud_infrastructure/   # Cloudflare, DO, Vercel, Netlify, IaC, k8s/docker
│   ├── version_control/        # GitHub, GitLab, Bitbucket tokens
│   ├── ai_ml/                  # OpenAI, Anthropic, HuggingFace, etc.
│   ├── payment/                # Stripe, PayPal, Square, Braintree, etc.
│   ├── ci_cd/                  # CircleCI, Travis, Jenkins, GitLab CI
│   ├── messaging/              # Slack, Discord, Telegram, Twilio, etc.
│   ├── auth_identity/          # Auth0, Okta, Clerk, Keycloak, OAuth/OIDC
│   ├── java_ecosystem/         # JDBC, Spring, Maven, Gradle, Keystore
│   ├── rust_ecosystem/         # Cargo, Crates.io, Rocket
│   ├── frontend/               # React, Next.js, Vite, Angular, Webpack
│   ├── desktop/                # Electron, Tauri
│   ├── mobile/                 # iOS, Android, Flutter, Expo, Fastlane
│   ├── databases/              # Postgres, MySQL, MongoDB, Redis, MSSQL, …
│   ├── private_keys/           # PEM blocks
│   ├── jwt/                    # JWT tokens
│   ├── password_in_code/       # Language-specific password literals
│   ├── pii/                    # SSN, credit cards, emails (bulk), phones (bulk)
│   ├── package_managers/       # npm, PyPI, RubyGems, NuGet, Hex.pm, …
│   └── other_generic/          # Generic API Key, Source Code Imports, IaC blocks
└── true_negatives/
    ├── code_snippets/          # Real Go/Python/JS/Java/Rust code, no secrets
    ├── log_output/             # Server / build / CI logs with hex IDs, timestamps
    ├── documentation/          # README fragments, API docs, tutorials w/ placeholders
    ├── yaml_configs/           # k8s, docker-compose, GitHub Actions w/ placeholders
    ├── json_payloads/          # package.json, tsconfig.json, API responses
    ├── markdown/               # Markdown w/ code fences, token-format strings
    ├── stack_traces/           # Java/Python/Go/Node stack traces (hex addrs)
    ├── tickets/                # Issue / PR text discussing key rotation
    ├── ai_prompts/             # Typical developer prompts to ChatGPT/Claude
    ├── csv_data/               # Tabular exports
    └── natural_language/       # Prose, emails about security policy
```

### File format

Each corpus file is JSON Lines (`.jsonl`). Each line is one sample:

```json
{"id": "tp-aws-001", "category": "cloud_providers", "pattern": "AWS Access Key", "content_b64": "...", "expect_blocked": true, "context": "env file with mixed config", "source": "synthetic-v1"}
```

For true negatives the `pattern` field is omitted (or empty):

```json
{"id": "tn-code-001", "category": "code_snippets", "content_b64": "...", "expect_blocked": false, "context": "Go HTTP handler with no secrets", "source": "synthetic-v1"}
```

`source` tracks provenance for regression analysis. Multiple sources may
coexist in the same category — the loader scans every `.jsonl` file under
each subdirectory recursively.

#### Why is `content` base64-encoded?

The corpus deliberately contains thousands of format-valid synthetic
credentials (Stripe `sk_live_…`, Twilio `AC…`, GitHub `ghp_…`, AWS
`AKIA…`, etc.) — that's the entire point: the regex pipeline can only
be evaluated against values that match its production patterns. If
those values are committed in plaintext, GitHub's push-protection
secret scanner blocks the push and human reviewers see false alarms in
the file diffs.

To sidestep both, the generator stores each sample's content in
`content_b64` (standard base64). The test loader in
`accuracy_large_test.go` decodes the field once on read. Every *other*
field — `id`, `category`, `pattern`, `context`, `source` — remains
plaintext so reviewers can still scan a JSONL line and understand
which pattern, which context kind, and which expected outcome it
exercises. To inspect a single sample's content interactively:

```bash
jq -r '.content_b64' \
    agent/internal/dlp/testdata/corpus/true_positives/payment/synthetic-v1.jsonl \
    | head -1 | base64 -d
```

### Regenerating the corpus

The corpus is produced by a small Go program at
[`testdata/cmd/generate_corpus`](../cmd/generate_corpus). From the
`agent/` directory:

```bash
go run ./internal/dlp/testdata/cmd/generate_corpus
```

The generator is deterministic (seeded `math/rand`), so re-running it
produces an identical corpus given the same `rules/dlp_patterns.json`
input. After regenerating, run:

```bash
go test -tags=large -run TestDLPAccuracyLarge ./internal/dlp/
```

…to confirm the new corpus still satisfies the accuracy budgets.

### Adding samples by hand

You may append additional samples to any `.jsonl` file. Keep IDs unique
within the category and set `source` to a label other than `synthetic-v1`
(e.g. `manual-2026q2`, `oss-corpus-fixtures`) so the generator can be
re-run without clobbering hand-written entries — the generator only
writes files whose basename matches `synthetic-v1.jsonl`.

### Reports

Running the large-scale test writes a structured report to
`testdata/corpus/last_run_report.json`. CI uploads this as a build
artifact for regression tracking across PRs.

`testdata/corpus/baseline_report.json` (when present) is the locked-in
reference report. The regression test
([`accuracy_regression_test.go`](../../accuracy_regression_test.go))
fails if any per-category recall drops by more than 2 percentage points
or overall FP rate increases by more than 1 percentage point. Update the
baseline with:

```bash
go test -tags=large -run TestDLPAccuracyRegression \
    ./internal/dlp/ -args -update-baseline
```

(`-args` is required so `go test` passes `-update-baseline` to the test
binary rather than treating it as a `go test` flag.)

### Budgets

The large-scale test enforces:

| Metric            | Budget |
| ----------------- | ------ |
| Overall FP rate   | < 5%   |
| Overall FN rate   | < 3%   |
| Per-category FN   | < 10%  |

The old 50-sample smoke check
([`accuracy_smoke_test.go`](../../accuracy_smoke_test.go)) keeps the
looser PHASES.md budgets (FP < 10%, FN < 5%) for fast local iteration.
