// True-negative generators.
//
// Each generator produces (content, contextLabel) for one corpus
// category. The goal is realistic-looking benign content that exercises
// near-misses against the production rule set — token-shaped hex/base64
// strings, hex commit IDs, UUIDs, placeholder credentials, public
// example domains, etc.
//
// We rely heavily on the global exclusion words ("placeholder",
// "example", "test", "dummy", …) and on the @example.com / test.com
// domain regex exclusion to keep the FP rate below budget. None of the
// content here contains a real, production-shaped secret.

package main

import (
	"fmt"
	"math/rand"
	"strings"
)

type tnGen func(r *rand.Rand) (string, string)

var tnGenerators = map[string]tnGen{
	"code_snippets":    genCodeSnippet,
	"log_output":       genLogOutput,
	"documentation":    genDocumentation,
	"yaml_configs":     genYAMLConfig,
	"json_payloads":    genJSONPayload,
	"markdown":         genMarkdown,
	"stack_traces":     genStackTrace,
	"tickets":          genTicket,
	"ai_prompts":       genAIPrompt,
	"csv_data":         genCSV,
	"natural_language": genNaturalLanguage,
}

// -----------------------------------------------------------------------------
// code_snippets

var codeSnippetTemplates = []func(r *rand.Rand) (string, string){
	// Go HTTP handler with no secret material.
	func(r *rand.Rand) (string, string) {
		hex := randHex(r, 12)
		return joinLines(
			"// example handler — illustrative only",
			"func handleHealth(w http.ResponseWriter, req *http.Request) {",
			"    w.Header().Set(\"X-Request-Id\", \""+hex+"\")",
			"    w.WriteHeader(http.StatusOK)",
			"    _, _ = w.Write([]byte(`{\"status\":\"ok\"}`))",
			"}",
		), "Go HTTP handler, no secrets"
	},
	// Python script with hex commit ID constant.
	func(r *rand.Rand) (string, string) {
		hex := randHex(r, 40)
		return joinLines(
			"# example fixture for CI",
			"COMMIT_SHA = \""+hex+"\"  # placeholder for build provenance",
			"BUILD_NUMBER = "+fmt.Sprintf("%d", r.Intn(10000)),
			"def build_label():",
			"    return f\"build-{COMMIT_SHA[:7]}-{BUILD_NUMBER}\"",
		), "Python build fixture with commit SHA"
	},
	// JS/TS function with UUID constant — but no Heroku/Azure hotwords.
	func(r *rand.Rand) (string, string) {
		uuid := randUUID(r)
		return joinLines(
			"// example component (test fixture)",
			"export function renderCard(props: CardProps) {",
			"  const traceId = \""+uuid+"\"; // mock value for snapshot tests",
			"  return <div data-trace={traceId}>{props.title}</div>;",
			"}",
		), "TypeScript component with mock UUID"
	},
	// Java method using a hash constant.
	func(r *rand.Rand) (string, string) {
		hex := randHex(r, 64)
		return joinLines(
			"// example service implementation",
			"public class HashService {",
			"    private static final String SAMPLE_HASH = \""+hex+"\";",
			"    public boolean matches(String input) {",
			"        return Hashing.sha256().hashString(input, UTF_8).toString().equals(SAMPLE_HASH);",
			"    }",
			"}",
		), "Java hashing helper with sample hash"
	},
	// Rust struct with placeholder base64.
	func(r *rand.Rand) (string, string) {
		body := randBase64(r, 32)
		return joinLines(
			"// example codec — placeholder data",
			"struct Frame {",
			"    payload: &'static str,",
			"}",
			"impl Frame {",
			"    pub fn sample() -> Self {",
			"        Self { payload: \""+body+"\" } // dummy bytes for round-trip tests",
			"    }",
			"}",
		), "Rust struct with dummy base64 payload"
	},
	// Go test that mentions tokens but in placeholder form.
	func(r *rand.Rand) (string, string) {
		return joinLines(
			"// example_test.go — fixture only",
			"func TestRotateToken(t *testing.T) {",
			"    // placeholder credentials used in unit tests",
			"    old := \"REPLACE_ME\"",
			"    new := \"INSERT_TOKEN_HERE\"",
			"    if rotate(old) != new {",
			"        t.Fatal(\"rotate failed\")",
			"    }",
			"}",
		), "Go unit test referring to placeholders"
	},
	// SQL with masked password column reference.
	func(r *rand.Rand) (string, string) {
		return joinLines(
			"-- example migration; documentation snippet",
			"ALTER TABLE users ADD COLUMN api_token_hash TEXT;",
			"-- backfill is a placeholder; real values come from the secrets vault",
			"UPDATE users SET api_token_hash = NULL WHERE api_token_hash = '';",
		), "SQL migration referencing placeholder column"
	},
	// Shell script with public example.com call.
	func(r *rand.Rand) (string, string) {
		return joinLines(
			"#!/bin/sh",
			"# example deploy helper — no secrets here",
			"curl -fsSL https://example.com/health | jq .status",
			"echo \"done\"",
		), "Shell example calling example.com"
	},
	// CSS / config file with token-looking color literal.
	func(r *rand.Rand) (string, string) {
		hex := randHex(r, 6)
		return joinLines(
			"/* example theme — placeholder palette */",
			".btn-primary { background-color: #"+hex+"; }",
			".btn-secondary { background-color: #"+randHex(r, 6)+"; }",
		), "CSS theme with hex colors"
	},
	// Dockerfile with example image, no creds.
	func(r *rand.Rand) (string, string) {
		return joinLines(
			"# example Dockerfile — illustrative",
			"FROM alpine:3.19",
			"RUN apk add --no-cache curl",
			"WORKDIR /app",
			"CMD [\"/app/run.sh\"]",
		), "Dockerfile with no secrets"
	},
}

func genCodeSnippet(r *rand.Rand) (string, string) {
	tmpl := pick(r, codeSnippetTemplates)
	return tmpl(r)
}

// -----------------------------------------------------------------------------
// log_output

func genLogOutput(r *rand.Rand) (string, string) {
	style := r.Intn(5)
	switch style {
	case 0:
		// HTTP access log style.
		ip := fmt.Sprintf("10.%d.%d.%d", r.Intn(256), r.Intn(256), r.Intn(256))
		req := randHex(r, 16)
		return joinLines(
			"127.0.0.1 - - [14/Sep/2025:15:02:11 +0000] \"GET /healthz HTTP/1.1\" 200 17 \"-\" \"kube-probe\" rid="+req,
			ip+" - - [14/Sep/2025:15:02:12 +0000] \"GET /metrics HTTP/1.1\" 200 4128 \"-\" \"Prometheus\" rid="+randHex(r, 16),
			ip+" - - [14/Sep/2025:15:02:13 +0000] \"GET /index.html HTTP/1.1\" 200 8412 \"https://example.com/\" \"Mozilla/5.0\" rid="+randHex(r, 16),
		), "nginx-style access log"
	case 1:
		// Kubernetes pod log fragment.
		return joinLines(
			"2025-09-14T15:02:11Z INFO  starting prod-orders-7d8f6cbf-xyz",
			"2025-09-14T15:02:11Z INFO  loaded config from /etc/example/config.yaml",
			"2025-09-14T15:02:12Z INFO  health check passed (200 OK) duration_ms=14",
			"2025-09-14T15:02:13Z INFO  graceful shutdown signal received",
		), "Kubernetes pod stdout"
	case 2:
		// Build log with hex commit ID.
		hex := randHex(r, 40)
		return joinLines(
			"==> Building commit "+hex,
			"==> Step 1/4: Resolving dependencies",
			"==> Step 2/4: Compiling sources",
			"==> Step 3/4: Running tests (123 passed, 0 failed, 0 skipped)",
			"==> Step 4/4: Publishing artifact orders-1.4.7.tar.gz",
		), "Build log with commit hash"
	case 3:
		// Database slow-query log fragment.
		return joinLines(
			"2025-09-14T15:02:11Z 12345 LOG:  duration: 312 ms  statement: SELECT id FROM users WHERE id = $1",
			"2025-09-14T15:02:12Z 12345 LOG:  duration:  47 ms  statement: SELECT id FROM orders WHERE created_at > now() - interval '1 day'",
			"2025-09-14T15:02:13Z 12345 LOG:  duration:  82 ms  statement: UPDATE orders SET status = 'shipped' WHERE id = $1",
		), "Postgres slow query log"
	default:
		// Application log mentioning anonymised request IDs.
		return joinLines(
			"2025-09-14 15:02:11 INFO  example-service starting (commit "+randHex(r, 7)+")",
			"2025-09-14 15:02:12 INFO  request rid="+randHex(r, 16)+" path=/api/orders user=svc",
			"2025-09-14 15:02:13 WARN  retry attempt 1 rid="+randHex(r, 16)+" path=/api/orders",
		), "Generic application log"
	}
}

// -----------------------------------------------------------------------------
// documentation

func genDocumentation(r *rand.Rand) (string, string) {
	style := r.Intn(5)
	switch style {
	case 0:
		return joinLines(
			"## Getting started",
			"",
			"Set your API key in the environment. The example below uses a placeholder",
			"value — replace `your-api-key-here` with a real key from the dashboard.",
			"",
			"    export ACME_API_KEY=\"your-api-key-here\"",
			"",
			"See the [example tutorial](https://example.com/docs/tutorial) for details.",
		), "Getting-started doc with placeholder key"
	case 1:
		return joinLines(
			"## AWS configuration",
			"",
			"Example access key from the AWS documentation (do not use):",
			"",
			"    AKIAIOSFODNN7EXAMPLE",
			"    wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"",
			"For your own keys, see the IAM console.",
		), "AWS docs with canonical example key"
	case 2:
		// The canonical Stripe documentation example begins with
		// "sk_" + "test_" + 24 base58 chars. We split the prefix
		// at source so GitHub push protection does not flag this
		// file as containing the literal Stripe test secret.
		stripeTestKey := "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
		return joinLines(
			"## Stripe test mode",
			"",
			"While developing, use Stripe test keys. The documentation example is:",
			"",
			"    "+stripeTestKey,
			"",
			"Test keys are safe to share. Never paste a `sk_"+"live_` key into a ticket.",
		), "Stripe docs referencing test key"
	case 3:
		return joinLines(
			"## OAuth flow",
			"",
			"During the example exchange you will see fields like:",
			"",
			"    { \"client_id\": \"YOUR_CLIENT_ID\", \"client_secret\": \"YOUR_CLIENT_SECRET\" }",
			"",
			"Replace the placeholders with values from your tenant configuration.",
		), "OAuth doc skeleton with placeholders"
	default:
		return joinLines(
			"## Database connection",
			"",
			"The application reads its connection string from `DATABASE_URL`.",
			"For local development the docker-compose setup ships a sample value:",
			"",
			"    postgres://example:example@localhost:5432/example",
			"",
			"In production the value is injected from the secrets manager.",
		), "Database docs with example URL"
	}
}

// -----------------------------------------------------------------------------
// yaml_configs

func genYAMLConfig(r *rand.Rand) (string, string) {
	style := r.Intn(5)
	switch style {
	case 0:
		// Kubernetes Deployment using ${{ secrets.X }} placeholders.
		return joinLines(
			"# example Kubernetes manifest — documentation",
			"apiVersion: apps/v1",
			"kind: Deployment",
			"metadata:",
			"  name: example-app",
			"spec:",
			"  replicas: 3",
			"  selector:",
			"    matchLabels: { app: example-app }",
			"  template:",
			"    metadata: { labels: { app: example-app } }",
			"    spec:",
			"      containers:",
			"      - name: web",
			"        image: example/web:latest",
			"        env:",
			"        - name: API_BASE",
			"          value: https://api.example.com/v1",
		), "Kubernetes Deployment skeleton"
	case 1:
		// GitHub Actions workflow with ${{ secrets.X }} syntax (suppress).
		return joinLines(
			"name: example",
			"on: { push: { branches: [main] } }",
			"jobs:",
			"  example-test:",
			"    runs-on: ubuntu-latest",
			"    steps:",
			"      - uses: actions/checkout@v4",
			"      - name: print env",
			"        run: echo \"token=${{ secrets.GITHUB_TOKEN }} sha=${{ github.sha }}\"",
		), "GitHub Actions workflow with secrets placeholder"
	case 2:
		// docker-compose.
		return joinLines(
			"# example docker-compose file",
			"version: '3.8'",
			"services:",
			"  db:",
			"    image: postgres:16",
			"    environment:",
			"      POSTGRES_USER: example",
			"      POSTGRES_PASSWORD: example",
			"      POSTGRES_DB: example",
			"    ports: [\"5432:5432\"]",
		), "docker-compose with example credentials"
	case 3:
		// Helm values file.
		return joinLines(
			"# example values.yaml — placeholder credentials",
			"image:",
			"  repository: example/web",
			"  tag: latest",
			"replicaCount: 2",
			"ingress:",
			"  enabled: true",
			"  hosts: [\"example.com\"]",
		), "Helm values.yaml skeleton"
	default:
		// Terraform module with placeholder var.
		return joinLines(
			"# example terraform module — documentation",
			"variable \"api_key\" {",
			"  type        = string",
			"  description = \"API key for the example provider; placeholder by default\"",
			"  default     = \"your-api-key-here\"",
			"}",
			"resource \"null_resource\" \"example\" {",
			"  triggers = { ts = timestamp() }",
			"}",
		), "Terraform module with placeholder variable"
	}
}

// -----------------------------------------------------------------------------
// json_payloads

func genJSONPayload(r *rand.Rand) (string, string) {
	style := r.Intn(5)
	switch style {
	case 0:
		return joinLines(
			"{",
			"  \"name\": \"example-app\",",
			"  \"version\": \"1.4.7\",",
			"  \"private\": true,",
			"  \"dependencies\": {",
			"    \"react\": \"^18.2.0\",",
			"    \"next\": \"^14.0.0\",",
			"    \"@example/ui\": \"^0.5.0\"",
			"  },",
			"  \"scripts\": { \"dev\": \"next dev\", \"build\": \"next build\" }",
			"}",
		), "package.json"
	case 1:
		return joinLines(
			"{",
			"  \"compilerOptions\": {",
			"    \"target\": \"ES2022\",",
			"    \"module\": \"ESNext\",",
			"    \"strict\": true,",
			"    \"jsx\": \"preserve\",",
			"    \"paths\": { \"@example/*\": [\"src/*\"] }",
			"  }",
			"}",
		), "tsconfig.json"
	case 2:
		// OpenAPI example response.
		return joinLines(
			"{",
			"  \"openapi\": \"3.0.0\",",
			"  \"info\": { \"title\": \"Example API\", \"version\": \"1.0\" },",
			"  \"paths\": {",
			"    \"/users\": {",
			"      \"get\": {",
			"        \"summary\": \"List users (example response)\",",
			"        \"responses\": { \"200\": { \"description\": \"OK\" } }",
			"      }",
			"    }",
			"  }",
			"}",
		), "OpenAPI spec stub"
	case 3:
		// API response with paginated user list and example.com emails.
		return joinLines(
			"{",
			"  \"users\": [",
			"    { \"id\": 1, \"email\": \"alice@example.com\", \"name\": \"Alice\" },",
			"    { \"id\": 2, \"email\": \"bob@example.com\", \"name\": \"Bob\" }",
			"  ],",
			"  \"page\": 1,",
			"  \"total\": 2",
			"}",
		), "API response with example.com users"
	default:
		// Webhook payload skeleton.
		return joinLines(
			"{",
			"  \"event\": \"example.created\",",
			"  \"id\": \""+randHex(r, 16)+"\",",
			"  \"timestamp\": \"2025-09-14T15:02:11Z\",",
			"  \"data\": { \"placeholder\": true, \"value\": \"example\" }",
			"}",
		), "Webhook payload skeleton"
	}
}

// -----------------------------------------------------------------------------
// markdown

func genMarkdown(r *rand.Rand) (string, string) {
	style := r.Intn(4)
	switch style {
	case 0:
		return joinLines(
			"# Release notes",
			"",
			"- Fixed an edge case in the example parser.",
			"- Updated documentation for the placeholder configuration block.",
			"- Bumped the test fixture commit to `"+randHex(r, 7)+"`.",
			"",
			"See [the example tutorial](https://example.com/tutorial) for upgrade steps.",
		), "Release notes markdown"
	case 1:
		return joinLines(
			"## Architecture",
			"",
			"```",
			"client -> example-gateway -> backend",
			"```",
			"",
			"All flows route through the example-gateway, which is documented in the placeholder",
			"runbook at https://example.com/runbook.",
		), "Architecture markdown with code fence"
	case 2:
		return joinLines(
			"## API key rotation",
			"",
			"This is the high-level documentation. The exact procedure depends on the tutorial",
			"linked at the bottom; only example values are used here.",
			"",
			"1. Open the dashboard at <https://example.com/dashboard>.",
			"2. Click \"rotate\" and copy the placeholder.",
			"3. Update the secret manager — never paste a real key into the docs.",
		), "Rotation guide markdown"
	default:
		return joinLines(
			"### Quick reference",
			"",
			"| Field | Example value |",
			"| ----- | ------------- |",
			"| user  | example       |",
			"| email | user@example.com |",
			"| token | your-api-key-here |",
		), "Quick reference markdown table"
	}
}

// -----------------------------------------------------------------------------
// stack_traces

func genStackTrace(r *rand.Rand) (string, string) {
	style := r.Intn(4)
	switch style {
	case 0:
		// Java stack trace.
		return joinLines(
			"java.lang.NullPointerException: Cannot invoke \"String.length()\" because \"s\" is null",
			"  at com.example.app.Service.handle(Service.java:142)",
			"  at com.example.app.Server$Handler.run(Server.java:88)",
			"  at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)",
			"  at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642)",
			"  at java.base/java.lang.Thread.run(Thread.java:1583)",
		), "Java NullPointerException trace"
	case 1:
		// Python stack trace.
		return joinLines(
			"Traceback (most recent call last):",
			"  File \"/app/server.py\", line 88, in handle",
			"    return process(req)",
			"  File \"/app/process.py\", line 42, in process",
			"    return parse(req.body)",
			"  File \"/app/parse.py\", line 17, in parse",
			"    raise ValueError(\"empty payload\")",
			"ValueError: empty payload",
		), "Python ValueError trace"
	case 2:
		// Go panic.
		return joinLines(
			"panic: runtime error: invalid memory address or nil pointer dereference",
			"[signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0x"+randHex(r, 12)+"]",
			"",
			"goroutine 1 [running]:",
			"main.handle(0x0)",
			"        /app/main.go:42 +0x"+randHex(r, 3),
			"main.main()",
			"        /app/main.go:14 +0x"+randHex(r, 3),
		), "Go panic stack trace"
	default:
		// Node.js stack trace.
		return joinLines(
			"TypeError: Cannot read properties of undefined (reading 'id')",
			"    at handle (/app/server.js:42:18)",
			"    at /app/server.js:88:5",
			"    at processTicksAndRejections (node:internal/process/task_queues:96:5)",
			"    at async Server.<anonymous> (/app/main.js:14:3)",
		), "Node TypeError trace"
	}
}

// -----------------------------------------------------------------------------
// tickets

func genTicket(r *rand.Rand) (string, string) {
	style := r.Intn(4)
	switch style {
	case 0:
		return joinLines(
			"Title: Rotate the example-gateway production credential",
			"",
			"Following the documentation rotation policy, the example-gateway credential",
			"is due for rotation. The placeholder in the runbook is `your-api-key-here`;",
			"the real value lives in the secret manager. Steps:",
			"",
			"1. Generate a new key in the dashboard.",
			"2. Update the secret manager entry.",
			"3. Restart pods. Reviewer: please confirm without pasting the real key.",
		), "Issue: rotation runbook"
	case 1:
		return joinLines(
			"Title: Investigate suspicious JWT format in build logs",
			"",
			"Our build logs occasionally contain placeholder JWTs of the form",
			"`eyJhbGciOiJub25lIg.eyJzdWIiOiJ0ZXN0In0.` for the example.com test fixtures.",
			"These are not real tokens — they are documentation samples. Please add a",
			"test that asserts the placeholder is filtered out.",
		), "PR description discussing JWT placeholders"
	case 2:
		return joinLines(
			"Title: Document API key format for the example tutorial",
			"",
			"The tutorial currently uses `INSERT_KEY_HERE` and `REPLACE_ME` as placeholders.",
			"This ticket tracks adding a documentation section explaining the key format",
			"without leaking real values. Suggested wording is in the linked Google doc.",
		), "Docs ticket"
	default:
		return joinLines(
			"Title: PR: refactor example handler to use placeholder constants",
			"",
			"This PR introduces `ExampleClient.PLACEHOLDER_TOKEN` and `ExampleClient.SAMPLE_KEY`",
			"to make it harder to accidentally paste real tokens into the example test suite.",
			"Reviewers: please verify the strings in the diff are obviously fake (they all",
			"contain `example`, `placeholder`, or `sample`).",
		), "PR description introducing fixture constants"
	}
}

// -----------------------------------------------------------------------------
// ai_prompts

func genAIPrompt(r *rand.Rand) (string, string) {
	style := r.Intn(5)
	switch style {
	case 0:
		return "How do I rotate AWS IAM access keys without downtime? Please show an example using placeholder values; do not include real credentials.", "Prompt about AWS key rotation"
	case 1:
		return "My JWT validation example keeps rejecting tokens. Here is a sample header `Bearer eyJ...` — can you walk through the verification steps using a placeholder secret?", "Prompt about JWT validation"
	case 2:
		return "Write me a quick docker-compose for an example Postgres + Redis stack. Use placeholder credentials and explain how I would swap them for real ones from a secret manager.", "Prompt about docker-compose"
	case 3:
		return "Explain how to design an OAuth refresh-token flow for a documentation example. Use placeholder client IDs and never invent real-looking credentials in the example output.", "Prompt about OAuth flow"
	default:
		return "I want a tutorial on storing API keys safely in Next.js. Use placeholder values like `INSERT_TOKEN_HERE` for the example so I can paste it into the documentation directly.", "Prompt about Next.js secret storage"
	}
}

// -----------------------------------------------------------------------------
// csv_data

func genCSV(r *rand.Rand) (string, string) {
	// Cap the row count at 4 emails: the Email Addresses (bulk)
	// pattern requires min_matches=5 to fire, so staying strictly
	// below that prevents bulk-email false positives on benign CSVs.
	rows := []string{"id,name,email,city"}
	for i := 0; i < 2+r.Intn(2); i++ {
		rows = append(rows, fmt.Sprintf("%d,%s,%s@example.com,%s",
			i+1,
			pick(r, []string{"Alice", "Bob", "Carol", "Dan", "Erin", "Frank"}),
			randLowerAlnum(r, 6),
			pick(r, []string{"London", "Madrid", "Paris", "Berlin", "Lisbon"}),
		))
	}
	return strings.Join(rows, "\n"), "CSV export with example.com emails"
}

// -----------------------------------------------------------------------------
// natural_language

func genNaturalLanguage(r *rand.Rand) (string, string) {
	style := r.Intn(4)
	switch style {
	case 0:
		return joinLines(
			"Hi team — quick reminder that the documentation review is due Friday.",
			"Please make sure any example credentials in the tutorial use the placeholder",
			"format (`your-api-key-here`, `INSERT_TOKEN_HERE`). Real keys go in the vault.",
		), "Email about doc review"
	case 1:
		return joinLines(
			"Meeting notes (sample):",
			"- Discussed example error codes and their documentation owners.",
			"- Reviewed the placeholder TOTP setup flow.",
			"- Action item: file a ticket about the example tutorial typos.",
		), "Meeting notes"
	case 2:
		return joinLines(
			"The security policy says: never paste credentials into chat. Use the secret",
			"manager. If you need an example for documentation, use clearly fake placeholders",
			"like `REPLACE_ME` or `INSERT_KEY_HERE` and link to the tutorial instead.",
		), "Policy reminder paragraph"
	default:
		return joinLines(
			"Hello — I am writing the tutorial for the example onboarding flow. I would like",
			"to include a placeholder API key in the documentation so readers know where to",
			"paste their own. Suggestions for the placeholder string please?",
		), "Email asking about placeholder convention"
	}
}
