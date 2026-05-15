// Context renderers for true positive samples.
//
// Each renderer takes a regex-matching value (produced by a value
// generator in values.go), a list of pattern hotwords, and a *rand.Rand
// and returns (content, contextLabel). The renderer is responsible for
// placing at least one hotword close to the match when the pattern's
// require_hotword bit demands it. Hotwords are also placed in the
// surrounding text for non-require_hotword patterns so the entropy +
// hotword score combination clears the per-severity threshold reliably.

package main

import (
	"fmt"
	"math/rand"
	"strings"
)

// tpContextKinds enumerates the rotation order of TP context renderers.
// 16 entries means each pattern gets 16 distinct context flavours per
// generator run (some flavours repeat with different surrounding text).
var tpContextKinds = []string{
	"env_file",
	"json_config",
	"yaml_config",
	"go_code",
	"python_code",
	"js_code",
	"markdown_fence",
	"ci_log",
	"shell_history",
	"chat_paste",
	"dotnet_appsettings",
	"java_properties",
	"ruby_config",
	"php_config",
	"multiline_prose",
	"terraform_block",
}

func renderTP(kind, value string, hotwords []string, r *rand.Rand) (string, string) {
	// Pick a representative hotword (or empty if the pattern declares
	// none). The hotword is injected literally into the context so the
	// pattern's CheckHotwords scan finds it. We deliberately prefer
	// hotwords that do NOT contain any global proximity-exclusion
	// dictionary word as a substring — otherwise embedding the hot
	// keyword would silently trigger the global exclusion and zero
	// out the score (e.g. "firebase-admin" → "admin", "admin-cli" →
	// "admin", "root_password" → "root"). If every candidate is
	// unsafe we still fall back to a raw pick so the pattern has
	// *some* sentinel.
	hot := pickSafeHotword(hotwords, r)
	switch kind {
	case "env_file":
		return renderEnvFile(value, hot, r), ".env file with production credentials"
	case "json_config":
		return renderJSONConfig(value, hot, r), "JSON application config"
	case "yaml_config":
		return renderYAMLConfig(value, hot, r), "YAML application config"
	case "go_code":
		return renderGoCode(value, hot, r), "Go source with inline credential"
	case "python_code":
		return renderPythonCode(value, hot, r), "Python source with inline credential"
	case "js_code":
		return renderJSCode(value, hot, r), "JavaScript / TypeScript with inline credential"
	case "markdown_fence":
		return renderMarkdownFence(value, hot, r), "Markdown doc with code fence"
	case "ci_log":
		return renderCILog(value, hot, r), "CI/CD log fragment with leaked credential"
	case "shell_history":
		return renderShellHistory(value, hot, r), "Shell history fragment"
	case "chat_paste":
		return renderChatPaste(value, hot, r), "Chat paste with surrounding prose"
	case "dotnet_appsettings":
		return renderDotNetConfig(value, hot, r), ".NET appsettings.json fragment"
	case "java_properties":
		return renderJavaProperties(value, hot, r), "Java .properties file fragment"
	case "ruby_config":
		return renderRubyConfig(value, hot, r), "Ruby Rails config initializer"
	case "php_config":
		return renderPHPConfig(value, hot, r), "PHP config file fragment"
	case "multiline_prose":
		return renderMultilineProse(value, hot, r), "Multi-line paste with prose context"
	case "terraform_block":
		return renderTerraformBlock(value, hot, r), "Terraform .tf fragment with leaked credential"
	default:
		return value, "raw value"
	}
}

// hotwordTag returns a short fragment containing the chosen hotword so
// it can be inlined adjacent to the value. Patterns with tight
// hotword_window settings (e.g. Generic API Key with window=50) need
// the keyword within a handful of bytes of the match to fire reliably.
func hotwordTag(hot string) string {
	if hot == "" {
		return ""
	}
	return hot
}

// globalProximityWords mirrors the union of the two "*" / proximity
// dictionary exclusions declared in rules/dlp_exclusions.json. Any
// time one of these words appears within 50–80 bytes of a match the
// pipeline applies the global exclusion penalty (-3) which is enough
// to zero out most patterns. Hotwords containing these as
// substrings will silently re-trigger the exclusion if injected
// verbatim into the surrounding context — e.g. "firebase-admin"
// contains "admin", "admin-cli" contains "admin", "root_password"
// contains "root". We use this list to skip such hotwords when a
// safer alternative is available.
var globalProximityWords = []string{
	"placeholder", "example", "test", "dummy", "sample", "xxx",
	"your-", "your_", "fake", "redacted", "<redacted>", "changeme",
	"todo", "documentation", "tutorial", "mock", "your-api-key-here",
	"your_api_key_here", "insert_token_here", "insert_key_here",
	"replace_me", "fixme", "tbd", "lorem", "ipsum", "password123",
	"letmein", "admin", "root", "stub_", "fake_", "dummy_", "mock_",
	"test_", "demo_", "example_", "your-org", "your-project",
	"your-tenant", "acmecorp", "examplecorp", "exampleapp",
	"00000000", "11111111", "deadbeef", "cafebabe",
	"secret-placeholder",
}

// hotwordContainsExclusion reports whether the given hot keyword
// contains a global-exclusion proximity word as a substring (case
// insensitive). Such hotwords cause the pipeline to apply the global
// proximity exclusion and zero the score whenever the hotword is
// injected verbatim near the match.
func hotwordContainsExclusion(hot string) bool {
	lower := strings.ToLower(hot)
	for _, w := range globalProximityWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// pickSafeHotword chooses a hotword from hotwords that does not
// contain a global proximity-exclusion word. If no safe hotword is
// available it falls back to picking any hotword so the renderer still
// has something to inject (the corpus is the source of truth — better
// to embed an imperfect hot than nothing). Returns the empty string
// when the pattern has no hotwords configured.
func pickSafeHotword(hotwords []string, r *rand.Rand) string {
	if len(hotwords) == 0 {
		return ""
	}
	safe := make([]string, 0, len(hotwords))
	for _, h := range hotwords {
		if !hotwordContainsExclusion(h) {
			safe = append(safe, h)
		}
	}
	if len(safe) > 0 {
		return pick(r, safe)
	}
	return pick(r, hotwords)
}

// hotComment renders a `# hot` style comment used as a sentinel line
// directly above the value in line-oriented renderers (env, props, etc).
func hotComment(hot string) string {
	if hot == "" {
		return ""
	}
	return "# " + hot + " credential for production deployment"
}

func renderEnvFile(value, hot string, r *rand.Rand) string {
	lines := []string{
		"# production environment",
		"NODE_ENV=production",
		"LOG_LEVEL=info",
	}
	if c := hotComment(hot); c != "" {
		lines = append(lines, c)
	}
	lines = append(lines, value)
	if hot != "" {
		// Trailing sentinel keeps the chosen hot keyword within ~10
		// bytes of the match end so patterns with tight hotword
		// windows (e.g. Generic API Key: window=50) still fire.
		lines = append(lines, "# "+hot+" was rotated above")
	}
	lines = append(lines, "OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.prod.internal:4317")
	return joinLines(lines...)
}

func renderJSONConfig(value, hot string, r *rand.Rand) string {
	hotKey := or(hot, "service")
	return "{\n" +
		`  "env": "production",` + "\n" +
		`  "` + hotKey + `": "production",` + "\n" +
		`  "credential": "` + jsonEscape(value) + `",` + "\n" +
		`  "` + hotKey + `_note": "rotate quarterly",` + "\n" +
		`  "region": "us-east-1"` + "\n" +
		"}"
}

func renderYAMLConfig(value, hot string, r *rand.Rand) string {
	hotKey := or(hot, "service")
	return "production:\n" +
		"  " + hotKey + ": enabled\n" +
		"  credential: |\n    " + value + "\n" +
		"  " + hotKey + "_note: rotate quarterly\n" +
		"  region: us-east-1\n"
}

func renderGoCode(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"// production credentials loaded at boot",
		`func loadConfig() *Config {`,
		`    return &Config{`,
		`        Service: "prod-orders",`,
		`        Credential: "`+goEscape(value)+`", // `+hotTag+` token for production`,
		`        // `+hotTag+` rotated, please verify`,
		`    }`,
		`}`,
	)
}

func renderPythonCode(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"# production credentials loaded at boot",
		"def load_config():",
		"    return {",
		`        "service": "prod-orders",`,
		`        "credential": "`+pythonEscape(value)+`",  # `+hotTag+` token for production`,
		`        # `+hotTag+` rotated, please verify`,
		"    }",
	)
}

func renderJSCode(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"// production credentials",
		`export const config = {`,
		`  service: "prod-orders",`,
		`  credential: "`+jsEscape(value)+`", // `+hotTag+` token for production`,
		`  // `+hotTag+` rotated, please verify`,
		`  region: "us-east-1",`,
		`};`,
	)
}

func renderMarkdownFence(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"## Incident Notes",
		"",
		"Below is the production "+hotTag+" credential block that I just rotated.",
		"",
		"```",
		hotTag+" credential:",
		value,
		"# "+hotTag+" rotated above",
		"```",
		"",
		"Please rotate again next quarter.",
	)
}

func renderCILog(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "credential")
	return joinLines(
		"[2025-09-14T15:02:11Z] info: starting "+hotTag+" pipeline",
		"[2025-09-14T15:02:18Z] info: resolving environment for production",
		"[2025-09-14T15:02:22Z] error: leaked "+hotTag+" in build output:",
		"  "+value+"  # "+hotTag+" leaked above",
		"[2025-09-14T15:02:23Z] error: aborting build for "+hotTag,
	)
}

func renderShellHistory(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "prod")
	return joinLines(
		"$ history | tail -3",
		"$ deploy --service "+hotTag+" --env production",
		"$ export PROD_CRED='"+value+"'  # "+hotTag+" credential for production",
		"$ # "+hotTag+" rotated, please verify",
		"$ ./run-migrations.sh",
	)
}

func renderChatPaste(value, hot string, r *rand.Rand) string {
	speaker := pick(r, []string{"alice", "bob", "carol"})
	hotTag := or(hot, "credential")
	return joinLines(
		speaker+": leaked production "+hotTag+" from prod1, rotate after we restore:",
		"["+hotTag+"]",
		value,
		"["+hotTag+" rotated above, thanks!]",
	)
}

func renderDotNetConfig(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		`{`,
		`  "Logging": { "LogLevel": { "Default": "Information" } },`,
		`  "Production": {`,
		`    "`+hotTag+`": "prod",`,
		`    "Credential": "`+jsonEscape(value)+`", "`+hotTag+`Note": "rotate quarterly"`,
		`  }`,
		`}`,
	)
}

func renderJavaProperties(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"# production deployment",
		"environment=production",
		"region=us-east-1",
		"# "+hotTag+" credential below",
		value,
		"# "+hotTag+" rotated above",
		hotTag+".note=rotate quarterly",
	)
}

func renderRubyConfig(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"Rails.application.configure do",
		"  config.cache_classes = true",
		`  config.credential = "`+rubyEscape(value)+`"  # `+hotTag+` token for production`,
		"  # "+hotTag+" rotated, please verify",
		"end",
	)
}

func renderPHPConfig(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"<?php // production config",
		`return [`,
		`    "env" => "production",`,
		`    "credential" => "`+phpEscape(value)+`",  // `+hotTag+` token for production`,
		`    // `+hotTag+` rotated, please verify`,
		`];`,
	)
}

func renderMultilineProse(value, hot string, r *rand.Rand) string {
	prose := pick(r, []string{
		"I just paged the on-call after seeing this in the build logs.",
		"Quick heads-up — this leaked into a screenshot a contractor posted.",
		"From the disclosure ticket, here is the production blob:",
		"Reproducer attached; please rotate immediately.",
	})
	hotTag := or(hot, "credential")
	return joinLines(
		prose,
		"",
		"Production "+hotTag+":",
		value,
		"("+hotTag+" rotated above)",
		"",
		"Please ack within the hour.",
	)
}

func renderTerraformBlock(value, hot string, r *rand.Rand) string {
	hotTag := or(hot, "service")
	return joinLines(
		"# production terraform module",
		`resource "production_credential" "prod" {`,
		`  name        = "prod-orders"`,
		`  environment = "production"`,
		`  value       = "`+jsonEscape(value)+`"  # `+hotTag+` token for production`,
		`  # `+hotTag+` rotated, please verify`,
		`}`,
	)
}

func or(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

// The escape helpers are intentional identities. The synthetic
// wrapper does not need to be syntactically valid JSON / Go / Python
// / Ruby / PHP — the corpus loader treats every sample as opaque
// text, and the regex scanner expects to see the value byte-for-byte.
// Escaping `"` would break patterns whose match contains literal
// quotes (e.g. `String password = "..."`), and escaping `\n` would
// hide the multi-line structure for patterns like Private Key Block
// or Source Code Imports. The corpus writer (encoding/json on the
// outer object) handles all the JSON escaping necessary for the .jsonl
// envelope itself.
func jsonEscape(s string) string   { return s }
func goEscape(s string) string     { return s }
func jsEscape(s string) string     { return s }
func pythonEscape(s string) string { return s }
func rubyEscape(s string) string   { return s }
func phpEscape(s string) string    { return s }

// Quick guard: format strings cannot accept a single literal "%".
var _ = fmt.Sprintf
