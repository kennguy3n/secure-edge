// Tests for the extended pattern set (Java / Rust / frontend /
// Electron / Tauri / AI-ML / iOS / Android / Flutter / RN / DB / cloud
// infra / CI-CD / messaging / payment / auth / password-in-code).
//
// Unlike pipeline_test.go (which uses an inline miniature pattern set)
// this file loads the real production rules/dlp_patterns.json and
// rules/dlp_exclusions.json so the assertions exercise the same
// pattern definitions that ship with the agent.

package dlp

import (
"context"
"path/filepath"
"runtime"
"testing"
)

// realPipeline builds a pipeline preloaded from the project's
// production rule files. Tests that need exclusion semantics or
// require_hotword from the real rules use this; tests that only need
// pattern detection without surrounding exclusion logic can still use
// the inline testPipeline.
func realPipeline(t *testing.T) *Pipeline {
t.Helper()
_, thisFile, _, _ := runtime.Caller(0)
// agent/internal/dlp/patterns_extended_test.go → repo root is three
// levels up from the directory of this file.
repo := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
patternsPath := filepath.Join(repo, "rules", "dlp_patterns.json")
exclusionsPath := filepath.Join(repo, "rules", "dlp_exclusions.json")

patterns, err := LoadPatterns(patternsPath)
if err != nil {
t.Fatalf("LoadPatterns(%s): %v", patternsPath, err)
}
exclusions, err := LoadExclusions(exclusionsPath)
if err != nil {
t.Fatalf("LoadExclusions(%s): %v", exclusionsPath, err)
}
p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(DefaultThresholds()))
p.Rebuild(patterns, exclusions)
return p
}

// extendedPositive describes a "this content must trip pattern X" test.
// allowedPatterns is the set of patterns that are acceptable as the
// top-scoring match — when more than one pattern can plausibly fire
// on the same content (e.g. AKIA inside BasicAWSCredentials hits both
// the broad AWS Access Key and the Java-SDK-specific pattern), we
// just need ONE of them to win.
type extendedPositive struct {
label            string
content          string
allowedPatterns  []string
}

// TestExtendedPatterns_TruePositives is one table-driven test per new
// pattern category. Two cases per category satisfies the brief.
func TestExtendedPatterns_TruePositives(t *testing.T) {
p := realPipeline(t)

cases := []extendedPositive{
// -- Task 1: Java ecosystem ----------------------------------
{
label: "Java JDBC PostgreSQL with embedded password",
content: "spring.datasource.url=jdbc:postgresql://db.internal:5432/" +
"orders?user=svc&password=S3rv1cE-PgX9mQ72LeapHorsE",
allowedPatterns: []string{
"JDBC PostgreSQL URL with Password",
"Database Connection String",
},
},
{
label: "Java keystore password literal",
content: "keytool -genkeypair -keystore release.jks -storepass " +
"R3leas3Pa$$word_Kp9 -keypass R3leas3Pa$$word_Kp9",
allowedPatterns: []string{"Java Keystore Password"},
},
{
label: "Spring datasource password",
content: "spring.datasource.url=jdbc:mysql://prod/users\n" +
"spring.datasource.password=Ub3rH4rdProdSecret!_42",
allowedPatterns: []string{
"Spring Datasource Password",
"JDBC MySQL URL with Password",
"Database Connection String",
"Password Assignment",
},
},
{
label: "AWS Java SDK BasicAWSCredentials",
content: "new BasicAWSCredentials(\"" + "AKIA" + "9F2D1JK4X8P0QRTM\", \"wJalrXUt" + "nFEMI/K7MDENG/bPxRfiCYE9KZkY5RPL\")",
allowedPatterns: []string{
"AWS Java SDK BasicAWSCredentials",
"AWS Access Key",
},
},

// -- Task 2: Rust --------------------------------------------
{
label: "Cargo registry token",
content: "# .cargo/credentials.toml for crates.io publish\n" +
"[registry]\ntoken = \"crates_iotokenR4K3piouseRBfGhWXyaC02cZmCJXtVZeV9pQwLhT\"",
allowedPatterns: []string{"Cargo Registry Token"},
},
{
label: "Rocket.toml secret key",
content: "# Rocket.toml\n[production]\nsecret_key = \"GtPWyTw7zb9hUEnzNoRSV3X1aXmJVqHRfWPaTrG0Pc\"",
allowedPatterns: []string{"Rocket.toml Secret Key"},
},

// -- Task 3: React/Angular/Frontend --------------------------
{
label: "React App env secret",
content: "// in .env for create-react-app\n" +
"REACT_APP_API_KEY=cra-prod-Q7sZ9pXmK3hLrT8nV2fW4yYbXk6E",
allowedPatterns: []string{"React App Environment Secret"},
},
{
label: "Next.js public env secret",
content: "// next.config.js process.env\n" +
"NEXT_PUBLIC_STRIPE_KEY=nxt_pub_GtPWyTw7zb9hUEnzNoRSV3X1",
allowedPatterns: []string{"Next.js Public Environment Secret"},
},
{
label: "Vite env secret",
content: "// vite.config.ts import.meta.env\n" +
"VITE_TOKEN=vit_QzXn9TpMrLb84Vfh6KsCw2YgEa7Hd",
allowedPatterns: []string{"Vite Environment Secret"},
},
{
label: "Firebase web config apiKey",
content: "firebase.initializeApp({\n" +
"  apiKey: \"" + "AIza" + "SyDLwxLO9rNwM5Bt4VuKf7QcJ2DhPmgZ31RJN\",\n" +
"  authDomain: \"my-app.firebaseapp.com\"\n" +
"});",
allowedPatterns: []string{
"Firebase Web Config apiKey",
"Google API Key",
},
},

// -- Task 4: Electron/Tauri ----------------------------------
{
label: "Tauri signing private key",
content: "TAURI_SIGNING_PRIVATE_KEY=dW50cnVzdGVkIGNvbW1lbnQ6IHJzaWduIGVuY3J5cHRlZCBzZWNyZXQga2V5VeryLongB64SignedBlob01234567890ABCDEFG",
allowedPatterns: []string{"Tauri Signing Private Key"},
},
{
label: "Electron Forge publish token",
content: "// CI env for electron-forge\n" +
"SNAPCRAFT_TOKEN=snap_TK_h5gJ2nP9wXcR4VzMqLaY7DfBoCk6Ut",
allowedPatterns: []string{"Electron Forge Publish Token"},
},

// -- Task 5: AI/ML platforms ---------------------------------
{
label: "OpenAI project key",
content: "// openai sdk client init\n" +
"OPENAI_API_KEY=" + "sk-" + "proj-" + "7XfBYrqZpKLM3HVeQT5cWN9JuAo2Dx1RtSGwIvZkUbHELONGRANDOMSEG",
allowedPatterns: []string{"OpenAI Project API Key"},
},
{
label: "OpenAI service account key",
content: "OPENAI_API_KEY=" + "sk-" + "svcacct-" + "9PqMxV2cHnB7aZyT5R8XfWLgEoDkUjY1NIvSGwEXTRAseglongRand",
allowedPatterns: []string{"OpenAI Service Account Key"},
},
{
label: "Anthropic API key",
content: "// claude client\n" +
"export ANTHROPIC_API_KEY=" + "sk-" + "ant-" + "api03-" + "V7Xq2HpL4cMt5Rk3GhJ9NbA1ZdYsErWoUiQxBnFvCmTaPyKjLgOsDhFeVcZxMtRpQwErTyUiOpAsDfGhJkLzXcVbNm",
allowedPatterns: []string{"Anthropic API Key"},
},
{
label: "HuggingFace token",
content: "huggingface-cli login --token " + "hf_" + "QrLp9zXk2VtMn7BcYsHfWoEiUaJdGxRYTU",
allowedPatterns: []string{"HuggingFace Access Token"},
},
{
label: "Groq API key",
content: "GROQ_API_KEY=" + "gsk_" + "KqWxRmZ9bV2nLcP7aT5Hjf3DyG6sUoE1IpAQ4HbXBNTrSV8RANDOMTAILLONG",
allowedPatterns: []string{"Groq API Key"},
},
{
label: "Replicate API token",
content: "REPLICATE_API_TOKEN=" + "r8_" + "9Pq2XmL4cVnR7BkTjHgYfWZaSdEoUbI",
allowedPatterns: []string{"Replicate API Token"},
},

// -- Task 6: iOS native --------------------------------------
{
label: "Apple APNs auth key filename",
content: "// fastlane lane :push do\n" +
"  apns_key_path: 'AuthKey_AB12CD34EF.p8'\n" +
"  apple_team_id: 'XYZ1234567'",
allowedPatterns: []string{"Apple APNs Auth Key Filename"},
},
{
label: "App Store Connect API key id",
content: "# appstore_connect config for fastlane apple asc deploy\n" +
"  issuer_id: a1b2c3d4e5f67890\n" +
"  key_id: 'K9P2QRMZNL'",
allowedPatterns: []string{
"Apple App Store Connect API Key ID",
},
},

// -- Task 7: Android native ----------------------------------
{
label: "google-services.json current_key",
content: "// firebase google-services.json client project_info\n" +
"\"current_key\": \"" + "AIza" + "SyD1234567ABCDEFqrSTuVwXyzABcDefGhIJ-Y\"",
allowedPatterns: []string{
"Google Services JSON API Key",
"Google API Key",
},
},
{
label: "Android signingConfigs password",
content: `android { signingConfigs { release { storeFile file('release.jks')` +
` storePassword "ProdReleaseStor3Pwd42" keyAlias "release"` +
` keyPassword "ProdReleaseKeyP4ssword42" } } }`,
allowedPatterns: []string{"Android Signing Store Password"},
},

// -- Task 8: Flutter / React Native --------------------------
{
label: "Expo access token",
content: "// .env for EAS Build\n" +
"EXPO_TOKEN=" + "eyJhbGciOiJI" + "UzI1NiJ9expoExtraLongRandomTokenForCI42",
allowedPatterns: []string{"Expo Access Token"},
},
{
label: "Fastlane Match password",
content: "// .env for fastlane match\n" +
"MATCH_PASSWORD=MatchProdR3p0Pa$$w0rd!42",
allowedPatterns: []string{"Fastlane Match Password"},
},

// -- Task 9: Database connection strings ---------------------
{
label: "MongoDB Atlas SRV with credentials",
content: "MONGODB_URI=mongodb+srv://service-user:Ub3rH4rdProdSecret42@" +
"cluster0.abcde.mongodb.net/orders",
allowedPatterns: []string{
"MongoDB Atlas SRV Connection",
"Database Connection String",
},
},
{
label: "MSSQL connection string with password",
content: "ConnectionString = \"Server=sql.prod.internal,1433;" +
"Database=Orders;User Id=svc_app;Password=Ub3rH4rdProdSecret42;\"",
allowedPatterns: []string{
"MSSQL Connection String with Password",
"Password Assignment",
},
},

// -- Task 10: Cloud infra ------------------------------------
{
label: "Cloudflare API token",
content: "// wrangler.toml env\n" +
"CLOUDFLARE_API_TOKEN=" + "k9P2qRmZnL5cVxBT4YjHfWoEi" + "UaJdGxRYTUNL_AbCdE",
allowedPatterns: []string{"Cloudflare API Token"},
},
{
label: "Vercel token",
content: "// .env.production for vercel\n" +
"VERCEL_TOKEN=NXqL9pZmK2cVjRT4HfYbWoEiUaJdGxRY",
allowedPatterns: []string{"Vercel Token"},
},
{
label: "DigitalOcean personal token",
content: "doctl auth init --access-token " + "dop_" + "v1_" +
"9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
allowedPatterns: []string{"DigitalOcean Personal Access Token"},
},
{
label: "Netlify token",
content: "// ntl login session\n" +
"NETLIFY_AUTH_TOKEN=" + "nfp_" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTUN",
allowedPatterns: []string{"Netlify Personal Access Token"},
},
{
label: "Supabase service role key",
content: "// supabase service_role key\n" +
"SUPABASE_SERVICE_ROLE=" + "sbp_" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTUN0Pq2",
allowedPatterns: []string{"Supabase Service Role Key"},
},

// -- Task 11: CI/CD ------------------------------------------
{
label: "GitLab pipeline trigger token",
content: "# .gitlab-ci.yml pipeline trigger\n" +
"PIPELINE_TRIGGER=" + "glptt-" + "9P2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqAbCd",
allowedPatterns: []string{"GitLab CI Pipeline Trigger Token"},
},
{
label: "Bitbucket Server token",
content: "# bitbucket data center access token\n" +
"Authorization: Bearer " + "BBDC-" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU",
allowedPatterns: []string{"Bitbucket Server Token (BBDC)"},
},

// -- Task 12: Messaging --------------------------------------
{
label: "Discord bot token",
content: "// discord bot token\n" +
"const DISCORD_TOKEN = '" + "MTEx" + "MjM0NTY3ODkwMTIzNDU2.GabcXY." +
"ABCDEFghijklmnopqrSTUVWXYZ0123456789';",
allowedPatterns: []string{"Discord Bot Token"},
},
{
label: "Telegram bot token",
content: "// telegram botfather bot token\n" +
"TELEGRAM_BOT_TOKEN=" + "8123456789" + ":AAEabcDEFghiJKLmnoPQRstuVWXyzABCDEF",
allowedPatterns: []string{"Telegram Bot Token"},
},

// -- Task 13: Payment ----------------------------------------
{
label: "Square access token",
content: "// squareup merchant\n" +
"SQUARE_ACCESS_TOKEN=" + "sq0" + "atp-Tk9P2qRmZnL5cVxBT4YjHa",
allowedPatterns: []string{"Square Access Token"},
},
{
label: "Adyen API key",
content: "# adyen payment api key\n" +
"ADYEN_API_KEY=" + "AQEvhmfu" + "XNWTK0Qc+iSHk3yqLEhWN9KZkY5RPLk9P2qRmZnL5cVxBT4YjHfWoEiUaJ",
allowedPatterns: []string{"Adyen API Key"},
},
{
label: "Plaid client secret",
content: "// plaid client_id and banking transactions\n" +
"PLAID_SECRET=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b",
allowedPatterns: []string{"Plaid Client Secret"},
},

// -- Task 14: Auth / Identity --------------------------------
{
label: "Auth0 client secret",
content: "# auth0 tenant client_id\n" +
"AUTH0_CLIENT_SECRET=K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqK9p2qRmZnL5cVxBT4YjHfW",
allowedPatterns: []string{
"Auth0 Client Secret",
"Azure AD Client Secret",
},
},
{
label: "Clerk secret key",
content: "// clerk.com backend frontend_api\n" +
"CLERK_SECRET_KEY=" + "sk_" + "live_" + "K9p2qRmZnL5cVxBT4YjHfWoEiUaJdGxRYTU0pqK9p2qRmZ",
allowedPatterns: []string{
"Clerk Secret Key",
"Stripe Live Secret Key",
},
},

// -- Task 15: Password-in-code -------------------------------
{
label: "Java password literal",
content: "package com.shipfast;\nimport java.util.*;\npublic class Conf {\n" +
"  String password = \"ProdServiceP4ss42xyz\";\n}",
allowedPatterns: []string{
"Java Password Literal",
"Password Assignment",
// Generic language-agnostic password literals also match
// the bare `password = "..."` shape; map iteration order
// decides which wins so we accept any of them.
"Rust Password Literal",
"Go Password Literal",
"Python Secret Key Literal",
},
},
{
label: "Rust password literal",
content: "use std::env;\nfn main() {\n" +
"  let password: &str = \"ProdServiceP4ss42xyz\";\n}",
allowedPatterns: []string{
"Rust Password Literal",
"Password Assignment",
"Java Password Literal",
"Go Password Literal",
"Python Secret Key Literal",
},
},
{
label: "Go password literal",
content: "package main\nimport \"fmt\"\nfunc main() {\n" +
"  password := \"ProdServiceP4ss42xyz\"\n  fmt.Println(password)\n}",
allowedPatterns: []string{
"Go Password Literal",
"Password Assignment",
"Java Password Literal",
"Rust Password Literal",
"Python Secret Key Literal",
},
},
{
label: "Python secret key literal",
content: "# django settings.py\nimport os\n" +
"SECRET_KEY = \"prodDjangoS3cretKeyForSigningCookies_Q9XmKpL\"",
allowedPatterns: []string{
"Python Secret Key Literal",
"Password Assignment",
},
},
}

for _, tc := range cases {
tc := tc
t.Run(tc.label, func(t *testing.T) {
got := p.Scan(context.Background(), tc.content)
if !got.Blocked {
t.Fatalf("expected block, got %+v", got)
}
if len(tc.allowedPatterns) == 0 {
return
}
for _, p := range tc.allowedPatterns {
if got.PatternName == p {
return
}
}
t.Fatalf("pattern = %q (score=%d), want one of %v",
got.PatternName, got.Score, tc.allowedPatterns)
})
}
}

// TestExtendedPatterns_FalsePositiveRegression asserts known benign
// content does NOT trigger a block, even though it contains
// pattern-like substrings. These cover the new exclusions added in
// rules/dlp_exclusions.json (Task 16/17).
func TestExtendedPatterns_FalsePositiveRegression(t *testing.T) {
p := realPipeline(t)

benign := []struct {
label   string
content string
}{
{
"OpenAI key in markdown docs",
"Set `OPENAI_API_KEY=" + "sk-" + "proj-" + "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE` in your `.env`.",
},
{
"AWS example key in tutorial",
"For example: AKIAIOSFODNN7EXAMPLE — do NOT commit real keys.",
},
{
"Stripe test key in docs",
"Use `" + "sk_" + "test_4242424242424242424242` during local development.",
},
{
"GitHub Actions template secret",
"runs:\n  - run: echo ${{ secrets.GITHUB_TOKEN }}",
},
{
"Discord token placeholder",
"// const token = 'YOUR_DISCORD_BOT_TOKEN'; // replace with your token",
},
{
"Firebase config in docs",
"```js\nconst firebaseConfig = { apiKey: \"" + "AIza" + "SyA12345678901234567890123456EXAMPLE\" };\n```",
},
{
"Test JSON fixture with sk_test",
"const stub = { stripe_key: '" + "sk_" + "test_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE' };",
},
{
"Code comment explaining format",
"// AWS access keys start with AKIA followed by 16 uppercase alphanumerics.",
},
{
"Import statement that looks like a token",
"import { ApiKey } from '@stripe/stripe-node';",
},
{
"Generic placeholders in prose",
"Please set your-api-key-here in CHANGEME.env before running.",
},
{
"Documentation phone numbers",
"Call 555-0100 to reach our example support line.",
},
{
"Mailinator email batch",
"contact: alice@example.com, bob@example.org, carol@test.com, dave@invalid",
},
{
"Reserved subscription id",
"AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000",
},
{
"Default localhost connection",
"DATABASE_URL=postgres://postgres:postgres@localhost:5432/myapp",
},
{
"Natural language with 'password'",
"Please choose a strong password before signing up; we never store your password in cleartext.",
},
}

for _, tc := range benign {
tc := tc
t.Run(tc.label, func(t *testing.T) {
got := p.Scan(context.Background(), tc.content)
if got.Blocked {
t.Fatalf("benign content blocked as %q (score=%d): %s",
got.PatternName, got.Score, tc.content)
}
})
}
}
