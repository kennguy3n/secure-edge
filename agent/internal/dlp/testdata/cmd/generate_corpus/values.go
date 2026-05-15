// Per-pattern value generators.
//
// Each generator must produce a string that, when embedded in any of
// the TP context renderers in contexts.go, will match the
// corresponding regex in rules/dlp_patterns.json.
//
// For "assignment-style" patterns (e.g. (?i)foo\s*[:=]\s*['"]?VALUE)
// the generator returns the full keyword-and-value line because the
// keyword is part of the regex.

package main

import (
	"fmt"
	"math/rand"
	"strings"
)

// valueGen is a function that returns a synthetic regex-matching value.
type valueGen func(r *rand.Rand) string

// valueGenerators maps pattern name -> generator. Patterns not in this
// map are skipped at generation time with a warning.
var valueGenerators = map[string]valueGen{}

func init() {
	// Cloud providers — AWS / Azure / GCP / Firebase / Google
	valueGenerators["AWS Access Key"] = func(r *rand.Rand) string {
		return "AKIA" + randUpperAlnum(r, 16)
	}
	valueGenerators["AWS Secret Access Key"] = func(r *rand.Rand) string {
		return "aws_secret_access_key=" + randFromAlphabet(r, alnum+"+/", 40)
	}
	valueGenerators["AWS Session Token"] = func(r *rand.Rand) string {
		return "aws_session_token=" + randFromAlphabet(r, alnum+"+/=", 140)
	}
	valueGenerators["AWS ARN"] = func(r *rand.Rand) string {
		svc := pick(r, []string{"iam", "s3", "kms", "lambda", "sns", "sqs", "ec2"})
		return fmt.Sprintf("arn:aws:%s:us-east-1:%012d:", svc, r.Int63n(999_999_999_999))
	}
	valueGenerators["AWS MWS Key"] = func(r *rand.Rand) string {
		return "amzn.mws." + randUUID(r)
	}
	valueGenerators["AWS Java SDK BasicAWSCredentials"] = func(r *rand.Rand) string {
		ak := "AKIA" + randUpperAlnum(r, 16)
		sk := randFromAlphabet(r, alnum+"+/", 40)
		return fmt.Sprintf("new BasicAWSCredentials(%q, %q)", ak, sk)
	}
	valueGenerators["AWS Secrets Manager SecretString Paste"] = func(r *rand.Rand) string {
		body := randFromAlphabet(r, alnum+"+/=._-", 80)
		return fmt.Sprintf(`{"ARN":"arn:aws:secretsmanager:us-east-1:%012d:secret:prod/db","Name":"prod/db","SecretString":"%s"}`,
			r.Int63n(999_999_999_999), body)
	}
	valueGenerators["AWS ECR Login Token"] = func(r *rand.Rand) string {
		return "ECR_LOGIN_PASSWORD=" + randFromAlphabet(r, alnum+"+/=", 240)
	}
	valueGenerators["Azure Storage Account Key"] = func(r *rand.Rand) string {
		return "AccountKey=" + randFromAlphabet(r, alnum+"+/", 86) + "=="
	}
	valueGenerators["Azure AD Client Secret"] = func(r *rand.Rand) string {
		return "client_secret=" + randFromAlphabet(r, alnum+"~._-", 40)
	}
	valueGenerators["Azure SAS Token"] = func(r *rand.Rand) string {
		return "?sv=2024-11-04&ss=b&sig=" + randFromAlphabet(r, alnum+"%/+=", 64)
	}
	valueGenerators["Azure Connection String"] = func(r *rand.Rand) string {
		acct := randLowerAlnum(r, 12)
		key := randFromAlphabet(r, alnum+"+/", 86) + "=="
		return fmt.Sprintf("DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net", acct, key)
	}
	valueGenerators["Azure DevOps PAT"] = func(r *rand.Rand) string {
		return "azuredevops=" + randBase32Lower(r, 52)
	}
	valueGenerators["Azure Subscription ID"] = func(r *rand.Rand) string {
		return randUUID(r)
	}
	valueGenerators["Azure Key Vault GetSecret Paste"] = func(r *rand.Rand) string {
		vault := randLowerAlnum(r, 10)
		name := randLowerAlnum(r, 8)
		ver := randHex(r, 32)
		return fmt.Sprintf(`{"value":"prodSecret-%s","id":"https://%s.vault.azure.net/secrets/%s/%s"}`,
			randAlnum(r, 12), vault, name, ver)
	}
	valueGenerators["GCP Service Account Key"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`{"type": "service_account", "project_id": "prod-%s", "private_key_id": "%s"}`,
			randLowerAlnum(r, 10), randHex(r, 40))
	}
	valueGenerators["GCP OAuth Client Secret"] = func(r *rand.Rand) string {
		return "GOCSPX-" + randFromAlphabet(r, alnum+"_-", 28)
	}
	valueGenerators["Google API Key"] = func(r *rand.Rand) string {
		return "AIza" + randFromAlphabet(r, alnum+"_-", 35)
	}
	valueGenerators["Firebase Cloud Messaging Server Key"] = func(r *rand.Rand) string {
		return "AAAA" + randFromAlphabet(r, alnum+"_-", 7) + ":" + randFromAlphabet(r, alnum+"_-", 140)
	}
	valueGenerators["Firebase Web Config apiKey"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`apiKey: "AIza%s"`, randFromAlphabet(r, alnum+"_-", 35))
	}
	valueGenerators["GCP Secret Manager Payload Paste"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`{"payload": {"data": "%s"}, "name": "projects/prod-%s/secrets/db/versions/3"}`,
			randBase64(r, 80), randLowerAlnum(r, 6))
	}
	valueGenerators["Firebase App Distribution Token"] = func(r *rand.Rand) string {
		return "FIREBASE_TOKEN=" + randFromAlphabet(r, alnum+"_-/.", 60)
	}
	valueGenerators["Firebase Admin SDK Private Key"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`"private_key_id": "%s", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----\n", "client_email": "firebase-adminsdk-prod@%s.iam.gserviceaccount.com"`,
			randHex(r, 40), randLowerAlnum(r, 10))
	}
	valueGenerators["Google Services JSON API Key"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`"current_key": "AIza%s"`, randFromAlphabet(r, alnum+"_-", 35))
	}

	// cloud_infrastructure
	valueGenerators["Cloudflare API Token"] = func(r *rand.Rand) string {
		return "CLOUDFLARE_API_TOKEN=" + randFromAlphabet(r, alnum+"_-", 40)
	}
	valueGenerators["DigitalOcean Personal Access Token"] = func(r *rand.Rand) string {
		return "dop_v1_" + randHex(r, 64)
	}
	valueGenerators["DigitalOcean OAuth Token"] = func(r *rand.Rand) string {
		return "doo_v1_" + randHex(r, 64)
	}
	valueGenerators["Vercel Token"] = func(r *rand.Rand) string {
		return "VERCEL_TOKEN=" + randAlnum(r, 24)
	}
	valueGenerators["Netlify Personal Access Token"] = func(r *rand.Rand) string {
		return "nfp_" + randAlnum(r, 40)
	}
	valueGenerators["Supabase Service Role Key"] = func(r *rand.Rand) string {
		return "sbp_" + randAlnum(r, 40)
	}
	valueGenerators["Supabase JWT Secret"] = func(r *rand.Rand) string {
		return "SUPABASE_JWT_SECRET=" + randFromAlphabet(r, alnum+"+/=_-", 48)
	}
	valueGenerators["Heroku API Key"] = func(r *rand.Rand) string {
		return randUUID(r)
	}
	valueGenerators["Datadog API Key"] = func(r *rand.Rand) string {
		return "dd_api_key=" + randHex(r, 32)
	}
	valueGenerators["HashiCorp Vault Token"] = func(r *rand.Rand) string {
		return "hvs." + randFromAlphabet(r, alnum+"_-", 48)
	}
	valueGenerators["Terraform State Sensitive Value"] = func(r *rand.Rand) string {
		val := randAlnum(r, 32)
		return fmt.Sprintf(`"sensitive": true, "type": "string", "value": "%s"`, val)
	}
	valueGenerators["Terraform Cloud API Token"] = func(r *rand.Rand) string {
		return randAlnum(r, 16) + ".atlasv1." + randAlnum(r, 60)
	}
	valueGenerators["Spacelift API Key"] = func(r *rand.Rand) string {
		return "SPACELIFT_API_KEY_SECRET=" + randFromAlphabet(r, alnum+"._-", 48)
	}
	valueGenerators["env0 API Key"] = func(r *rand.Rand) string {
		return "ENV0_API_KEY_SECRET=" + randFromAlphabet(r, alnum+"._-", 48)
	}
	valueGenerators["Scalr API Token"] = func(r *rand.Rand) string {
		return "SCALR_TOKEN=" + randFromAlphabet(r, alnum+"._-", 48)
	}
	valueGenerators["Pulumi Stack Config Secret"] = func(r *rand.Rand) string {
		return "secure:v1:" + randFromAlphabet(r, alnum+"+/=_-", 48)
	}
	valueGenerators["Internal URLs"] = func(r *rand.Rand) string {
		host := randLowerAlnum(r, 8)
		tld := pick(r, []string{"internal", "corp", "intranet", "local"})
		return fmt.Sprintf("https://%s.%s/dashboard", host, tld)
	}
	valueGenerators["Kubernetes Secret YAML"] = func(r *rand.Rand) string {
		val := randBase64(r, 60)
		return joinLines(
			"apiVersion: v1",
			"kind: Secret",
			"metadata:",
			"  name: prod-db",
			"  namespace: production",
			"type: Opaque",
			"data:",
			"  password: "+val+"==",
		)
	}
	valueGenerators["Docker Registry Auth"] = func(r *rand.Rand) string {
		auth := randBase64(r, 40)
		// Use a non-example.com host so the global *.example.com regex
		// exclusion does not penalise the surrounding match.
		return fmt.Sprintf(`{"auths": {"registry.prod.internal": {"auth": "%s"}}}`, auth)
	}
	valueGenerators["Helm Values Password"] = func(r *rand.Rand) string {
		return "adminPassword: " + randAlnum(r, 20)
	}
	valueGenerators["Harbor Robot Token"] = func(r *rand.Rand) string {
		return fmt.Sprintf("robot$prod+%s=%s", randLowerAlnum(r, 8), randFromAlphabet(r, alnum+"._-", 36))
	}
	valueGenerators["Quay.io Encrypted Password"] = func(r *rand.Rand) string {
		return "QUAY_PASSWORD=" + randFromAlphabet(r, alnum+"._-", 40)
	}
	valueGenerators["GCR JSON Key Paste"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`{"type": "service_account", "project_id": "prod-%s", "private_key_id": "%s", "registry": "gcr.io"}`,
			randLowerAlnum(r, 8), randHex(r, 40))
	}

	// version_control
	valueGenerators["GitHub Personal Access Token"] = func(r *rand.Rand) string {
		return "ghp_" + randAlnum(r, 36)
	}
	valueGenerators["GitLab Personal Access Token"] = func(r *rand.Rand) string {
		return "glpat-" + randFromAlphabet(r, alnum+"_-", 24)
	}
	valueGenerators["Bitbucket Server Token (BBDC)"] = func(r *rand.Rand) string {
		return "BBDC-" + randFromAlphabet(r, alnum+"_-", 36)
	}
	valueGenerators["Bitbucket App Password"] = func(r *rand.Rand) string {
		return "BITBUCKET_APP_PASSWORD=" + randAlnum(r, 24)
	}

	// ai_ml
	valueGenerators["OpenAI Project API Key"] = func(r *rand.Rand) string {
		return "sk-proj-" + randFromAlphabet(r, alnum+"_-", 48)
	}
	valueGenerators["OpenAI Service Account Key"] = func(r *rand.Rand) string {
		return "sk-svcacct-" + randFromAlphabet(r, alnum+"_-", 48)
	}
	valueGenerators["OpenAI User API Key"] = func(r *rand.Rand) string {
		return "sk-" + randAlnum(r, 24) + "T3BlbkFJ" + randAlnum(r, 24)
	}
	valueGenerators["Anthropic API Key"] = func(r *rand.Rand) string {
		return "sk-ant-api03-" + randFromAlphabet(r, alnum+"_-", 88)
	}
	valueGenerators["HuggingFace Access Token"] = func(r *rand.Rand) string {
		return "hf_" + randAlnum(r, 36)
	}
	valueGenerators["Cohere API Key"] = func(r *rand.Rand) string {
		return "cohere_api_key=" + randAlnum(r, 40)
	}
	valueGenerators["Replicate API Token"] = func(r *rand.Rand) string {
		return "r8_" + randAlnum(r, 32)
	}
	valueGenerators["Pinecone API Key"] = func(r *rand.Rand) string {
		return "pinecone_api_key=" + randUUID(r)
	}
	valueGenerators["Mistral API Key"] = func(r *rand.Rand) string {
		return "mistral_api_key=" + randAlnum(r, 36)
	}
	valueGenerators["Weights and Biases API Key"] = func(r *rand.Rand) string {
		return "WANDB_API_KEY=" + randHex(r, 40)
	}
	valueGenerators["LangSmith API Key"] = func(r *rand.Rand) string {
		return "lsv2_pt_" + randAlnum(r, 36) + "_" + randAlnum(r, 12)
	}
	valueGenerators["Together AI API Key"] = func(r *rand.Rand) string {
		return "together_api_key=" + randHex(r, 64)
	}
	valueGenerators["Groq API Key"] = func(r *rand.Rand) string {
		return "gsk_" + randAlnum(r, 56)
	}

	// payment
	valueGenerators["Stripe Live Secret Key"] = func(r *rand.Rand) string {
		return "sk_live_" + randAlnum(r, 28)
	}
	valueGenerators["Stripe Restricted Key"] = func(r *rand.Rand) string {
		return "rk_live_" + randAlnum(r, 28)
	}
	valueGenerators["Square Access Token"] = func(r *rand.Rand) string {
		return "sq0atp-" + randFromAlphabet(r, alnum+"_-", 22)
	}
	valueGenerators["Square OAuth Secret"] = func(r *rand.Rand) string {
		return "sq0csp-" + randFromAlphabet(r, alnum+"_-", 43)
	}
	valueGenerators["Braintree Access Token"] = func(r *rand.Rand) string {
		return "access_token$production$" + randLowerAlnum(r, 16) + "$" + randHex(r, 32)
	}
	valueGenerators["Adyen API Key"] = func(r *rand.Rand) string {
		return "AQE" + randFromAlphabet(r, alnum+"+/=", 80)
	}
	valueGenerators["PayPal Client Secret"] = func(r *rand.Rand) string {
		return "PAYPAL_SECRET=E" + randFromAlphabet(r, alnum+"_-", 48)
	}
	valueGenerators["Plaid Client Secret"] = func(r *rand.Rand) string {
		return "PLAID_SECRET=" + randHex(r, 30)
	}
	valueGenerators["Coinbase Commerce API Key"] = func(r *rand.Rand) string {
		return "COINBASE_COMMERCE_API_KEY=" + randUUID(r)
	}
	valueGenerators["Vonage Nexmo API Secret"] = func(r *rand.Rand) string {
		return "vonage_api_secret=" + randAlnum(r, 16)
	}

	// ci_cd
	valueGenerators["CircleCI Personal Token"] = func(r *rand.Rand) string {
		return "CIRCLE_TOKEN=" + randHex(r, 40)
	}
	valueGenerators["Travis CI Token"] = func(r *rand.Rand) string {
		return "TRAVIS_TOKEN=" + randFromAlphabet(r, alnum+"_-", 30)
	}
	valueGenerators["Jenkins API Token"] = func(r *rand.Rand) string {
		return "JENKINS_TOKEN=" + randHex(r, 32)
	}
	valueGenerators["GitLab CI Pipeline Trigger Token"] = func(r *rand.Rand) string {
		return "glptt-" + randAlnum(r, 40)
	}

	// messaging
	valueGenerators["Slack Token"] = func(r *rand.Rand) string {
		kind := pick(r, []string{"a", "b", "p", "r", "s"})
		return "xox" + kind + "-" + randAlnum(r, 12) + "-" + randAlnum(r, 12) + "-" + randAlnum(r, 24)
	}
	valueGenerators["Discord Bot Token"] = func(r *rand.Rand) string {
		// The pattern's Aho-Corasick prefix is "MT" and the regex is
		// `[MN][A-Za-z\\d]{23,28}\\.[A-Za-z\\d_\\-]{6,7}\\.[A-Za-z\\d_\\-]{27,38}`.
		// We always start with "MT" so the prefix bucket fires and the
		// regex still matches (M is in [MN] and the second char T is in
		// the 23+ alnum span).
		return "MT" + randAlnum(r, 23) + "." + randFromAlphabet(r, alnum+"_-", 6) + "." + randFromAlphabet(r, alnum+"_-", 30)
	}
	valueGenerators["Discord Webhook URL"] = func(r *rand.Rand) string {
		id := fmt.Sprintf("%d", 100_000_000_000_000_000+r.Int63n(900_000_000_000_000_000))
		return "https://discord.com/api/webhooks/" + id + "/" + randFromAlphabet(r, alnum+"_-", 64)
	}
	valueGenerators["Telegram Bot Token"] = func(r *rand.Rand) string {
		bot := fmt.Sprintf("%010d", 1_000_000_000+r.Int63n(8_999_999_999))
		return bot + ":" + randFromAlphabet(r, alnum+"_-", 35)
	}
	valueGenerators["Twilio Account SID"] = func(r *rand.Rand) string {
		return "AC" + randHex(r, 32)
	}
	valueGenerators["Twilio API Key"] = func(r *rand.Rand) string {
		return "SK" + randHex(r, 32)
	}
	valueGenerators["SendGrid API Key"] = func(r *rand.Rand) string {
		return "SG." + randFromAlphabet(r, alnum+"_-", 22) + "." + randFromAlphabet(r, alnum+"_-", 43)
	}
	valueGenerators["Mailchimp API Key"] = func(r *rand.Rand) string {
		return randHex(r, 32) + "-us" + fmt.Sprintf("%d", 1+r.Intn(20))
	}

	// auth_identity
	valueGenerators["Auth0 Client Secret"] = func(r *rand.Rand) string {
		return "AUTH0_CLIENT_SECRET=" + randFromAlphabet(r, alnum+"_-", 64)
	}
	valueGenerators["Okta API Token"] = func(r *rand.Rand) string {
		return "00" + randFromAlphabet(r, alnum+"_-", 38)
	}
	valueGenerators["OneLogin API Credentials"] = func(r *rand.Rand) string {
		return "ONELOGIN_CLIENT_SECRET=" + randHex(r, 56)
	}
	valueGenerators["Keycloak Client Secret"] = func(r *rand.Rand) string {
		return "KEYCLOAK_CLIENT_SECRET=" + randUUID(r)
	}
	valueGenerators["Clerk Secret Key"] = func(r *rand.Rand) string {
		return "sk_live_" + randAlnum(r, 48)
	}
	valueGenerators["Clerk Publishable Key"] = func(r *rand.Rand) string {
		return "pk_live_" + randAlnum(r, 48)
	}
	valueGenerators["OAuth2 Refresh Token Assignment"] = func(r *rand.Rand) string {
		return "refresh_token=" + randFromAlphabet(r, alnum+"._-/+=", 60)
	}
	valueGenerators["OIDC ID Token Assignment"] = func(r *rand.Rand) string {
		return "id_token=eyJ" + randFromAlphabet(r, alnum+"_-", 32) + ".eyJ" +
			randFromAlphabet(r, alnum+"_-", 60) + "." + randFromAlphabet(r, alnum+"_-", 36)
	}
	valueGenerators["Auth0 Management API Token"] = func(r *rand.Rand) string {
		return "AUTH0_MGMT_TOKEN=eyJ" + randFromAlphabet(r, alnum+"_-", 60) + "." +
			randFromAlphabet(r, alnum+"_-", 60) + "." + randFromAlphabet(r, alnum+"_-", 36)
	}
	valueGenerators["Keycloak Admin Token"] = func(r *rand.Rand) string {
		// Prefix is "KEYCLOAK_". Use the KEYCLOAK_TOKEN form (one of the
		// regex's three accepted variable names) so the Aho-Corasick
		// bucket and the regex both match.
		return "KEYCLOAK_TOKEN=eyJ" + randFromAlphabet(r, alnum+"_-", 60) + "." +
			randFromAlphabet(r, alnum+"_-", 60) + "." + randFromAlphabet(r, alnum+"_-", 36)
	}

	// java_ecosystem
	valueGenerators["JDBC PostgreSQL URL with Password"] = func(r *rand.Rand) string {
		return fmt.Sprintf("jdbc:postgresql://db.prod.internal:5432/orders?user=svc&password=%s", randAlnum(r, 20))
	}
	valueGenerators["JDBC MySQL URL with Password"] = func(r *rand.Rand) string {
		return fmt.Sprintf("jdbc:mysql://db.prod.internal:3306/orders?user=svc&password=%s", randAlnum(r, 20))
	}
	valueGenerators["JDBC Oracle URL with Password"] = func(r *rand.Rand) string {
		return fmt.Sprintf("jdbc:oracle:thin:svc/%s@oracle.prod.internal:1521:ORCL", randAlnum(r, 20))
	}
	valueGenerators["JDBC SQL Server URL with Password"] = func(r *rand.Rand) string {
		return fmt.Sprintf("jdbc:sqlserver://db.prod.internal:1433;databaseName=orders;user=svc;password=%s", randAlnum(r, 20))
	}
	valueGenerators["Spring Datasource Password"] = func(r *rand.Rand) string {
		return "spring.datasource.password=" + randAlnum(r, 20)
	}
	valueGenerators["Spring OAuth2 Client Secret"] = func(r *rand.Rand) string {
		return "spring.security.oauth2.client.registration.google.client-secret=" + randAlnum(r, 40)
	}
	valueGenerators["Java Keystore Password"] = func(r *rand.Rand) string {
		return "-storepass " + randAlnum(r, 16)
	}
	valueGenerators["Maven Settings Password"] = func(r *rand.Rand) string {
		return "<password>" + randAlnum(r, 24) + "</password>"
	}
	valueGenerators["Gradle Repository Credentials"] = func(r *rand.Rand) string {
		return `credentials { username = "svc"; password = "` + randAlnum(r, 24) + `" }`
	}

	// rust_ecosystem
	valueGenerators["Cargo Registry Token"] = func(r *rand.Rand) string {
		return `[registry]
token = "` + randFromAlphabet(r, alnum+"_-", 48) + `"`
	}
	valueGenerators["Crates.io API Token"] = func(r *rand.Rand) string {
		return "cio" + randAlnum(r, 40)
	}
	valueGenerators["Rocket.toml Secret Key"] = func(r *rand.Rand) string {
		return `secret_key = "` + randFromAlphabet(r, alnum+"+/=_-", 48) + `"`
	}

	// frontend
	valueGenerators["React App Environment Secret"] = func(r *rand.Rand) string {
		field := pick(r, []string{"SECRET", "TOKEN", "API_KEY", "PASSWORD"})
		return "REACT_APP_" + field + "=" + randFromAlphabet(r, alnum+"_-", 24)
	}
	valueGenerators["Next.js Public Environment Secret"] = func(r *rand.Rand) string {
		field := pick(r, []string{"SECRET", "TOKEN", "API_KEY", "PASSWORD"})
		return "NEXT_PUBLIC_" + field + "=" + randFromAlphabet(r, alnum+"_-", 24)
	}
	valueGenerators["Vite Environment Secret"] = func(r *rand.Rand) string {
		field := pick(r, []string{"SECRET", "TOKEN", "API_KEY", "PASSWORD"})
		return "VITE_" + field + "=" + randFromAlphabet(r, alnum+"_-", 24)
	}
	valueGenerators["Angular Environment Secret"] = func(r *rand.Rand) string {
		val := randFromAlphabet(r, alnum+"_-", 24)
		return `environment.prod = { apiKey: "` + val + `" }`
	}
	valueGenerators["Webpack DefinePlugin Secret"] = func(r *rand.Rand) string {
		val := randFromAlphabet(r, alnum+"_-", 24)
		return `new webpack.DefinePlugin({ API_KEY: JSON.stringify("` + val + `") })`
	}

	// desktop
	valueGenerators["Tauri Signing Private Key"] = func(r *rand.Rand) string {
		return "TAURI_SIGNING_PRIVATE_KEY=" + randFromAlphabet(r, alnum+"+/=_-", 80)
	}
	valueGenerators["Electron Forge Publish Token"] = func(r *rand.Rand) string {
		return "FORGE_PUBLISH_TOKEN=" + randFromAlphabet(r, alnum+"_-", 36)
	}
	valueGenerators["Electron Builder Publish Credentials"] = func(r *rand.Rand) string {
		return "GH_TOKEN=" + randFromAlphabet(r, alnum+"_-", 36)
	}

	// mobile
	valueGenerators["Apple App Store Connect API Key ID"] = func(r *rand.Rand) string {
		return "KEY_ID=" + randUpperAlnum(r, 10)
	}
	valueGenerators["Apple Developer Team ID"] = func(r *rand.Rand) string {
		return "DEVELOPMENT_TEAM=" + randUpperAlnum(r, 10)
	}
	valueGenerators["Cocoapods Trunk Token"] = func(r *rand.Rand) string {
		return "COCOAPODS_TRUNK_TOKEN=" + randAlnum(r, 40)
	}
	valueGenerators["Xcode Cloud Secret"] = func(r *rand.Rand) string {
		field := pick(r, []string{"SECRET", "TOKEN", "KEY", "PASSWORD"})
		return "XCODE_CLOUD_" + field + "=" + randFromAlphabet(r, alnum+"_-", 24)
	}
	valueGenerators["Apple APNs Auth Key Filename"] = func(r *rand.Rand) string {
		return "AuthKey_" + randUpperAlnum(r, 10) + ".p8"
	}
	valueGenerators["Android Signing Store Password"] = func(r *rand.Rand) string {
		return `storePassword "` + randAlnum(r, 16) + `"`
	}
	valueGenerators["Play Console Service Account JSON"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`"type": "service_account",
"project_id": "prod-androidpublisher-%s"`, randLowerAlnum(r, 8))
	}
	valueGenerators["Android Maps API Key in local.properties"] = func(r *rand.Rand) string {
		return "MAPS_API_KEY=AIza" + randFromAlphabet(r, alnum+"_-", 35)
	}
	valueGenerators["Expo Access Token"] = func(r *rand.Rand) string {
		return "EXPO_TOKEN=" + randFromAlphabet(r, alnum+"_-", 36)
	}
	valueGenerators["React Native CodePush Deployment Key"] = func(r *rand.Rand) string {
		return `CodePushDeploymentKey = "` + randFromAlphabet(r, alnum+"_-", 37) + `"`
	}
	valueGenerators["Fastlane Match Password"] = func(r *rand.Rand) string {
		return "MATCH_PASSWORD=" + randAlnum(r, 24)
	}
	valueGenerators["EAS Build Secret"] = func(r *rand.Rand) string {
		field := pick(r, []string{"SECRET", "TOKEN", "KEY", "PASSWORD"})
		return "EAS_" + field + "=" + randFromAlphabet(r, alnum+"_-", 24)
	}
	valueGenerators["Flutter Dart Environment Secret"] = func(r *rand.Rand) string {
		// The pattern allows up to 32 non-alphanumeric chars between
		// flutter_dotenv and API_KEY, so flutter_dotenv['API_KEY'] (['
		// is non-alnum) is the canonical leak syntax. The .env between
		// flutter_dotenv and API_KEY is alphanumeric and breaks the regex.
		return `flutter_dotenv['API_KEY'] = "` + randFromAlphabet(r, alnum+"_-", 24) + `"`
	}

	// databases
	valueGenerators["Database Connection String"] = func(r *rand.Rand) string {
		return fmt.Sprintf("postgres://svc:%s@db.prod.internal:5432/orders", randAlnum(r, 20))
	}
	valueGenerators["MongoDB Atlas SRV Connection"] = func(r *rand.Rand) string {
		return fmt.Sprintf("mongodb+srv://svc:%s@cluster0.%s.mongodb.net/orders", randAlnum(r, 20), randLowerAlnum(r, 5))
	}
	valueGenerators["MSSQL Connection String with Password"] = func(r *rand.Rand) string {
		return fmt.Sprintf("Server=db.prod.internal;Database=orders;User Id=svc;Password=%s;", randAlnum(r, 20))
	}
	valueGenerators["Redis URL with Password"] = func(r *rand.Rand) string {
		return fmt.Sprintf("redis://svc:%s@redis.prod.internal:6379", randAlnum(r, 20))
	}
	valueGenerators["SQLite PRAGMA Encryption Key"] = func(r *rand.Rand) string {
		return `PRAGMA key = "` + randAlnum(r, 24) + `"`
	}
	valueGenerators["Cassandra Auth Provider Credentials"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`PlainTextAuthProvider("svc", "%s")`, randAlnum(r, 20))
	}
	valueGenerators["Elasticsearch URL with Credentials"] = func(r *rand.Rand) string {
		return fmt.Sprintf("https://svc:%s@elastic.prod.internal:9200/index/_search", randAlnum(r, 20))
	}

	// private_keys
	valueGenerators["Private Key Block"] = func(r *rand.Rand) string {
		kind := pick(r, []string{"RSA ", "EC ", "OPENSSH ", ""})
		body := randBase64(r, 200)
		return "-----BEGIN " + kind + "PRIVATE KEY-----\n" + body + "\n-----END " + kind + "PRIVATE KEY-----"
	}

	// jwt
	valueGenerators["JWT Token"] = func(r *rand.Rand) string {
		return "eyJ" + randFromAlphabet(r, alnum+"_-", 24) + "." +
			"eyJ" + randFromAlphabet(r, alnum+"_-", 60) + "." +
			randFromAlphabet(r, alnum+"_-", 36)
	}

	// password_in_code
	valueGenerators["Password Assignment"] = func(r *rand.Rand) string {
		field := pick(r, []string{"password", "passwd", "pwd"})
		return field + `="` + randAlnum(r, 16) + `"`
	}
	valueGenerators["Java Password Literal"] = func(r *rand.Rand) string {
		field := pick(r, []string{"password", "passwd", "secret", "apiKey"})
		return `String ` + field + ` = "` + randAlnum(r, 16) + `";`
	}
	valueGenerators["Rust Password Literal"] = func(r *rand.Rand) string {
		field := pick(r, []string{"password", "passwd", "secret", "api_key"})
		return `let ` + field + `: &str = "` + randAlnum(r, 16) + `";`
	}
	valueGenerators["Go Password Literal"] = func(r *rand.Rand) string {
		field := pick(r, []string{"password", "passwd", "secret", "apiKey"})
		return field + ` := "` + randAlnum(r, 16) + `"`
	}
	valueGenerators["Swift Password Literal"] = func(r *rand.Rand) string {
		field := pick(r, []string{"password", "passwd", "secret", "apiKey"})
		return `let ` + field + `: String = "` + randAlnum(r, 16) + `"`
	}
	valueGenerators["Kotlin Password Literal"] = func(r *rand.Rand) string {
		field := pick(r, []string{"password", "passwd", "secret", "apiKey"})
		return `val ` + field + `: String = "` + randAlnum(r, 16) + `"`
	}
	valueGenerators["Dart Password Literal"] = func(r *rand.Rand) string {
		field := pick(r, []string{"password", "passwd", "secret", "apiKey"})
		return `final ` + field + ` = "` + randAlnum(r, 16) + `";`
	}
	valueGenerators["Python Secret Key Literal"] = func(r *rand.Rand) string {
		field := pick(r, []string{"SECRET_KEY", "API_KEY", "PRIVATE_KEY", "PASSWORD"})
		return field + ` = "` + randAlnum(r, 24) + `"`
	}

	// pii — these patterns need min_matches >= 5 (emails, phones).
	valueGenerators["Email Addresses (bulk)"] = func(r *rand.Rand) string {
		var b strings.Builder
		for i := 0; i < 6; i++ {
			fmt.Fprintf(&b, "%s.%s@%s.io\n",
				randLowerAlnum(r, 6), randLowerAlnum(r, 5), randLowerAlnum(r, 6))
		}
		return b.String()
	}
	valueGenerators["Phone Numbers (bulk, US)"] = func(r *rand.Rand) string {
		var b strings.Builder
		for i := 0; i < 6; i++ {
			fmt.Fprintf(&b, "+1 (%d%d%d) %d%d%d-%d%d%d%d\n",
				2+r.Intn(8), r.Intn(10), r.Intn(10),
				r.Intn(10), r.Intn(10), r.Intn(10),
				r.Intn(10), r.Intn(10), r.Intn(10), r.Intn(10))
		}
		return b.String()
	}
	valueGenerators["US Social Security Number"] = func(r *rand.Rand) string {
		return fmt.Sprintf("%03d-%02d-%04d", 100+r.Intn(800), 10+r.Intn(89), 1000+r.Intn(8999))
	}
	valueGenerators["Credit Card Number"] = func(r *rand.Rand) string {
		// Visa: 4 + 15 digits = 16 total.
		var b strings.Builder
		b.WriteByte('4')
		for i := 0; i < 15; i++ {
			fmt.Fprintf(&b, "%d", r.Intn(10))
		}
		return b.String()
	}

	// package_managers
	valueGenerators["npm Token"] = func(r *rand.Rand) string {
		return "npm_" + randAlnum(r, 36)
	}
	valueGenerators["PyPI API Token"] = func(r *rand.Rand) string {
		return "pypi-" + randFromAlphabet(r, alnum+"_-", 110)
	}
	valueGenerators["RubyGems API Key"] = func(r *rand.Rand) string {
		return "rubygems_" + randHex(r, 48)
	}
	valueGenerators["Composer Packagist Token"] = func(r *rand.Rand) string {
		return "packagist_token=" + randAlnum(r, 48)
	}
	valueGenerators["NuGet API Key"] = func(r *rand.Rand) string {
		return "oy2" + randBase32Lower(r, 43)
	}
	valueGenerators["Hex.pm API Key"] = func(r *rand.Rand) string {
		return "HEX_API_KEY=" + randFromAlphabet(r, upper+digits, 48)
	}
	valueGenerators["Pub.dev OAuth Refresh Token"] = func(r *rand.Rand) string {
		return "PUB_DEV_TOKEN=" + randFromAlphabet(r, alnum+"._-/+=", 48)
	}
	valueGenerators["CocoaPods Trunk Session Cookie"] = func(r *rand.Rand) string {
		return "_pods_session=" + randFromAlphabet(r, alnum+"._%+/=-", 40)
	}

	// other_generic
	valueGenerators["Generic API Key"] = func(r *rand.Rand) string {
		return "api_key=" + randFromAlphabet(r, alnum+"_-", 32)
	}
	valueGenerators["Source Code Imports"] = func(r *rand.Rand) string {
		// Source Code Imports' regex matches `package <ident>` *or*
		// `import <ident>` / `from <ident>` / `require <ident>` / `use
		// <ident>` lines. The global exclusion
		// `^\s*(import|from|require|use|using)...` suppresses every
		// match in the latter set, so we anchor on multiple `package`
		// lines (which the global exclusion does not cover). The
		// surrounding imports still serve as additional un-suppressed
		// matches in the env_file context (where the match starts at
		// column 0); in code-style wrappers the first match line is
		// indented and only the subsequent `package` lines anchor at
		// column 0 after a `\n`, so we use four package lines to keep
		// the multi-match count >= min_matches=3 across all contexts.
		return joinLines(
			"package main",
			"package productionconfig",
			"package serviceregistry",
			"package paymentgateway",
			"import os",
			"import sys",
			"import json",
		)
	}
	valueGenerators["Ansible Vault Block"] = func(r *rand.Rand) string {
		return "$ANSIBLE_VAULT;1.1;AES256\n" + randHex(r, 200)
	}
	valueGenerators["Puppet Hiera eyaml Block"] = func(r *rand.Rand) string {
		return "ENC[PKCS7," + randFromAlphabet(r, alnum+"+/=", 64) + "]"
	}
	valueGenerators["Chef Encrypted Data Bag"] = func(r *rand.Rand) string {
		return fmt.Sprintf(`"cipher": "aes-256-cbc", "encrypted_data": "%s"`, randBase64(r, 80))
	}
}
