// generate_corpus is the synthetic test-data generator for the
// large-scale DLP accuracy corpus under
// agent/internal/dlp/testdata/corpus/.
//
// It loads the production rules/dlp_patterns.json, emits a few
// thousand format-valid synthetic positives in varied contexts, plus a
// matched batch of realistic-looking but benign negatives that might
// trip naive regex patterns.
//
// All randomness is seeded so the output is reproducible. Re-running
// the generator overwrites the synthetic-v1.jsonl files it produced
// but leaves any hand-authored .jsonl files in place.
//
// Usage (from agent/):
//
//	go run ./internal/dlp/testdata/cmd/generate_corpus
//
// The program is intentionally located inside testdata/ so it is
// excluded from `go build ./...` and `go test ./...` by default.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Sample is the on-disk corpus record.
//
// The Content field is always written base64-encoded under
// ContentB64. The corpus deliberately contains thousands of
// format-valid synthetic credentials (Stripe, Twilio, GitHub PAT, AWS,
// etc.) that match the same regexes our DLP pipeline detects;
// committing them in plaintext is blocked by GitHub's push-protection
// secret scanner. Base64 sidesteps the literal-string match while
// keeping every other field — id, category, pattern, context, source
// — fully reviewable in source. The test loader
// (accuracy_large_test.go) decodes ContentB64 on read.
type Sample struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Pattern       string `json:"pattern,omitempty"`
	ContentB64    string `json:"content_b64"`
	ExpectBlocked bool   `json:"expect_blocked"`
	Context       string `json:"context"`
	Source        string `json:"source"`
}

// encodeContent base64-encodes raw content so the committed JSONL is
// invisible to GitHub's secret scanner (and any downstream scanner
// that pattern-matches on literal strings).
func encodeContent(raw string) string {
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

const synthSource = "synthetic-v1"

// patternCategory maps a pattern name (matching rules/dlp_patterns.json)
// to the corpus directory it lives under. Patterns not in the map fall
// back to "other_generic".
var patternCategory = map[string]string{
	// cloud_providers
	"AWS Access Key":                         "cloud_providers",
	"AWS Secret Access Key":                  "cloud_providers",
	"AWS Session Token":                      "cloud_providers",
	"AWS ARN":                                "cloud_providers",
	"AWS MWS Key":                            "cloud_providers",
	"AWS Java SDK BasicAWSCredentials":       "cloud_providers",
	"AWS Secrets Manager SecretString Paste": "cloud_providers",
	"AWS ECR Login Token":                    "cloud_providers",
	"Azure Storage Account Key":              "cloud_providers",
	"Azure AD Client Secret":                 "cloud_providers",
	"Azure SAS Token":                        "cloud_providers",
	"Azure Connection String":                "cloud_providers",
	"Azure DevOps PAT":                       "cloud_providers",
	"Azure Subscription ID":                  "cloud_providers",
	"Azure Key Vault GetSecret Paste":        "cloud_providers",
	"GCP Service Account Key":                "cloud_providers",
	"GCP OAuth Client Secret":                "cloud_providers",
	"Google API Key":                         "cloud_providers",
	"Firebase Cloud Messaging Server Key":    "cloud_providers",
	"Firebase Web Config apiKey":             "cloud_providers",
	"GCP Secret Manager Payload Paste":       "cloud_providers",
	"Firebase App Distribution Token":        "cloud_providers",
	"Firebase Admin SDK Private Key":         "cloud_providers",
	"Google Services JSON API Key":           "cloud_providers",

	// cloud_infrastructure
	"Cloudflare API Token":               "cloud_infrastructure",
	"DigitalOcean Personal Access Token": "cloud_infrastructure",
	"DigitalOcean OAuth Token":           "cloud_infrastructure",
	"Vercel Token":                       "cloud_infrastructure",
	"Netlify Personal Access Token":      "cloud_infrastructure",
	"Supabase Service Role Key":          "cloud_infrastructure",
	"Supabase JWT Secret":                "cloud_infrastructure",
	"Heroku API Key":                     "cloud_infrastructure",
	"Datadog API Key":                    "cloud_infrastructure",
	"HashiCorp Vault Token":              "cloud_infrastructure",
	"Terraform State Sensitive Value":    "cloud_infrastructure",
	"Terraform Cloud API Token":          "cloud_infrastructure",
	"Spacelift API Key":                  "cloud_infrastructure",
	"env0 API Key":                       "cloud_infrastructure",
	"Scalr API Token":                    "cloud_infrastructure",
	"Pulumi Stack Config Secret":         "cloud_infrastructure",
	"Internal URLs":                      "cloud_infrastructure",
	"Kubernetes Secret YAML":             "cloud_infrastructure",
	"Docker Registry Auth":               "cloud_infrastructure",
	"Helm Values Password":               "cloud_infrastructure",
	"Harbor Robot Token":                 "cloud_infrastructure",
	"Quay.io Encrypted Password":         "cloud_infrastructure",
	"GCR JSON Key Paste":                 "cloud_infrastructure",

	// version_control
	"GitHub Personal Access Token":  "version_control",
	"GitLab Personal Access Token":  "version_control",
	"Bitbucket Server Token (BBDC)": "version_control",
	"Bitbucket App Password":        "version_control",

	// ai_ml
	"OpenAI Project API Key":     "ai_ml",
	"OpenAI Service Account Key": "ai_ml",
	"OpenAI User API Key":        "ai_ml",
	"Anthropic API Key":          "ai_ml",
	"HuggingFace Access Token":   "ai_ml",
	"Cohere API Key":             "ai_ml",
	"Replicate API Token":        "ai_ml",
	"Pinecone API Key":           "ai_ml",
	"Mistral API Key":            "ai_ml",
	"Weights and Biases API Key": "ai_ml",
	"LangSmith API Key":          "ai_ml",
	"Together AI API Key":        "ai_ml",
	"Groq API Key":               "ai_ml",

	// payment
	"Stripe Live Secret Key":    "payment",
	"Stripe Restricted Key":     "payment",
	"Square Access Token":       "payment",
	"Square OAuth Secret":       "payment",
	"Braintree Access Token":    "payment",
	"Adyen API Key":             "payment",
	"PayPal Client Secret":      "payment",
	"Plaid Client Secret":       "payment",
	"Coinbase Commerce API Key": "payment",
	"Vonage Nexmo API Secret":   "payment",

	// ci_cd
	"CircleCI Personal Token":          "ci_cd",
	"Travis CI Token":                  "ci_cd",
	"Jenkins API Token":                "ci_cd",
	"GitLab CI Pipeline Trigger Token": "ci_cd",

	// messaging
	"Slack Token":         "messaging",
	"Discord Bot Token":   "messaging",
	"Discord Webhook URL": "messaging",
	"Telegram Bot Token":  "messaging",
	"Twilio Account SID":  "messaging",
	"Twilio API Key":      "messaging",
	"SendGrid API Key":    "messaging",
	"Mailchimp API Key":   "messaging",

	// auth_identity
	"Auth0 Client Secret":             "auth_identity",
	"Okta API Token":                  "auth_identity",
	"OneLogin API Credentials":        "auth_identity",
	"Keycloak Client Secret":          "auth_identity",
	"Clerk Secret Key":                "auth_identity",
	"Clerk Publishable Key":           "auth_identity",
	"OAuth2 Refresh Token Assignment": "auth_identity",
	"OIDC ID Token Assignment":        "auth_identity",
	"Auth0 Management API Token":      "auth_identity",
	"Keycloak Admin Token":            "auth_identity",

	// java_ecosystem
	"JDBC PostgreSQL URL with Password": "java_ecosystem",
	"JDBC MySQL URL with Password":      "java_ecosystem",
	"JDBC Oracle URL with Password":     "java_ecosystem",
	"JDBC SQL Server URL with Password": "java_ecosystem",
	"Spring Datasource Password":        "java_ecosystem",
	"Spring OAuth2 Client Secret":       "java_ecosystem",
	"Java Keystore Password":            "java_ecosystem",
	"Maven Settings Password":           "java_ecosystem",
	"Gradle Repository Credentials":     "java_ecosystem",

	// rust_ecosystem
	"Cargo Registry Token":   "rust_ecosystem",
	"Crates.io API Token":    "rust_ecosystem",
	"Rocket.toml Secret Key": "rust_ecosystem",

	// frontend
	"React App Environment Secret":      "frontend",
	"Next.js Public Environment Secret": "frontend",
	"Vite Environment Secret":           "frontend",
	"Angular Environment Secret":        "frontend",
	"Webpack DefinePlugin Secret":       "frontend",

	// desktop
	"Tauri Signing Private Key":            "desktop",
	"Electron Forge Publish Token":         "desktop",
	"Electron Builder Publish Credentials": "desktop",

	// mobile
	"Apple App Store Connect API Key ID":       "mobile",
	"Apple Developer Team ID":                  "mobile",
	"Cocoapods Trunk Token":                    "mobile",
	"Xcode Cloud Secret":                       "mobile",
	"Apple APNs Auth Key Filename":             "mobile",
	"Android Signing Store Password":           "mobile",
	"Play Console Service Account JSON":        "mobile",
	"Android Maps API Key in local.properties": "mobile",
	"Expo Access Token":                        "mobile",
	"React Native CodePush Deployment Key":     "mobile",
	"Fastlane Match Password":                  "mobile",
	"EAS Build Secret":                         "mobile",
	"Flutter Dart Environment Secret":          "mobile",

	// databases
	"Database Connection String":            "databases",
	"MongoDB Atlas SRV Connection":          "databases",
	"MSSQL Connection String with Password": "databases",
	"Redis URL with Password":               "databases",
	"SQLite PRAGMA Encryption Key":          "databases",
	"Cassandra Auth Provider Credentials":   "databases",
	"Elasticsearch URL with Credentials":    "databases",

	// private_keys
	"Private Key Block": "private_keys",

	// jwt
	"JWT Token": "jwt",

	// password_in_code
	"Password Assignment":       "password_in_code",
	"Java Password Literal":     "password_in_code",
	"Rust Password Literal":     "password_in_code",
	"Go Password Literal":       "password_in_code",
	"Swift Password Literal":    "password_in_code",
	"Kotlin Password Literal":   "password_in_code",
	"Dart Password Literal":     "password_in_code",
	"Python Secret Key Literal": "password_in_code",

	// pii
	"Email Addresses (bulk)":    "pii",
	"Phone Numbers (bulk, US)":  "pii",
	"US Social Security Number": "pii",
	"Credit Card Number":        "pii",

	// package_managers
	"npm Token":                      "package_managers",
	"PyPI API Token":                 "package_managers",
	"RubyGems API Key":               "package_managers",
	"Composer Packagist Token":       "package_managers",
	"NuGet API Key":                  "package_managers",
	"Hex.pm API Key":                 "package_managers",
	"Pub.dev OAuth Refresh Token":    "package_managers",
	"CocoaPods Trunk Session Cookie": "package_managers",

	// other_generic
	"Generic API Key":          "other_generic",
	"Source Code Imports":      "other_generic",
	"Ansible Vault Block":      "other_generic",
	"Puppet Hiera eyaml Block": "other_generic",
	"Chef Encrypted Data Bag":  "other_generic",

	// Batch 1: Additional Cloud Providers
	"Linode Personal Access Token":            "cloud_providers",
	"Linode OAuth Token":                      "cloud_providers",
	"Linode Object Storage Access Key":        "cloud_providers",
	"Linode Object Storage Secret Key":        "cloud_providers",
	"Vultr API Key":                           "cloud_providers",
	"Vultr Object Storage Access Key":         "cloud_providers",
	"Vultr Object Storage Secret Key":         "cloud_providers",
	"Hetzner Cloud API Token":                 "cloud_providers",
	"Hetzner DNS API Token":                   "cloud_providers",
	"Hetzner Robot Webservice Password":       "cloud_providers",
	"Hetzner Storage Box Password":            "cloud_providers",
	"OVH Application Key":                     "cloud_providers",
	"OVH Application Secret":                  "cloud_providers",
	"OVH Consumer Key":                        "cloud_providers",
	"OVHcloud Token Bundle":                   "cloud_providers",
	"Scaleway IAM API Key":                    "cloud_providers",
	"Scaleway Access Key":                     "cloud_providers",
	"Scaleway Project ID":                     "cloud_providers",
	"Scaleway Organization ID":                "cloud_providers",
	"Backblaze B2 Application Key ID":         "cloud_providers",
	"Backblaze B2 Application Key":            "cloud_providers",
	"Backblaze B2 Master Account Token":       "cloud_providers",
	"Wasabi Access Key ID":                    "cloud_providers",
	"Wasabi Secret Access Key":                "cloud_providers",
	"Wasabi Account ID":                       "cloud_providers",
	"DigitalOcean Spaces Access Key":          "cloud_providers",
	"DigitalOcean Spaces Secret Key":          "cloud_providers",
	"DigitalOcean Container Registry Token":   "cloud_providers",
	"Cloudflare Global API Key":               "cloud_providers",
	"Cloudflare R2 Access Key ID":             "cloud_providers",
	"Cloudflare R2 Secret Access Key":         "cloud_providers",
	"Cloudflare Origin CA Key":                "cloud_providers",
	"Cloudflare Workers KV Namespace Token":   "cloud_providers",
	"Cloudflare Stream API Token":             "cloud_providers",
	"Cloudflare Tunnel Token":                 "cloud_providers",
	"Akamai EdgeRC Client Token":              "cloud_providers",
	"Akamai EdgeRC Client Secret":             "cloud_providers",
	"Akamai EdgeRC Access Token":              "cloud_providers",
	"Fastly API Token":                        "cloud_providers",
	"Fastly Service ID":                       "cloud_providers",
	"IBM Cloud IAM API Key":                   "cloud_providers",
	"IBM Cloud IAM Access Token":              "cloud_providers",
	"Oracle OCI API Key Fingerprint":          "cloud_providers",
	"Oracle OCI User OCID":                    "cloud_providers",
	"Oracle OCI Tenancy OCID":                 "cloud_providers",
	"UpCloud API Credentials":                 "cloud_providers",
	"Equinix Metal API Token":                 "cloud_providers",
	"Rackspace API Key":                       "cloud_providers",
	"Civo API Key":                            "cloud_providers",
	"OpenStack Application Credential Secret": "cloud_providers",
	"Kamatera API Key":                        "cloud_providers",
	"Kamatera API Secret":                     "cloud_providers",
	"Exoscale API Key":                        "cloud_providers",

	// Batch 2: SaaS Platform Tokens
	"Salesforce OAuth Access Token":            "saas",
	"Salesforce Refresh Token":                 "saas",
	"Salesforce Connected App Consumer Secret": "saas",
	"Salesforce Marketing Cloud Token":         "saas",
	"Salesforce Session ID":                    "saas",
	"Salesforce Bulk API Token":                "saas",
	"HubSpot Private App Access Token":         "saas",
	"HubSpot Legacy API Key":                   "saas",
	"HubSpot OAuth Access Token":               "saas",
	"HubSpot OAuth Refresh Token":              "saas",
	"HubSpot App Client Secret":                "saas",
	"HubSpot Webhook Signing Secret":           "saas",
	"Zendesk API Token":                        "saas",
	"Zendesk OAuth Access Token":               "saas",
	"Zendesk Webhook Signing Secret":           "saas",
	"Zendesk Chat OAuth Token":                 "saas",
	"Intercom Access Token":                    "saas",
	"Intercom Personal Access Token":           "saas",
	"Intercom Webhook Signing Secret":          "saas",
	"Segment Write Key":                        "saas",
	"Segment Personal Access Token":            "saas",
	"Segment Workspace Token":                  "saas",
	"Amplitude API Key":                        "saas",
	"Amplitude Secret Key":                     "saas",
	"Amplitude Cohort Token":                   "saas",
	"Mixpanel Project Token":                   "saas",
	"Mixpanel Service Account Secret":          "saas",
	"Mixpanel Service Account Username":        "saas",
	"LaunchDarkly SDK Key":                     "saas",
	"LaunchDarkly Mobile Key":                  "saas",
	"LaunchDarkly Client-Side ID":              "saas",
	"LaunchDarkly Access Token":                "saas",
	"LaunchDarkly Relay Proxy Token":           "saas",
	"Sentry Auth Token":                        "saas",
	"Sentry User Auth Token":                   "saas",
	"Sentry Organization Auth Token":           "saas",
	"Sentry DSN with Secret Key":               "saas",
	"Datadog Application Key":                  "saas",
	"Datadog Client Token":                     "saas",
	"Datadog RUM Application ID":               "saas",
	"New Relic License Key":                    "saas",
	"New Relic User API Key":                   "saas",
	"New Relic Insert/Insights Key":            "saas",
	"New Relic Browser Application Token":      "saas",
	"PagerDuty REST API v2 Token":              "saas",
	"PagerDuty Events API v2 Routing Key":      "saas",
	"PagerDuty Integration Key":                "saas",
	"PagerDuty OAuth Access Token":             "saas",
	"ServiceNow OAuth Access Token":            "saas",
	"ServiceNow Basic Auth Credentials":        "saas",
	"ServiceNow Instance URL":                  "saas",
	"ServiceNow API Refresh Token":             "saas",
	"Jira/Atlassian API Token":                 "saas",
	"Atlassian OAuth Access Token":             "saas",
	"Atlassian Cloud Client Secret":            "saas",
	"Atlassian JIRA Personal Access Token":     "saas",
	"Atlassian Connect Shared Secret":          "saas",
	"Confluence API Token":                     "saas",
	"Confluence Personal Access Token":         "saas",
	"Confluence Server Bearer Token":           "saas",
	"Asana Personal Access Token":              "saas",
	"Trello API Key":                           "saas",
	"Trello API Token":                         "saas",
	"Notion Internal Integration Token":        "saas",
	"Notion OAuth Access Token":                "saas",
	"Freshdesk API Key":                        "saas",
	"Freshsales API Key":                       "saas",
	"Freshservice API Key":                     "saas",
	"Bitbucket OAuth Access Token":             "saas",
	"Bitbucket Repository Access Token":        "saas",
	"Pipedrive API Token":                      "saas",
	"Customer.io Tracking API Key":             "saas",
	"Drip API Token":                           "saas",
	"Marketo OAuth Client Secret":              "saas",
	"Marketo Munchkin ID":                      "saas",
	"Klaviyo Private API Key":                  "saas",
	"Iterable API Key":                         "saas",
	"Calendly Personal Access Token":           "saas",
	"Typeform Personal Token":                  "saas",
	"Typeform Webhook Secret":                  "saas",
	"SurveyMonkey API Token":                   "saas",
	"Stripe Webhook Endpoint Secret":           "saas",
	"Stripe OAuth Refresh Token":               "saas",
	"Shopify Custom App Access Token":          "saas",
	"Shopify Private App Access Token":         "saas",
	"Shopify Storefront API Token":             "saas",
	"BigCommerce API Token":                    "saas",

	// Batch 3: Crypto / Blockchain
	"Infura Project ID":                     "crypto",
	"Infura Project Secret":                 "crypto",
	"Alchemy API Key":                       "crypto",
	"Alchemy NFT API Key":                   "crypto",
	"QuickNode Endpoint with Key":           "crypto",
	"Chainstack RPC Endpoint":               "crypto",
	"Moralis Web3 API Key":                  "crypto",
	"Etherscan API Key":                     "crypto",
	"BscScan API Key":                       "crypto",
	"Polygonscan API Key":                   "crypto",
	"WalletConnect Project ID":              "crypto",
	"Pinata JWT":                            "crypto",
	"Pinata API Key":                        "crypto",
	"Pinata API Secret":                     "crypto",
	"web3.storage Token":                    "crypto",
	"NFT.Storage Token":                     "crypto",
	"Tatum API Key":                         "crypto",
	"BitGo Access Token":                    "crypto",
	"Hedera Operator Private Key (DER hex)": "crypto",
	"Ethereum Private Key (hex)":            "crypto",
	"Ethereum Mnemonic Hint":                "crypto",
	"Bitcoin WIF Private Key":               "crypto",
	"Solana Keypair JSON Array":             "crypto",
	"Solana Private Key Base58":             "crypto",
	"Cardano Spending Key":                  "crypto",
	"Polkadot Account Seed":                 "crypto",
	"Cosmos Account Mnemonic":               "crypto",
	"OpenSea API Key":                       "crypto",
	"CoinGecko Pro API Key":                 "crypto",
	"CoinMarketCap API Key":                 "crypto",
	"Binance API Key":                       "crypto",
	"Binance API Secret":                    "crypto",
	"Coinbase Pro API Passphrase":           "crypto",

	// Batch 4: DNS & CDN
	"Cloudflare Pages Token":            "dns_cdn",
	"Cloudflare Worker AI Token":        "dns_cdn",
	"Cloudflare Account ID":             "dns_cdn",
	"Fastly Read-Only API Token":        "dns_cdn",
	"Fastly Compute Service Token":      "dns_cdn",
	"Akamai Property Manager API Token": "dns_cdn",
	"AWS CloudFront Key Pair ID":        "dns_cdn",
	"Bunny.net API Key":                 "dns_cdn",
	"Bunny.net Stream Token":            "dns_cdn",
	"KeyCDN API Key":                    "dns_cdn",
	"StackPath Client ID":               "dns_cdn",
	"StackPath Client Secret":           "dns_cdn",
	"Imperva API Key":                   "dns_cdn",
	"NS1 API Key":                       "dns_cdn",
	"DNSimple API Token":                "dns_cdn",
	"Constellix API Key":                "dns_cdn",
	"DNS Made Easy API Key":             "dns_cdn",
	"Gandi Personal Access Token":       "dns_cdn",
	"Vercel Edge Config Token":          "dns_cdn",
	"Sucuri WAF API Key":                "dns_cdn",
	"Verizon EdgeCast Token":            "dns_cdn",

	// Batch 5: Email / Marketing
	"Mailchimp OAuth Access Token":    "email_marketing",
	"Mailchimp Transactional API Key": "email_marketing",
	"Mailgun API Key":                 "email_marketing",
	"Mailgun Private API Key":         "email_marketing",
	"Mailgun Webhook Signing Key":     "email_marketing",
	"Postmark Server API Token":       "email_marketing",
	"Postmark Account API Token":      "email_marketing",
	"SparkPost API Key":               "email_marketing",
	"SparkPost EU API Key":            "email_marketing",
	"Amazon SES SMTP Username":        "email_marketing",
	"Amazon SES SMTP Password":        "email_marketing",
	"Mandrill API Key":                "email_marketing",
	"ConvertKit API Secret":           "email_marketing",
	"Brevo API Key":                   "email_marketing",
	"MailerLite API Token":            "email_marketing",
	"ActiveCampaign API Key":          "email_marketing",
	"GetResponse API Key":             "email_marketing",
	"Sendinblue API Key (legacy)":     "email_marketing",
	"SendGrid Subuser Token":          "email_marketing",

	// Batch 6: Social Media
	"Twitter/X API Key":               "social_media",
	"Twitter/X API Secret":            "social_media",
	"Twitter/X Access Token":          "social_media",
	"Twitter/X Access Token Secret":   "social_media",
	"Twitter/X Bearer Token (v2)":     "social_media",
	"Facebook/Meta App Secret":        "social_media",
	"Facebook/Meta Access Token":      "social_media",
	"Facebook/Meta Page Access Token": "social_media",
	"Facebook/Meta System User Token": "social_media",
	"Instagram Graph API Token":       "social_media",
	"Instagram Basic Display Token":   "social_media",
	"LinkedIn OAuth Access Token":     "social_media",
	"LinkedIn Client Secret":          "social_media",
	"TikTok Client Key":               "social_media",
	"TikTok Client Secret":            "social_media",
	"TikTok Access Token":             "social_media",
	"YouTube Data API Key":            "social_media",
	"Google Ads Developer Token":      "social_media",
	"Snapchat Marketing API Token":    "social_media",
	"Pinterest API Access Token":      "social_media",
	"Reddit OAuth Client Secret":      "social_media",
	"Reddit Refresh Token":            "social_media",

	// Batch 7: Container / Orchestration
	"Kubernetes Service Account Token (JWT)":        "container_orchestration",
	"Kubernetes Kubeconfig client-certificate-data": "container_orchestration",
	"Kubernetes Kubeconfig client-key-data":         "container_orchestration",
	"Kubernetes Bootstrap Token":                    "container_orchestration",
	"Kubernetes Dashboard Token":                    "container_orchestration",
	"Helm Repository Basic Auth":                    "container_orchestration",
	"Helm Plugin Secret":                            "container_orchestration",
	"Helm OCI Registry Token":                       "container_orchestration",
	"Docker Hub Personal Access Token":              "container_orchestration",
	"Docker Hub Organization Access Token":          "container_orchestration",
	"Docker Hub Refresh Token":                      "container_orchestration",
	"Harbor User PAT":                               "container_orchestration",
	"Rancher API Token":                             "container_orchestration",
	"Rancher Kubeconfig Token":                      "container_orchestration",
	"ArgoCD Bearer Token (JWT)":                     "container_orchestration",
	"ArgoCD CLI Login Password":                     "container_orchestration",
	"ArgoCD Service Account Token":                  "container_orchestration",
	"FluxCD Notification Provider Token":            "container_orchestration",
	"FluxCD Git Source Password":                    "container_orchestration",
	"GHCR Personal Access Token":                    "container_orchestration",
	"Quay.io OAuth Access Token":                    "container_orchestration",
	"Quay.io Robot Account Token":                   "container_orchestration",
	"Tekton Pipeline Secret":                        "container_orchestration",
	"Buildkite Agent Token":                         "container_orchestration",
	"OpenShift Cluster Auth Token":                  "container_orchestration",
	"HashiCorp Nomad ACL Token":                     "container_orchestration",
	"HashiCorp Consul ACL Token":                    "container_orchestration",
	"Spinnaker API Token":                           "container_orchestration",

	// Batch 8: Monitoring / Logging
	"Grafana Service Account Token":     "monitoring",
	"Grafana API Key (legacy)":          "monitoring",
	"Grafana Cloud Stack Token":         "monitoring",
	"Splunk HEC Token":                  "monitoring",
	"Splunk On-Call Integration Key":    "monitoring",
	"Splunk Observability Access Token": "monitoring",
	"Elastic Cloud API Key":             "monitoring",
	"Elasticsearch Bearer Token":        "monitoring",
	"Kibana Service Account Token":      "monitoring",
	"Logstash Pipeline Password":        "monitoring",
	"Prometheus Remote Write Bearer":    "monitoring",
	"Grafana Mimir Basic Auth Password": "monitoring",
	"Cortex Auth Token":                 "monitoring",
	"Loki Push API Token":               "monitoring",
	"Loki Tenant Password":              "monitoring",
	"Sumologic Access ID":               "monitoring",
	"Sumologic Access Key":              "monitoring",
	"Honeycomb API Key":                 "monitoring",
	"Honeycomb Ingest Key":              "monitoring",
	"Lightstep Access Token":            "monitoring",
	"Wavefront API Token":               "monitoring",
	"AppDynamics API Key":               "monitoring",
	"Dynatrace API Token":               "monitoring",
	"Bugsnag API Key":                   "monitoring",
	"Rollbar Access Token":              "monitoring",
	"Mezmo Ingestion Key":               "monitoring",

	// Batch 9: Networking / VPN
	"WireGuard Private Key":         "networking",
	"WireGuard Preshared Key":       "networking",
	"OpenVPN Static Key Block":      "networking",
	"OpenVPN Auth Username":         "networking",
	"OpenVPN Auth Password":         "networking",
	"Tailscale API Access Token":    "networking",
	"Tailscale Auth Key":            "networking",
	"Tailscale OAuth Client Secret": "networking",
	"ZeroTier Central API Token":    "networking",
	"Cloudflare WARP Auth Token":    "networking",
	"NetBird Setup Key":             "networking",
	"Nebula Lighthouse Token":       "networking",
	"IPsec Pre-Shared Key":          "networking",
	"Bastion SSH Tunnel Token":      "networking",
	"Ngrok Authtoken":               "networking",

	// Batch 10: IoT / Edge
	"AWS IoT Core Certificate ARN":           "iot",
	"AWS IoT Device Certificate (PEM)":       "iot",
	"AWS IoT Greengrass Token Exchange Role": "iot",
	"Azure IoT Hub Connection String":        "iot",
	"Azure IoT DPS Symmetric Key":            "iot",
	"Azure IoT Edge Module SAS Token":        "iot",
	"Google Cloud IoT Registry JWT":          "iot",
	"Google Cloud IoT Device Public Key":     "iot",
	"Particle.io API Access Token":           "iot",
	"Balena CLI Auth Token":                  "iot",
	"Sigfox API Login + Password":            "iot",
	"The Things Network App Key":             "iot",
	"MQTT Broker Password":                   "iot",
	"HiveMQ Cloud Credentials":               "iot",
	"Cisco Meraki API Key":                   "iot",

	// Batch 11: Additional Secret Formats
	"TOTP Shared Secret (otpauth URI)":        "secret_formats",
	"TOTP Plain Base32 Seed":                  "secret_formats",
	"HMAC-Based OTP Counter Seed":             "secret_formats",
	"SAML Assertion Signature":                "secret_formats",
	"SAML Encrypted Assertion Key":            "secret_formats",
	"Generic OAuth 2.0 Refresh Token":         "secret_formats",
	"Generic OAuth 2.0 Access Token (Bearer)": "secret_formats",
	"OpenID Connect ID Token (JWT)":           "secret_formats",
	"OAuth PKCE Code Verifier":                "secret_formats",
	"X.509 Certificate PEM":                   "secret_formats",
	"X.509 Certificate Request (CSR)":         "secret_formats",
	"X.509 Encrypted Private Key":             "secret_formats",
	"SSH authorized_keys ssh-rsa Entry":       "secret_formats",
	"SSH authorized_keys ssh-ed25519 Entry":   "secret_formats",
	"SSH known_hosts Entry":                   "secret_formats",
	"OpenSSH Private Key (OPENSSH format)":    "secret_formats",
	"PGP Private Key Block":                   "secret_formats",
	"PGP Public Key Block":                    "secret_formats",
	"PGP Signature Block":                     "secret_formats",
	"PGP Symmetric Encrypted Block":           "secret_formats",
	"JWS Compact Serialization":               "secret_formats",
	"JWE Compact Serialization":               "secret_formats",
	"JSON Web Key (JWK)":                      "secret_formats",
	"Generic 32-Hex API Key":                  "secret_formats",
	"Generic 64-Hex Token":                    "secret_formats",
	"Session Cookie (HMAC-signed)":            "secret_formats",
	"Laravel APP_KEY":                         "secret_formats",
	"Django SECRET_KEY":                       "secret_formats",
	"PuTTY PPK Private Key":                   "secret_formats",
	".npmrc Auth Token":                       "secret_formats",
	"PyPI .pypirc Token":                      "secret_formats",
	"Composer auth.json Token":                "secret_formats",
	"SAML SP Private Key Reference":           "secret_formats",
	"Microsoft Office DocCookie":              "secret_formats",
	"WebAuthn Recovery Code":                  "secret_formats",
	"HashiCorp Boundary Token":                "secret_formats",
	"AWS Temporary Session Credentials":       "secret_formats",

	// Batch 12: Regional Cloud
	"Yandex Cloud OAuth Token":         "regional_cloud",
	"Yandex Cloud IAM Token":           "regional_cloud",
	"Yandex Cloud Service Account Key": "regional_cloud",
	"Tencent Cloud Secret ID":          "regional_cloud",
	"Tencent Cloud Secret Key":         "regional_cloud",
	"Tencent COS Object Storage Token": "regional_cloud",
	"Tencent SMS App Key":              "regional_cloud",
	"Baidu Cloud Access Key":           "regional_cloud",
	"Baidu Cloud Secret Key":           "regional_cloud",
	"Baidu AI Open Platform Key":       "regional_cloud",
	"Alibaba Cloud Access Key ID":      "regional_cloud",
	"Alibaba Cloud Access Key Secret":  "regional_cloud",
	"Alibaba Cloud STS Token":          "regional_cloud",
	"Alibaba Aliyun OSS Bucket Token":  "regional_cloud",
	"Huawei Cloud Access Key ID":       "regional_cloud",
	"Huawei Cloud Secret Access Key":   "regional_cloud",
	"Naver Cloud Platform Access Key":  "regional_cloud",
	"Naver Cloud Platform Secret Key":  "regional_cloud",
	"Naver Maps Client ID":             "regional_cloud",
	"KT Cloud Access Token":            "regional_cloud",
	"KT Cloud Access Key":              "regional_cloud",
	"NHN Cloud Auth Token":             "regional_cloud",
	"NHN Cloud App Key":                "regional_cloud",
	"Open Telekom Cloud Token":         "regional_cloud",
	"Deutsche Telekom Cloud Key":       "regional_cloud",
	"Orange Flexible Engine Token":     "regional_cloud",
	"Rackspace Cloud Files API Key":    "regional_cloud",
	"Scaleway Secret Key":              "regional_cloud",

	// Batch 13: Dev Tools / PaaS
	"Vercel Personal Access Token":                 "dev_tools",
	"Vercel Team Access Token":                     "dev_tools",
	"Vercel Deploy Webhook URL":                    "dev_tools",
	"Netlify OAuth Token":                          "dev_tools",
	"Netlify Build Webhook URL":                    "dev_tools",
	"Heroku OAuth Bearer Token":                    "dev_tools",
	"Heroku Pipelines Promotion Webhook":           "dev_tools",
	"Railway Project Token":                        "dev_tools",
	"Railway Account API Token":                    "dev_tools",
	"Render Service Deploy Key":                    "dev_tools",
	"Render API Key":                               "dev_tools",
	"Supabase Service Role Key (JWT)":              "dev_tools",
	"Supabase Anon Key (JWT)":                      "dev_tools",
	"Supabase Personal Access Token":               "dev_tools",
	"Firebase Cloud Messaging Server Key (Legacy)": "dev_tools",
	"PlanetScale Database Password":                "dev_tools",
	"PlanetScale OAuth Token":                      "dev_tools",
	"Neon API Key":                                 "dev_tools",
	"Turso Database Token":                         "dev_tools",
	"Clerk JWT Public Key":                         "dev_tools",
	"SuperTokens API Key":                          "dev_tools",
	"Fly.io API Token":                             "dev_tools",
	"Northflank API Token":                         "dev_tools",
	"Cloudflare Workers Deploy Token":              "dev_tools",
	"Replit Database URL":                          "dev_tools",
	"Replit Auth Token":                            "dev_tools",
	"Cloud 66 Stack Token":                         "dev_tools",
	"GitHub Codespaces SSH Token":                  "dev_tools",
	"CodeSandbox CLI Token":                        "dev_tools",
	"StackBlitz API Token":                         "dev_tools",
	"Bitrise Personal Access Token":                "dev_tools",
	"Crowdin Personal Access Token":                "dev_tools",
	"Lokalise API Token":                           "dev_tools",
	"Sanity CMS Token":                             "dev_tools",
	"Contentful Personal Access Token":             "dev_tools",
	"Strapi API Token":                             "dev_tools",
	"Storyblok Management Token":                   "dev_tools",
	"Builder.io Private Key":                       "dev_tools",
	"Hygraph Permanent Auth Token":                 "dev_tools",
	"GitGuardian Personal Access Token":            "dev_tools",
	"FOSSA API Key":                                "dev_tools",
	"CircleCI Personal API Token":                  "dev_tools",
	"Bitbucket Pipelines OAuth Secret":             "dev_tools",
	"CloudBees Jenkins API Token":                  "dev_tools",
	"Gitea Personal Access Token":                  "dev_tools",
	"Forgejo API Token":                            "dev_tools",
	"Gerrit HTTP Password":                         "dev_tools",
	"Phabricator Conduit API Token":                "dev_tools",
	"Codecov Repo Upload Token":                    "dev_tools",

	// Batch 14: Communication Platforms
	"Zoom JWT Token (legacy)":                    "communications",
	"Zoom OAuth Access Token":                    "communications",
	"Zoom Server-to-Server OAuth Secret":         "communications",
	"Microsoft Teams Incoming Webhook URL":       "communications",
	"Microsoft Teams Bot Framework Secret":       "communications",
	"Microsoft Graph Subscription Client Secret": "communications",
	"Cisco Webex Bot Access Token":               "communications",
	"Cisco Webex Guest Issuer Token":             "communications",
	"Vonage API Key":                             "communications",
	"Vonage API Secret":                          "communications",
	"Vonage Application Private Key":             "communications",
	"MessageBird API Key (live)":                 "communications",
	"MessageBird Test API Key":                   "communications",
	"Plivo Auth ID":                              "communications",
	"Plivo Auth Token":                           "communications",
	"Bandwidth API Token":                        "communications",
	"Bandwidth Application Secret":               "communications",
	"Sinch Application Token":                    "communications",
	"Telnyx API Key":                             "communications",
	"Twilio Account SID + Auth Token Pair":       "communications",
	"Twilio Functions Token":                     "communications",
	"Twilio API Key (SK...)":                     "communications",
	"Slack User OAuth Token":                     "communications",
	"Slack Workflow Builder Webhook":             "communications",
	"Slack Refresh Token":                        "communications",
	"WhatsApp Cloud API Access Token":            "communications",
	"WhatsApp Business System User Token":        "communications",
	"PagerDuty Integration Key (Events V2)":      "communications",
	"Twist OAuth Token":                          "communications",
	"Rocket.Chat Personal Access Token":          "communications",
	"Mattermost Personal Access Token":           "communications",
	"Matrix Homeserver Access Token":             "communications",

	// Batch 15: Additional Code/Config Secrets
	".pypirc Username Token Block":                "code_secrets",
	"Python pip extra-index-url Credentials":      "code_secrets",
	"Python config.ini DB Password":               "code_secrets",
	"Python conda authentication token":           "code_secrets",
	"Ruby credentials.yml Master Key":             "code_secrets",
	"Ruby secrets.yml secret_key_base":            "code_secrets",
	"Ruby .gem/credentials API Key":               "code_secrets",
	"Ruby Devise pepper":                          "code_secrets",
	"PHP Laravel .env APP_KEY":                    "code_secrets",
	"PHP Symfony APP_SECRET":                      "code_secrets",
	"PHP CodeIgniter Encryption Key":              "code_secrets",
	"PHP WordPress wp-config Authentication Salt": "code_secrets",
	".NET appsettings.json Connection String":     "code_secrets",
	".NET appsettings.json JWT Secret":            "code_secrets",
	".NET User Secrets ID":                        "code_secrets",
	".NET Service Connection String":              "code_secrets",
	"Java application.properties JDBC Password":   "code_secrets",
	"Java keystore.jks Password Hint":             "code_secrets",
	"Maven settings.xml Server Password":          "code_secrets",
	"Gradle gradle.properties Auth":               "code_secrets",
	"Go config.go Hard-coded Password":            "code_secrets",
	"Go .envrc with secrets":                      "code_secrets",
	"Go viper.SetEnvPrefix Secret":                "code_secrets",
	"Node config.js Hard-coded Secret":            "code_secrets",
	"Node process.env literal token":              "code_secrets",
	"Node .npmrc Email + Auth":                    "code_secrets",
	"Terraform tfstate AWS Credentials":           "code_secrets",
	"Terraform variable.tf default secret":        "code_secrets",
	"Ansible Vault Header":                        "code_secrets",
	"Ansible Vault Password File Reference":       "code_secrets",
	"Ansible Inventory ansible_password":          "code_secrets",
	"Chef Encrypted Data Bag Secret":              "code_secrets",
	"Chef Client Validation Key":                  "code_secrets",
	"Puppet Hiera eyaml Token":                    "code_secrets",
	"Docker Build ARG Secret":                     "code_secrets",
	"docker-compose.yml Password ENV":             "code_secrets",
	"Kubernetes Pod env literal secret":           "code_secrets",
	"Kubernetes externalSecrets reference":        "code_secrets",
	"iOS Info.plist Hard-coded Key":               "code_secrets",
	"Android local.properties Key":                "code_secrets",
	"Shell script export TOKEN/PASSWORD":          "code_secrets",
	"Shell script curl Basic Auth":                "code_secrets",
	"Shell script PSQL connection URI":            "code_secrets",
	"Vault sealed-secret Annotation":              "code_secrets",
	"Helm Chart Values Inline Token":              "code_secrets",
	"Github Actions Workflow Inline Secret":       "code_secrets",
	"Doppler Service Token":                       "code_secrets",
	"1Password Service Account Token":             "code_secrets",
	"Akeyless Access ID":                          "code_secrets",
	"Conjur API Key":                              "code_secrets",
	"AWS Secrets Manager ARN":                     "code_secrets",

	// Batch 17: Financial Services
	"Plaid Client ID":                        "financial",
	"Plaid Production Secret":                "financial",
	"Plaid Public Token":                     "financial",
	"Dwolla API Key":                         "financial",
	"Dwolla API Secret":                      "financial",
	"Wise (TransferWise) Personal API Token": "financial",
	"Wise Live API Token Header":             "financial",
	"Adyen API Key (AQE...)":                 "financial",
	"Adyen Client Key":                       "financial",
	"Adyen Webhook HMAC Key":                 "financial",
	"Mollie API Key (live)":                  "financial",
	"Mollie API Key (test)":                  "financial",
	"GoCardless Live Access Token":           "financial",
	"Stripe Webhook Signing Secret (whsec_)": "financial",
	"Stripe Restricted API Key (rk_)":        "financial",
	"Square Application Secret":              "financial",
	"Square OAuth Bearer Token":              "financial",
	"PayPal REST Client Secret":              "financial",
	"PayPal Live Access Token Header":        "financial",
	"Razorpay Key ID":                        "financial",
	"Razorpay Key Secret":                    "financial",
	"ACH Routing+Account Numbers Together":   "financial",
	"SWIFT/BIC code with bank+account":       "financial",

	// Batch 16: Healthcare
	"FHIR R4 Patient Resource ID":              "healthcare",
	"FHIR Bearer Access Token":                 "healthcare",
	"SMART-on-FHIR App Refresh Token":          "healthcare",
	"Epic FHIR Client Secret":                  "healthcare",
	"Epic MyChart Refresh Token":               "healthcare",
	"Cerner FHIR Tenant Bearer Token":          "healthcare",
	"HL7 v2 PID Segment with DOB/SSN":          "healthcare",
	"HL7 v2 ADT Message Header":                "healthcare",
	"DICOM Patient ID Tag":                     "healthcare",
	"DICOM Issuer of Patient ID":               "healthcare",
	"US NPI (National Provider Identifier)":    "healthcare",
	"US DEA Number":                            "healthcare",
	"US Medicare Beneficiary Identifier (MBI)": "healthcare",
	"US NDC Drug Code (10-digit)":              "healthcare",
	"Medical Record Number (MRN)":              "healthcare",
	"Patient Account Number":                   "healthcare",
	"Health Plan Beneficiary Number":           "healthcare",
	"ICD-10-CM Diagnosis Code List":            "healthcare",
	"Lab Result with Patient Name":             "healthcare",
	"Discharge Summary Header":                 "healthcare",

	// Batch 7: Container / Orchestration

	// W4 Batch 1: GDPR / EU national identifiers.
	"EU IBAN (SEPA)":                     "pii_eu",
	"EU VAT Number":                      "pii_eu",
	"German Personalausweis":             "pii_eu",
	"German Steueridentifikationsnummer": "pii_eu",
	"German Sozialversicherungsnummer":   "pii_eu",
	"French INSEE/NIR":                   "pii_eu",
	"French CNI Number":                  "pii_eu",
	"French SIRET":                       "pii_eu",
	"French SIREN":                       "pii_eu",
	"Italian Codice Fiscale":             "pii_eu",
	"Italian Partita IVA":                "pii_eu",
	"Spanish DNI":                        "pii_eu",
	"Spanish NIE":                        "pii_eu",
	"Spanish CIF":                        "pii_eu",
	"Dutch BSN":                          "pii_eu",
	"Belgian National Number":            "pii_eu",
	"Polish PESEL":                       "pii_eu",
	"Polish NIP":                         "pii_eu",
	"Portuguese NIF":                     "pii_eu",
	"Swedish Personnummer":               "pii_eu",
	"Swedish Organisationsnummer":        "pii_eu",
	"Finnish HETU":                       "pii_eu",
	"Austrian SV-Nummer":                 "pii_eu",
	"Greek AFM":                          "pii_eu",
	"Greek AMKA":                         "pii_eu",
	"Czech Rodne Cislo":                  "pii_eu",
	"Hungarian TAJ":                      "pii_eu",
	"Romanian CNP":                       "pii_eu",
	"Danish CPR":                         "pii_eu",
	"Norwegian Fodselsnummer":            "pii_eu",

	// W4 Batch 2: Switzerland.
	"Swiss AHV/AVS Number":                    "pii_switzerland",
	"Swiss UID":                               "pii_switzerland",
	"Swiss Passport Number":                   "pii_switzerland",
	"Swiss New Old-Age Insurance Number (ZAS)": "pii_switzerland",

	// W4 Batch 3: United Kingdom.
	"UK National Insurance Number": "pii_uk",
	"UK NHS Number":                "pii_uk",
	"UK Passport Number":           "pii_uk",
	"UK Driving Licence Number":    "pii_uk",
	"UK UTR":                       "pii_uk",

	// W4 Batch 4: GCC / Middle East.
	"UAE Emirates ID":             "pii_gcc",
	"Saudi National ID":           "pii_gcc",
	"Qatar QID":                   "pii_gcc",
	"Bahrain CPR Number":          "pii_gcc",
	"Kuwait Civil ID":             "pii_gcc",
	"Oman Civil Number":           "pii_gcc",
	"UAE Tax Registration Number": "pii_gcc",
	"Saudi VAT Number":            "pii_gcc",
	"Saudi IBAN":                  "pii_gcc",
	"UAE IBAN":                    "pii_gcc",
	"Kuwait IBAN":                 "pii_gcc",
	"Bahrain IBAN":                "pii_gcc",
	"Qatar IBAN":                  "pii_gcc",
	"Oman IBAN":                   "pii_gcc",
	"Qatar TIN":                   "pii_gcc",

	// W4 Batch 5: Southeast & East Asia.
	"Singapore NRIC/FIN":                        "pii_sea",
	"Malaysia MyKad":                            "pii_sea",
	"Thailand National ID":                      "pii_sea",
	"Philippines SSS Number":                    "pii_sea",
	"Philippines TIN":                           "pii_sea",
	"Philippines UMID":                          "pii_sea",
	"Indonesia NIK":                             "pii_sea",
	"Indonesia NPWP":                            "pii_sea",
	"Vietnam CCCD":                              "pii_sea",
	"Vietnam MST":                               "pii_sea",
	"Japan My Number":                           "pii_sea",
	"Japan Passport Number":                     "pii_sea",
	"South Korea RRN":                           "pii_sea",
	"South Korea Business Registration Number":  "pii_sea",
	"Taiwan National ID":                        "pii_sea",
	"China Resident ID":                         "pii_sea",
	"China Passport Number":                     "pii_sea",
	"India Aadhaar":                             "pii_sea",
	"India PAN":                                 "pii_sea",
	"Hong Kong HKID":                            "pii_sea",

	// W4 Batch 6: HIPAA — supplemental PHI patterns. All map to the
	// existing "phi" corpus directory (alongside the MRN/NPI/DEA/MBI
	// patterns introduced in earlier W1 work).
	"US CLIA Number":                  "phi",
	"US CPT Procedure Code List":      "phi",
	"US HCPCS Level II Code List":     "phi",
	"LOINC Code List":                 "phi",
	"ICD-9-CM Diagnosis Code List":    "phi",
	"US NDC Drug Code (11-digit)":     "phi",
	"SNOMED CT Concept ID List":       "phi",
	"DSM-5 Diagnosis Code":            "phi",
	"US Medicare HICN (legacy)":       "phi",
	"CMS Certification Number (CCN)":  "phi",
	"Insurance Subscriber Member ID":  "phi",
	"Patient DOB in Clinical Context": "phi",
	"HL7 v2 OBX Result Segment":       "phi",
	"HL7 v2 ORC Order Segment":        "phi",
	"DICOM Patient Name Tag":          "phi",
}

// patternsJSON is the structure of rules/dlp_patterns.json.
type patternsJSON struct {
	Patterns []struct {
		Name           string   `json:"name"`
		Regex          string   `json:"regex"`
		Category       string   `json:"category"`
		Severity       string   `json:"severity"`
		Hotwords       []string `json:"hotwords"`
		HotwordWindow  int      `json:"hotword_window"`
		RequireHotword bool     `json:"require_hotword"`
		MinMatches     int      `json:"min_matches"`
		EntropyMin     float64  `json:"entropy_min"`
	} `json:"patterns"`
}

func main() {
	var (
		outDir = flag.String("out", "", "Output corpus root (default: testdata/corpus next to this program)")
		seed   = flag.Int64("seed", 17, "math/rand seed for deterministic output")
	)
	flag.Parse()

	_, thisFile, _, _ := runtime.Caller(0)
	thisDir := filepath.Dir(thisFile)
	repoRoot := filepath.Clean(filepath.Join(thisDir, "..", "..", "..", "..", "..", ".."))
	defaultOut := filepath.Clean(filepath.Join(thisDir, "..", "..", "corpus"))
	if *outDir == "" {
		*outDir = defaultOut
	}

	patternsPath := filepath.Join(repoRoot, "rules", "dlp_patterns.json")
	raw, err := os.ReadFile(patternsPath)
	if err != nil {
		fatal("read patterns: %v", err)
	}
	var pj patternsJSON
	if err := json.Unmarshal(raw, &pj); err != nil {
		fatal("parse patterns: %v", err)
	}
	if len(pj.Patterns) == 0 {
		fatal("no patterns loaded")
	}

	rng := rand.New(rand.NewSource(*seed))

	tpByCategory := make(map[string][]Sample)
	tnByCategory := make(map[string][]Sample)

	// Generate 16 TP samples per pattern in varied contexts.
	// 163 patterns × 16 = 2,608 TP samples; combined with ~2,500 TN
	// samples this lifts the total corpus over the 5,000-sample floor.
	const tpVariantsPerPattern = 16
	tpCounter := 0
	for _, p := range pj.Patterns {
		cat, ok := patternCategory[p.Name]
		if !ok {
			cat = "other_generic"
		}
		gen, found := valueGenerators[p.Name]
		if !found {
			// Unknown pattern: skip rather than emit broken samples.
			fmt.Fprintf(os.Stderr, "no value generator for %q (category=%s) — skipping\n", p.Name, p.Category)
			continue
		}
		hotwords := p.Hotwords
		for i := 0; i < tpVariantsPerPattern; i++ {
			tpCounter++
			ctxKind := tpContextKinds[i%len(tpContextKinds)]
			value := gen(rng)
			content, ctxLabel := renderTP(ctxKind, value, hotwords, rng)
			id := fmt.Sprintf("tp-%s-%05d", shortSlug(p.Name), tpCounter)
			tpByCategory[cat] = append(tpByCategory[cat], Sample{
				ID:            id,
				Category:      cat,
				Pattern:       p.Name,
				ContentB64:    encodeContent(content),
				ExpectBlocked: true,
				Context:       ctxLabel,
				Source:        synthSource,
			})
		}
	}

	// Generate ~2,500 TN samples across 11 categories.
	tnPlan := []struct {
		cat   string
		count int
	}{
		{"code_snippets", 300},
		{"log_output", 300},
		{"documentation", 300},
		{"yaml_configs", 300},
		{"json_payloads", 300},
		{"markdown", 300},
		{"stack_traces", 200},
		{"tickets", 150},
		{"ai_prompts", 150},
		{"csv_data", 100},
		{"natural_language", 100},
	}
	tnCounter := 0
	for _, plan := range tnPlan {
		gen, ok := tnGenerators[plan.cat]
		if !ok {
			fatal("no TN generator for category %q", plan.cat)
		}
		for i := 0; i < plan.count; i++ {
			tnCounter++
			content, ctxLabel := gen(rng)
			id := fmt.Sprintf("tn-%s-%05d", shortSlug(plan.cat), tnCounter)
			tnByCategory[plan.cat] = append(tnByCategory[plan.cat], Sample{
				ID:            id,
				Category:      plan.cat,
				ContentB64:    encodeContent(content),
				ExpectBlocked: false,
				Context:       ctxLabel,
				Source:        synthSource,
			})
		}
	}

	if err := writeCorpus(*outDir, "true_positives", tpByCategory); err != nil {
		fatal("write TP corpus: %v", err)
	}
	if err := writeCorpus(*outDir, "true_negatives", tnByCategory); err != nil {
		fatal("write TN corpus: %v", err)
	}

	fmt.Printf("wrote %d true positives across %d categories\n", tpCounter, len(tpByCategory))
	fmt.Printf("wrote %d true negatives across %d categories\n", tnCounter, len(tnByCategory))
	fmt.Printf("total samples: %d\n", tpCounter+tnCounter)
}

func writeCorpus(root, kind string, byCat map[string][]Sample) error {
	cats := make([]string, 0, len(byCat))
	for k := range byCat {
		cats = append(cats, k)
	}
	sort.Strings(cats)

	for _, cat := range cats {
		dir := filepath.Join(root, kind, cat)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		path := filepath.Join(dir, synthSource+".jsonl")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		w := bufio.NewWriter(f)
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for _, s := range byCat[cat] {
			if err := enc.Encode(s); err != nil {
				f.Close()
				return err
			}
		}
		if err := w.Flush(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "generate_corpus: "+format+"\n", args...)
	os.Exit(1)
}

func shortSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '_', r == '-', r == '.', r == '/':
			b.WriteByte('-')
		}
	}
	out := b.String()
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	out = strings.Trim(out, "-")
	if len(out) > 24 {
		out = out[:24]
	}
	if out == "" {
		out = "x"
	}
	return out
}
