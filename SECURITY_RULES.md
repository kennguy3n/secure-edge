# Secure Edge — Security Rules Reference

This document is a curated overview of the foundational DLP patterns.
The authoritative and complete list is
[`rules/dlp_patterns.json`](./rules/dlp_patterns.json). For the W4
global-PII expansion, see the [W4 section](#w4--global-pii-coverage-added)
below. For the schema and authoring workflow, see
[`docs/dlp-pattern-authoring-guide.md`](./docs/dlp-pattern-authoring-guide.md).

## Coverage summary

812 patterns across 22 categories (counted from `rules/dlp_patterns.json`):

| Category             | Patterns | Examples                                                                                                                                  |
|----------------------|---------:|-------------------------------------------------------------------------------------------------------------------------------------------|
| `cloud`              | 462      | AWS, GCP, Azure, IBM, Alibaba, Oracle, DigitalOcean / Linode / Vultr / Hetzner / OVH / Scaleway / regional clouds, monitoring & VPN PATs  |
| `code_secret`        | 60       | GitHub / GitLab / Bitbucket PATs, .pypirc tokens, Rails master.key, Laravel APP\_KEY, Terraform / Ansible / Chef / Puppet / Docker / K8s   |
| `credential`         | 37       | shell `export` literals, JDBC URLs, env-file passwords, Salt / Helm / sealed-secret literals                                              |
| `phi`                | 35       | FHIR / SMART-on-FHIR tokens, Epic / Cerner credentials, HL7 v2 PID/OBX/ORC, DICOM tags, NPI, DEA, MBI, MRN, ICD-10 / ICD-9 / CPT / HCPCS / LOINC / SNOMED / DSM-5, NDC, CLIA |
| `database_registry`  | 34       | Postgres / MongoDB URIs, Docker / npm tokens, registry credentials                                                                        |
| `pii_eu`             | 30       | GDPR — IBAN, DE Personalausweis / Steueridentifikationsnummer, FR INSEE/NIR / SIREN / SIRET, IT Codice Fiscale, ES DNI/NIE, NL BSN, BE Rijksregister, PL PESEL, PT NIF, SE Personnummer, FI HETU, GR AFM, HU TAJ, EU VAT |
| `financial`          | 20       | Stripe (whsec\_, rk\_), Plaid, Dwolla, Adyen, Wise, GoCardless, PayPal, Square, Coinbase, Razorpay                                          |
| `pii_sea`            | 20       | Singapore NRIC/FIN, Malaysia MyKad, Thai NID, Philippines SSS/TIN/UMID, Indonesia NIK/NPWP, Vietnam CCCD/MST, Japan My Number / Passport, Korea RRN / Biz Reg, Taiwan NID, China Resident ID / Passport, India Aadhaar / PAN, Hong Kong HKID |
| `mobile_desktop`     | 17       | Apple App Store Connect, Google Play, code-signing, iOS Info.plist, Android local.properties                                              |
| `pii_gcc`            | 15       | UAE Emirates ID / TRN / IBAN, Saudi National ID (Iqama) / IBAN, Qatar QID, Bahrain CPR, Kuwait Civil ID, Oman Civil Number, GCC VAT IDs   |
| `ai_ml`              | 13       | OpenAI, Anthropic, Google AI, Replicate, HuggingFace                                                                                      |
| `package_manager`    | 12       | npm, PyPI, Maven, NuGet, RubyGems                                                                                                         |
| `ci_cd`              | 8        | CircleCI, TeamCity, Bitrise, Buildkite                                                                                                    |
| `messaging`          | 8        | Slack, Twilio, SendGrid, Discord, Mailgun, Zoom JWT, Microsoft Teams, Vonage, MessageBird                                                 |
| `auth`               | 8        | OIDC ID tokens, OAuth refresh tokens, JWT secrets, SAML assertions, Auth0, Okta, Stripe Connect, Twilio Authy                             |
| `infra_secret`       | 7        | Terraform, Vault, Pulumi                                                                                                                  |
| `pii_uk`             | 5        | UK NINO, NHS Number, UK Passport, UK Driver's Licence, UK UTR                                                                             |
| `pii_ccpa`           | 5        | California Driver's Licence / State ID / Medi-Cal Beneficiary ID / Vehicle Plate / CDTFA Sales Tax Permit                                 |
| `payments`           | 5        | Stripe, Square, PayPal, Braintree                                                                                                         |
| `pii`                | 4        | US SSN, credit cards, emails, phones                                                                                                      |
| `pii_switzerland`    | 4        | Swiss AHV / AVS, Swiss UID (CHE-…), Swiss Passport, Swiss New Old-Age Insurance Number (ZAS). Swiss IBANs (`CH..`) are matched by the `EU IBAN (SEPA)` pattern in `pii_eu`. |
| `iac`                | 3        | Atlas, Spacelift, Env0                                                                                                                    |

Sub-sections below group patterns by family for readability rather
than by JSON category. Counts in the per-family section headers
reflect the foundational set, not the W1- or W4-expanded set.

### W4 — Global PII coverage (added)

The W4 expansion adds 94 region-specific personal-data patterns
covering jurisdictions where GDPR, HIPAA, CCPA, GCC privacy laws,
the UK Data Protection Act, and the Swiss FADP / nFADP require
specific identifier classes to be treated as personal data. The
new patterns are grouped by category in `dlp_patterns.json`:

| Category          | Patterns | Coverage                                                                                                                                                                  |
|-------------------|---------:|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pii_eu`          | 30       | GDPR — IBAN, EU VAT, DE Personalausweis / Steueridentifikationsnummer / Sozialversicherungsnummer, FR INSEE / SIREN / SIRET / CNI, IT Codice Fiscale / Partita IVA, ES DNI / NIE / CIF, NL BSN, BE Rijksregister, PL PESEL / NIP, PT NIF, SE Personnummer / Organisationsnummer, FI HETU, GR AFM, HU TAJ |
| `pii_switzerland` | 4        | Swiss AHV/AVS (756.xxxx.xxxx.xx), Swiss UID (CHE-xxx.xxx.xxx), Swiss Passport, Swiss New Old-Age Insurance Number (ZAS). Swiss IBANs (`CH..`) are matched by the `EU IBAN (SEPA)` pattern in `pii_eu`. |
| `pii_uk`          | 5        | UK NINO, NHS Number, UK Passport, UK Driver's Licence, UK UTR                                                                                                             |
| `pii_gcc`         | 15       | UAE Emirates ID (784-...), UAE TRN, UAE IBAN, Saudi National ID (Iqama), Saudi IBAN, Saudi VAT, Qatar QID, Bahrain CPR, Kuwait Civil ID, Oman Civil Number                 |
| `pii_sea`         | 20       | Singapore NRIC/FIN, Malaysia MyKad, Thai National ID, Philippines SSS/TIN/UMID, Indonesia NIK / NPWP, Vietnam CCCD / MST, Japan My Number / Passport, South Korea RRN / Business Registration, Taiwan National ID, China Resident ID / Passport, India Aadhaar / PAN, Hong Kong HKID |
| `phi`             | 15 new   | US CLIA, CPT (bulk), HCPCS Level II (bulk), LOINC (bulk), ICD-9-CM (bulk), NDC 11-digit, SNOMED CT (bulk), DSM-5, Medicare HICN (legacy), CMS Certification Number, Insurance Subscriber/Member ID, Patient DOB in clinical context, HL7 v2 OBX / ORC, DICOM (0010,0010) Patient Name Tag |
| `pii_ccpa`        | 5        | California Driver's Licence, California State ID, California Medi-Cal Beneficiary ID, California Vehicle Plate, CDTFA Sales Tax Permit                                    |

Notes on the W4 set:

- Most national-ID patterns set `require_hotword: true` because their
  shapes (9–13 digits, sometimes with separators) collide with too
  many innocent strings to fire safely on shape alone. Each pattern's
  hotword list uses multi-syllabic, locale-specific phrases (e.g.
  `numer identyfikacji` for PL NIP, `numéro de sécurité sociale` for
  FR INSEE/NIR, `身分證` / `Taiwan ID` for TW NID, `subscriber id` /
  `member id` for insurance IDs) to keep the hotword AC scan
  selective.
- Bulk-detection patterns (CPT / HCPCS / LOINC / ICD-9 / SNOMED CT)
  use the `(?:CODE\b[\s,;|]+){N}CODE\b` form to fire only on lists
  of N+ codes, which is how these classes appear in real claims
  data — a single 5-digit number in isolation is not a CPT secret.
- Test/example values are not pre-excluded — the W4 expansion relies
  on the existing generic dictionary exclusions
  (`placeholder`, `example`, `test`, `dummy`, …) in
  `rules/dlp_exclusions.json`, which apply to every pattern via
  `applies_to: "*"`.

Columns:

- **Pattern** — the `name` field; also what appears in the block
  notification.
- **Severity** — `critical` / `high` / `medium` / `low`.
- **Prefix** — Aho-Corasick literal prefix; `_(none)_` means the
  pattern runs via the full-content fallback path.
- **Hotword required** — `yes` if `require_hotword: true`; the pattern
  does not block unless a hotword fires.

---

## Cloud Providers (20)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| AWS ARN | high | `arn:aws:` | yes |
| AWS Access Key | critical | `AKIA` | no |
| AWS ECR Login Token | critical | `ECR_` | no |
| AWS Java SDK BasicAWSCredentials | critical | `BasicAWSCredentials` | no |
| AWS MWS Key | critical | `amzn.mws.` | no |
| AWS Secret Access Key | critical | `secret` | no |
| AWS Secrets Manager SecretString Paste | critical | `"SecretString"` | yes |
| AWS Session Token | critical | `aws_session_token` | no |
| Azure AD Client Secret | critical | `client_secret` | yes |
| Azure Connection String | critical | `DefaultEndpointsProtocol` | no |
| Azure DevOps PAT | critical | `_(none)_` | no |
| Azure Key Vault GetSecret Paste | critical | `vault.azure.net/secrets/` | no |
| Azure SAS Token | critical | `sig=` | yes |
| Azure Storage Account Key | critical | `AccountKey=` | no |
| Azure Subscription ID | high | `_(none)_` | yes |
| GCP OAuth Client Secret | critical | `GOCSPX-` | no |
| GCP Secret Manager Payload Paste | critical | `"payload"` | yes |
| GCP Service Account Key | critical | `service_account` | no |
| GCR JSON Key Paste | critical | `service_account` | no |
| Google Services JSON API Key | high | `current_key` | no |

## Cloud Infrastructure (21)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Ansible Vault Block | critical | `$ANSIBLE_VAULT` | no |
| Chef Encrypted Data Bag | critical | `"cipher"` | yes |
| Cloudflare API Token | critical | `_(none)_` | no |
| DigitalOcean OAuth Token | critical | `doo_v1_` | no |
| DigitalOcean Personal Access Token | critical | `dop_v1_` | no |
| Docker Registry Auth | critical | `"auths"` | no |
| env0 API Key | critical | `ENV0_API_KEY` | no |
| Harbor Robot Token | critical | `robot$` | no |
| Helm Values Password | high | `Password` | yes |
| Kubernetes Secret YAML | high | `kind: Secret` | yes |
| Netlify Personal Access Token | critical | `nfp_` | no |
| Pulumi Stack Config Secret | high | `secure:v1:` | no |
| Puppet Hiera eyaml Block | critical | `ENC[PKCS7` | no |
| Quay.io Encrypted Password | critical | `QUAY_` | no |
| Scalr API Token | critical | `SCALR_TOKEN` | no |
| Spacelift API Key | critical | `SPACELIFT_API_KEY` | no |
| Supabase JWT Secret | critical | `SUPABASE_JWT_SECRET` | no |
| Supabase Service Role Key | critical | `sbp_` | no |
| Terraform Cloud API Token | critical | `.atlasv1.` | no |
| Terraform State Sensitive Value | high | `"sensitive"` | yes |
| Vercel Token | critical | `VERCEL_TOKEN` | no |

## Version Control (5)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Bitbucket App Password | critical | `bitbucket` | no |
| Bitbucket Server Token (BBDC) | critical | `BBDC-` | no |
| GitHub Personal Access Token | critical | `ghp_` | no |
| GitLab CI Pipeline Trigger Token | critical | `glptt-` | no |
| GitLab Personal Access Token | critical | `glpat-` | no |

## AI / ML Platforms (13)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Anthropic API Key | critical | `sk-ant-api03-` | no |
| Cohere API Key | critical | `cohere` | yes |
| Groq API Key | critical | `gsk_` | no |
| HuggingFace Access Token | critical | `hf_` | no |
| LangSmith API Key | critical | `lsv2_` | no |
| Mistral API Key | critical | `mistral` | yes |
| OpenAI Project API Key | critical | `sk-proj-` | no |
| OpenAI Service Account Key | critical | `sk-svcacct-` | no |
| OpenAI User API Key | critical | `sk-` | no |
| Pinecone API Key | critical | `pinecone` | yes |
| Replicate API Token | critical | `r8_` | no |
| Together AI API Key | critical | `together` | yes |
| Weights and Biases API Key | critical | `wandb` | no |

## Payment / Financial (9)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Adyen API Key | critical | `AQE` | yes |
| Braintree Access Token | critical | `access_token$production$` | no |
| Coinbase Commerce API Key | critical | `COINBASE` | no |
| PayPal Client Secret | critical | `paypal` | no |
| Plaid Client Secret | critical | `PLAID` | no |
| Square Access Token | critical | `sq0atp-` | no |
| Square OAuth Secret | critical | `sq0csp-` | no |
| Stripe Live Secret Key | critical | `sk_live_` | no |
| Stripe Restricted Key | critical | `rk_live_` | no |

## CI / CD (3)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| CircleCI Personal Token | critical | `circle` | no |
| Jenkins API Token | critical | `jenkins` | no |
| Travis CI Token | critical | `TRAVIS_` | no |

## Messaging / Communication (9)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Discord Bot Token | critical | `MT` | yes |
| Discord Webhook URL | high | `discord` | no |
| Mailchimp API Key | high | `_(none)_` | yes |
| SendGrid API Key | critical | `SG.` | no |
| Slack Token | critical | `xox` | no |
| Telegram Bot Token | critical | `_(none)_` | yes |
| Twilio API Key | critical | `SK` | yes |
| Twilio Account SID | critical | `AC` | yes |
| Vonage Nexmo API Secret | high | `_(none)_` | yes |

## Auth / Identity (11)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Auth0 Client Secret | critical | `AUTH0_CLIENT_SECRET` | no |
| Auth0 Management API Token | critical | `AUTH0_` | yes |
| Clerk Publishable Key | low | `pk_` | yes |
| Clerk Secret Key | critical | `sk_` | yes |
| Firebase Admin SDK Private Key | critical | `private_key_id` | no |
| Keycloak Admin Token | critical | `KEYCLOAK_` | yes |
| Keycloak Client Secret | high | `KEYCLOAK` | no |
| OAuth2 Refresh Token Assignment | high | `refresh_token` | yes |
| OIDC ID Token Assignment | high | `id_token` | yes |
| Okta API Token | critical | `00` | yes |
| OneLogin API Credentials | critical | `ONELOGIN` | no |

## Java Ecosystem (10)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Gradle Repository Credentials | high | `credentials` | yes |
| JDBC MySQL URL with Password | critical | `jdbc:mysql://` | no |
| JDBC Oracle URL with Password | critical | `jdbc:oracle:` | no |
| JDBC PostgreSQL URL with Password | critical | `jdbc:postgresql://` | no |
| JDBC SQL Server URL with Password | critical | `jdbc:sqlserver://` | no |
| Java Keystore Password | critical | `storepass` | yes |
| Java Password Literal | high | `String` | yes |
| Maven Settings Password | high | `<password>` | yes |
| Spring Datasource Password | critical | `spring.datasource.password` | no |
| Spring OAuth2 Client Secret | critical | `spring.security.oauth2` | no |

## Rust Ecosystem (4)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Cargo Registry Token | critical | `[registry]` | no |
| Crates.io API Token | critical | `cio` | yes |
| Rocket.toml Secret Key | high | `secret_key` | yes |
| Rust Password Literal | high | `let` | yes |

## Frontend (React / Angular / Vite) (7)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Angular Environment Secret | high | `environment.` | yes |
| Firebase Web Config apiKey | high | `AIza` | yes |
| Next.js Public Environment Secret | high | `NEXT_PUBLIC_` | no |
| React App Environment Secret | high | `REACT_APP_` | no |
| React Native CodePush Deployment Key | high | `CodePushDeploymentKey` | no |
| Vite Environment Secret | high | `VITE_` | no |
| Webpack DefinePlugin Secret | high | `DefinePlugin` | no |

## Desktop (Electron / Tauri) (3)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Electron Builder Publish Credentials | critical | `_(none)_` | yes |
| Electron Forge Publish Token | critical | `_(none)_` | no |
| Tauri Signing Private Key | critical | `_(none)_` | no |

## iOS Native (6)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Apple APNs Auth Key Filename | high | `AuthKey_` | yes |
| Apple App Store Connect API Key ID | high | `key` | yes |
| Apple Developer Team ID | medium | `team` | yes |
| CocoaPods Trunk Session Cookie | high | `_pods_session` | no |
| Cocoapods Trunk Token | critical | `COCOAPODS_TRUNK_TOKEN` | no |
| Xcode Cloud Secret | critical | `XCODE_CLOUD_` | no |

## Android Native (3)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Android Maps API Key in local.properties | high | `MAPS_API_KEY` | no |
| Android Signing Store Password | critical | `Password` | yes |
| Play Console Service Account JSON | critical | `service_account` | yes |

## Flutter / React Native (5)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Dart Password Literal | high | `_(none)_` | yes |
| EAS Build Secret | high | `EAS_` | no |
| Expo Access Token | critical | `EXPO_TOKEN` | no |
| Fastlane Match Password | critical | `MATCH_PASSWORD` | no |
| Flutter Dart Environment Secret | high | `_(none)_` | yes |

## Databases (7)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Cassandra Auth Provider Credentials | high | `PlainTextAuthProvider` | no |
| Database Connection String | critical | `_(none)_` | no |
| Elasticsearch URL with Credentials | high | `https://` | yes |
| MSSQL Connection String with Password | critical | `_(none)_` | no |
| MongoDB Atlas SRV Connection | critical | `mongodb+srv://` | no |
| Redis URL with Password | high | `redis` | no |
| SQLite PRAGMA Encryption Key | high | `PRAGMA` | yes |

## Private Keys / PEM (1)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Private Key Block | critical | `-----BEGIN` | no |

## JWT (1)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| JWT Token | high | `eyJ` | no |

## Password-in-Code (6)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Go Password Literal | high | `_(none)_` | yes |
| Kotlin Password Literal | high | `val` | yes |
| Password Assignment | high | `_(none)_` | yes |
| Python Secret Key Literal | high | `_(none)_` | yes |
| Source Code Imports | low | `_(none)_` | no |
| Swift Password Literal | high | `let` | yes |

## PII (4)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Credit Card Number | critical | `_(none)_` | no |
| Email Addresses (bulk) | medium | `@` | no |
| Phone Numbers (bulk, US) | medium | `_(none)_` | no |
| US Social Security Number | critical | `_(none)_` | no |

## Package Managers (5)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Composer Packagist Token | high | `packagist` | yes |
| Hex.pm API Key | high | `HEX_` | yes |
| NuGet API Key | critical | `oy2` | no |
| Pub.dev OAuth Refresh Token | high | `PUB_DEV_TOKEN` | yes |
| RubyGems API Key | critical | `rubygems_` | no |

## Other / Generic (10)

| Pattern | Severity | Prefix | Hotword required |
| --- | --- | --- | --- |
| Datadog API Key | high | `_(none)_` | no |
| Firebase App Distribution Token | critical | `_(none)_` | no |
| Firebase Cloud Messaging Server Key | critical | `AAAA` | no |
| Generic API Key | high | `api` | yes |
| Google API Key | critical | `AIza` | no |
| HashiCorp Vault Token | critical | `_(none)_` | no |
| Heroku API Key | high | `_(none)_` | yes |
| Internal URLs | high | `_(none)_` | no |
| npm Token | critical | `npm_` | no |
| PyPI API Token | critical | `pypi-` | no |

---

## Coverage notes

Accuracy is enforced by three CI-gated test layers (smoke, large,
regression). See
[ARCHITECTURE.md § DLP accuracy methodology](./ARCHITECTURE.md#dlp-accuracy-methodology) for
budgets, corpus sizes, and source files.
