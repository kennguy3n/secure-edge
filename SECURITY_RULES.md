# Secure Edge — Security Rules Reference

> **Authoritative source:** [`rules/dlp_patterns.json`](./rules/dlp_patterns.json)
>
> **Pattern authoring:** [`docs/dlp-pattern-authoring-guide.md`](./docs/dlp-pattern-authoring-guide.md)
>
> **Accuracy methodology:** [ARCHITECTURE.md § DLP accuracy methodology](./ARCHITECTURE.md#dlp-accuracy-methodology)

---

## Overview

Secure Edge ships **812 DLP patterns** across **22 categories** covering cloud credentials, secrets in code, PII/PHI across multiple jurisdictions, financial tokens, and more. Every pattern is enforced by a layered pipeline:

```
Aho–Corasick prefix scan → regex → hotword gate → entropy check
→ exclusion filter → severity scorer → threshold
```

---

## Reading the tables

| Column | Meaning |
|--------|---------|
| **Pattern** | The `name` field from `dlp_patterns.json`; appears in block notifications. |
| **Severity** | `critical` · `high` · `medium` · `low` — drives the scoring weight. |
| **Prefix** | Aho–Corasick literal prefix for fast pre-filtering. `—` means the pattern uses the full-content fallback path. |
| **Hotword required** | `yes` if `require_hotword: true`; the pattern fires only when a nearby hotword is also present. |

---

## Detection methodology

**Hotword gating.** National-ID patterns whose shape (9–13 digits with optional separators) collides with common numeric strings require a locale-specific hotword (e.g. `numer identyfikacji` for PL NIP, `numéro de sécurité sociale` for FR INSEE/NIR, `身分證` for TW NID, `subscriber id` / `member id` for insurance IDs).

**Bulk-code detection.** Medical and billing code patterns (CPT, HCPCS, LOINC, ICD-9, SNOMED CT) use the form `(?:CODE\b[\s,;|]+){N}CODE\b` and fire only on lists of N+ codes — a single 5-digit number in isolation is not a match.

**Generic exclusions.** Placeholder values (`example`, `test`, `dummy`, …) are filtered by `rules/dlp_exclusions.json`, which applies globally via `applies_to: "*"`.

**Accuracy.** Three CI-gated test layers (smoke, large, regression) enforce precision and recall budgets. See [ARCHITECTURE.md § DLP accuracy methodology](./ARCHITECTURE.md#dlp-accuracy-methodology).

---

## Coverage at a glance

| Category | Patterns | Highlights |
|----------|----------|------------|
| **Cloud & infrastructure** | | |
| `cloud` | 462 | AWS, GCP, Azure, IBM, Alibaba, Oracle, DigitalOcean, Linode, Vultr, Hetzner, OVH, Scaleway, regional clouds, monitoring & VPN PATs |
| `infra_secret` | 7 | Terraform, Vault, Pulumi |
| `iac` | 3 | Atlas, Spacelift, Env0 |
| **Code secrets & credentials** | | |
| `code_secret` | 60 | GitHub/GitLab/Bitbucket PATs, `.pypirc`, Rails `master.key`, Laravel `APP_KEY`, Terraform, Ansible, Chef, Puppet, Docker, K8s |
| `credential` | 37 | Shell `export` literals, JDBC URLs, env-file passwords, Salt/Helm/sealed-secret literals |
| **Auth & identity** | | |
| `auth` | 8 | OIDC ID tokens, OAuth refresh tokens, JWT secrets, SAML assertions, Auth0, Okta, Stripe Connect, Twilio Authy |
| **DevOps & CI/CD** | | |
| `ci_cd` | 8 | CircleCI, TeamCity, Bitrise, Buildkite |
| `package_manager` | 12 | npm, PyPI, Maven, NuGet, RubyGems |
| `database_registry` | 34 | Postgres/MongoDB URIs, Docker/npm tokens, registry credentials |
| **SaaS & third-party services** | | |
| `ai_ml` | 13 | OpenAI, Anthropic, Google AI, Replicate, HuggingFace |
| `financial` | 20 | Stripe, Plaid, Dwolla, Adyen, Wise, GoCardless, PayPal, Square, Coinbase, Razorpay |
| `messaging` | 8 | Slack, Twilio, SendGrid, Discord, Mailgun, Zoom, Microsoft Teams, Vonage, MessageBird |
| `payments` | 5 | Stripe, Square, PayPal, Braintree |
| **Application frameworks** | | |
| `mobile_desktop` | 17 | Apple App Store Connect, Google Play, code-signing, iOS `Info.plist`, Android `local.properties` |
| **Personal & protected data** | | |
| `pii` | 4 | US SSN, credit cards, emails (bulk), phones (bulk) |
| `pii_eu` | 30 | GDPR — IBAN, EU VAT, DE/FR/IT/ES/NL/BE/PL/PT/SE/FI/GR/HU national IDs and tax numbers |
| `pii_uk` | 5 | UK NINO, NHS Number, UK Passport, UK Driver's Licence, UK UTR |
| `pii_switzerland` | 4 | Swiss AHV/AVS, Swiss UID (CHE-…), Swiss Passport, Swiss ZAS. Swiss IBANs matched by `pii_eu`. |
| `pii_gcc` | 15 | UAE Emirates ID/TRN/IBAN, Saudi National ID (Iqama)/IBAN, Qatar QID, Bahrain CPR, Kuwait Civil ID, Oman Civil Number, GCC VAT IDs |
| `pii_sea` | 20 | SG NRIC/FIN, MY MyKad, TH NID, PH SSS/TIN/UMID, ID NIK/NPWP, VN CCCD/MST, JP My Number, KR RRN, TW NID, CN Resident ID, IN Aadhaar/PAN, HK HKID |
| `pii_ccpa` | 5 | CA Driver's Licence, State ID, Medi-Cal Beneficiary ID, Vehicle Plate, CDTFA Sales Tax Permit |
| `phi` | 35 | FHIR/SMART-on-FHIR tokens, Epic/Cerner credentials, HL7 v2, DICOM, NPI, DEA, MBI, MRN, ICD-10/ICD-9, CPT, HCPCS, LOINC, SNOMED, DSM-5, NDC, CLIA |

---

## Pattern reference

### Cloud & infrastructure

#### Cloud providers (20)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
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
| Azure DevOps PAT | critical | — | no |
| Azure Key Vault GetSecret Paste | critical | `vault.azure.net/secrets/` | no |
| Azure SAS Token | critical | `sig=` | yes |
| Azure Storage Account Key | critical | `AccountKey=` | no |
| Azure Subscription ID | high | — | yes |
| GCP OAuth Client Secret | critical | `GOCSPX-` | no |
| GCP Secret Manager Payload Paste | critical | `"payload"` | yes |
| GCP Service Account Key | critical | `service_account` | no |
| GCR JSON Key Paste | critical | `service_account` | no |
| Google Services JSON API Key | high | `current_key` | no |

#### Cloud infrastructure (21)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Ansible Vault Block | critical | `$ANSIBLE_VAULT` | no |
| Chef Encrypted Data Bag | critical | `"cipher"` | yes |
| Cloudflare API Token | critical | — | no |
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

---

### Code secrets & credentials

#### Version control (5)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Bitbucket App Password | critical | `bitbucket` | no |
| Bitbucket Server Token (BBDC) | critical | `BBDC-` | no |
| GitHub Personal Access Token | critical | `ghp_` | no |
| GitLab CI Pipeline Trigger Token | critical | `glptt-` | no |
| GitLab Personal Access Token | critical | `glpat-` | no |

#### Private keys (1)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Private Key Block | critical | `-----BEGIN` | no |

#### JWT (1)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| JWT Token | high | `eyJ` | no |

#### Passwords in code (6)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Go Password Literal | high | — | yes |
| Kotlin Password Literal | high | `val` | yes |
| Password Assignment | high | — | yes |
| Python Secret Key Literal | high | — | yes |
| Source Code Imports | low | — | no |
| Swift Password Literal | high | `let` | yes |

---

### Auth & identity (11)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
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

---

### DevOps & CI/CD

#### CI/CD (3)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| CircleCI Personal Token | critical | `circle` | no |
| Jenkins API Token | critical | `jenkins` | no |
| Travis CI Token | critical | `TRAVIS_` | no |

#### Package managers (5)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Composer Packagist Token | high | `packagist` | yes |
| Hex.pm API Key | high | `HEX_` | yes |
| NuGet API Key | critical | `oy2` | no |
| Pub.dev OAuth Refresh Token | high | `PUB_DEV_TOKEN` | yes |
| RubyGems API Key | critical | `rubygems_` | no |

---

### Databases (7)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Cassandra Auth Provider Credentials | high | `PlainTextAuthProvider` | no |
| Database Connection String | critical | — | no |
| Elasticsearch URL with Credentials | high | `https://` | yes |
| MSSQL Connection String with Password | critical | — | no |
| MongoDB Atlas SRV Connection | critical | `mongodb+srv://` | no |
| Redis URL with Password | high | `redis` | no |
| SQLite PRAGMA Encryption Key | high | `PRAGMA` | yes |

---

### SaaS & third-party services

#### AI & ML platforms (13)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
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

#### Payments & financial (9)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Adyen API Key | critical | `AQE` | yes |
| Braintree Access Token | critical | `access_token$production$` | no |
| Coinbase Commerce API Key | critical | `COINBASE` | no |
| PayPal Client Secret | critical | `paypal` | no |
| Plaid Client Secret | critical | `PLAID` | no |
| Square Access Token | critical | `sq0atp-` | no |
| Square OAuth Secret | critical | `sq0csp-` | no |
| Stripe Live Secret Key | critical | `sk_live_` | no |
| Stripe Restricted Key | critical | `rk_live_` | no |

#### Messaging & communication (9)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Discord Bot Token | critical | `MT` | yes |
| Discord Webhook URL | high | `discord` | no |
| Mailchimp API Key | high | — | yes |
| SendGrid API Key | critical | `SG.` | no |
| Slack Token | critical | `xox` | no |
| Telegram Bot Token | critical | — | yes |
| Twilio API Key | critical | `SK` | yes |
| Twilio Account SID | critical | `AC` | yes |
| Vonage Nexmo API Secret | high | — | yes |

#### Other & generic (10)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Datadog API Key | high | — | no |
| Firebase App Distribution Token | critical | — | no |
| Firebase Cloud Messaging Server Key | critical | `AAAA` | no |
| Generic API Key | high | `api` | yes |
| Google API Key | critical | `AIza` | no |
| HashiCorp Vault Token | critical | — | no |
| Heroku API Key | high | — | yes |
| Internal URLs | high | — | no |
| npm Token | critical | `npm_` | no |
| PyPI API Token | critical | `pypi-` | no |

---

### Application frameworks

#### Java ecosystem (10)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
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

#### Rust ecosystem (4)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Cargo Registry Token | critical | `[registry]` | no |
| Crates.io API Token | critical | `cio` | yes |
| Rocket.toml Secret Key | high | `secret_key` | yes |
| Rust Password Literal | high | `let` | yes |

#### Frontend — React, Angular, Vite (7)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Angular Environment Secret | high | `environment.` | yes |
| Firebase Web Config apiKey | high | `AIza` | yes |
| Next.js Public Environment Secret | high | `NEXT_PUBLIC_` | no |
| React App Environment Secret | high | `REACT_APP_` | no |
| React Native CodePush Deployment Key | high | `CodePushDeploymentKey` | no |
| Vite Environment Secret | high | `VITE_` | no |
| Webpack DefinePlugin Secret | high | `DefinePlugin` | no |

#### Desktop — Electron, Tauri (3)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Electron Builder Publish Credentials | critical | — | yes |
| Electron Forge Publish Token | critical | — | no |
| Tauri Signing Private Key | critical | — | no |

#### iOS native (6)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Apple APNs Auth Key Filename | high | `AuthKey_` | yes |
| Apple App Store Connect API Key ID | high | `key` | yes |
| Apple Developer Team ID | medium | `team` | yes |
| CocoaPods Trunk Session Cookie | high | `_pods_session` | no |
| Cocoapods Trunk Token | critical | `COCOAPODS_TRUNK_TOKEN` | no |
| Xcode Cloud Secret | critical | `XCODE_CLOUD_` | no |

#### Android native (3)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Android Maps API Key in local.properties | high | `MAPS_API_KEY` | no |
| Android Signing Store Password | critical | `Password` | yes |
| Play Console Service Account JSON | critical | `service_account` | yes |

#### Flutter & React Native (5)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Dart Password Literal | high | — | yes |
| EAS Build Secret | high | `EAS_` | no |
| Expo Access Token | critical | `EXPO_TOKEN` | no |
| Fastlane Match Password | critical | `MATCH_PASSWORD` | no |
| Flutter Dart Environment Secret | high | — | yes |

---

### Personal & protected data

> Patterns in this group cover PII, PHI, and regulated identifiers
> across multiple jurisdictions. Most national-ID patterns set
> `require_hotword: true` because their digit-based shapes collide
> with common numeric strings. Bulk medical-code patterns (CPT, HCPCS,
> LOINC, ICD-9, SNOMED CT) fire only on lists of N+ codes.
> Individual pattern rows are defined in
> [`rules/dlp_patterns.json`](./rules/dlp_patterns.json).

#### PII — US general (4)

| Pattern | Severity | Prefix | Hotword required |
|---------|----------|--------|------------------|
| Credit Card Number | critical | — | no |
| Email Addresses (bulk) | medium | `@` | no |
| Phone Numbers (bulk, US) | medium | — | no |
| US Social Security Number | critical | — | no |

#### PII — EU / GDPR (30 patterns)

IBAN, EU VAT, DE Personalausweis / Steueridentifikationsnummer / Sozialversicherungsnummer, FR INSEE / SIREN / SIRET / CNI, IT Codice Fiscale / Partita IVA, ES DNI / NIE / CIF, NL BSN, BE Rijksregister, PL PESEL / NIP, PT NIF, SE Personnummer / Organisationsnummer, FI HETU, GR AFM, HU TAJ.

#### PII — UK (5 patterns)

UK NINO, NHS Number, UK Passport, UK Driver's Licence, UK UTR.

#### PII — Switzerland (4 patterns)

Swiss AHV/AVS (756.xxxx.xxxx.xx), Swiss UID (CHE-xxx.xxx.xxx), Swiss Passport, Swiss ZAS. Swiss IBANs (`CH..`) are matched by the EU IBAN (SEPA) pattern in `pii_eu`.

#### PII — GCC (15 patterns)

UAE Emirates ID (784-…) / TRN / IBAN, Saudi National ID (Iqama) / IBAN / VAT, Qatar QID, Bahrain CPR, Kuwait Civil ID, Oman Civil Number.

#### PII — South & East Asia (20 patterns)

Singapore NRIC/FIN, Malaysia MyKad, Thai National ID, Philippines SSS/TIN/UMID, Indonesia NIK/NPWP, Vietnam CCCD/MST, Japan My Number / Passport, South Korea RRN / Business Registration, Taiwan National ID, China Resident ID / Passport, India Aadhaar / PAN, Hong Kong HKID.

#### PII — CCPA / California (5 patterns)

California Driver's Licence, California State ID, Medi-Cal Beneficiary ID, California Vehicle Plate, CDTFA Sales Tax Permit.

#### PHI — Healthcare (35 patterns)

FHIR/SMART-on-FHIR tokens, Epic/Cerner credentials, HL7 v2 PID/OBX/ORC, DICOM tags, NPI, DEA, MBI, MRN, ICD-10/ICD-9, CPT (bulk), HCPCS Level II (bulk), LOINC (bulk), SNOMED CT (bulk), DSM-5, NDC, CLIA, Medicare HICN (legacy), CMS Certification Number, Insurance Subscriber/Member ID, Patient DOB in clinical context.
