use crate::detection::PatternRule;
use crate::models::SecretType;

/// Returns all built-in pattern rules for the Phase 1 pattern library.
pub fn all_patterns() -> Vec<PatternRule> {
    vec![
        // 1 ── AWS Access Key ID
        PatternRule {
            name: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            regex: r"(AKIA[0-9A-Z]{16})".to_string(),
            secret_type: SecretType::AwsAccessKey,
            base_confidence: 0.95,
            remediation:
                "Rotate this key in the AWS IAM console and audit CloudTrail for unauthorized use."
                    .to_string(),
        },
        // 2 ── AWS Secret Access Key
        PatternRule {
            name: "aws-secret-access-key".to_string(),
            description: "AWS Secret Access Key".to_string(),
            regex: r"(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})".to_string(),
            secret_type: SecretType::AwsSecretKey,
            base_confidence: 0.85,
            remediation:
                "Rotate this key in the AWS IAM console and audit CloudTrail for unauthorized use."
                    .to_string(),
        },
        // 3 ── GitHub PAT (classic — ghp_ / ghs_)
        PatternRule {
            name: "github-pat".to_string(),
            description: "GitHub Personal Access Token".to_string(),
            regex: r"(gh[ps]_[A-Za-z0-9]{36,})".to_string(),
            secret_type: SecretType::GitHubPat,
            base_confidence: 0.98,
            remediation:
                "Revoke this token at https://github.com/settings/tokens and rotate dependent services."
                    .to_string(),
        },
        // 4 ── GitHub OAuth token
        PatternRule {
            name: "github-oauth".to_string(),
            description: "GitHub OAuth Token".to_string(),
            regex: r"(gho_[A-Za-z0-9]{36,})".to_string(),
            secret_type: SecretType::GitHubOAuth,
            base_confidence: 0.98,
            remediation:
                "Revoke this OAuth token at https://github.com/settings/applications."
                    .to_string(),
        },
        // 5 ── GitHub fine-grained PAT
        PatternRule {
            name: "github-fine-grained-pat".to_string(),
            description: "GitHub Fine-Grained Personal Access Token".to_string(),
            regex: r"(github_pat_[A-Za-z0-9_]{22,})".to_string(),
            secret_type: SecretType::GitHubPat,
            base_confidence: 0.98,
            remediation:
                "Revoke this token at https://github.com/settings/tokens and rotate dependent services."
                    .to_string(),
        },
        // 6 ── Stripe secret (live) key
        PatternRule {
            name: "stripe-secret-key".to_string(),
            description: "Stripe Live Secret Key".to_string(),
            regex: r"(sk_live_[A-Za-z0-9]{24,})".to_string(),
            secret_type: SecretType::StripeKey,
            base_confidence: 0.98,
            remediation:
                "Rotate this key in the Stripe dashboard and audit recent API activity."
                    .to_string(),
        },
        // 7 ── Stripe test key
        PatternRule {
            name: "stripe-test-key".to_string(),
            description: "Stripe Test Secret Key".to_string(),
            regex: r"(sk_test_[A-Za-z0-9]{24,})".to_string(),
            secret_type: SecretType::StripeKey,
            base_confidence: 0.70,
            remediation:
                "Test keys carry no financial risk but must not be committed. Remove from source."
                    .to_string(),
        },
        // 8 ── Slack bot token
        PatternRule {
            name: "slack-bot-token".to_string(),
            description: "Slack Bot Token".to_string(),
            regex: r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,})".to_string(),
            secret_type: SecretType::SlackToken,
            base_confidence: 0.95,
            remediation: "Revoke this token in the Slack app settings and rotate it.".to_string(),
        },
        // 9 ── Slack user token
        PatternRule {
            name: "slack-user-token".to_string(),
            description: "Slack User Token".to_string(),
            regex: r"(xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9-]{20,})".to_string(),
            secret_type: SecretType::SlackToken,
            base_confidence: 0.95,
            remediation: "Revoke this token in the Slack app settings and rotate it.".to_string(),
        },
        // 10 ── PEM private key header
        PatternRule {
            name: "private-key-pem".to_string(),
            description: "PEM Private Key Header".to_string(),
            regex: r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)".to_string(),
            secret_type: SecretType::PrivateKey,
            base_confidence: 0.99,
            remediation:
                "Revoke and regenerate this key. Remove it from all source files and git history."
                    .to_string(),
        },
        // 11 ── JSON Web Token
        PatternRule {
            name: "jwt".to_string(),
            description: "JSON Web Token (JWT)".to_string(),
            regex: r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})".to_string(),
            secret_type: SecretType::Jwt,
            base_confidence: 0.80,
            remediation:
                "Invalidate this JWT and rotate the signing key if it has been exposed."
                    .to_string(),
        },
        // 12 ── Database URL with credentials
        PatternRule {
            name: "database-url".to_string(),
            description: "Database URL with embedded credentials".to_string(),
            regex: r"((postgres|mysql|mongodb)://[^:\s]+:[^@\s]{3,}@[^\s]+)".to_string(),
            secret_type: SecretType::DatabaseUrl,
            base_confidence: 0.90,
            remediation:
                "Rotate the database password and move credentials to environment variables or a secrets manager."
                    .to_string(),
        },
        // 13 ── Generic connection string
        PatternRule {
            name: "generic-connection-string".to_string(),
            description: "Connection string with embedded credentials".to_string(),
            regex: r"((redis|amqp|rabbitmq)://[^:\s]+:[^@\s]{3,}@[^\s]+)".to_string(),
            secret_type: SecretType::DatabaseUrl,
            base_confidence: 0.88,
            remediation:
                "Move these credentials to environment variables or a secrets manager.".to_string(),
        },
        // 14 ── Heroku API key
        PatternRule {
            name: "heroku-api-key".to_string(),
            description: "Heroku API Key".to_string(),
            regex: r"(?i)heroku[a-z0-9_\-]{0,20}\s*[=:]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.80,
            remediation:
                "Revoke this key in the Heroku dashboard under Account Settings > API Key."
                    .to_string(),
        },
        // 15 ── SendGrid API key
        PatternRule {
            name: "sendgrid-api-key".to_string(),
            description: "SendGrid API Key".to_string(),
            regex: r"(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.98,
            remediation:
                "Revoke this key in the SendGrid dashboard and rotate dependent services."
                    .to_string(),
        },
        // 16 ── Twilio API key
        PatternRule {
            name: "twilio-api-key".to_string(),
            description: "Twilio API Key".to_string(),
            regex: r"(SK[0-9a-fA-F]{32})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.90,
            remediation:
                "Revoke this key in the Twilio console and rotate dependent services.".to_string(),
        },
        // 17 ── npm access token
        PatternRule {
            name: "npm-token".to_string(),
            description: "npm Access Token".to_string(),
            regex: r"(npm_[A-Za-z0-9]{36})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.95,
            remediation: "Revoke this token at https://www.npmjs.com/settings/tokens.".to_string(),
        },
        // 18 ── PyPI API token
        PatternRule {
            name: "pypi-token".to_string(),
            description: "PyPI API Token".to_string(),
            regex: r"(pypi-[A-Za-z0-9_-]{50,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.95,
            remediation:
                "Revoke this token at https://pypi.org/manage/account/token/ and rotate CI pipelines."
                    .to_string(),
        },
        // 19 ── HTTP Authorization Bearer token
        PatternRule {
            name: "generic-bearer-token".to_string(),
            description: "HTTP Authorization Bearer Token".to_string(),
            regex: r"(?i)Authorization:\s*Bearer\s+([A-Za-z0-9_.~+/=\-]{20,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.65,
            remediation:
                "Rotate the token and remove it from any logged or stored HTTP headers.".to_string(),
        },
        // 20 ── Shell export of a secret variable
        PatternRule {
            name: "export-secret-assignment".to_string(),
            description: "Shell export of a secret variable".to_string(),
            regex: r"(?i)export\s+(?:SECRET|TOKEN|API_KEY|PASSWORD|PASSWD|SECRET_KEY)[_A-Z0-9]*\s*=\s*(\S{8,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.60,
            remediation:
                "Move secrets out of shell scripts and into a secrets manager or encrypted vault."
                    .to_string(),
        },
        // =====================================================================
        // Block 15 — Expanded Pattern Library (patterns 21–42)
        // =====================================================================
        //
        // Batch A — Cloud Providers
        //
        // 21 ── GCP Service Account Key
        PatternRule {
            name: "gcp-service-account-key".to_string(),
            description: "GCP Service Account Key".to_string(),
            regex: r#"(?i)(?:private_key|private_key_id)["']?\s*[:=]\s*["']?(-----BEGIN [A-Z ]*PRIVATE KEY-----|[A-Za-z0-9/+=]{40,})["']?"#.to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.95,
            remediation:
                "Delete this service account key in the GCP IAM console and create a new one."
                    .to_string(),
        },
        // 22 ── GCP OAuth Refresh Token
        PatternRule {
            name: "gcp-oauth-refresh-token".to_string(),
            description: "GCP OAuth Refresh Token".to_string(),
            regex: r#"(?i)(?:refresh_token|client_secret)["']?\s*[:=]\s*["']?(1//[A-Za-z0-9_-]{20,})["']?"#
                .to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.85,
            remediation:
                "Revoke this refresh token in the GCP OAuth consent screen and rotate credentials."
                    .to_string(),
        },
        // 23 ── Azure Client Secret
        PatternRule {
            name: "azure-client-secret".to_string(),
            description: "Azure Client Secret".to_string(),
            regex: r"(?i)(?:client_secret|azure[_-]?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*\x22?([A-Za-z0-9~._-]{34,})\x22?".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.88,
            remediation:
                "Rotate this secret in Azure AD app registrations and update dependent services."
                    .to_string(),
        },
        // 24 ── Azure Storage Key
        PatternRule {
            name: "azure-storage-key".to_string(),
            description: "Azure Storage Account Key".to_string(),
            regex: r"(?i)(?:account_key|storage_key|AccountKey|AZURE_STORAGE_KEY)\s*[=:]\s*\x22?([A-Za-z0-9/+=]{86,90})\x22?".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.92,
            remediation:
                "Rotate this storage key in the Azure portal and update connection strings."
                    .to_string(),
        },
        // 25 ── Azure SAS Token
        PatternRule {
            name: "azure-sas-token".to_string(),
            description: "Azure Shared Access Signature Token".to_string(),
            regex: r"[?&]sig=([A-Za-z0-9%/+=]{30,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.90,
            remediation:
                "Regenerate the SAS token and revoke the old one via the Azure portal."
                    .to_string(),
        },
        // 26 ── DigitalOcean Token
        PatternRule {
            name: "digitalocean-token".to_string(),
            description: "DigitalOcean Personal Access Token".to_string(),
            regex: r"(do[po]_v1_[a-f0-9]{64})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.95,
            remediation:
                "Revoke this token in the DigitalOcean API settings and generate a new one."
                    .to_string(),
        },
        //
        // Batch B — Git Platforms
        //
        // 27 ── GitLab Personal Access Token
        PatternRule {
            name: "gitlab-pat".to_string(),
            description: "GitLab Personal Access Token".to_string(),
            regex: r"(glpat-[A-Za-z0-9_-]{20,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.98,
            remediation:
                "Revoke this token in GitLab User Settings > Access Tokens and rotate it."
                    .to_string(),
        },
        // 28 ── GitLab Pipeline Trigger Token
        PatternRule {
            name: "gitlab-pipeline-token".to_string(),
            description: "GitLab Pipeline Trigger Token".to_string(),
            regex: r"(glptt-[A-Za-z0-9_-]{20,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.90,
            remediation:
                "Revoke this trigger token in GitLab CI/CD Settings > Pipeline triggers."
                    .to_string(),
        },
        // 29 ── Bitbucket App Password
        PatternRule {
            name: "bitbucket-app-password".to_string(),
            description: "Bitbucket App Password".to_string(),
            regex: r"(ATBB[A-Za-z0-9]{32,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.80,
            remediation:
                "Revoke this app password in Bitbucket Personal Settings > App passwords."
                    .to_string(),
        },
        //
        // Batch C — SaaS / API Keys
        //
        // 30 ── Shopify Token
        PatternRule {
            name: "shopify-token".to_string(),
            description: "Shopify Access Token".to_string(),
            regex: r"(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.95,
            remediation:
                "Rotate this token in the Shopify Partner Dashboard or admin app settings."
                    .to_string(),
        },
        // 31 ── Mailgun API Key
        PatternRule {
            name: "mailgun-api-key".to_string(),
            description: "Mailgun API Key".to_string(),
            regex: r"(?i)(?:mailgun|mg)[_\-]?(?:api[_\-]?)?key\s*[=:]\s*\x22?(key-[a-f0-9]{32,})\x22?"
                .to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.95,
            remediation:
                "Rotate this API key in the Mailgun dashboard under Settings > API Keys."
                    .to_string(),
        },
        // 32 ── Datadog API Key
        PatternRule {
            name: "datadog-api-key".to_string(),
            description: "Datadog API Key".to_string(),
            regex: r"(?i)(?:datadog|dd)[_\-]?(?:api[_\-]?)?key\s*[=:]\s*\x22?([a-f0-9]{32})\x22?"
                .to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.90,
            remediation:
                "Revoke this API key in the Datadog Organization Settings and generate a new one."
                    .to_string(),
        },
        // 33 ── HashiCorp Vault Token
        PatternRule {
            name: "hashicorp-vault-token".to_string(),
            description: "HashiCorp Vault Token".to_string(),
            regex: r"(hvs\.[A-Za-z0-9_-]{24,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.92,
            remediation:
                "Revoke this Vault token and audit the Vault audit log for unauthorized access."
                    .to_string(),
        },
        // 34 ── HashiCorp Terraform Cloud Token
        PatternRule {
            name: "hashicorp-terraform-token".to_string(),
            description: "HashiCorp Terraform Cloud Token".to_string(),
            regex: r"([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.92,
            remediation:
                "Revoke this token in Terraform Cloud under User Settings > Tokens."
                    .to_string(),
        },
        //
        // Batch D — AI Providers
        //
        // 35 ── OpenAI API Key
        PatternRule {
            name: "openai-api-key".to_string(),
            description: "OpenAI API Key".to_string(),
            regex: r"(sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"
                .to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.98,
            remediation:
                "Revoke this key at https://platform.openai.com/api-keys and generate a new one."
                    .to_string(),
        },
        // 36 ── Anthropic API Key
        PatternRule {
            name: "anthropic-api-key".to_string(),
            description: "Anthropic API Key".to_string(),
            regex: r"(sk-ant-[A-Za-z0-9_-]{20,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.98,
            remediation:
                "Revoke this key in the Anthropic Console and generate a new one.".to_string(),
        },
        //
        // Batch E — Infrastructure
        //
        // 37 ── Docker Auth (base64)
        PatternRule {
            name: "docker-auth-base64".to_string(),
            description: "Docker Registry Auth (base64)".to_string(),
            regex: r#"(?i)"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})""#.to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.85,
            remediation:
                "Remove this auth entry from Docker config and use credential helpers instead."
                    .to_string(),
        },
        // 38 ── Kubernetes Bearer Token
        PatternRule {
            name: "kubernetes-bearer-token".to_string(),
            description: "Kubernetes Bearer Token".to_string(),
            regex: r#"(?i)(?:token|bearer)\s*[=:]\s*"?([A-Za-z0-9._-]{100,})"?"#.to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.80,
            remediation:
                "Rotate this service account token and audit RBAC bindings in the cluster."
                    .to_string(),
        },
        // 39 ── SSH Unencrypted Private Key Header
        PatternRule {
            name: "ssh-unencrypted-key-header".to_string(),
            description: "SSH Unencrypted Private Key Header".to_string(),
            regex: r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----)"
                .to_string(),
            secret_type: SecretType::PrivateKey,
            base_confidence: 0.99,
            remediation:
                "Encrypt this key with a passphrase or regenerate it. Remove from source control."
                    .to_string(),
        },
        // 40 ── age Secret Key
        PatternRule {
            name: "age-secret-key".to_string(),
            description: "age Encryption Secret Key".to_string(),
            regex: r"(AGE-SECRET-KEY-1[A-Za-z0-9]{58,})".to_string(),
            secret_type: SecretType::PrivateKey,
            base_confidence: 0.95,
            remediation:
                "Generate a new age key and re-encrypt any files that used the old key."
                    .to_string(),
        },
        // 41 ── GitHub App Private Key
        PatternRule {
            name: "github-app-private-key".to_string(),
            description: "GitHub App Private Key".to_string(),
            regex: r"(?i)github[_\- ]?app.{0,40}(-----BEGIN [A-Z ]*PRIVATE KEY-----)"
                .to_string(),
            secret_type: SecretType::PrivateKey,
            base_confidence: 0.95,
            remediation:
                "Regenerate this key in the GitHub App settings and update all consumers."
                    .to_string(),
        },
        // 42 ── Basic Auth URL
        PatternRule {
            name: "basic-auth-url".to_string(),
            description: "URL with embedded basic-auth credentials".to_string(),
            regex: r"(https?://[^:\s]+:[^@\s]{3,}@[A-Za-z0-9][-A-Za-z0-9.]+)".to_string(),
            secret_type: SecretType::DatabaseUrl,
            base_confidence: 0.88,
            remediation:
                "Move credentials out of URLs and into environment variables or a secrets manager."
                    .to_string(),
        },
    ]
}
