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
    ]
}
