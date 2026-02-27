"""Patterns for detecting hardcoded secrets and credentials."""

from __future__ import annotations

import re

# Secret patterns for detecting hardcoded credentials
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i:aws)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
    ("GitHub Personal Access Token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    (
        "Generic API Key",
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?"),
    ),
    (
        "Generic Secret",
        re.compile(r"(?i)(secret|password|passwd|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?"),
    ),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9\-]{32,}")),
    ("Stripe Key", re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}")),
    ("Private Key Header", re.compile(r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----")),
]

# Provider-specific credential patterns for cred004-cred023
PROVIDER_SECRET_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "gcp": [
        ("GCP Service Account", re.compile(r'"type"\s*:\s*"service_account"')),
        (
            "GCP Service Key Env",
            re.compile(
                r"GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_SERVICE_KEY",
                re.IGNORECASE,
            ),
        ),
    ],
    "azure": [
        (
            "Azure Client Secret",
            re.compile(r"AZURE_CLIENT_SECRET|AZURE_TENANT_ID", re.IGNORECASE),
        ),
        (
            "Azure Connection String",
            re.compile(r"SharedAccessKey=[A-Za-z0-9+/=]{20,}"),
        ),
    ],
    "database": [
        (
            "Database Connection String",
            re.compile(r"(postgres|mysql|mongodb|redis|mssql)://[^@\s]+:[^@\s]+@"),
        ),
        (
            "Database URL Env",
            re.compile(r"DATABASE_URL|DB_PASSWORD|DB_CONNECTION", re.IGNORECASE),
        ),
    ],
    "ssh": [
        (
            "SSH Private Key",
            re.compile(r"-----BEGIN\s+(RSA|OPENSSH|DSA|EC)\s*PRIVATE\s+KEY-----"),
        ),
        (
            "SSH Key Path",
            re.compile(r"\.ssh/(id_rsa|id_ed25519|id_ecdsa)", re.IGNORECASE),
        ),
    ],
    "jwt": [
        (
            "JWT Secret Env",
            re.compile(
                r"JWT_SECRET|JWT_KEY|JWT_SIGNING_KEY|JWT_PRIVATE_KEY",
                re.IGNORECASE,
            ),
        ),
    ],
    "oauth": [
        (
            "OAuth Client Secret",
            re.compile(r"(client_secret|OAUTH_.*SECRET)\s*[:=]", re.IGNORECASE),
        ),
    ],
    "smtp": [
        (
            "SMTP Credentials",
            re.compile(r"SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASSWORD", re.IGNORECASE),
        ),
        ("SMTP URI", re.compile(r"smtp://[^@\s]+:[^@\s]+@")),
    ],
    "docker": [
        (
            "Docker Registry Auth",
            re.compile(r"\.dockerconfigjson|DOCKER_AUTH_CONFIG", re.IGNORECASE),
        ),
    ],
    "kubernetes": [
        (
            "Kubernetes Token",
            re.compile(
                r"KUBECONFIG|KUBERNETES_SERVICE_ACCOUNT_TOKEN",
                re.IGNORECASE,
            ),
        ),
    ],
    "terraform": [
        (
            "Terraform Token",
            re.compile(
                r"TF_TOKEN_|TERRAFORM_TOKEN|TF_VAR_.*SECRET",
                re.IGNORECASE,
            ),
        ),
        ("Terraform State", re.compile(r"\.tfstate")),
    ],
    "npm": [
        ("NPM Token", re.compile(r"NPM_TOKEN|npm_token", re.IGNORECASE)),
        (
            "NPM Registry Auth",
            re.compile(r"//registry\.npmjs\.org/:_authToken="),
        ),
    ],
    "pypi": [
        (
            "PyPI Token",
            re.compile(r"PYPI_TOKEN|TWINE_PASSWORD", re.IGNORECASE),
        ),
        ("PyPI Token Value", re.compile(r"pypi-[A-Za-z0-9\-_]{16,}")),
    ],
    "encryption": [
        (
            "Encryption Key Env",
            re.compile(
                r"ENCRYPTION_KEY|AES_KEY|KMS_KEY_ID|MASTER_KEY",
                re.IGNORECASE,
            ),
        ),
    ],
    "webhook": [
        (
            "Webhook Secret",
            re.compile(
                r"WEBHOOK_SECRET|SIGNING_SECRET|X.HUB.SIGNATURE",
                re.IGNORECASE,
            ),
        ),
    ],
    "ldap": [
        (
            "LDAP Bind Password",
            re.compile(r"LDAP_BIND_PASSWORD|LDAP_PASSWORD", re.IGNORECASE),
        ),
        ("LDAP URI Credentials", re.compile(r"ldaps?://[^@\s]+:[^@\s]+@")),
    ],
    "redis": [
        (
            "Redis Password",
            re.compile(r"REDIS_PASSWORD|REDIS_AUTH", re.IGNORECASE),
        ),
        ("Redis URI Credentials", re.compile(r"redis://:[^@\s]+@")),
    ],
    "firebase": [
        (
            "Firebase Credentials",
            re.compile(r"FIREBASE_.*KEY|FIREBASE_TOKEN", re.IGNORECASE),
        ),
        (
            "Firebase Admin SDK",
            re.compile(r"firebase-adminsdk.*\.json"),
        ),
    ],
    "twilio": [
        (
            "Twilio Auth Token",
            re.compile(r"TWILIO_AUTH_TOKEN", re.IGNORECASE),
        ),
        ("Twilio Account SID", re.compile(r"AC[a-f0-9]{32}")),
    ],
    "sendgrid": [
        (
            "SendGrid API Key",
            re.compile(r"SENDGRID_API_KEY", re.IGNORECASE),
        ),
        (
            "SendGrid Key Value",
            re.compile(r"SG\.[A-Za-z0-9\-_]{22,}"),
        ),
    ],
    "vault": [
        (
            "Vault Token",
            re.compile(r"VAULT_TOKEN|VAULT_ADDR", re.IGNORECASE),
        ),
        ("Vault Token Value", re.compile(r"hvs\.[A-Za-z0-9]{20,}")),
    ],
}

# Vault and secret management config keys
VAULT_CONFIG_KEYS: set[str] = {
    "vault",
    "vault_addr",
    "vault_token",
    "vault_path",
    "secrets_manager",
    "aws_secretsmanager",
    "azure_keyvault",
    "gcp_secretmanager",
    "hashicorp_vault",
    "key_management",
    "kms",
}

# Secret rotation config keys
SECRET_ROTATION_KEYS: set[str] = {
    "rotation",
    "rotate",
    "rotation_period",
    "rotation_schedule",
    "auto_rotate",
    "key_rotation",
    "secret_rotation",
    "max_age",
    "expiry",
    "renewal",
}
