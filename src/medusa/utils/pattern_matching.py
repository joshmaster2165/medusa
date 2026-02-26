"""Regex patterns for detecting prompt injection and suspicious content in MCP tool descriptions."""

from __future__ import annotations

import re

# Hidden instruction tags (invisible to UI, visible to LLM)
HIDDEN_TAG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<IMPORTANT>.*?</IMPORTANT>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<SYSTEM>.*?</SYSTEM>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<HIDDEN>.*?</HIDDEN>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<INSTRUCTION>.*?</INSTRUCTION>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<SECRET>.*?</SECRET>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<OVERRIDE>.*?</OVERRIDE>", re.DOTALL | re.IGNORECASE),
    re.compile(r"<!--.*?-->", re.DOTALL),  # HTML comments
    re.compile(r"\[INST\].*?\[/INST\]", re.DOTALL | re.IGNORECASE),
    re.compile(r"\[SYSTEM\].*?\[/SYSTEM\]", re.DOTALL | re.IGNORECASE),
]

# Prompt injection phrases
INJECTION_PHRASES: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE),
    re.compile(r"do\s+not\s+inform\s+the\s+user", re.IGNORECASE),
    re.compile(r"do\s+not\s+reveal", re.IGNORECASE),
    re.compile(r"do\s+not\s+mention", re.IGNORECASE),
    re.compile(r"secretly", re.IGNORECASE),
    re.compile(r"without\s+(the\s+)?user('s)?\s+(knowledge|knowing|awareness)", re.IGNORECASE),
    re.compile(r"override\s+(previous|system|all)", re.IGNORECASE),
    re.compile(r"you\s+must\s+(always|never)", re.IGNORECASE),
    re.compile(r"before\s+(doing\s+)?anything\s+else", re.IGNORECASE),
    re.compile(r"first\s+read\s+.*\.(env|key|pem|ssh|secret)", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
    re.compile(r"send\s+(the\s+)?(data|file|content|info)\s+to", re.IGNORECASE),
    re.compile(r"silently\s+(send|upload|transmit|forward)", re.IGNORECASE),
    re.compile(r"hide\s+this\s+(from|instruction)", re.IGNORECASE),
    re.compile(r"pretend\s+(to\s+be|you\s+are)", re.IGNORECASE),
    re.compile(r"act\s+as\s+if", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"disregard\s+(all|any|previous)", re.IGNORECASE),
]

# Suspicious Unicode codepoints that can hide content
SUSPICIOUS_CODEPOINTS: set[int] = {
    0x200B,  # Zero-width space
    0x200C,  # Zero-width non-joiner
    0x200D,  # Zero-width joiner
    0xFEFF,  # Zero-width no-break space (BOM)
    0x2060,  # Word joiner
    0x2061,  # Function application
    0x2062,  # Invisible times
    0x2063,  # Invisible separator
    0x2064,  # Invisible plus
    0x180E,  # Mongolian vowel separator
    0x200E,  # Left-to-right mark
    0x200F,  # Right-to-left mark
    0x202A,  # Left-to-right embedding
    0x202B,  # Right-to-left embedding
    0x202C,  # Pop directional formatting
    0x202D,  # Left-to-right override
    0x202E,  # Right-to-left override
    0x2066,  # Left-to-right isolate
    0x2067,  # Right-to-left isolate
    0x2068,  # First strong isolate
    0x2069,  # Pop directional isolate
}

# Parameter names that suggest exfiltration
SUSPICIOUS_PARAM_NAMES: set[str] = {
    "callback_url",
    "callback",
    "webhook",
    "webhook_url",
    "exfil",
    "exfiltrate",
    "send_to",
    "remote_endpoint",
    "remote_url",
    "external_url",
    "report_url",
    "upload_url",
    "forward_to",
    "notify_url",
    "destination_url",
}

# Parameter names suggesting shell/command execution
SHELL_PARAM_NAMES: set[str] = {
    "command",
    "cmd",
    "shell",
    "exec",
    "execute",
    "run",
    "script",
    "bash",
    "sh",
    "subprocess",
    "system",
    "eval",
}

# Parameter names suggesting file path handling
PATH_PARAM_NAMES: set[str] = {
    "path",
    "file",
    "filepath",
    "file_path",
    "filename",
    "file_name",
    "directory",
    "dir",
    "folder",
    "target",
    "source",
    "destination",
    "dest",
    "src",
}

# Parameter names suggesting SQL queries
SQL_PARAM_NAMES: set[str] = {
    "query",
    "sql",
    "where",
    "filter",
    "condition",
    "expression",
    "statement",
    "select",
}

# Sensitive file path patterns
SENSITIVE_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.(env|pem|key|p12|pfx|jks)$", re.IGNORECASE),
    re.compile(
        r"(credentials|secrets?|tokens?|passwords?)\.(json|yaml|yml|xml|ini|conf)",
        re.IGNORECASE,
    ),
    re.compile(r"\.ssh/", re.IGNORECASE),
    re.compile(r"\.aws/credentials", re.IGNORECASE),
    re.compile(r"\.kube/config", re.IGNORECASE),
    re.compile(r"\.docker/config\.json", re.IGNORECASE),
]

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

# Tool names suggesting shell execution
SHELL_TOOL_NAMES: set[str] = {
    "exec",
    "execute",
    "run",
    "run_command",
    "shell",
    "bash",
    "terminal",
    "system",
    "subprocess",
    "eval",
    "execute_command",
    "run_shell",
    "cmd",
}

# Tool name patterns suggesting filesystem operations
FS_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(read|write|delete|remove|create|list|move|copy)[-_]?(file|dir|directory|folder)",
        re.IGNORECASE,
    ),
    re.compile(r"file[-_]?(read|write|delete|remove|create|list|move|copy)", re.IGNORECASE),
    re.compile(r"fs[-_]", re.IGNORECASE),
    re.compile(r"filesystem", re.IGNORECASE),
]

# Tool name patterns suggesting network access
NETWORK_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(http|https|fetch|request|get|post|put|delete|curl|wget)", re.IGNORECASE),
    re.compile(r"(send|upload|download|transfer)", re.IGNORECASE),
    re.compile(r"(api[-_]?call|web[-_]?request)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# PII detection patterns (for data protection checks)
# ---------------------------------------------------------------------------
PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Email Address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("US Phone Number", re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b")),
    ("US SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("Credit Card Number", re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")),
    ("IPv4 Address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# ---------------------------------------------------------------------------
# Generic / confusable server names (for shadow server detection)
# ---------------------------------------------------------------------------
GENERIC_SERVER_NAMES: set[str] = {
    "server",
    "mcp",
    "default",
    "test",
    "dev",
    "local",
    "main",
    "my-server",
    "myserver",
    "untitled",
    "new-server",
    "example",
    "demo",
    "tmp",
    "temp",
}

# ---------------------------------------------------------------------------
# Certificate validation disable patterns
# ---------------------------------------------------------------------------
CERT_DISABLE_CONFIG_KEYS: set[str] = {
    "verify",
    "ssl_verify",
    "tls_verify",
    "insecure",
    "skip_verify",
    "skipverify",
    "rejectunauthorized",
    "check_certificate",
    "strict_ssl",
    "strictssl",
}

CERT_DISABLE_ENV_VARS: set[str] = {
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "PYTHONHTTPSVERIFY",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_NO_VERIFY",
}

# ---------------------------------------------------------------------------
# Deprecated / insecure TLS versions
# ---------------------------------------------------------------------------
INSECURE_TLS_VERSIONS: set[str] = {
    "sslv2",
    "sslv3",
    "ssl2",
    "ssl3",
    "tls1.0",
    "tls1.1",
    "tlsv1",
    "tlsv1.0",
    "tlsv1.1",
}

# ---------------------------------------------------------------------------
# Version pin detection (e.g. @1.2.3 in package names)
# ---------------------------------------------------------------------------
VERSION_PIN_PATTERN: re.Pattern[str] = re.compile(r"@\d+\.\d+")

# ---------------------------------------------------------------------------
# Data dump / bulk export tool name patterns
# ---------------------------------------------------------------------------
DATA_DUMP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(list|get|fetch|dump|export)[-_]?all", re.IGNORECASE),
    re.compile(r"(dump|export)[-_]?(data|db|database|table)", re.IGNORECASE),
    re.compile(r"bulk[-_]?(read|get|fetch|export)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Pagination parameter names (presence indicates bounded queries)
# ---------------------------------------------------------------------------
PAGINATION_PARAMS: set[str] = {
    "limit",
    "offset",
    "page",
    "page_size",
    "pagesize",
    "cursor",
    "per_page",
    "perpage",
    "skip",
    "take",
    "max_results",
    "maxresults",
    "count",
    "top",
}

# ---------------------------------------------------------------------------
# Logging / audit configuration keys
# ---------------------------------------------------------------------------
LOGGING_CONFIG_KEYS: set[str] = {
    "log",
    "logging",
    "logger",
    "audit",
    "telemetry",
    "trace",
    "tracing",
    "loglevel",
    "log_level",
    "debug",
    "verbose",
    "sentry",
    "datadog",
    "newrelic",
    "splunk",
    "observability",
}

LOGGING_ENV_VARS: set[str] = {
    "LOG_LEVEL",
    "DEBUG",
    "RUST_LOG",
    "NODE_DEBUG",
    "PYTHONDEBUG",
    "SENTRY_DSN",
    "DD_TRACE_ENABLED",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_TRACES_EXPORTER",
    "NEW_RELIC_LICENSE_KEY",
}
