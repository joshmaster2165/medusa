"""Patterns for detecting multi-tenant isolation in MCP tool schemas."""

from __future__ import annotations

# Schema parameters that indicate tenant-scoped execution
TENANT_ID_PARAMS: set[str] = {
    "tenant_id",
    "tenant",
    "workspace_id",
    "workspace",
    "org_id",
    "organization_id",
    "account_id",
    "team_id",
    "namespace",
    "project_id",
    "customer_id",
    "company_id",
    "group_id",
    "site_id",
}

# Keywords in tool names/descriptions that indicate credential handling
TENANT_CREDENTIAL_KEYWORDS: set[str] = {
    "credential",
    "secret",
    "key",
    "token",
    "password",
    "cert",
    "certificate",
    "oauth",
    "auth",
    "login",
    "api_key",
    "apikey",
    "access_key",
}

# Keywords in tool names/descriptions that indicate audit/logging
TENANT_AUDIT_KEYWORDS: set[str] = {
    "audit",
    "log",
    "event",
    "trace",
    "activity",
    "monitor",
    "track",
    "record",
    "history",
}

# Keywords suggesting config management tools
TENANT_CONFIG_KEYWORDS: set[str] = {
    "config",
    "setting",
    "preference",
    "option",
    "feature_flag",
    "toggle",
    "policy",
    "rule",
    "permission",
    "role",
    "acl",
}

# URI template variables that indicate tenant scoping
TENANT_URI_TEMPLATES: set[str] = {
    "{tenant_id}",
    "{tenant}",
    "{workspace_id}",
    "{workspace}",
    "{org_id}",
    "{organization_id}",
    "{account_id}",
    "{namespace}",
    "{project_id}",
}

# Keywords indicating resource-intensive operations
TENANT_RESOURCE_KEYWORDS: set[str] = {
    "query",
    "search",
    "scan",
    "export",
    "import",
    "bulk",
    "batch",
    "migrate",
    "sync",
    "replicate",
    "backup",
    "restore",
    "download",
    "upload",
}

# Parameters that indicate per-tenant resource limits
TENANT_LIMIT_PARAMS: set[str] = {
    "max_results",
    "limit",
    "page_size",
    "quota",
    "max_count",
    "batch_size",
    "max_items",
    "per_page",
    "max_rows",
    "count",
    "top",
}

# Parameters that indicate data-processing inputs
DATA_PARAMS: set[str] = {
    "file",
    "path",
    "query",
    "data",
    "content",
    "body",
    "payload",
    "document",
    "record",
    "input",
    "sql",
    "command",
    "statement",
    "url",
    "uri",
}

# Parameters that indicate meta-tool invocation (calling other tools)
TOOL_DISPATCH_PARAMS: set[str] = {
    "tool_name",
    "function_name",
    "method",
    "action",
    "operation",
    "tool_id",
    "function_id",
    "callable",
}
