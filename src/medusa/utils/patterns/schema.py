"""Patterns for detecting dangerous parameter names, data dumps, and pagination."""

from __future__ import annotations

import re

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

# Data dump / bulk export tool name patterns
DATA_DUMP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(list|get|fetch|dump|export)[-_]?all", re.IGNORECASE),
    re.compile(r"(dump|export)[-_]?(data|db|database|table)", re.IGNORECASE),
    re.compile(r"bulk[-_]?(read|get|fetch|export)", re.IGNORECASE),
]

# Pagination parameter names (presence indicates bounded queries)
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

# LDAP-related parameter names
LDAP_PARAM_NAMES: set[str] = {
    "ldap_query",
    "ldap_filter",
    "dn",
    "distinguished_name",
    "ldap_search",
    "base_dn",
    "search_filter",
    "ldap_bind",
}

# NoSQL/MongoDB-related parameter names
NOSQL_PARAM_NAMES: set[str] = {
    "mongo_query",
    "collection",
    "aggregate",
    "pipeline",
    "document",
    "nosql_query",
    "find_query",
}

# HTTP header parameter names
HEADER_PARAM_NAMES: set[str] = {
    "header",
    "headers",
    "host",
    "referer",
    "user_agent",
    "origin",
    "x_forwarded_for",
    "content_type",
}

# XML-related parameter names
XML_PARAM_NAMES: set[str] = {
    "xml",
    "xml_data",
    "xml_input",
    "soap",
    "wsdl",
    "xslt",
    "xml_content",
    "xml_body",
}

# XPath-related parameter names
XPATH_PARAM_NAMES: set[str] = {
    "xpath",
    "xpath_query",
    "xpath_expression",
    "xml_path",
    "node_path",
}

# URL parameter names
URL_PARAM_NAMES: set[str] = {
    "url",
    "uri",
    "endpoint",
    "link",
    "href",
    "redirect",
    "callback_url",
    "webhook_url",
    "target_url",
    "return_url",
}

# Email parameter names
EMAIL_PARAM_NAMES: set[str] = {
    "email",
    "mail",
    "to",
    "from",
    "cc",
    "bcc",
    "recipient",
    "sender",
    "email_address",
}

# File upload parameter names
FILE_PARAM_NAMES: set[str] = {
    "file",
    "upload",
    "attachment",
    "document",
    "image",
    "media",
    "binary",
    "blob",
}

# CSV-related parameter names
CSV_PARAM_NAMES: set[str] = {
    "csv",
    "csv_data",
    "spreadsheet",
    "tsv",
    "delimiter",
}

# Environment variable parameter names
ENV_PARAM_NAMES: set[str] = {
    "env",
    "environment",
    "env_var",
    "env_name",
    "env_value",
    "variable",
    "config_var",
}

# Template parameter names (for SSTI)
TEMPLATE_PARAM_NAMES: set[str] = {
    "template",
    "template_string",
    "render",
    "format_string",
    "mustache",
    "handlebars",
    "jinja",
}
