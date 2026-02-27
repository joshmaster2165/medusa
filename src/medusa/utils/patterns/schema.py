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
