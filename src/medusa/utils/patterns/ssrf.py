"""Patterns for detecting SSRF, network access, and egress risks."""

from __future__ import annotations

import re

# Private IP address ranges in CIDR notation
PRIVATE_IP_RANGES: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

# Cloud provider metadata service URLs
CLOUD_METADATA_URLS: set[str] = {
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "fd00:ec2::254",
}

# Patterns matching localhost addresses
LOCALHOST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\blocalhost\b", re.IGNORECASE),
    re.compile(r"\b127\.0\.0\.1\b"),
    re.compile(r"\b0\.0\.0\.0\b"),
    re.compile(r"::1\b"),
    re.compile(r"\[::1\]"),
]

# Dangerous URI schemes that should not be allowed in user input
DANGEROUS_SCHEMES: set[str] = {
    "file",
    "gopher",
    "dict",
    "ftp",
    "ldap",
    "tftp",
}

# Parameter names commonly used for URL/endpoint inputs
URL_PARAM_NAMES: set[str] = {
    "url",
    "uri",
    "endpoint",
    "host",
    "hostname",
    "target",
    "redirect",
    "callback",
    "webhook",
    "link",
    "href",
    "fetch",
    "proxy",
    "forward",
    "destination",
    "next",
    "return_url",
    "redirect_uri",
    "callback_url",
}

# Patterns matching internal service hostnames
INTERNAL_SERVICE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"[a-z0-9\-]+\.internal\b", re.IGNORECASE),
    re.compile(r"[a-z0-9\-]+\.local\b", re.IGNORECASE),
    re.compile(r"[a-z0-9\-]+\.svc\.cluster\.local\b", re.IGNORECASE),
]
