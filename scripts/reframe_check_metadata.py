#!/usr/bin/env python3
"""Reframe all check metadata YAML files to CIS/STIG-style language.

Transforms titles from "Missing X" to "Ensure X is configured" and
descriptions from "Detects...that lack" to "Verifies that...".
"""

import csv
import re
import sys
from pathlib import Path

import yaml


CHECKS_DIR = Path(__file__).resolve().parent.parent / "src" / "medusa" / "checks"

# ---------------------------------------------------------------------------
# Title transformation rules (order matters — first match wins)
# ---------------------------------------------------------------------------
TITLE_RULES: list[tuple[re.Pattern, str]] = [
    # [AI] titles — keep as-is
    (re.compile(r"^\[AI\]"), None),
    # "Missing X" → "Ensure X is configured"
    (re.compile(r"^Missing\s+(.+)$", re.I), r"Ensure \1 is configured"),
    # "No X on Y" → "Ensure X is enabled for Y"
    (re.compile(r"^No\s+(.+?)\s+on\s+(.+)$", re.I), r"Ensure \1 is enabled for \2"),
    # "No X" → "Ensure X is enabled"
    (re.compile(r"^No\s+(.+)$", re.I), r"Ensure \1 is enabled"),
    # "Insecure X" → "Ensure X meets security requirements"
    (re.compile(r"^Insecure\s+(.+)$", re.I), r"Ensure \1 meets security requirements"),
    # "Weak X" → "Ensure \1 has sufficient strength"
    (re.compile(r"^Weak\s+(.+)$", re.I), r"Ensure \1 has sufficient strength"),
    # "Hardcoded X" → "Ensure X is not hardcoded"
    (re.compile(r"^Hardcoded\s+(.+)$", re.I), r"Ensure \1 is not hardcoded"),
    # "Plaintext X in Y" → "Ensure X is not stored in plaintext in Y"
    (re.compile(r"^Plaintext\s+(.+?)\s+in\s+(.+)$", re.I), r"Ensure \1 is not stored in plaintext in \2"),
    # "Secrets in X" → "Ensure secrets are not present in X"
    (re.compile(r"^Secrets\s+in\s+(.+)$", re.I), r"Ensure secrets are not present in \1"),
    # "X in Y" (credential/token exposure patterns) → "Ensure X is not exposed in Y"
    (re.compile(r"^(Bearer Token|API Key|Credentials?|Token)\s+in\s+(.+)$", re.I), r"Ensure \1 is not exposed in \2"),
    # "Overly Permissive X" → "Ensure X follows least-privilege"
    (re.compile(r"^Overly\s+Permissive\s+(.+)$", re.I), r"Ensure \1 follows least-privilege"),
    # "Excessive X" → "Ensure X is bounded"
    (re.compile(r"^Excessive\s+(.+)$", re.I), r"Ensure \1 is bounded"),
    # "Unencrypted X" → "Ensure X uses encryption"
    (re.compile(r"^Unencrypted\s+(.+)$", re.I), r"Ensure \1 uses encryption"),
    # "Unnecessary X Enabled" → "Ensure unnecessary X is disabled"
    (re.compile(r"^Unnecessary\s+(.+?)\s+Enabled$", re.I), r"Ensure unnecessary \1 is disabled"),
    # "X Enabled" (bad config) → "Ensure X is disabled in production"
    (re.compile(r"^(Debug Mode)\s+Enabled$", re.I), r"Ensure \1 is disabled in production"),
    # "Default X" → "Ensure X does not use defaults"
    (re.compile(r"^Default\s+(.+)$", re.I), r"Ensure \1 does not use defaults"),
    # "X Exposed" → "Ensure X is not exposed"
    (re.compile(r"^(.+?)\s+Exposed$", re.I), r"Ensure \1 is not exposed"),
    # "X Detected" → "Ensure X is not present"
    (re.compile(r"^(.+?)\s+Detected$", re.I), r"Ensure \1 is not present"),
    # "X Risk via Y" → "Ensure Y is protected against X"
    (re.compile(r"^(.+?)\s+Risk\s+via\s+(.+)$", re.I), r"Ensure \2 is protected against \1"),
    # "X Risk" → "Ensure protection against X"
    (re.compile(r"^(.+?)\s+Risk$", re.I), r"Ensure protection against \1"),
    # "X Vulnerability" → "Ensure protection against X vulnerability"
    (re.compile(r"^(.+?)\s+Vulnerability$", re.I), r"Ensure protection against \1 vulnerability"),
    # "X Attack" → "Ensure protection against X attack"
    (re.compile(r"^(.+?)\s+Attack$", re.I), r"Ensure protection against \1 attack"),
    # "X Injection" → "Ensure protection against X injection"
    (re.compile(r"^(.+?)\s+Injection$", re.I), r"Ensure protection against \1 injection"),
    # "X Exposure" → "Ensure X is not exposed"
    (re.compile(r"^(.+?)\s+Exposure$", re.I), r"Ensure \1 is not exposed"),
    # "X Leakage" → "Ensure X is not leaked"
    (re.compile(r"^(.+?)\s+Leakage$", re.I), r"Ensure \1 is not leaked"),
    # "Rug Pull Detection — X" → "Ensure protection against rug pull — X"
    (re.compile(r"^Rug Pull Detection\s*[—–-]\s*(.+)$", re.I), r"Ensure protection against rug pull — \1"),
    # "X / Y" (compound) → "Ensure protection against X / Y"
    (re.compile(r"^(Tool Shadowing)\s*/\s*(.+)$", re.I), r"Ensure protection against \1 / \2"),
    # "Hidden X in Y" → "Ensure Y does not contain hidden X"
    (re.compile(r"^Hidden\s+(.+?)\s+in\s+(.+)$", re.I), r"Ensure \2 does not contain hidden \1"),
    # "X Without Y" → "Ensure Y is configured for X"
    (re.compile(r"^(.+?)\s+Without\s+(.+)$", re.I), r"Ensure \2 is configured for \1"),
    # "Shared X" → "Ensure X is not shared"
    (re.compile(r"^Shared\s+(.+)$", re.I), r"Ensure \1 is not shared"),
    # "X Capability Detected" → "Ensure X capability is controlled"
    (re.compile(r"^(.+?)\s+Capability\s+Detected$", re.I), r"Ensure \1 capability is controlled"),
    # --- Additional patterns for remaining noun-phrase titles ---
    # "Unbounded X" → "Ensure X is bounded"
    (re.compile(r"^Unbounded\s+(.+)$", re.I), r"Ensure \1 is bounded"),
    # "Unrestricted X" → "Ensure X is restricted"
    (re.compile(r"^Unrestricted\s+(.+)$", re.I), r"Ensure \1 is restricted"),
    # "Unauthorized X" → "Ensure X is authorized"
    (re.compile(r"^Unauthorized\s+(.+)$", re.I), r"Ensure \1 is authorized"),
    # "Unsigned X" → "Ensure X is signed"
    (re.compile(r"^Unsigned\s+(.+)$", re.I), r"Ensure \1 is signed"),
    # "Conflicting X" → "Ensure X does not conflict"
    (re.compile(r"^Conflicting\s+(.+)$", re.I), r"Ensure \1 does not conflict"),
    # "Overprivileged X" → "Ensure X follows least-privilege"
    (re.compile(r"^Overprivileged\s+(.+)$", re.I), r"Ensure \1 follows least-privilege"),
    # "Permissive X" → "Ensure X follows least-privilege"
    (re.compile(r"^Permissive\s+(.+)$", re.I), r"Ensure \1 follows least-privilege"),
    # "Verbose X" → "Ensure X does not disclose sensitive information"
    (re.compile(r"^Verbose\s+(.+)$", re.I), r"Ensure \1 does not disclose sensitive information"),
    # "Insufficient X" → "Ensure X is sufficient"
    (re.compile(r"^Insufficient\s+(.+)$", re.I), r"Ensure \1 is sufficient"),
    # "Suspicious X" → "Ensure X is validated"
    (re.compile(r"^Suspicious\s+(.+)$", re.I), r"Ensure \1 is validated"),
    # "Unmasked X" → "Ensure X is masked"
    (re.compile(r"^Unmasked\s+(.+)$", re.I), r"Ensure \1 is masked"),
    # "Unverified X" → "Ensure X is verified"
    (re.compile(r"^Unverified\s+(.+)$", re.I), r"Ensure \1 is verified"),
    # "Untrusted X" → "Ensure X is trusted and verified"
    (re.compile(r"^Untrusted\s+(.+)$", re.I), r"Ensure \1 is trusted and verified"),
    # "Unpinned X" → "Ensure X is pinned"
    (re.compile(r"^Unpinned\s+(.+)$", re.I), r"Ensure \1 is pinned"),
    # "Abandoned X" → "Ensure X is actively maintained"
    (re.compile(r"^Abandoned\s+(.+)$", re.I), r"Ensure \1 is actively maintained"),
    # "Writable X" → "Ensure X is not writable"
    (re.compile(r"^Writable\s+(.+)$", re.I), r"Ensure \1 is not writable"),
    # "Exposed X" → "Ensure X is not exposed"
    (re.compile(r"^Exposed\s+(.+)$", re.I), r"Ensure \1 is not exposed"),
    # "Known X" → "Ensure no known X"
    (re.compile(r"^Known\s+(.+)$", re.I), r"Ensure no known \1"),
    # "Dangerous X" → "Ensure X is safe"
    (re.compile(r"^Dangerous\s+(.+)$", re.I), r"Ensure \1 is safe"),
    # "Empty X" → "Ensure X is populated"
    (re.compile(r"^Empty\s+(.+)$", re.I), r"Ensure \1 is populated"),
    # "Untyped X" → "Ensure X is typed"
    (re.compile(r"^Untyped\s+(.+)$", re.I), r"Ensure \1 is typed"),
    # "Abnormal X" → "Ensure X is within normal bounds"
    (re.compile(r"^Abnormal(?:ly)?\s+(.+)$", re.I), r"Ensure \1 is within normal bounds"),
    # "Open X" → "Ensure X is restricted"
    (re.compile(r"^Open\s+(.+)$", re.I), r"Ensure \1 is restricted"),
    # "Deeply Nested X" → "Ensure X depth is limited"
    (re.compile(r"^Deeply\s+Nested\s+(.+)$", re.I), r"Ensure \1 depth is limited"),
    # "Recursive X" → "Ensure X recursion is limited"
    (re.compile(r"^Recursive\s+(.+)$", re.I), r"Ensure \1 recursion is limited"),
    # "Wildcard X" → "Ensure X does not use wildcards"
    (re.compile(r"^Wildcard\s+(.+)$", re.I), r"Ensure \1 does not use wildcards"),
    # "Generic X" → "Ensure X is specific and unique"
    (re.compile(r"^Generic\s+(.+)$", re.I), r"Ensure \1 is specific and unique"),
    # "Duplicate X" → "Ensure X is unique"
    (re.compile(r"^Duplicate\s+(.+)$", re.I), r"Ensure \1 is unique"),
    # "Schema-Less X" → "Ensure X has a schema"
    (re.compile(r"^Schema-?[Ll]ess\s+(.+)$", re.I), r"Ensure \1 has a schema"),
    # "Inconsistent X" → "Ensure X is consistent"
    (re.compile(r"^Inconsistent\s+(.+)$", re.I), r"Ensure \1 is consistent"),
    # --- Threat/attack noun-phrase patterns ---
    # "X Poisoning" → "Ensure protection against X poisoning"
    (re.compile(r"^(.+?)\s+Poisoning$", re.I), r"Ensure protection against \1 poisoning"),
    # "X Hijacking" → "Ensure protection against X hijacking"
    (re.compile(r"^(.+?)\s+Hijacking$", re.I), r"Ensure protection against \1 hijacking"),
    # "X Hacking" → "Ensure protection against X hacking"
    (re.compile(r"^(.+?)\s+Hacking$", re.I), r"Ensure protection against \1 hacking"),
    # "X Impersonation" → "Ensure protection against X impersonation"
    (re.compile(r"^(.+?)\s+Impersonation$", re.I), r"Ensure protection against \1 impersonation"),
    # "X Manipulation" → "Ensure protection against X manipulation"
    (re.compile(r"^(.+?)\s+Manipulation$", re.I), r"Ensure protection against \1 manipulation"),
    # "X Exhaustion" → "Ensure protection against X exhaustion"
    (re.compile(r"^(.+?)\s+Exhaustion$", re.I), r"Ensure protection against \1 exhaustion"),
    # "X Accumulation" → "Ensure protection against X accumulation"
    (re.compile(r"^(.+?)\s+Accumulation$", re.I), r"Ensure protection against \1 accumulation"),
    # "X Contamination" → "Ensure protection against X contamination"
    (re.compile(r"^(.+?)\s+Contamination$", re.I), r"Ensure protection against \1 contamination"),
    # "X Hoarding" → "Ensure protection against X hoarding"
    (re.compile(r"^(.+?)\s+Hoarding$", re.I), r"Ensure protection against \1 hoarding"),
    # "X Self-Modification" → "Ensure X self-modification is prevented"
    (re.compile(r"^(.+?)\s+Self-Modification$", re.I), r"Ensure \1 self-modification is prevented"),
    # "X Fixation" → "Ensure protection against X fixation"
    (re.compile(r"^(.+?)\s+Fixation\b", re.I), r"Ensure protection against \1 fixation"),
    # "X Escalation" → "Ensure protection against X escalation"
    (re.compile(r"^(.+?)\s+Escalation$", re.I), r"Ensure protection against \1 escalation"),
    # "X Exfiltration" → "Ensure protection against X exfiltration"
    (re.compile(r"^(.+?)\s+Exfiltration$", re.I), r"Ensure protection against \1 exfiltration"),
    # "X Spoofing" → "Ensure protection against X spoofing"
    (re.compile(r"^(.+?)\s+Spoofing$", re.I), r"Ensure protection against \1 spoofing"),
    # "X Enumeration" → "Ensure protection against X enumeration"
    (re.compile(r"^(.+?)\s+Enumeration$", re.I), r"Ensure protection against \1 enumeration"),
    # "X Abuse" → "Ensure protection against X abuse"
    (re.compile(r"^(.+?)\s+Abuse$", re.I), r"Ensure protection against \1 abuse"),
    # "X Bypass" → "Ensure protection against X bypass"
    (re.compile(r"^(.+?)\s+Bypass$", re.I), r"Ensure protection against \1 bypass"),
    # "X Following" → "Ensure X following is restricted"
    (re.compile(r"^(.+?)\s+Following$", re.I), r"Ensure \1 following is restricted"),
    # "X Violation" → "Ensure protection against X violation"
    (re.compile(r"^(.+?)\s+Violation$", re.I), r"Ensure protection against \1 violation"),
    # "X Mismatch" → "Ensure X is consistent"
    (re.compile(r"^(.+?)\s+Mismatch$", re.I), r"Ensure \1 is consistent"),
    # "X Collision" → "Ensure X is unique"
    (re.compile(r"^(.+?)\s+Collision$", re.I), r"Ensure \1 is unique"),
    # "X Drift" → "Ensure X integrity is maintained"
    (re.compile(r"^(.+?)\s+Drift(?:\s+Detection)?$", re.I), r"Ensure \1 integrity is maintained"),
    # "X Detection" → "Ensure protection against X"
    (re.compile(r"^(.+?)\s+Detection$", re.I), r"Ensure protection against \1"),
    # --- Specific patterns for remaining titles ---
    # "X Enabled" → "Ensure X is disabled"
    (re.compile(r"^(.+?)\s+Enabled$", re.I), r"Ensure \1 is disabled"),
    # "X Absent" → "Ensure X is present"
    (re.compile(r"^(.+?)\s+Absent$", re.I), r"Ensure \1 is present"),
    # "X Present" → "Ensure X is not present"
    (re.compile(r"^(.+?)\s+Present$", re.I), r"Ensure \1 is not present"),
    # "X Access" (capability) → "Ensure X access is controlled"
    (re.compile(r"^(.+?)\s+Access$", re.I), r"Ensure \1 access is controlled"),
    # "X Sprawl" → "Ensure X is controlled"
    (re.compile(r"^(.+?)\s+Sprawl$", re.I), r"Ensure \1 is controlled"),
    # "X Override" → "Ensure X override is prevented"
    (re.compile(r"^(.+?)\s+Override$", re.I), r"Ensure \1 override is prevented"),
    # --- Compound patterns with "in/via/over" ---
    # "Sensitive X in Y" → "Ensure sensitive X is not present in Y"
    (re.compile(r"^(Sensitive\s+.+?)\s+in\s+(.+)$", re.I), r"Ensure \1 is not present in \2"),
    # "X in Y" (general data location) → "Ensure X is not present in Y"
    (re.compile(r"^(PII|Data|Secret[s]?|Token[s]?|Session\s+\w+)\s+in\s+(.+)$", re.I), r"Ensure \1 is not present in \2"),
    # "X via Y" → "Ensure protection against X via Y"
    (re.compile(r"^(.+?)\s+via\s+(.+)$", re.I), r"Ensure protection against \1 via \2"),
    # "X Over Y" → "Ensure X is not used over Y"
    (re.compile(r"^(.+?)\s+Over\s+(.+)$", re.I), r"Ensure \1 is not used over \2"),
    # "Cross-X Y Z" → "Ensure protection against cross-X Y Z"
    (re.compile(r"^(Cross-\S+)\s+(.+)$", re.I), r"Ensure protection against \1 \2"),
    # --- Catch-all for remaining noun phrases (must be last) ---
    # Titles that describe a thing to protect against
    (re.compile(r"^(.+)$"), r"Ensure protection against \1"),
]

# ---------------------------------------------------------------------------
# Description transformation rules
# ---------------------------------------------------------------------------
DESC_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^Detects MCP server deployments that lack\b"), "Verifies that the MCP server has"),
    (re.compile(r"^Detects MCP servers? that lack\b"), "Verifies that the MCP server has"),
    (re.compile(r"^Detects MCP servers? exposed\b"), "Checks whether the MCP server is exposed"),
    (re.compile(r"^Detects MCP servers?\b"), "Checks the MCP server for"),
    (re.compile(r"^Detects when\b"), "Checks whether"),
    (re.compile(r"^Detects\b"), "Checks for"),
    (re.compile(r"^Checks for MCP servers? that lack\b"), "Verifies that the MCP server has"),
    (re.compile(r"^Identifies\b"), "Checks for"),
    (re.compile(r"^Scans for\b"), "Checks for"),
]


def fix_grammar(title: str) -> str:
    """Fix is/are agreement for plural nouns in generated titles."""
    # Common plural endings that need "are" instead of "is"
    plural_patterns = [
        r"((?:Binaries|Endpoints|Secrets|Paths|Names|Annotations|Messages|"
        r"Descriptions|Parameters|Values|Fields|Tokens|Keys|Certificates|"
        r"Headers|Flags|Policies|Communications|Capabilities|Operations|"
        r"Dependencies|Sources|Properties|Updates|Scripts|Rights|"
        r"Credentials|Resources|Definitions|Arguments|Tools|Checks|"
        r"Counts|Variables|Services|Modules|Tasks|Rules|Queries|"
        r"Capabilities|Communications|Operations|Indicators))\s+is\b"
    ]
    for pat in plural_patterns:
        title = re.sub(pat, r"\1 are", title)

    # Fix "does not conflict" → "do not conflict" for plural nouns
    title = re.sub(
        r"(Names|Descriptions|Parameters|Tools|Keys)\s+does\b",
        r"\1 do",
        title,
    )

    return title


# Specific title overrides for titles that don't transform well with regex
TITLE_OVERRIDES: dict[str, str] = {
    "Shared Secrets Across Servers": "Ensure secrets are not shared across servers",
    "Shared Secrets Across Environments": "Ensure secrets are not shared across environments",
    "Generic or Duplicate-Prone Server Name": "Ensure server name is specific and unique",
    "JWT Secret in Environment": "Ensure JWT secret is not present in environment variables",
    "JWT Weak Signing Key": "Ensure JWT signing key has sufficient strength",
    "Token Scope Too Broad": "Ensure token scope follows least-privilege",
    "Basic Auth Over HTTP": "Ensure basic authentication is not used over HTTP",
    "Session ID Stored in URL": "Ensure session ID is not stored in URL",
    "PII in Tool/Resource/Prompt Definitions": "Ensure PII is not present in tool/resource/prompt definitions",
    "Information Disclosure via Errors": "Ensure errors do not disclose sensitive information",
    "Data Leakage via Error Messages": "Ensure error messages do not leak sensitive data",
    "API Version in Error Messages": "Ensure API version is not disclosed in error messages",
    "Sensitive File Paths in Errors": "Ensure sensitive file paths are not disclosed in errors",
    "Sensitive Data in Logs": "Ensure sensitive data is not present in logs",
    "DNS Over HTTP": "Ensure DNS uses encrypted transport",
    "Mixed Content Transport": "Ensure transport does not mix encrypted and unencrypted content",
    "Self-Signed Certificate Usage": "Ensure certificates are not self-signed in production",
    "Certificate Pinning Absent": "Ensure certificate pinning is configured",
    "Expired TLS Certificate": "Ensure TLS certificates are not expired",
    "Wildcard Certificate Usage": "Ensure wildcard certificates are not used",
    "Context Poisoning via Resource Content": "Ensure protection against context poisoning via resource content",
    "Package Installation Rights": "Ensure package installation rights are restricted",
    "IDOR in Resource Access": "Ensure protection against IDOR in resource access",
    "Horizontal Privilege Escalation": "Ensure protection against horizontal privilege escalation",
    "Cross-Tenant Data Access": "Ensure cross-tenant data access is prevented",
    "Cross-Tenant Tool Access": "Ensure cross-tenant tool access is prevented",
    "Cross-Site Session Sharing": "Ensure cross-site session sharing is prevented",
    "Session Hijacking via XSS": "Ensure protection against session hijacking via XSS",
    "Cloud Metadata Service Access": "Ensure cloud metadata service access is restricted",
    "Directory Listing Enabled": "Ensure directory listing is disabled",
    "Debug Endpoints Enabled": "Ensure debug endpoints are disabled",
    "Debug Mode Indicators": "Ensure debug mode indicators are not present",
    "Integer Overflow Risk": "Ensure protection against integer overflow",
    "Regular Expression DoS (ReDoS)": "Ensure protection against regular expression DoS (ReDoS)",
    "Regex Denial of Service (ReDoS)": "Ensure protection against regex denial of service (ReDoS)",
    "HTTP Header Injection (CRLF)": "Ensure protection against HTTP header injection (CRLF)",
    "XML External Entity Injection (XXE)": "Ensure protection against XML external entity injection (XXE)",
    "Child Data Protection (COPPA)": "Ensure child data protection (COPPA) compliance",
    "Excessive Tool/Resource/Prompt Counts (Over-Sharing)": "Ensure tool/resource/prompt counts are bounded",
    "Tool Shadowing / Namespace Collision": "Ensure protection against tool shadowing / namespace collision",
    "Rug Pull Detection \u2014 Tool Definition Drift": "Ensure protection against rug pull \u2014 tool definition drift",
    "WebSocket Session Security": "Ensure WebSocket session security is configured",
    "Terraform State Secrets": "Ensure Terraform state does not contain secrets",
    "Cron/Scheduled Task Creation": "Ensure cron/scheduled task creation is restricted",
    "Sudo/Root Elevation": "Ensure sudo/root elevation is restricted",
    "Session Token in Logs": "Ensure session tokens are not present in logs",
    "Code Evaluation in Server Args": "Ensure server args do not contain code evaluation",
    "Remote Code Loading in Args": "Ensure server args do not load remote code",
    "Shell Metacharacters in Server Command": "Ensure server command does not contain shell metacharacters",
    "Install Scripts Present": "Ensure install scripts are reviewed for safety",
    "Native Binary Dependencies": "Ensure native binary dependencies are verified",
    "Secret Sprawl": "Ensure secret sprawl is controlled",
    "High-Entropy Default Values": "Ensure default values do not contain high-entropy secrets",
    "Bulk Data Export Tool": "Ensure bulk data export is controlled",
    "Schema Poisoning via Default Values": "Ensure protection against schema poisoning via default values",
    "Cross-Origin Data Sharing": "Ensure cross-origin data sharing is controlled",
    "Data Minimization Violation": "Ensure data minimization principles are followed",
    "Overly Broad Session Cookie Scope": "Ensure session cookie scope follows least-privilege",
    "Configuration Stored in World-Writable Path": "Ensure configuration is not stored in world-writable path",
    "Lockfile Integrity Tampered": "Ensure lockfile integrity is maintained",
    "Tool Schema Drift Detection": "Ensure tool schema integrity is maintained",
    "Instruction Hierarchy Violation": "Ensure instruction hierarchy is enforced",
    "Inconsistent Tool Naming Convention": "Ensure tool naming convention is consistent",
    "Permissive Server Capabilities": "Ensure server capabilities follow least-privilege",
    "XML External Entity Injection (XXE)": "Ensure protection against XML external entity injection (XXE)",
    "XML External Entity (XXE) Injection": "Ensure protection against XML external entity (XXE) injection",
    "Exposed Version Information": "Ensure version information is not exposed",
    "Writable Directory Binary Path": "Ensure binary path is not in a writable directory",
    "Dangerous Default Prompt Arguments": "Ensure default prompt arguments are safe",
    "Cross-Conversation Context Contamination": "Ensure protection against cross-conversation context contamination",
    "Multi-Turn Conversation Manipulation": "Ensure protection against multi-turn conversation manipulation",
    "Sampling Without Rate Limit": "Ensure sampling has rate limiting configured",
}


def transform_title(title: str) -> str:
    """Apply CIS/STIG-style title transformation."""
    # Check overrides first
    if title in TITLE_OVERRIDES:
        return TITLE_OVERRIDES[title]

    for pattern, replacement in TITLE_RULES:
        if replacement is None:
            # Skip rule (e.g., [AI] titles)
            if pattern.search(title):
                return title
        else:
            new_title, n = pattern.subn(replacement, title, count=1)
            if n > 0:
                return fix_grammar(new_title)
    # No rule matched — return as-is
    return title


def transform_description(desc: str) -> str:
    """Apply description transformation rules."""
    desc = desc.strip()
    for pattern, replacement in DESC_RULES:
        new_desc, n = pattern.subn(replacement, desc, count=1)
        if n > 0:
            return new_desc
    return desc


def transform_remediation(remediation: str) -> str:
    """Convert paragraph remediation to numbered steps if not already."""
    remediation = remediation.strip()
    # Already numbered
    if re.match(r"^\d+\.", remediation):
        return remediation

    # Split on sentence boundaries
    sentences = re.split(r"(?<=[.!])\s+", remediation)
    sentences = [s.strip() for s in sentences if s.strip()]

    if len(sentences) <= 1:
        return remediation

    # Number each sentence
    numbered = []
    for i, s in enumerate(sentences, 1):
        # Remove trailing period if present (we'll re-add consistent formatting)
        s = s.rstrip(".")
        numbered.append(f"{i}. {s}.")
    return "\n".join(numbered)


def process_yaml_file(filepath: Path, dry_run: bool = False) -> dict:
    """Process a single metadata YAML file and return change info."""
    with open(filepath) as f:
        data = yaml.safe_load(f)

    if not data or "title" not in data:
        return {"file": str(filepath), "old_title": "", "new_title": "", "changed": False}

    old_title = data["title"]
    old_desc = data.get("description", "")
    old_remediation = data.get("remediation", "")

    new_title = transform_title(old_title)
    new_desc = transform_description(old_desc) if old_desc else old_desc
    new_remediation = transform_remediation(old_remediation) if old_remediation else old_remediation

    changed = new_title != old_title or new_desc != old_desc or new_remediation != old_remediation

    if changed and not dry_run:
        data["title"] = new_title
        if new_desc != old_desc:
            data["description"] = new_desc
        if new_remediation != old_remediation:
            data["remediation"] = new_remediation

        with open(filepath, "w") as f:
            yaml.dump(
                data,
                f,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
                width=120,
            )

    return {
        "file": str(filepath.relative_to(CHECKS_DIR.parent.parent.parent)),
        "check_id": data.get("check_id", ""),
        "old_title": old_title,
        "new_title": new_title,
        "title_changed": new_title != old_title,
        "desc_changed": new_desc != old_desc,
        "remediation_changed": new_remediation != old_remediation,
    }


def main():
    dry_run = "--dry-run" in sys.argv

    yaml_files = sorted(CHECKS_DIR.rglob("*.metadata.yaml"))
    print(f"Found {len(yaml_files)} metadata YAML files")

    results = []
    for f in yaml_files:
        result = process_yaml_file(f, dry_run=dry_run)
        results.append(result)

    # Write CSV report
    csv_path = Path(__file__).parent / "reframe_review.csv"
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=["check_id", "old_title", "new_title", "title_changed", "desc_changed", "remediation_changed"],
        )
        writer.writeheader()
        for r in results:
            writer.writerow({k: r[k] for k in writer.fieldnames})

    # Summary
    title_changed = sum(1 for r in results if r["title_changed"])
    desc_changed = sum(1 for r in results if r["desc_changed"])
    remed_changed = sum(1 for r in results if r["remediation_changed"])
    unchanged = sum(1 for r in results if not r["title_changed"])

    print(f"\nTitle changes: {title_changed}/{len(results)}")
    print(f"Description changes: {desc_changed}/{len(results)}")
    print(f"Remediation changes: {remed_changed}/{len(results)}")
    print(f"Titles unchanged: {unchanged}/{len(results)}")
    print(f"\nReview CSV: {csv_path}")

    if dry_run:
        print("\n[DRY RUN] No files were modified.")
        # Print sample changes
        print("\nSample title changes:")
        for r in results[:30]:
            if r["title_changed"]:
                print(f"  {r['check_id']}: {r['old_title']}")
                print(f"        → {r['new_title']}")
    else:
        print(f"\n{title_changed + desc_changed + remed_changed} total field changes applied.")


if __name__ == "__main__":
    main()
