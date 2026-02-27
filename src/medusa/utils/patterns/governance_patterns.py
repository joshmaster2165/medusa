"""Patterns for detecting governance, compliance, and policy configuration."""

from __future__ import annotations

# Policy configuration keys
POLICY_CONFIG_KEYS: set[str] = {
    "policy",
    "security_policy",
    "privacy_policy",
    "terms_of_service",
    "acceptable_use",
    "data_policy",
    "retention_policy",
}

# Compliance framework configuration keys
COMPLIANCE_CONFIG_KEYS: set[str] = {
    "compliance",
    "gdpr",
    "hipaa",
    "soc2",
    "pci",
    "iso27001",
    "fedramp",
    "ccpa",
    "regulation",
}

# Incident response configuration keys
INCIDENT_RESPONSE_KEYS: set[str] = {
    "incident_response",
    "incident",
    "breach_notification",
    "escalation",
    "on_call",
    "alert",
    "pager",
}

# Change management configuration keys
CHANGE_MANAGEMENT_KEYS: set[str] = {
    "change_management",
    "change_control",
    "approval_workflow",
    "review_process",
    "deployment_pipeline",
}

# Governance audit configuration keys
GOVERNANCE_AUDIT_KEYS: set[str] = {
    "audit_schedule",
    "audit_log",
    "compliance_check",
    "security_review",
    "penetration_test",
    "vulnerability_scan",
}

# Data governance configuration keys
DATA_GOVERNANCE_KEYS: set[str] = {
    "data_classification",
    "data_catalog",
    "data_lineage",
    "data_quality",
    "data_steward",
    "data_owner",
}

# Vendor assessment configuration keys
VENDOR_ASSESSMENT_KEYS: set[str] = {
    "vendor_assessment",
    "third_party_risk",
    "supplier_risk",
    "due_diligence",
    "vendor_review",
}
