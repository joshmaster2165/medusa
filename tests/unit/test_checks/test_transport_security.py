"""Unit tests for all Transport Security checks (TS-001 through TS-004)."""

from __future__ import annotations

import pytest

from medusa.checks.transport_security.ts001_unencrypted_transport import UnencryptedTransportCheck
from medusa.checks.transport_security.ts002_missing_cert_validation import (
    MissingCertValidationCheck,
)
from medusa.checks.transport_security.ts003_insecure_tls_config import InsecureTlsConfigCheck
from medusa.checks.transport_security.ts004_missing_transport_auth import MissingTransportAuthCheck
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# TS-001: Unencrypted Transport
# ==========================================================================


class TestTS001UnencryptedTransport:
    """Tests for UnencryptedTransportCheck."""

    @pytest.fixture()
    def check(self) -> UnencryptedTransportCheck:
        return UnencryptedTransportCheck()

    async def test_metadata_loads_correctly(self, check: UnencryptedTransportCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts001"
        assert meta.category == "transport_security"
        assert meta.severity == Severity.CRITICAL

    async def test_fails_on_http_url(
        self, check: UnencryptedTransportCheck, http_vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_https_url(
        self, check: UnencryptedTransportCheck, http_secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_stdio(
        self, check: UnencryptedTransportCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_detects_http_in_config_raw(self, check: UnencryptedTransportCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url=None,
            config_raw={"url": "http://api.example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_http_proxy(self, check: UnencryptedTransportCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            env={"HTTP_PROXY": "http://proxy.internal:8080"},
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


# ==========================================================================
# TS-002: Missing Certificate Validation
# ==========================================================================


class TestTS002MissingCertValidation:
    """Tests for MissingCertValidationCheck."""

    @pytest.fixture()
    def check(self) -> MissingCertValidationCheck:
        return MissingCertValidationCheck()

    async def test_metadata_loads_correctly(self, check: MissingCertValidationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts002"
        assert meta.category == "transport_security"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_node_tls_reject(
        self, check: MissingCertValidationCheck, http_vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_vulnerable_snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_secure_snapshot(
        self, check: MissingCertValidationCheck, http_secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_stdio(
        self, check: MissingCertValidationCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_detects_verify_false_in_config(self, check: MissingCertValidationCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp", "verify": "false"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_nested_ssl_verify(self, check: MissingCertValidationCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "transport": {"ssl_verify": "false"},
            },
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_detects_git_ssl_no_verify(self, check: MissingCertValidationCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            env={"GIT_SSL_NO_VERIFY": "0"},
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


# ==========================================================================
# TS-003: Insecure TLS Configuration
# ==========================================================================


class TestTS003InsecureTlsConfig:
    """Tests for InsecureTlsConfigCheck."""

    @pytest.fixture()
    def check(self) -> InsecureTlsConfigCheck:
        return InsecureTlsConfigCheck()

    async def test_metadata_loads_correctly(self, check: InsecureTlsConfigCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts003"
        assert meta.category == "transport_security"
        assert meta.severity == Severity.MEDIUM

    async def test_skips_stdio(
        self, check: InsecureTlsConfigCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_tls_1_0(self, check: InsecureTlsConfigCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"tls_version": "tls1.0"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_sslv3(self, check: InsecureTlsConfigCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"ssl_version": "sslv3"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_modern_tls(self, check: InsecureTlsConfigCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"tls_version": "tls1.3"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_passes_on_no_tls_config(self, check: InsecureTlsConfigCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_detects_nested_tls_version(self, check: InsecureTlsConfigCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"transport": {"min_tls_version": "tlsv1.1"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1


# ==========================================================================
# TS-004: Missing Transport Authentication Headers
# ==========================================================================


class TestTS004MissingTransportAuth:
    """Tests for MissingTransportAuthCheck."""

    @pytest.fixture()
    def check(self) -> MissingTransportAuthCheck:
        return MissingTransportAuthCheck()

    async def test_metadata_loads_correctly(self, check: MissingTransportAuthCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts004"
        assert meta.category == "transport_security"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_no_headers(
        self, check: MissingTransportAuthCheck, http_vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_vulnerable_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_passes_on_auth_header(
        self, check: MissingTransportAuthCheck, http_secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_stdio(
        self, check: MissingTransportAuthCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_detects_x_api_key(self, check: MissingTransportAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"headers": {"X-API-Key": "key123"}},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_fails_on_non_auth_headers(self, check: MissingTransportAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"headers": {"Content-Type": "application/json"}},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
