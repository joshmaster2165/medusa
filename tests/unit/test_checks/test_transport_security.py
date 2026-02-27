"""Unit tests for all Transport Security checks (TS-001 through TS-019)."""

from __future__ import annotations

import pytest

from medusa.checks.transport_security.ts001_unencrypted_transport import UnencryptedTransportCheck
from medusa.checks.transport_security.ts002_missing_cert_validation import (
    MissingCertValidationCheck,
)
from medusa.checks.transport_security.ts003_insecure_tls_config import InsecureTlsConfigCheck
from medusa.checks.transport_security.ts004_missing_transport_auth import MissingTransportAuthCheck
from medusa.checks.transport_security.ts005_mixed_content import MixedContentCheck
from medusa.checks.transport_security.ts006_weak_cipher_suites import WeakCipherSuitesCheck
from medusa.checks.transport_security.ts007_missing_hsts import MissingHstsCheck
from medusa.checks.transport_security.ts008_certificate_pinning_absent import (
    CertificatePinningAbsentCheck,
)
from medusa.checks.transport_security.ts009_self_signed_certificate import (
    SelfSignedCertificateCheck,
)
from medusa.checks.transport_security.ts010_expired_certificate import ExpiredCertificateCheck
from medusa.checks.transport_security.ts011_wildcard_certificate import WildcardCertificateCheck
from medusa.checks.transport_security.ts012_missing_cors_headers import MissingCorsHeadersCheck
from medusa.checks.transport_security.ts013_overly_permissive_cors import OverlyPermissiveCorsCheck
from medusa.checks.transport_security.ts014_websocket_without_tls import WebsocketWithoutTlsCheck
from medusa.checks.transport_security.ts015_sse_without_tls import SseWithoutTlsCheck
from medusa.checks.transport_security.ts016_missing_content_security_policy import (
    MissingContentSecurityPolicyCheck,
)
from medusa.checks.transport_security.ts017_dns_over_http import DnsOverHttpCheck
from medusa.checks.transport_security.ts018_proxy_without_tls import ProxyWithoutTlsCheck
from medusa.checks.transport_security.ts019_missing_certificate_transparency import (
    MissingCertificateTransparencyCheck,
)
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


# ==========================================================================
# TS-005: Mixed Content
# ==========================================================================


class TestMixedContentCheck:
    """Tests for MixedContentCheck."""

    @pytest.fixture()
    def check(self) -> MixedContentCheck:
        return MixedContentCheck()

    async def test_metadata_loads_correctly(self, check: MixedContentCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts005"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: MixedContentCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_http_resource_in_https_server(self, check: MixedContentCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "resource_url": "http://cdn.example.com/image.png",
            },
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_all_https(self, check: MixedContentCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "resource_url": "https://cdn.example.com/image.png",
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_skips_http_primary(self, check: MixedContentCheck) -> None:
        # Mixed content only applies when primary is HTTPS; HTTP primary is handled by ts001
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://example.com/mcp",
            config_raw={"url": "http://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        # No mixed content violation on a plain HTTP server
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) == 0


# ==========================================================================
# TS-006: Weak Cipher Suites
# ==========================================================================


class TestWeakCipherSuitesCheck:
    """Tests for WeakCipherSuitesCheck."""

    @pytest.fixture()
    def check(self) -> WeakCipherSuitesCheck:
        return WeakCipherSuitesCheck()

    async def test_metadata_loads_correctly(self, check: WeakCipherSuitesCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts006"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: WeakCipherSuitesCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_rc4_cipher(self, check: WeakCipherSuitesCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"ciphers": "RC4-MD5:AES256-GCM-SHA384"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_des_cipher(self, check: WeakCipherSuitesCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"cipher_suites": "DES-CBC3-SHA"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_strong_cipher(self, check: WeakCipherSuitesCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"ciphers": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_on_no_cipher_config(self, check: WeakCipherSuitesCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-007: Missing HSTS
# ==========================================================================


class TestMissingHstsCheck:
    """Tests for MissingHstsCheck."""

    @pytest.fixture()
    def check(self) -> MissingHstsCheck:
        return MissingHstsCheck()

    async def test_metadata_loads_correctly(self, check: MissingHstsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts007"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: MissingHstsCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_hsts(self, check: MissingHstsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_hsts_configured(self, check: MissingHstsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "hsts": {"max_age": 31536000, "include_subdomains": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_on_strict_transport_security_header(
        self, check: MissingHstsCheck
    ) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "headers": {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-008: Certificate Pinning Absent
# ==========================================================================


class TestCertificatePinningAbsentCheck:
    """Tests for CertificatePinningAbsentCheck."""

    @pytest.fixture()
    def check(self) -> CertificatePinningAbsentCheck:
        return CertificatePinningAbsentCheck()

    async def test_metadata_loads_correctly(self, check: CertificatePinningAbsentCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts008"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: CertificatePinningAbsentCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_pinning(self, check: CertificatePinningAbsentCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_cert_pinning(self, check: CertificatePinningAbsentCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "certificate_pinning": {"pin_sha256": "abc123"},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-009: Self-Signed Certificate
# ==========================================================================


class TestSelfSignedCertificateCheck:
    """Tests for SelfSignedCertificateCheck."""

    @pytest.fixture()
    def check(self) -> SelfSignedCertificateCheck:
        return SelfSignedCertificateCheck()

    async def test_metadata_loads_correctly(self, check: SelfSignedCertificateCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts009"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: SelfSignedCertificateCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_self_signed_true(self, check: SelfSignedCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"tls": {"self_signed": True}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_verify_false(self, check: SelfSignedCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"tls": {"verify": False}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_no_self_signed_config(self, check: SelfSignedCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-010: Expired Certificate
# ==========================================================================


class TestExpiredCertificateCheck:
    """Tests for ExpiredCertificateCheck."""

    @pytest.fixture()
    def check(self) -> ExpiredCertificateCheck:
        return ExpiredCertificateCheck()

    async def test_metadata_loads_correctly(self, check: ExpiredCertificateCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts010"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: ExpiredCertificateCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_cert_monitoring(self, check: ExpiredCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_cert_expiry_monitoring(self, check: ExpiredCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "cert_expiry_check": True,
                "cert_monitor": {"enabled": True},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-011: Wildcard Certificate
# ==========================================================================


class TestWildcardCertificateCheck:
    """Tests for WildcardCertificateCheck."""

    @pytest.fixture()
    def check(self) -> WildcardCertificateCheck:
        return WildcardCertificateCheck()

    async def test_metadata_loads_correctly(self, check: WildcardCertificateCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts011"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: WildcardCertificateCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_wildcard_cert(self, check: WildcardCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"tls": {"cert_name": "*.example.com"}},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_specific_cert(self, check: WildcardCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"tls": {"cert_name": "api.example.com"}},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_on_no_cert_config(self, check: WildcardCertificateCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-012: Missing CORS Headers
# ==========================================================================


class TestMissingCorsHeadersCheck:
    """Tests for MissingCorsHeadersCheck."""

    @pytest.fixture()
    def check(self) -> MissingCorsHeadersCheck:
        return MissingCorsHeadersCheck()

    async def test_metadata_loads_correctly(self, check: MissingCorsHeadersCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts012"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: MissingCorsHeadersCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_cors(self, check: MissingCorsHeadersCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_cors_configured(self, check: MissingCorsHeadersCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "cors": {"allowed_origins": ["https://app.example.com"]},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-013: Overly Permissive CORS
# ==========================================================================


class TestOverlyPermissiveCorsCheck:
    """Tests for OverlyPermissiveCorsCheck."""

    @pytest.fixture()
    def check(self) -> OverlyPermissiveCorsCheck:
        return OverlyPermissiveCorsCheck()

    async def test_metadata_loads_correctly(self, check: OverlyPermissiveCorsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts013"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: OverlyPermissiveCorsCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_wildcard_origin(self, check: OverlyPermissiveCorsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"cors_origin": "*"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_wildcard_in_list(self, check: OverlyPermissiveCorsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"allowed_origins": ["*", "https://trusted.example.com"]},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_no_cors_config(self, check: OverlyPermissiveCorsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_on_specific_origin(self, check: OverlyPermissiveCorsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"cors_origin": "https://app.example.com"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-014: WebSocket Without TLS
# ==========================================================================


class TestWebsocketWithoutTlsCheck:
    """Tests for WebsocketWithoutTlsCheck."""

    @pytest.fixture()
    def check(self) -> WebsocketWithoutTlsCheck:
        return WebsocketWithoutTlsCheck()

    async def test_metadata_loads_correctly(self, check: WebsocketWithoutTlsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts014"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: WebsocketWithoutTlsCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_ws_url(self, check: WebsocketWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="ws://example.com/mcp",
            config_raw={"url": "ws://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_ws_in_config(self, check: WebsocketWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"websocket_url": "ws://realtime.example.com/ws"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_wss_url(self, check: WebsocketWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"websocket_url": "wss://realtime.example.com/ws"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-015: SSE Without TLS
# ==========================================================================


class TestSseWithoutTlsCheck:
    """Tests for SseWithoutTlsCheck."""

    @pytest.fixture()
    def check(self) -> SseWithoutTlsCheck:
        return SseWithoutTlsCheck()

    async def test_metadata_loads_correctly(self, check: SseWithoutTlsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts015"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: SseWithoutTlsCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_skips_http_transport(self, check: SseWithoutTlsCheck) -> None:
        # ts015 only fires for SSE transport type specifically
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://example.com/mcp",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_fails_on_sse_over_http(self, check: SseWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="sse",
            transport_url="http://example.com/sse",
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_sse_over_https(self, check: SseWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="sse",
            transport_url="https://example.com/sse",
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-016: Missing Content Security Policy
# ==========================================================================


class TestMissingContentSecurityPolicyCheck:
    """Tests for MissingContentSecurityPolicyCheck."""

    @pytest.fixture()
    def check(self) -> MissingContentSecurityPolicyCheck:
        return MissingContentSecurityPolicyCheck()

    async def test_metadata_loads_correctly(self, check: MissingContentSecurityPolicyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts016"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: MissingContentSecurityPolicyCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_csp(self, check: MissingContentSecurityPolicyCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_csp_configured(self, check: MissingContentSecurityPolicyCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "content_security_policy": "default-src 'self'",
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_on_csp_header(self, check: MissingContentSecurityPolicyCheck) -> None:
        snapshot = make_snapshot(
            transport_type="sse",
            transport_url="https://example.com/sse",
            config_raw={
                "headers": {"Content-Security-Policy": "default-src 'self'"},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-017: DNS Over HTTP
# ==========================================================================


class TestDnsOverHttpCheck:
    """Tests for DnsOverHttpCheck."""

    @pytest.fixture()
    def check(self) -> DnsOverHttpCheck:
        return DnsOverHttpCheck()

    async def test_metadata_loads_correctly(self, check: DnsOverHttpCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts017"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: DnsOverHttpCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_skips_without_dns_config(self, check: DnsOverHttpCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_fails_on_dns_without_doh(self, check: DnsOverHttpCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"dns_server": "8.8.8.8"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_dns_with_doh(self, check: DnsOverHttpCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "dns_server": "8.8.8.8",
                "dns_over_https": "https://dns.google/dns-query",
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-018: Proxy Without TLS
# ==========================================================================


class TestProxyWithoutTlsCheck:
    """Tests for ProxyWithoutTlsCheck."""

    @pytest.fixture()
    def check(self) -> ProxyWithoutTlsCheck:
        return ProxyWithoutTlsCheck()

    async def test_metadata_loads_correctly(self, check: ProxyWithoutTlsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts018"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: ProxyWithoutTlsCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_skips_without_proxy_config(self, check: ProxyWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_fails_on_http_proxy_in_config(self, check: ProxyWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"proxy": "http://proxy.internal:8080"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_fails_on_http_proxy_in_env(self, check: ProxyWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            env={"HTTP_PROXY": "http://proxy.internal:8080"},
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_https_proxy(self, check: ProxyWithoutTlsCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"proxy": "https://proxy.internal:8443"},
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1


# ==========================================================================
# TS-019: Missing Certificate Transparency
# ==========================================================================


class TestMissingCertificateTransparencyCheck:
    """Tests for MissingCertificateTransparencyCheck."""

    @pytest.fixture()
    def check(self) -> MissingCertificateTransparencyCheck:
        return MissingCertificateTransparencyCheck()

    async def test_metadata_loads_correctly(
        self, check: MissingCertificateTransparencyCheck
    ) -> None:
        meta = check.metadata()
        assert meta.check_id == "ts019"
        assert meta.category == "transport_security"

    async def test_skips_stdio(
        self, check: MissingCertificateTransparencyCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_fails_on_no_ct_monitoring(
        self, check: MissingCertificateTransparencyCheck
    ) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    async def test_passes_on_ct_monitoring_configured(
        self, check: MissingCertificateTransparencyCheck
    ) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "certificate_transparency": {"enabled": True, "monitor": "crt.sh"},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1

    async def test_passes_on_expect_ct_header(
        self, check: MissingCertificateTransparencyCheck
    ) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "headers": {"Expect-CT": "max-age=86400, enforce"},
            },
        )
        findings = await check.execute(snapshot)
        pass_findings = [f for f in findings if f.status == Status.PASS]
        assert len(pass_findings) >= 1
