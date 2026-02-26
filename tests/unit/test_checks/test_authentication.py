"""Unit tests for all Authentication checks (AUTH-001 through AUTH-004).

Each check is tested for:
- FAIL on the appropriate vulnerable snapshot
- PASS on the appropriate secure snapshot
- Graceful handling (skip) for non-HTTP transports
- Additional edge cases specific to each check
"""

from __future__ import annotations

import pytest

from medusa.checks.authentication.auth001_no_authentication import NoAuthenticationCheck
from medusa.checks.authentication.auth002_weak_oauth import WeakOAuthCheck
from medusa.checks.authentication.auth003_missing_tls import MissingTLSCheck
from medusa.checks.authentication.auth004_localhost_no_auth import LocalhostNoAuthCheck
from medusa.core.check import ServerSnapshot
from medusa.core.models import Severity, Status
from tests.conftest import make_snapshot

# ==========================================================================
# AUTH-001: No Authentication on HTTP Transport
# ==========================================================================


class TestAuth001NoAuthentication:
    """Tests for NoAuthenticationCheck."""

    @pytest.fixture()
    def check(self) -> NoAuthenticationCheck:
        return NoAuthenticationCheck()

    async def test_metadata_loads_correctly(self, check: NoAuthenticationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth001"
        assert meta.category == "authentication"
        assert meta.severity == Severity.CRITICAL

    async def test_fails_on_http_no_auth(
        self, check: NoAuthenticationCheck, http_vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_vulnerable_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "no authentication" in findings[0].status_extended.lower()

    async def test_passes_on_http_with_auth(
        self, check: NoAuthenticationCheck, http_secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_stdio_transport(
        self, check: NoAuthenticationCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0, "stdio transport should be skipped"

    async def test_detects_auth_in_headers(self, check: NoAuthenticationCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "headers": {"Authorization": "Bearer token123"},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_detects_auth_in_nested_config(self, check: NoAuthenticationCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "url": "https://example.com/mcp",
                "server": {"oauth": {"client_id": "abc"}},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_detects_x_api_key_header(self, check: NoAuthenticationCheck) -> None:
        snapshot = make_snapshot(
            transport_type="sse",
            transport_url="https://example.com/sse",
            config_raw={
                "url": "https://example.com/sse",
                "headers": {"X-API-Key": "key123"},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_no_config_raw_fails(self, check: NoAuthenticationCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://example.com/mcp",
            config_raw=None,
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL


# ==========================================================================
# AUTH-002: Weak OAuth Configuration
# ==========================================================================


class TestAuth002WeakOAuth:
    """Tests for WeakOAuthCheck."""

    @pytest.fixture()
    def check(self) -> WeakOAuthCheck:
        return WeakOAuthCheck()

    async def test_metadata_loads_correctly(self, check: WeakOAuthCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth002"
        assert meta.category == "authentication"
        assert meta.severity == Severity.HIGH

    async def test_skips_stdio_transport(
        self, check: WeakOAuthCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_skips_http_without_oauth(self, check: WeakOAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={"url": "https://example.com/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0, "No OAuth config means AUTH-001 handles it"

    async def test_fails_on_missing_pkce(self, check: WeakOAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "oauth": {
                    "client_id": "abc",
                    "grant_type": "authorization_code",
                    "scopes": "read:data",
                },
            },
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1
        pkce_findings = [f for f in fail_findings if "PKCE" in f.status_extended]
        assert len(pkce_findings) >= 1

    async def test_fails_on_broad_scopes(self, check: WeakOAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "oauth": {
                    "client_id": "abc",
                    "code_challenge_method": "S256",
                    "scopes": "* admin",
                    "grant_type": "authorization_code",
                },
            },
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        scope_findings = [f for f in fail_findings if "scope" in f.status_extended.lower()]
        assert len(scope_findings) >= 1

    async def test_fails_on_implicit_grant(self, check: WeakOAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "oauth": {
                    "client_id": "abc",
                    "code_challenge_method": "S256",
                    "scopes": "read:data",
                    "grant_type": "implicit",
                },
            },
        )
        findings = await check.execute(snapshot)
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        grant_findings = [f for f in fail_findings if "implicit" in f.status_extended.lower()]
        assert len(grant_findings) >= 1

    async def test_passes_on_proper_oauth(self, check: WeakOAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="https://example.com/mcp",
            config_raw={
                "oauth": {
                    "client_id": "abc",
                    "code_challenge_method": "S256",
                    "scopes": "read:data write:data",
                    "grant_type": "authorization_code",
                },
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ==========================================================================
# AUTH-003: Missing TLS on HTTP Transport
# ==========================================================================


class TestAuth003MissingTLS:
    """Tests for MissingTLSCheck."""

    @pytest.fixture()
    def check(self) -> MissingTLSCheck:
        return MissingTLSCheck()

    async def test_metadata_loads_correctly(self, check: MissingTLSCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth003"
        assert meta.category == "authentication"
        assert meta.severity == Severity.CRITICAL

    async def test_fails_on_http_url(
        self, check: MissingTLSCheck, http_vulnerable_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_vulnerable_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert (
            "cleartext" in findings[0].status_extended.lower()
            or "plain HTTP" in findings[0].status_extended
        )

    async def test_passes_on_https_url(
        self, check: MissingTLSCheck, http_secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(http_secure_snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_stdio_transport(
        self, check: MissingTLSCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_skips_http_without_url(self, check: MissingTLSCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url=None,
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_http_url_explicit(self, check: MissingTLSCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://192.168.1.1:8080/mcp",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_https_url_explicit(self, check: MissingTLSCheck) -> None:
        snapshot = make_snapshot(
            transport_type="sse",
            transport_url="https://secure.example.com/sse",
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ==========================================================================
# AUTH-004: Localhost Binding Without Authentication
# ==========================================================================


class TestAuth004LocalhostNoAuth:
    """Tests for LocalhostNoAuthCheck."""

    @pytest.fixture()
    def check(self) -> LocalhostNoAuthCheck:
        return LocalhostNoAuthCheck()

    async def test_metadata_loads_correctly(self, check: LocalhostNoAuthCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth004"
        assert meta.category == "authentication"
        assert meta.severity == Severity.HIGH

    async def test_fails_on_localhost_no_auth(self, check: LocalhostNoAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://localhost:3000/mcp",
            config_raw={"url": "http://localhost:3000/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "DNS rebinding" in findings[0].status_extended

    async def test_passes_on_localhost_with_auth(self, check: LocalhostNoAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://localhost:3000/mcp",
            config_raw={
                "url": "http://localhost:3000/mcp",
                "headers": {"Authorization": "Bearer token"},
            },
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    async def test_skips_non_localhost_http(self, check: LocalhostNoAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://example.com:8080/mcp",
            config_raw={"url": "http://example.com:8080/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 0

    async def test_skips_stdio_transport(
        self, check: LocalhostNoAuthCheck, secure_snapshot: ServerSnapshot
    ) -> None:
        findings = await check.execute(secure_snapshot)
        assert len(findings) == 0

    async def test_detects_127_0_0_1(self, check: LocalhostNoAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://127.0.0.1:8080/mcp",
            config_raw={"url": "http://127.0.0.1:8080/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    async def test_detects_0_0_0_0(self, check: LocalhostNoAuthCheck) -> None:
        snapshot = make_snapshot(
            transport_type="http",
            transport_url="http://0.0.0.0:8080/mcp",
            config_raw={"url": "http://0.0.0.0:8080/mcp"},
        )
        findings = await check.execute(snapshot)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
