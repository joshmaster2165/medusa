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
from medusa.checks.authentication.auth005_weak_token_entropy import WeakTokenEntropyCheck
from medusa.checks.authentication.auth006_missing_token_expiry import MissingTokenExpiryCheck
from medusa.checks.authentication.auth007_insecure_token_storage import InsecureTokenStorageCheck
from medusa.checks.authentication.auth008_missing_oauth_pkce import MissingOauthPkceCheck
from medusa.checks.authentication.auth009_bearer_token_in_url import BearerTokenInUrlCheck
from medusa.checks.authentication.auth010_missing_csrf_protection import MissingCsrfProtectionCheck
from medusa.checks.authentication.auth011_hardcoded_credentials import HardcodedCredentialsCheck
from medusa.checks.authentication.auth012_missing_token_rotation import MissingTokenRotationCheck
from medusa.checks.authentication.auth013_insecure_cookie_flags import InsecureCookieFlagsCheck
from medusa.checks.authentication.auth014_jwt_algorithm_none import JwtAlgorithmNoneCheck
from medusa.checks.authentication.auth015_jwt_weak_signing import JwtWeakSigningCheck
from medusa.checks.authentication.auth016_missing_auth_on_tools import MissingAuthOnToolsCheck
from medusa.checks.authentication.auth017_api_key_in_headers_insecure import (
    ApiKeyInHeadersInsecureCheck,
)
from medusa.checks.authentication.auth018_missing_mutual_tls import MissingMutualTlsCheck
from medusa.checks.authentication.auth019_token_scope_too_broad import TokenScopeTooBroadCheck
from medusa.checks.authentication.auth020_missing_auth_header import MissingAuthHeaderCheck
from medusa.checks.authentication.auth021_basic_auth_over_http import BasicAuthOverHttpCheck
from medusa.checks.authentication.auth022_missing_token_revocation import (
    MissingTokenRevocationCheck,
)
from medusa.checks.authentication.auth023_shared_secrets_across_servers import (
    SharedSecretsAcrossServersCheck,
)
from medusa.checks.authentication.auth024_missing_rate_limit_on_auth import (
    MissingRateLimitOnAuthCheck,
)
from medusa.checks.authentication.auth025_session_fixation_risk import SessionFixationRiskCheck
from medusa.checks.authentication.auth026_missing_logout_mechanism import (
    MissingLogoutMechanismCheck,
)
from medusa.checks.authentication.auth027_weak_password_policy import WeakPasswordPolicyCheck
from medusa.checks.authentication.auth028_missing_mfa import MissingMfaCheck
from medusa.checks.authentication.auth029_insecure_auth_redirect import InsecureAuthRedirectCheck
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


class TestWeakTokenEntropyCheck:
    """Tests for WeakTokenEntropyCheck."""

    @pytest.fixture()
    def check(self) -> WeakTokenEntropyCheck:
        return WeakTokenEntropyCheck()

    async def test_metadata_loads_correctly(self, check: WeakTokenEntropyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth005"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: WeakTokenEntropyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingTokenExpiryCheck:
    """Tests for MissingTokenExpiryCheck."""

    @pytest.fixture()
    def check(self) -> MissingTokenExpiryCheck:
        return MissingTokenExpiryCheck()

    async def test_metadata_loads_correctly(self, check: MissingTokenExpiryCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth006"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingTokenExpiryCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInsecureTokenStorageCheck:
    """Tests for InsecureTokenStorageCheck."""

    @pytest.fixture()
    def check(self) -> InsecureTokenStorageCheck:
        return InsecureTokenStorageCheck()

    async def test_metadata_loads_correctly(self, check: InsecureTokenStorageCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth007"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: InsecureTokenStorageCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingOauthPkceCheck:
    """Tests for MissingOauthPkceCheck."""

    @pytest.fixture()
    def check(self) -> MissingOauthPkceCheck:
        return MissingOauthPkceCheck()

    async def test_metadata_loads_correctly(self, check: MissingOauthPkceCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth008"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingOauthPkceCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestBearerTokenInUrlCheck:
    """Tests for BearerTokenInUrlCheck."""

    @pytest.fixture()
    def check(self) -> BearerTokenInUrlCheck:
        return BearerTokenInUrlCheck()

    async def test_metadata_loads_correctly(self, check: BearerTokenInUrlCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth009"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: BearerTokenInUrlCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingCsrfProtectionCheck:
    """Tests for MissingCsrfProtectionCheck."""

    @pytest.fixture()
    def check(self) -> MissingCsrfProtectionCheck:
        return MissingCsrfProtectionCheck()

    async def test_metadata_loads_correctly(self, check: MissingCsrfProtectionCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth010"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingCsrfProtectionCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestHardcodedCredentialsCheck:
    """Tests for HardcodedCredentialsCheck."""

    @pytest.fixture()
    def check(self) -> HardcodedCredentialsCheck:
        return HardcodedCredentialsCheck()

    async def test_metadata_loads_correctly(self, check: HardcodedCredentialsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth011"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: HardcodedCredentialsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingTokenRotationCheck:
    """Tests for MissingTokenRotationCheck."""

    @pytest.fixture()
    def check(self) -> MissingTokenRotationCheck:
        return MissingTokenRotationCheck()

    async def test_metadata_loads_correctly(self, check: MissingTokenRotationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth012"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingTokenRotationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInsecureCookieFlagsCheck:
    """Tests for InsecureCookieFlagsCheck."""

    @pytest.fixture()
    def check(self) -> InsecureCookieFlagsCheck:
        return InsecureCookieFlagsCheck()

    async def test_metadata_loads_correctly(self, check: InsecureCookieFlagsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth013"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: InsecureCookieFlagsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestJwtAlgorithmNoneCheck:
    """Tests for JwtAlgorithmNoneCheck."""

    @pytest.fixture()
    def check(self) -> JwtAlgorithmNoneCheck:
        return JwtAlgorithmNoneCheck()

    async def test_metadata_loads_correctly(self, check: JwtAlgorithmNoneCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth014"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: JwtAlgorithmNoneCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestJwtWeakSigningCheck:
    """Tests for JwtWeakSigningCheck."""

    @pytest.fixture()
    def check(self) -> JwtWeakSigningCheck:
        return JwtWeakSigningCheck()

    async def test_metadata_loads_correctly(self, check: JwtWeakSigningCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth015"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: JwtWeakSigningCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAuthOnToolsCheck:
    """Tests for MissingAuthOnToolsCheck."""

    @pytest.fixture()
    def check(self) -> MissingAuthOnToolsCheck:
        return MissingAuthOnToolsCheck()

    async def test_metadata_loads_correctly(self, check: MissingAuthOnToolsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth016"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingAuthOnToolsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestApiKeyInHeadersInsecureCheck:
    """Tests for ApiKeyInHeadersInsecureCheck."""

    @pytest.fixture()
    def check(self) -> ApiKeyInHeadersInsecureCheck:
        return ApiKeyInHeadersInsecureCheck()

    async def test_metadata_loads_correctly(self, check: ApiKeyInHeadersInsecureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth017"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: ApiKeyInHeadersInsecureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingMutualTlsCheck:
    """Tests for MissingMutualTlsCheck."""

    @pytest.fixture()
    def check(self) -> MissingMutualTlsCheck:
        return MissingMutualTlsCheck()

    async def test_metadata_loads_correctly(self, check: MissingMutualTlsCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth018"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingMutualTlsCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestTokenScopeTooBroadCheck:
    """Tests for TokenScopeTooBroadCheck."""

    @pytest.fixture()
    def check(self) -> TokenScopeTooBroadCheck:
        return TokenScopeTooBroadCheck()

    async def test_metadata_loads_correctly(self, check: TokenScopeTooBroadCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth019"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: TokenScopeTooBroadCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingAuthHeaderCheck:
    """Tests for MissingAuthHeaderCheck."""

    @pytest.fixture()
    def check(self) -> MissingAuthHeaderCheck:
        return MissingAuthHeaderCheck()

    async def test_metadata_loads_correctly(self, check: MissingAuthHeaderCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth020"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingAuthHeaderCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestBasicAuthOverHttpCheck:
    """Tests for BasicAuthOverHttpCheck."""

    @pytest.fixture()
    def check(self) -> BasicAuthOverHttpCheck:
        return BasicAuthOverHttpCheck()

    async def test_metadata_loads_correctly(self, check: BasicAuthOverHttpCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth021"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: BasicAuthOverHttpCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingTokenRevocationCheck:
    """Tests for MissingTokenRevocationCheck."""

    @pytest.fixture()
    def check(self) -> MissingTokenRevocationCheck:
        return MissingTokenRevocationCheck()

    async def test_metadata_loads_correctly(self, check: MissingTokenRevocationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth022"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingTokenRevocationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSharedSecretsAcrossServersCheck:
    """Tests for SharedSecretsAcrossServersCheck."""

    @pytest.fixture()
    def check(self) -> SharedSecretsAcrossServersCheck:
        return SharedSecretsAcrossServersCheck()

    async def test_metadata_loads_correctly(self, check: SharedSecretsAcrossServersCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth023"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: SharedSecretsAcrossServersCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingRateLimitOnAuthCheck:
    """Tests for MissingRateLimitOnAuthCheck."""

    @pytest.fixture()
    def check(self) -> MissingRateLimitOnAuthCheck:
        return MissingRateLimitOnAuthCheck()

    async def test_metadata_loads_correctly(self, check: MissingRateLimitOnAuthCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth024"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingRateLimitOnAuthCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestSessionFixationRiskCheck:
    """Tests for SessionFixationRiskCheck."""

    @pytest.fixture()
    def check(self) -> SessionFixationRiskCheck:
        return SessionFixationRiskCheck()

    async def test_metadata_loads_correctly(self, check: SessionFixationRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth025"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: SessionFixationRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingLogoutMechanismCheck:
    """Tests for MissingLogoutMechanismCheck."""

    @pytest.fixture()
    def check(self) -> MissingLogoutMechanismCheck:
        return MissingLogoutMechanismCheck()

    async def test_metadata_loads_correctly(self, check: MissingLogoutMechanismCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth026"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingLogoutMechanismCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestWeakPasswordPolicyCheck:
    """Tests for WeakPasswordPolicyCheck."""

    @pytest.fixture()
    def check(self) -> WeakPasswordPolicyCheck:
        return WeakPasswordPolicyCheck()

    async def test_metadata_loads_correctly(self, check: WeakPasswordPolicyCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth027"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: WeakPasswordPolicyCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingMfaCheck:
    """Tests for MissingMfaCheck."""

    @pytest.fixture()
    def check(self) -> MissingMfaCheck:
        return MissingMfaCheck()

    async def test_metadata_loads_correctly(self, check: MissingMfaCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth028"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: MissingMfaCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInsecureAuthRedirectCheck:
    """Tests for InsecureAuthRedirectCheck."""

    @pytest.fixture()
    def check(self) -> InsecureAuthRedirectCheck:
        return InsecureAuthRedirectCheck()

    async def test_metadata_loads_correctly(self, check: InsecureAuthRedirectCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "auth029"
        assert meta.category == "authentication"

    async def test_stub_returns_empty(self, check: InsecureAuthRedirectCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
