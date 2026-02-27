"""Unit tests for SSRF & Network checks (ssrf001-ssrf020)."""

from __future__ import annotations

import pytest

from medusa.checks.ssrf_and_network.ssrf001_private_ip_access import PrivateIpAccessCheck
from medusa.checks.ssrf_and_network.ssrf002_cloud_metadata_ssrf import CloudMetadataSsrfCheck
from medusa.checks.ssrf_and_network.ssrf003_dns_rebinding_risk import DnsRebindingRiskCheck
from medusa.checks.ssrf_and_network.ssrf004_unrestricted_egress import UnrestrictedEgressCheck
from medusa.checks.ssrf_and_network.ssrf005_localhost_access import LocalhostAccessCheck
from medusa.checks.ssrf_and_network.ssrf006_internal_service_access import (
    InternalServiceAccessCheck,
)
from medusa.checks.ssrf_and_network.ssrf007_url_redirect_following import UrlRedirectFollowingCheck
from medusa.checks.ssrf_and_network.ssrf008_protocol_smuggling import ProtocolSmugglingCheck
from medusa.checks.ssrf_and_network.ssrf009_ip_address_bypass import IpAddressBypassCheck
from medusa.checks.ssrf_and_network.ssrf010_missing_url_scheme_validation import (
    MissingUrlSchemeValidationCheck,
)
from medusa.checks.ssrf_and_network.ssrf011_missing_egress_allowlist import (
    MissingEgressAllowlistCheck,
)
from medusa.checks.ssrf_and_network.ssrf012_network_scanning_capability import (
    NetworkScanningCapabilityCheck,
)
from medusa.checks.ssrf_and_network.ssrf013_port_scanning_risk import PortScanningRiskCheck
from medusa.checks.ssrf_and_network.ssrf014_file_scheme_access import FileSchemeAccessCheck
from medusa.checks.ssrf_and_network.ssrf015_gopher_protocol_risk import GopherProtocolRiskCheck
from medusa.checks.ssrf_and_network.ssrf016_missing_request_timeout import (
    MissingRequestTimeoutCheck,
)
from medusa.checks.ssrf_and_network.ssrf017_unbounded_redirect_chain import (
    UnboundedRedirectChainCheck,
)
from medusa.checks.ssrf_and_network.ssrf018_internal_api_exposure import InternalApiExposureCheck
from medusa.checks.ssrf_and_network.ssrf019_kubernetes_api_access import KubernetesApiAccessCheck
from medusa.checks.ssrf_and_network.ssrf020_docker_api_access import DockerApiAccessCheck
from medusa.core.models import Status
from tests.conftest import make_snapshot

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _url_tool(name: str = "fetch_url", url_param_constrained: bool = False) -> dict:
    """Build a tool with a URL parameter, optionally constrained."""
    url_def: dict = {"type": "string"}
    if url_param_constrained:
        url_def["pattern"] = r"^https://api\.example\.com/.*$"
    return {
        "name": name,
        "description": f"Fetches {name}",
        "inputSchema": {
            "type": "object",
            "properties": {"url": url_def},
            "required": ["url"],
        },
    }


# ==========================================================================
# SSRF-001: Private IP Address Access
# ==========================================================================


class TestPrivateIpAccessCheck:
    @pytest.fixture()
    def check(self) -> PrivateIpAccessCheck:
        return PrivateIpAccessCheck()

    async def test_metadata_loads_correctly(self, check: PrivateIpAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf001"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_unconstrained_url_param(self, check: PrivateIpAccessCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool(url_param_constrained=False)])
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_constrained_url_param(self, check: PrivateIpAccessCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool(url_param_constrained=True)])
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: PrivateIpAccessCheck) -> None:
        snapshot = make_snapshot(tools=[])
        findings = await check.execute(snapshot)
        assert findings == []

    async def test_non_url_tool_is_skipped(self, check: PrivateIpAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Weather tool.",
                    "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert all(f.status == Status.PASS for f in findings)


# ==========================================================================
# SSRF-002: Cloud Metadata SSRF
# ==========================================================================


class TestCloudMetadataSsrfCheck:
    @pytest.fixture()
    def check(self) -> CloudMetadataSsrfCheck:
        return CloudMetadataSsrfCheck()

    async def test_metadata_loads_correctly(self, check: CloudMetadataSsrfCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf002"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_cloud_metadata_reference(self, check: CloudMetadataSsrfCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch_metadata",
                    "description": "Fetches http://169.254.169.254/latest/meta-data",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: CloudMetadataSsrfCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "list_items",
                    "description": "Lists items.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: CloudMetadataSsrfCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-003: DNS Rebinding Risk
# ==========================================================================


class TestDnsRebindingRiskCheck:
    @pytest.fixture()
    def check(self) -> DnsRebindingRiskCheck:
        return DnsRebindingRiskCheck()

    async def test_metadata_loads_correctly(self, check: DnsRebindingRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf003"
        assert meta.category == "ssrf_and_network"

    async def test_fails_without_dns_protection_config(self, check: DnsRebindingRiskCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool()], config_raw={"command": "node"})
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_dns_cache_config(self, check: DnsRebindingRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[_url_tool()],
            config_raw={"dns_cache": True, "command": "node"},
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: DnsRebindingRiskCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-004: Unrestricted Egress
# ==========================================================================


class TestUnrestrictedEgressCheck:
    @pytest.fixture()
    def check(self) -> UnrestrictedEgressCheck:
        return UnrestrictedEgressCheck()

    async def test_metadata_loads_correctly(self, check: UnrestrictedEgressCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf004"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_unconstrained_url_no_allowlist(
        self, check: UnrestrictedEgressCheck
    ) -> None:
        snapshot = make_snapshot(tools=[_url_tool()], config_raw={"command": "node"})
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_allowlist_in_config(self, check: UnrestrictedEgressCheck) -> None:
        snapshot = make_snapshot(
            tools=[_url_tool()],
            config_raw={"allowlist": ["api.example.com"]},
        )
        findings = await check.execute(snapshot)
        assert all(f.status != Status.FAIL for f in findings)

    async def test_passes_with_constrained_url(self, check: UnrestrictedEgressCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool(url_param_constrained=True)])
        findings = await check.execute(snapshot)
        assert all(f.status != Status.FAIL for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: UnrestrictedEgressCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-005: Localhost Access
# ==========================================================================


class TestLocalhostAccessCheck:
    @pytest.fixture()
    def check(self) -> LocalhostAccessCheck:
        return LocalhostAccessCheck()

    async def test_metadata_loads_correctly(self, check: LocalhostAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf005"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_unconstrained_url(self, check: LocalhostAccessCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool(url_param_constrained=False)])
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_when_localhost_in_description(self, check: LocalhostAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch",
                    "description": "Fetches data from localhost:8080",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"url": {"type": "string", "pattern": ".*"}},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: LocalhostAccessCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-006: Internal Service Access
# ==========================================================================


class TestInternalServiceAccessCheck:
    @pytest.fixture()
    def check(self) -> InternalServiceAccessCheck:
        return InternalServiceAccessCheck()

    async def test_metadata_loads_correctly(self, check: InternalServiceAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf006"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_internal_hostname_in_description(
        self, check: InternalServiceAccessCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "call_internal",
                    "description": "Calls payments.internal service",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_on_cluster_local_reference(
        self, check: InternalServiceAccessCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "k8s_call",
                    "description": "Accesses redis.svc.cluster.local",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: InternalServiceAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "list_items",
                    "description": "Lists items.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: InternalServiceAccessCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-007: URL Redirect Following
# ==========================================================================


class TestUrlRedirectFollowingCheck:
    @pytest.fixture()
    def check(self) -> UrlRedirectFollowingCheck:
        return UrlRedirectFollowingCheck()

    async def test_metadata_loads_correctly(self, check: UrlRedirectFollowingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf007"
        assert meta.category == "ssrf_and_network"

    async def test_fails_without_redirect_control(self, check: UrlRedirectFollowingCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool()], config_raw={"command": "node"})
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_max_redirects_config(self, check: UrlRedirectFollowingCheck) -> None:
        snapshot = make_snapshot(
            tools=[_url_tool()],
            config_raw={"max_redirects": 3, "command": "node"},
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: UrlRedirectFollowingCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-008: Protocol Smuggling
# ==========================================================================


class TestProtocolSmugglingCheck:
    @pytest.fixture()
    def check(self) -> ProtocolSmugglingCheck:
        return ProtocolSmugglingCheck()

    async def test_metadata_loads_correctly(self, check: ProtocolSmugglingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf008"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_unconstrained_url_param(self, check: ProtocolSmugglingCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool(url_param_constrained=False)])
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_on_gopher_mention_in_description(
        self, check: ProtocolSmugglingCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "raw_fetch",
                    "description": "Fetch using gopher:// for raw TCP",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: ProtocolSmugglingCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "list_items",
                    "description": "Lists items.",
                    "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: ProtocolSmugglingCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-009: IP Address Bypass
# ==========================================================================


class TestIpAddressBypassCheck:
    @pytest.fixture()
    def check(self) -> IpAddressBypassCheck:
        return IpAddressBypassCheck()

    async def test_metadata_loads_correctly(self, check: IpAddressBypassCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf009"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_unconstrained_url_param(self, check: IpAddressBypassCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool(url_param_constrained=False)])
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_enum_constrained_url(self, check: IpAddressBypassCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch",
                    "description": "Fetches from allowed URLs.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "enum": ["https://api.example.com"]},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert all(f.status != Status.FAIL for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: IpAddressBypassCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-010: Missing URL Scheme Validation
# ==========================================================================


class TestMissingUrlSchemeValidationCheck:
    @pytest.fixture()
    def check(self) -> MissingUrlSchemeValidationCheck:
        return MissingUrlSchemeValidationCheck()

    async def test_metadata_loads_correctly(self, check: MissingUrlSchemeValidationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf010"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_url_without_scheme_constraint(
        self, check: MissingUrlSchemeValidationCheck
    ) -> None:
        snapshot = make_snapshot(tools=[_url_tool(url_param_constrained=False)])
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_https_pattern(self, check: MissingUrlSchemeValidationCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch",
                    "description": "Safe fetch.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"url": {"type": "string", "pattern": "^https?://.*"}},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert all(f.status != Status.FAIL for f in findings)

    async def test_passes_with_https_enum(self, check: MissingUrlSchemeValidationCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "fetch",
                    "description": "Safe fetch.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "enum": ["https://api.example.com/data"]},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert all(f.status != Status.FAIL for f in findings)

    async def test_empty_tools_returns_no_findings(
        self, check: MissingUrlSchemeValidationCheck
    ) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-011: Missing Egress Allowlist
# ==========================================================================


class TestMissingEgressAllowlistCheck:
    @pytest.fixture()
    def check(self) -> MissingEgressAllowlistCheck:
        return MissingEgressAllowlistCheck()

    async def test_metadata_loads_correctly(self, check: MissingEgressAllowlistCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf011"
        assert meta.category == "ssrf_and_network"

    async def test_fails_without_allowlist_config(self, check: MissingEgressAllowlistCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool()], config_raw={"command": "node"})
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_allowlist_config(self, check: MissingEgressAllowlistCheck) -> None:
        snapshot = make_snapshot(
            tools=[_url_tool()],
            config_raw={"allowlist": ["api.example.com"], "command": "node"},
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(
        self, check: MissingEgressAllowlistCheck
    ) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-012: Network Scanning Capability
# ==========================================================================


class TestNetworkScanningCapabilityCheck:
    @pytest.fixture()
    def check(self) -> NetworkScanningCapabilityCheck:
        return NetworkScanningCapabilityCheck()

    async def test_metadata_loads_correctly(self, check: NetworkScanningCapabilityCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf012"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_host_and_port_params(
        self, check: NetworkScanningCapabilityCheck
    ) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "check_service",
                    "description": "Check if a service is up.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string"},
                            "port": {"type": "integer"},
                        },
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_on_scan_tool_name(self, check: NetworkScanningCapabilityCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "network_scan",
                    "description": "Scans the network.",
                    "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: NetworkScanningCapabilityCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Weather tool.",
                    "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(
        self, check: NetworkScanningCapabilityCheck
    ) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-013: Port Scanning Risk
# ==========================================================================


class TestPortScanningRiskCheck:
    @pytest.fixture()
    def check(self) -> PortScanningRiskCheck:
        return PortScanningRiskCheck()

    async def test_metadata_loads_correctly(self, check: PortScanningRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf013"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_unconstrained_port_param(self, check: PortScanningRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "connect",
                    "description": "Connect to a host.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"port": {"type": "integer"}},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_port_enum(self, check: PortScanningRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "connect",
                    "description": "Connect to a host.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"port": {"type": "integer", "enum": [80, 443]}},
                    },
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert all(f.status != Status.FAIL for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: PortScanningRiskCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-014: File Scheme Access
# ==========================================================================


class TestFileSchemeAccessCheck:
    @pytest.fixture()
    def check(self) -> FileSchemeAccessCheck:
        return FileSchemeAccessCheck()

    async def test_metadata_loads_correctly(self, check: FileSchemeAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf014"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_file_uri_in_description(self, check: FileSchemeAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "read_local",
                    "description": "Reads file://etc/passwd",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_on_file_uri_resource(self, check: FileSchemeAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "safe_tool",
                    "description": "Safe.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            resources=[{"uri": "file:///etc/passwd", "name": "System Password File"}],
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_resources(self, check: FileSchemeAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "safe_tool",
                    "description": "Safe.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            resources=[{"uri": "https://api.example.com/data", "name": "API Data"}],
        )
        findings = await check.execute(snapshot)
        assert all(f.status != Status.FAIL for f in findings)

    async def test_empty_tools_and_resources_returns_no_findings(
        self, check: FileSchemeAccessCheck
    ) -> None:
        assert await check.execute(make_snapshot(tools=[], resources=[])) == []


# ==========================================================================
# SSRF-015: Gopher Protocol Risk
# ==========================================================================


class TestGopherProtocolRiskCheck:
    @pytest.fixture()
    def check(self) -> GopherProtocolRiskCheck:
        return GopherProtocolRiskCheck()

    async def test_metadata_loads_correctly(self, check: GopherProtocolRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf015"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_gopher_mention(self, check: GopherProtocolRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "raw_fetch",
                    "description": "Supports gopher:// and dict:// protocols",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: GopherProtocolRiskCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_data",
                    "description": "Gets data via HTTPS.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: GopherProtocolRiskCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-016: Missing Request Timeout
# ==========================================================================


class TestMissingRequestTimeoutCheck:
    @pytest.fixture()
    def check(self) -> MissingRequestTimeoutCheck:
        return MissingRequestTimeoutCheck()

    async def test_metadata_loads_correctly(self, check: MissingRequestTimeoutCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf016"
        assert meta.category == "ssrf_and_network"

    async def test_fails_without_timeout_config(self, check: MissingRequestTimeoutCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool()], config_raw={"command": "node"})
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_timeout_config(self, check: MissingRequestTimeoutCheck) -> None:
        snapshot = make_snapshot(
            tools=[_url_tool()],
            config_raw={"timeout": 30, "command": "node"},
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: MissingRequestTimeoutCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-017: Unbounded Redirect Chain
# ==========================================================================


class TestUnboundedRedirectChainCheck:
    @pytest.fixture()
    def check(self) -> UnboundedRedirectChainCheck:
        return UnboundedRedirectChainCheck()

    async def test_metadata_loads_correctly(self, check: UnboundedRedirectChainCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf017"
        assert meta.category == "ssrf_and_network"

    async def test_fails_without_redirect_limit(self, check: UnboundedRedirectChainCheck) -> None:
        snapshot = make_snapshot(tools=[_url_tool()], config_raw={"command": "node"})
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_with_max_redirects(self, check: UnboundedRedirectChainCheck) -> None:
        snapshot = make_snapshot(
            tools=[_url_tool()],
            config_raw={"max_redirects": 5},
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(
        self, check: UnboundedRedirectChainCheck
    ) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-018: Internal API Exposure
# ==========================================================================


class TestInternalApiExposureCheck:
    @pytest.fixture()
    def check(self) -> InternalApiExposureCheck:
        return InternalApiExposureCheck()

    async def test_metadata_loads_correctly(self, check: InternalApiExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf018"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_internal_api_path(self, check: InternalApiExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "health_check",
                    "description": "Calls /internal/health to check service status.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_on_actuator_path(self, check: InternalApiExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "metrics",
                    "description": "Exposes /actuator/metrics endpoint.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: InternalApiExposureCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Gets weather data from public API.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: InternalApiExposureCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-019: Kubernetes API Access
# ==========================================================================


class TestKubernetesApiAccessCheck:
    @pytest.fixture()
    def check(self) -> KubernetesApiAccessCheck:
        return KubernetesApiAccessCheck()

    async def test_metadata_loads_correctly(self, check: KubernetesApiAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf019"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_k8s_reference(self, check: KubernetesApiAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "k8s_list_pods",
                    "description": "Lists pods via kubectl",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_on_cluster_local_reference(self, check: KubernetesApiAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "call_service",
                    "description": "Calls api.svc.cluster.local",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: KubernetesApiAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Weather tool.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: KubernetesApiAccessCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []


# ==========================================================================
# SSRF-020: Docker API Access
# ==========================================================================


class TestDockerApiAccessCheck:
    @pytest.fixture()
    def check(self) -> DockerApiAccessCheck:
        return DockerApiAccessCheck()

    async def test_metadata_loads_correctly(self, check: DockerApiAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf020"
        assert meta.category == "ssrf_and_network"

    async def test_fails_on_docker_sock_reference(self, check: DockerApiAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "docker_exec",
                    "description": "Executes commands via /var/run/docker.sock",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_fails_on_docker_run_mention(self, check: DockerApiAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "run_container",
                    "description": "Runs docker run commands.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.FAIL for f in findings)

    async def test_passes_on_safe_tool(self, check: DockerApiAccessCheck) -> None:
        snapshot = make_snapshot(
            tools=[
                {
                    "name": "get_weather",
                    "description": "Weather tool.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
        findings = await check.execute(snapshot)
        assert any(f.status == Status.PASS for f in findings)

    async def test_empty_tools_returns_no_findings(self, check: DockerApiAccessCheck) -> None:
        assert await check.execute(make_snapshot(tools=[])) == []
