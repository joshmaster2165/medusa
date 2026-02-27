"""Unit tests for Ssrf And Network checks (auto-generated stubs)."""

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
from tests.conftest import make_snapshot


class TestPrivateIpAccessCheck:
    """Tests for PrivateIpAccessCheck."""

    @pytest.fixture()
    def check(self) -> PrivateIpAccessCheck:
        return PrivateIpAccessCheck()

    async def test_metadata_loads_correctly(self, check: PrivateIpAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf001"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: PrivateIpAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestCloudMetadataSsrfCheck:
    """Tests for CloudMetadataSsrfCheck."""

    @pytest.fixture()
    def check(self) -> CloudMetadataSsrfCheck:
        return CloudMetadataSsrfCheck()

    async def test_metadata_loads_correctly(self, check: CloudMetadataSsrfCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf002"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: CloudMetadataSsrfCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDnsRebindingRiskCheck:
    """Tests for DnsRebindingRiskCheck."""

    @pytest.fixture()
    def check(self) -> DnsRebindingRiskCheck:
        return DnsRebindingRiskCheck()

    async def test_metadata_loads_correctly(self, check: DnsRebindingRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf003"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: DnsRebindingRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnrestrictedEgressCheck:
    """Tests for UnrestrictedEgressCheck."""

    @pytest.fixture()
    def check(self) -> UnrestrictedEgressCheck:
        return UnrestrictedEgressCheck()

    async def test_metadata_loads_correctly(self, check: UnrestrictedEgressCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf004"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: UnrestrictedEgressCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestLocalhostAccessCheck:
    """Tests for LocalhostAccessCheck."""

    @pytest.fixture()
    def check(self) -> LocalhostAccessCheck:
        return LocalhostAccessCheck()

    async def test_metadata_loads_correctly(self, check: LocalhostAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf005"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: LocalhostAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInternalServiceAccessCheck:
    """Tests for InternalServiceAccessCheck."""

    @pytest.fixture()
    def check(self) -> InternalServiceAccessCheck:
        return InternalServiceAccessCheck()

    async def test_metadata_loads_correctly(self, check: InternalServiceAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf006"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: InternalServiceAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUrlRedirectFollowingCheck:
    """Tests for UrlRedirectFollowingCheck."""

    @pytest.fixture()
    def check(self) -> UrlRedirectFollowingCheck:
        return UrlRedirectFollowingCheck()

    async def test_metadata_loads_correctly(self, check: UrlRedirectFollowingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf007"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: UrlRedirectFollowingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestProtocolSmugglingCheck:
    """Tests for ProtocolSmugglingCheck."""

    @pytest.fixture()
    def check(self) -> ProtocolSmugglingCheck:
        return ProtocolSmugglingCheck()

    async def test_metadata_loads_correctly(self, check: ProtocolSmugglingCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf008"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: ProtocolSmugglingCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestIpAddressBypassCheck:
    """Tests for IpAddressBypassCheck."""

    @pytest.fixture()
    def check(self) -> IpAddressBypassCheck:
        return IpAddressBypassCheck()

    async def test_metadata_loads_correctly(self, check: IpAddressBypassCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf009"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: IpAddressBypassCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingUrlSchemeValidationCheck:
    """Tests for MissingUrlSchemeValidationCheck."""

    @pytest.fixture()
    def check(self) -> MissingUrlSchemeValidationCheck:
        return MissingUrlSchemeValidationCheck()

    async def test_metadata_loads_correctly(self, check: MissingUrlSchemeValidationCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf010"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: MissingUrlSchemeValidationCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingEgressAllowlistCheck:
    """Tests for MissingEgressAllowlistCheck."""

    @pytest.fixture()
    def check(self) -> MissingEgressAllowlistCheck:
        return MissingEgressAllowlistCheck()

    async def test_metadata_loads_correctly(self, check: MissingEgressAllowlistCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf011"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: MissingEgressAllowlistCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestNetworkScanningCapabilityCheck:
    """Tests for NetworkScanningCapabilityCheck."""

    @pytest.fixture()
    def check(self) -> NetworkScanningCapabilityCheck:
        return NetworkScanningCapabilityCheck()

    async def test_metadata_loads_correctly(self, check: NetworkScanningCapabilityCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf012"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: NetworkScanningCapabilityCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestPortScanningRiskCheck:
    """Tests for PortScanningRiskCheck."""

    @pytest.fixture()
    def check(self) -> PortScanningRiskCheck:
        return PortScanningRiskCheck()

    async def test_metadata_loads_correctly(self, check: PortScanningRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf013"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: PortScanningRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestFileSchemeAccessCheck:
    """Tests for FileSchemeAccessCheck."""

    @pytest.fixture()
    def check(self) -> FileSchemeAccessCheck:
        return FileSchemeAccessCheck()

    async def test_metadata_loads_correctly(self, check: FileSchemeAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf014"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: FileSchemeAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestGopherProtocolRiskCheck:
    """Tests for GopherProtocolRiskCheck."""

    @pytest.fixture()
    def check(self) -> GopherProtocolRiskCheck:
        return GopherProtocolRiskCheck()

    async def test_metadata_loads_correctly(self, check: GopherProtocolRiskCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf015"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: GopherProtocolRiskCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestMissingRequestTimeoutCheck:
    """Tests for MissingRequestTimeoutCheck."""

    @pytest.fixture()
    def check(self) -> MissingRequestTimeoutCheck:
        return MissingRequestTimeoutCheck()

    async def test_metadata_loads_correctly(self, check: MissingRequestTimeoutCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf016"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: MissingRequestTimeoutCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestUnboundedRedirectChainCheck:
    """Tests for UnboundedRedirectChainCheck."""

    @pytest.fixture()
    def check(self) -> UnboundedRedirectChainCheck:
        return UnboundedRedirectChainCheck()

    async def test_metadata_loads_correctly(self, check: UnboundedRedirectChainCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf017"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: UnboundedRedirectChainCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestInternalApiExposureCheck:
    """Tests for InternalApiExposureCheck."""

    @pytest.fixture()
    def check(self) -> InternalApiExposureCheck:
        return InternalApiExposureCheck()

    async def test_metadata_loads_correctly(self, check: InternalApiExposureCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf018"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: InternalApiExposureCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestKubernetesApiAccessCheck:
    """Tests for KubernetesApiAccessCheck."""

    @pytest.fixture()
    def check(self) -> KubernetesApiAccessCheck:
        return KubernetesApiAccessCheck()

    async def test_metadata_loads_correctly(self, check: KubernetesApiAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf019"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: KubernetesApiAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)


class TestDockerApiAccessCheck:
    """Tests for DockerApiAccessCheck."""

    @pytest.fixture()
    def check(self) -> DockerApiAccessCheck:
        return DockerApiAccessCheck()

    async def test_metadata_loads_correctly(self, check: DockerApiAccessCheck) -> None:
        meta = check.metadata()
        assert meta.check_id == "ssrf020"
        assert meta.category == "ssrf_and_network"

    async def test_stub_returns_empty(self, check: DockerApiAccessCheck) -> None:
        snapshot = make_snapshot()
        findings = await check.execute(snapshot)
        assert isinstance(findings, list)
