"""Tests for the Demo Service."""

# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
import pytest

# First Party
from edgewalker.core.demo_service import DemoService
from edgewalker.modules.cve_scan.models import CveScanModel
from edgewalker.modules.password_scan.models import PasswordScanModel
from edgewalker.modules.port_scan.models import PortScanModel


@pytest.mark.asyncio
@patch("edgewalker.core.demo_service.save_results")
@patch("asyncio.sleep", return_value=None)
async def test_demo_service_port_scan(mock_sleep, mock_save):
    """Test the demo port scan."""
    callback = MagicMock()
    service = DemoService(progress_callback=callback)

    result = await service.perform_port_scan("192.168.1.0/24")

    assert isinstance(result, PortScanModel)
    assert result.is_demo is True
    assert len(result.hosts) == 2
    assert callback.called
    assert mock_save.called
    # Check some specific notifications
    callback.assert_any_call("phase", "Starting demo scan on 192.168.1.0/24...")
    callback.assert_any_call("host_found", "192.168.1.1")


@pytest.mark.asyncio
@patch("edgewalker.core.demo_service.save_results")
@patch("asyncio.sleep", return_value=None)
async def test_demo_service_credential_scan(mock_sleep, mock_save):
    """Test the demo credential scan."""
    callback = MagicMock()
    service = DemoService(progress_callback=callback)

    result = await service.perform_credential_scan()

    assert isinstance(result, PasswordScanModel)
    assert result.is_demo is True
    assert len(result.results) == 1
    assert callback.called
    assert mock_save.called
    callback.assert_any_call("phase", "Testing for default passwords...")
    callback.assert_any_call("cred_found", "192.168.1.15 SSH:22 -- admin:12345")


@pytest.mark.asyncio
@patch("edgewalker.core.demo_service.save_results")
@patch("asyncio.sleep", return_value=None)
async def test_demo_service_cve_scan(mock_sleep, mock_save):
    """Test the demo CVE scan."""
    callback = MagicMock()
    service = DemoService(progress_callback=callback)

    result = await service.perform_cve_scan()

    assert isinstance(result, CveScanModel)
    assert result.is_demo is True
    assert len(result.results) == 1
    assert callback.called
    assert mock_save.called
    callback.assert_any_call("phase", "Checking for known vulnerabilities...")


def test_demo_service_no_callback():
    """Test the demo service without a callback."""
    service = DemoService()
    # Should not raise any errors
    service._notify("test", "message")
