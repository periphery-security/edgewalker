# Standard Library
from unittest.mock import MagicMock, patch

# Third Party
from typer.testing import CliRunner

# First Party
from edgewalker.cli.cli import app
from edgewalker.core.config import Settings

runner = CliRunner()


def test_config_show_with_overrides_and_warnings():
    """Test config show command with overrides and security warnings."""
    with (
        patch(
            "edgewalker.cli.cli.get_active_overrides",
            return_value={"EW_THEME": "environment variable"},
        ),
        patch.object(Settings, "get_security_warnings", return_value=["Test Warning"]),
        patch.object(Settings, "get_field_info") as mock_info,
    ):
        mock_info.return_value = {
            "value": "periphery",
            "default": "periphery",
            "is_overridden": True,
            "override_source": "environment variable",
            "is_modified": False,
            "security_warning": "Test Warning",
        }

        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "environment variable" in result.stdout
        assert "SECURITY WARNINGS" in result.stdout
        assert "Test Warning" in result.stdout


def test_config_set_errors():
    """Test config set command with errors."""
    # Test AttributeError
    with patch("edgewalker.cli.cli.update_setting", side_effect=AttributeError("Invalid key")):
        result = runner.invoke(app, ["config", "set", "invalid_key", "value"])
        assert result.exit_code == 0
        assert "Error: Invalid key" in result.stdout

    # Test ValueError
    with patch("edgewalker.cli.cli.update_setting", side_effect=ValueError("Invalid value")):
        result = runner.invoke(app, ["config", "set", "api_timeout", "not-an-int"])
        assert result.exit_code == 0
        assert "Error: Invalid value" in result.stdout


def test_run_guided_scan_with_warnings_confirm_yes():
    """Test run guided scan with warnings and user confirms yes."""
    with (
        patch.object(Settings, "get_security_warnings", return_value=["Insecure API"]),
        patch("edgewalker.cli.cli.get_active_overrides", return_value={"EW_THEME": "env"}),
        patch("typer.confirm", return_value=True),
        patch("edgewalker.cli.cli.GuidedScanner") as mock_guided,
    ):
        # Mock the async run
        with patch("asyncio.run"):
            result = runner.invoke(app, ["scan"], input="y\n")
            assert result.exit_code == 0
            assert "SECURITY WARNING" in result.stdout
            assert "CONFIGURATION OVERRIDES ACTIVE" in result.stdout


def test_run_guided_scan_with_warnings_confirm_no():
    """Test run guided scan with warnings and user confirms no."""
    with (
        patch.object(Settings, "get_security_warnings", return_value=["Insecure API"]),
        patch("typer.confirm", return_value=False),
    ):
        result = runner.invoke(app, ["scan"], input="n\n")
        assert result.exit_code == 0
        assert "Scan cancelled" in result.stdout


def test_version_command_full_coverage():
    """Test version command to cover dependency gathering logic."""
    with (
        patch(
            "shutil.which", side_effect=lambda x: "/usr/bin/" + x if x in ["uv", "pip"] else None
        ),
        patch("subprocess.check_output", return_value="uv 0.1.0"),
        patch("importlib.metadata.requires", return_value=["rich>=14.3.3", "typer[all]>=0.15.1"]),
        patch("importlib.metadata.version", return_value="1.0.0"),
    ):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "EdgeWalker CLI" in result.stdout
        assert "rich" in result.stdout
        assert "typer" in result.stdout


# Standard Library
import importlib.metadata


def test_version_command_fallback_pyproject():
    """Test version command fallback to pyproject.toml."""
    with (
        patch("importlib.metadata.requires", side_effect=importlib.metadata.PackageNotFoundError),
        patch("pathlib.Path.exists", return_value=True),
        patch("builtins.open", MagicMock()),
    ):
        # Mock tomllib.load
        with patch("tomllib.load", return_value={"project": {"dependencies": ["pydantic>=2.0.0"]}}):
            with patch("importlib.metadata.version", return_value="2.0.0"):
                result = runner.invoke(app, ["version"])
                assert result.exit_code == 0
                assert "pydantic" in result.stdout


def test_config_show_modified():
    """Test config show command with modified settings."""
    with patch.object(Settings, "get_field_info") as mock_info:
        mock_info.return_value = {
            "value": "modified",
            "default": "original",
            "is_overridden": False,
            "override_source": None,
            "is_modified": True,
            "security_warning": None,
        }
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "modified" in result.stdout
        assert "config.yaml" in result.stdout


def test_config_set_success():
    """Test config set command success."""
    with patch("edgewalker.cli.cli.update_setting") as mock_update:
        result = runner.invoke(app, ["config", "set", "theme", "dracula"])
        assert result.exit_code == 0
        assert "Successfully updated theme to dracula" in result.stdout
        mock_update.assert_called_once_with("theme", "dracula")


def test_config_path():
    """Test config path command."""
    result = runner.invoke(app, ["config", "path"])
    assert result.exit_code == 0
    assert "config.yaml" in result.stdout


def test_other_commands():
    """Test other CLI commands (report, results, clear, tui)."""
    with (
        patch("edgewalker.cli.cli.ScanController") as mock_ctrl,
        patch("edgewalker.cli.cli.ResultManager") as mock_res,
        patch("edgewalker.cli.cli.EdgeWalkerApp") as mock_app,
    ):
        runner.invoke(app, ["report"])
        mock_ctrl.return_value.view_device_risk.assert_called_once()

        runner.invoke(app, ["results"])
        mock_res.return_value.view_results.assert_called_once_with(interactive=True)

        runner.invoke(app, ["clear"])
        mock_res.return_value.clear_results.assert_called_once_with(interactive=False)

        runner.invoke(app, ["tui"])
        mock_app.return_value.run.assert_called_once()


def test_main_callback():
    """Test main callback with verbosity and log file."""
    with patch("edgewalker.cli.cli.setup_logging") as mock_setup:
        result = runner.invoke(app, ["-vv", "--log-file", "test.log", "version"])
        assert result.exit_code == 0
        mock_setup.assert_called_once_with(verbosity=2, log_file="test.log")


def test_interactive_mode():
    """Test interactive_mode entry point."""
    # First Party
    from edgewalker.cli.cli import interactive_mode

    with patch("edgewalker.cli.cli.InteractiveMenu") as mock_menu, patch("asyncio.run") as mock_run:
        interactive_mode()
        mock_run.assert_called_once()
