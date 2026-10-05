"""Integration tests for Typer CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from phish_analyzer.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """Verify version command output."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Phishing URL Analyzer" in result.stdout
    assert "0.1.0" in result.stdout


def test_cli_analyze_human_output() -> None:
    """Verify human-readable terminal rendering."""
    result = runner.invoke(app, ["analyze", "https://google.com"])
    assert result.exit_code == 0
    assert "Threat Evaluation Result" in result.stdout
    assert "BENIGN" in result.stdout
    assert "google[.]com" in result.stdout


def test_cli_analyze_json_output() -> None:
    """Verify machine-readable JSON output."""
    result = runner.invoke(app, ["analyze", "http://0x7f000001/admin", "--json"])
    assert result.exit_code == 0

    data = json.loads(result.stdout)
    assert data["raw_url"] == "http://0x7f000001/admin"
    assert data["risk_level"] == "MALICIOUS"
    assert data["threat_score"] >= 70
    assert len(data["triggers"]) > 0


def test_cli_analyze_cef_output() -> None:
    """Verify ArcSight CEF syslog output format."""
    result = runner.invoke(app, ["analyze", "http://p\u0430ypal.com/auth", "--cef"])
    assert result.exit_code == 0
    assert result.stdout.startswith("CEF:0|DefensiveSecurity|PhishAnalyzer|0.1.0|")
    assert "request=" in result.stdout


def test_cli_analyze_no_defang() -> None:
    """Verify raw undefanged URL display when --no-defang is passed."""
    result = runner.invoke(app, ["analyze", "https://example.com/test", "--no-defang"])
    assert result.exit_code == 0
    assert "https://example.com/test" in result.stdout


def test_cli_batch_processing(tmp_path: Path) -> None:
    """Verify batch processing and aggregate reporting."""
    batch_file = tmp_path / "urls.txt"
    batch_file.write_text(
        "# Sample URL feed\n"
        "https://google.com\n"
        "http://0x7f000001/test\n"
        "http://verify-account.tk/login\n",
        encoding="utf-8",
    )
    output_jsonl = tmp_path / "results.jsonl"

    result = runner.invoke(
        app,
        ["batch", str(batch_file), "--output", str(output_jsonl)],
    )
    assert result.exit_code == 0
    assert "Batch Triage Summary" in result.stdout
    assert output_jsonl.exists()

    saved_lines = output_jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert len(saved_lines) == 3


def test_cli_batch_empty_file(tmp_path: Path) -> None:
    """Verify graceful handling of empty batch file."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("# Only comments\n\n", encoding="utf-8")

    result = runner.invoke(app, ["batch", str(empty_file)])
    assert result.exit_code == 0
    assert "No valid URLs found" in result.stdout
