"""Tests that launch the command-line tool."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "admin-access.json"


def run_cli(arguments):
    return subprocess.run(
        [sys.executable, "-m", "iam_detector.cli"] + arguments,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_text_findings_return_one():
    result = run_cli([str(EXAMPLE)])

    assert result.returncode == 1
    assert "[Critical] IAM001" in result.stdout
    assert "Why:" in result.stdout
    assert "Fix:" in result.stdout
    assert result.stderr == ""


def test_json_output_is_parseable():
    result = run_cli([str(EXAMPLE), "--format", "json"])

    report = json.loads(result.stdout)

    assert result.returncode == 1
    assert report["finding_count"] == 1
    assert report["findings"][0]["severity"] == "Critical"
    assert result.stderr == ""


def test_no_findings_return_zero(tmp_path):
    policy_file = tmp_path / "limited.json"
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::synthetic-demo/*",
        }
    }
    policy_file.write_text(json.dumps(policy), encoding="utf-8")

    result = run_cli([str(policy_file)])

    assert result.returncode == 0
    assert "Findings: 0" in result.stdout
    assert "not a guarantee of safety" in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize(
    "contents",
    [
        '{"Statement":',
        "[]",
        '{"Statement": {"Effect": "Allow", "Action": 7, "Resource": "*"}}',
    ],
)
def test_invalid_input_returns_two_without_traceback(tmp_path, contents):
    policy_file = tmp_path / "invalid.json"
    policy_file.write_text(contents, encoding="utf-8")

    result = run_cli([str(policy_file)])

    assert result.returncode == 2
    assert "Error:" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""


def test_missing_file_returns_two(tmp_path):
    result = run_cli([str(tmp_path / "missing.json")])

    assert result.returncode == 2
    assert "Could not read policy file" in result.stderr
    assert result.stdout == ""


def test_help_is_available():
    result = run_cli(["--help"])

    assert result.returncode == 0
    assert "--format" in result.stdout
    assert "policy" in result.stdout
    assert result.stderr == ""
