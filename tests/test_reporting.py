"""Tests for readable and machine-readable reports."""

import json

from iam_detector.analyzer import analyze_policy
from iam_detector.reporting import render_json, render_text


def sample_findings():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::synthetic-demo/*",
            },
        ]
    }
    return analyze_policy(policy)


def test_text_includes_severity_location_and_remediation():
    findings = sample_findings()

    report = render_text(findings)

    assert "Findings: 2" in report
    assert "[Critical] IAM001" in report
    assert "[Medium] IAM002" in report
    assert "Statement: 1" in report
    assert "Statement: 2" in report

    for finding in findings:
        assert finding.description in report
        assert finding.remediation in report


def test_empty_text_explains_detection_limitations():
    report = render_text([])

    assert "Findings: 0" in report
    assert "No findings from the implemented checks." in report
    assert "not a guarantee of safety" in report


def test_json_preserves_finding_details():
    findings = sample_findings()

    report = json.loads(render_json(findings))

    assert report["schema_version"] == 1
    assert report["finding_count"] == 2
    assert [item["rule_id"] for item in report["findings"]] == [
        "IAM001",
        "IAM002",
    ]
    assert [item["severity"] for item in report["findings"]] == [
        "Critical",
        "Medium",
    ]
    assert [item["statement_index"] for item in report["findings"]] == [1, 2]

    for original, exported in zip(findings, report["findings"], strict=True):
        assert exported["description"] == original.description
        assert exported["remediation"] == original.remediation


def test_empty_json_is_valid_and_explicit():
    report = json.loads(render_json([]))

    assert report["finding_count"] == 0
    assert report["findings"] == []
    assert "not a guarantee of safety" in report["scope"]
