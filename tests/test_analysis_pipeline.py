"""Tests connecting policy loading, validation, and security checks."""

from pathlib import Path

import pytest

from iam_detector.analyzer import (
    PolicyInputError,
    analyze_policy,
    load_policy,
)
from iam_detector.models import Severity


def test_analyzes_example_file():
    repository = Path(__file__).resolve().parents[1]
    policy = load_policy(repository / "examples" / "admin-access.json")

    findings = analyze_policy(policy)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].statement_index == 1


def test_limited_action_has_no_admin_finding():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::synthetic-demo/*",
        }
    }

    assert analyze_policy(policy) == []


def test_findings_identify_correct_statements():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]},
        ]
    }

    findings = analyze_policy(policy)

    assert [finding.statement_index for finding in findings] == [2, 4]


def test_invalid_later_statement_prevents_partial_report():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": 7, "Resource": "*"},
        ]
    }

    with pytest.raises(PolicyInputError, match="Statement 2 Action"):
        analyze_policy(policy)
