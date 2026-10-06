"""Tests for broad service-level permissions."""

import pytest

from iam_detector.analyzer import analyze_policy, normalize_statement
from iam_detector.checks import check_service_wildcard
from iam_detector.models import Severity


@pytest.mark.parametrize(
    "action,resource,severity",
    [
        ("s3:*", "*", Severity.HIGH),
        ("S3:*", "arn:aws:s3:::synthetic-demo/*", Severity.MEDIUM),
        (
            ["s3:*", "S3:*"],
            ["arn:aws:s3:::synthetic-demo/*", "*"],
            Severity.HIGH,
        ),
    ],
)
def test_severity_considers_resource_scope(action, resource, severity):
    statement = normalize_statement(
        {"Effect": "Allow", "Action": action, "Resource": resource}
    )

    finding = check_service_wildcard(statement)

    assert finding is not None
    assert finding.severity == severity
    assert finding.title == "Broad service permissions: s3"
    assert finding.description
    assert finding.remediation


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"},
        {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "NotResource": "arn:aws:s3:::synthetic-demo/*",
        },
        {"Effect": "Allow", "Action": ["*", "s3:*"], "Resource": "*"},
    ],
)
def test_other_patterns_do_not_trigger_this_rule(statement):
    assert check_service_wildcard(normalize_statement(statement)) is None


def test_conditions_are_disclosed_without_assuming_protection():
    statement = normalize_statement(
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        }
    )

    finding = check_service_wildcard(statement)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "Conditions are present" in finding.description


def test_analyzer_runs_service_wildcard_check():
    policy = {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}

    findings = analyze_policy(policy)

    assert len(findings) == 1
    assert findings[0].rule_id == "IAM002"
