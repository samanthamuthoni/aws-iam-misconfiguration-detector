"""Tests for Allow statements using permission exclusions."""

import pytest

from iam_detector.analyzer import normalize_statement
from iam_detector.checks import check_allow_exclusions
from iam_detector.models import Severity


@pytest.mark.parametrize(
    "fields, expected_severity",
    [
        (
            {"NotAction": "iam:*", "Resource": "*"},
            Severity.HIGH,
        ),
        (
            {
                "NotAction": ["s3:DeleteBucket"],
                "Resource": "arn:aws:s3:::synthetic-demo",
            },
            Severity.MEDIUM,
        ),
        (
            {
                "Action": "s3:PutObject",
                "NotResource": "arn:aws:s3:::synthetic-protected/*",
            },
            Severity.HIGH,
        ),
        (
            {
                "NotAction": ["iam:*"],
                "NotResource": ["arn:aws:s3:::synthetic-protected/*"],
            },
            Severity.HIGH,
        ),
    ],
)
def test_allow_exclusions_produce_review_findings(fields, expected_severity):
    statement = normalize_statement({"Effect": "Allow", **fields})
    finding = check_allow_exclusions(statement, index=2)

    assert finding is not None
    assert finding.rule_id == "IAM003"
    assert finding.severity == expected_severity
    assert finding.statement_index == 2
    assert finding.description
    assert finding.remediation


@pytest.mark.parametrize(
    "effect, fields",
    [
        ("Deny", {"NotAction": "iam:*", "Resource": "*"}),
        ("Deny", {"Action": "s3:*", "NotResource": "arn:aws:s3:::demo/*"}),
        ("Allow", {"Action": "s3:GetObject", "Resource": "*"}),
        ("Allow", {"NotAction": ["iam:*", "*"], "Resource": "*"}),
        ("Allow", {"Action": "s3:PutObject", "NotResource": ["*"]}),
    ],
)
def test_rule_skips_statements_without_an_allow_exclusion_risk(effect, fields):
    statement = normalize_statement({"Effect": effect, **fields})

    assert check_allow_exclusions(statement) is None


def test_condition_presence_does_not_automatically_lower_severity():
    statement = normalize_statement(
        {
            "Effect": "Allow",
            "NotAction": "iam:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }
    )
    finding = check_allow_exclusions(statement)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "effectiveness has not been evaluated" in finding.description
