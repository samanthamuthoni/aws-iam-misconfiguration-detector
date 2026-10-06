"""Tests for the unconditional administrative-access check."""

import pytest

from iam_detector.analyzer import normalize_statement
from iam_detector.checks import check_admin_access
from iam_detector.models import Severity


@pytest.mark.parametrize("actions", ["*", ["s3:GetObject", "*"]])
def test_reports_admin_access_with_explanation_and_remediation(actions):
    statement = normalize_statement(
        {"Effect": "Allow", "Action": actions, "Resource": "*"}
    )

    finding = check_admin_access(statement, index=2)

    assert finding is not None
    assert finding.rule_id == "IAM001"
    assert finding.severity == Severity.CRITICAL
    assert finding.statement_index == 2
    assert finding.title
    assert finding.description
    assert finding.remediation


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "arn:aws:s3:::synthetic-demo/*",
        },
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": "*",
            "NotResource": "arn:aws:s3:::synthetic-demo/*",
        },
    ],
)
def test_other_patterns_do_not_trigger_this_specific_rule(statement):
    assert check_admin_access(normalize_statement(statement)) is None


def test_conditioned_statement_is_deferred():
    statement = normalize_statement(
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }
    )

    assert check_admin_access(statement) is None
