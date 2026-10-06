import pytest

from iam_detector.analyzer import normalize_statement
from iam_detector.checks import check_passrole
from iam_detector.models import Severity


@pytest.mark.parametrize(
    ("action", "resource", "severity"),
    [
        ("iam:PassRole", "*", Severity.HIGH),
        (["IAM:PASSROLE"], ["*"], Severity.HIGH),
        (
            "iam:PassRole",
            "arn:aws:iam::111122223333:role/app-*",
            Severity.MEDIUM,
        ),
        (
            "iam:PassRole",
            "arn:aws:iam::111122223333:role/app-?",
            Severity.MEDIUM,
        ),
    ],
)
def test_wildcard_passrole_is_flagged(action, resource, severity):
    statement = normalize_statement(
        {"Effect": "Allow", "Action": action, "Resource": resource}
    )
    finding = check_passrole(statement, index=2)

    assert finding is not None
    assert finding.rule_id == "IAM004"
    assert finding.severity == severity
    assert finding.statement_index == 2
    assert "greater privileges" in finding.description
    assert "iam:PassedToService" in finding.remediation


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::111122223333:role/app-reader",
        },
    ],
)
def test_unmatched_passrole_statements_have_no_finding(statement):
    assert check_passrole(normalize_statement(statement)) is None


def test_conditions_are_disclosed_without_assuming_safety():
    statement = normalize_statement(
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {
                "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
            },
        }
    )
    finding = check_passrole(statement)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "effectiveness has not been evaluated" in finding.description
