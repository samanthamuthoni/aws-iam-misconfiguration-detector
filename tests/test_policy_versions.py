import pytest

from iam_detector.analyzer import normalize_statement
from iam_detector.checks import check_policy_versions
from iam_detector.models import Severity


@pytest.mark.parametrize(
    ("action", "resource", "severity"),
    [
        ("iam:CreatePolicyVersion", "*", Severity.HIGH),
        ("iam:SetDefaultPolicyVersion", "*", Severity.HIGH),
        (
            ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
            "*",
            Severity.HIGH,
        ),
        (
            "iam:CreatePolicyVersion",
            "arn:aws:iam::111122223333:policy/app",
            Severity.MEDIUM,
        ),
        ("iam:Create*", "arn:aws:iam::111122223333:policy/app-*", Severity.MEDIUM),
        ("IAM:SetDefaultPolicyVersio?", "*", Severity.HIGH),
    ],
)
def test_policy_version_permissions(action, resource, severity):
    statement = normalize_statement(
        {"Effect": "Allow", "Action": action, "Resource": resource}
    )
    finding = check_policy_versions(statement, index=3)

    assert finding is not None
    assert finding.rule_id == "IAM005"
    assert finding.severity == severity
    assert finding.statement_index == 3
    assert "not proof" in finding.description
    assert "approved customer-managed policy ARNs" in finding.remediation


@pytest.mark.parametrize(
    "policy_statement",
    [
        {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:GetPolicy", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:CreatePolicyVersionExtra", "Resource": "*"},
        {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": "iam:CreatePolicyVersion",
            "NotResource": "arn:aws:iam::111122223333:policy/protected",
        },
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
    ],
)
def test_policy_versions_skips_other_cases(policy_statement):
    statement = normalize_statement(policy_statement)
    assert check_policy_versions(statement) is None


def test_conditions_do_not_silently_suppress_review():
    statement = normalize_statement(
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }
    )
    finding = check_policy_versions(statement)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "effectiveness is not evaluated" in finding.description
    assert "iam:CreatePolicyVersion" in finding.description
    assert "iam:SetDefaultPolicyVersion" in finding.description
