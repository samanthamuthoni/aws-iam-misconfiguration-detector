import pytest

from iam_detector.analyzer import normalize_statement
from iam_detector.checks import check_passrole


@pytest.mark.parametrize(
    ("action", "expected_finding"),
    [
        ("iam:*", True),
        ("iam:Pass*", True),
        ("IAM:PassRol?", True),
        (["s3:GetObject", "iam:Pass*"], True),
        ("iam:Delete*", False),
        ("iam:PassRoleExtra", False),
    ],
)
def test_passrole_action_patterns(action, expected_finding):
    statement = normalize_statement(
        {
            "Effect": "Allow",
            "Action": action,
            "Resource": "arn:aws:iam::111122223333:role/app-*",
        }
    )
    finding = check_passrole(statement)

    assert (finding is not None) == expected_finding


@pytest.mark.parametrize(
    ("resource", "condition", "expected_finding"),
    [
        ("*", None, False),
        ("*", {"Bool": {"aws:MultiFactorAuthPresent": "true"}}, True),
        ("arn:aws:iam::111122223333:role/app-*", None, True),
    ],
)
def test_global_action_overlap(resource, condition, expected_finding):
    policy_statement = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": resource,
    }
    if condition is not None:
        policy_statement["Condition"] = condition

    statement = normalize_statement(policy_statement)
    finding = check_passrole(statement)

    assert (finding is not None) == expected_finding
