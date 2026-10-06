"""Tests for required IAM permission fields."""

import pytest

from iam_detector.analyzer import PolicyInputError, normalize_statement


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_normalizes_string_fields(effect):
    statement = {
        "Effect": effect,
        "Action": "s3:GetObject",
        "Resource": "*",
    }
    result = normalize_statement(statement)

    assert result["Effect"] == effect
    assert result["Action"] == ["s3:GetObject"]
    assert result["Resource"] == ["*"]
    assert statement["Action"] == "s3:GetObject"


def test_preserves_exclusion_fields():
    statement = {
        "Effect": "Allow",
        "NotAction": "iam:*",
        "NotResource": "arn:aws:s3:::synthetic-demo/*",
    }
    result = normalize_statement(statement)

    assert result["NotAction"] == ["iam:*"]
    assert result["NotResource"] == ["arn:aws:s3:::synthetic-demo/*"]


@pytest.mark.parametrize(
    "statement",
    [
        {"Action": "*", "Resource": "*"},
        {"Effect": "allow", "Action": "*", "Resource": "*"},
        {"Effect": "Allow", "Resource": "*"},
        {"Effect": "Allow", "Action": "*"},
        {
            "Effect": "Allow",
            "Action": "*",
            "NotAction": "iam:*",
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "NotResource": "*",
        },
    ],
)
def test_rejects_missing_or_conflicting_fields(statement):
    with pytest.raises(PolicyInputError):
        normalize_statement(statement)


def test_error_identifies_statement_number():
    with pytest.raises(PolicyInputError, match="Statement 2"):
        normalize_statement({}, index=2)
