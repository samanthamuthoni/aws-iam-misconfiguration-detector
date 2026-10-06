"""Tests for permission-value normalization."""

import pytest

from iam_detector.analyzer import PolicyInputError, normalize_strings


def test_string_becomes_list():
    assert normalize_strings("s3:GetObject", "Action") == ["s3:GetObject"]


def test_list_keeps_its_values():
    actions = ["s3:GetObject", "s3:ListBucket"]
    assert normalize_strings(actions, "Action") == actions


@pytest.mark.parametrize(
    "value",
    [None, 7, "", " ", [], ["s3:GetObject", 7], [""]],
)
def test_rejects_invalid_values(value):
    with pytest.raises(PolicyInputError, match="Action"):
        normalize_strings(value, "Action")
