"""Tests for IAM statement containers."""

import pytest

from iam_detector.analyzer import PolicyInputError, get_statements


def test_single_statement_becomes_list():
    statement = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    assert get_statements({"Statement": statement}) == [statement]


def test_multiple_statements_preserve_order():
    statements = [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
    ]
    assert get_statements({"Statement": statements}) == statements


def test_rejects_missing_statement():
    with pytest.raises(PolicyInputError, match="missing Statement"):
        get_statements({})


def test_rejects_empty_statement_list():
    with pytest.raises(PolicyInputError, match="non-empty list"):
        get_statements({"Statement": []})


def test_rejects_wrong_container_type():
    with pytest.raises(PolicyInputError, match="Statement must"):
        get_statements({"Statement": "Allow"})


def test_rejects_non_object_entry():
    statements = [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        7,
    ]
    with pytest.raises(PolicyInputError, match="Statement 2"):
        get_statements({"Statement": statements})