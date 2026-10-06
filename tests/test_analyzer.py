"""Tests for reading policy files."""

import json

import pytest

from iam_detector.analyzer import PolicyInputError, load_policy


def test_reads_valid_policy(tmp_path):
    expected = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ],
    }
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(expected), encoding="utf-8")

    assert load_policy(policy_file) == expected


def test_rejects_broken_json(tmp_path):
    policy_file = tmp_path / "broken.json"
    policy_file.write_text('{"Statement":', encoding="utf-8")

    with pytest.raises(PolicyInputError, match="Invalid JSON"):
        load_policy(policy_file)


def test_rejects_json_array(tmp_path):
    policy_file = tmp_path / "array.json"
    policy_file.write_text("[]", encoding="utf-8")

    with pytest.raises(PolicyInputError, match="JSON object"):
        load_policy(policy_file)


def test_rejects_missing_file(tmp_path):
    missing_file = tmp_path / "missing.json"

    with pytest.raises(PolicyInputError, match="Could not read policy file"):
        load_policy(missing_file)