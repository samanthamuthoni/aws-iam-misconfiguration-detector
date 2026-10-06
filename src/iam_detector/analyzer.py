from iam_detector.checks import check_passrole

"""Read policy files for offline analysis."""

import json
from pathlib import Path
from typing import Any

from iam_detector.checks import (
    check_admin_access,
    check_allow_exclusions,
    check_service_wildcard,
)
from iam_detector.models import Finding


class PolicyInputError(ValueError):
    """Raised when a policy file cannot be read or understood."""


def load_policy(path: str | Path) -> dict[str, Any]:
    """Read a JSON file and require a top-level JSON object."""
    policy_path = Path(path)

    try:
        text = policy_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PolicyInputError(f"Could not read policy file: {policy_path}") from error

    try:
        policy = json.loads(text)
    except json.JSONDecodeError as error:
        raise PolicyInputError(
            f"Invalid JSON at line {error.lineno}, column {error.colno}."
        ) from error

    if not isinstance(policy, dict):
        raise PolicyInputError("The policy must be a JSON object.")

    return policy


def get_statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Check the Statement container and return a list of statements."""
    if "Statement" not in policy:
        raise PolicyInputError("The policy is missing Statement.")

    statements = policy["Statement"]

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list) or not statements:
        raise PolicyInputError("Statement must be an object or a non-empty list.")

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            raise PolicyInputError(f"Statement {index} must be a JSON object.")

    return statements


def normalize_strings(value: Any, field_name: str) -> list[str]:
    """Require non-empty strings and return them as a list."""
    if isinstance(value, str):
        values = [value]
    else:
        values = value

    if not isinstance(values, list) or not values:
        raise PolicyInputError(
            f"{field_name} must be a string or a non-empty list of strings."
        )

    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise PolicyInputError(f"{field_name} must contain non-empty strings.")

    return list(values)


def normalize_statement(statement: dict[str, Any], index: int = 1) -> dict[str, Any]:
    """Validate required permission fields and normalize their values."""
    if statement.get("Effect") not in ("Allow", "Deny"):
        raise PolicyInputError(f"Statement {index} Effect must be Allow or Deny.")

    normalized = statement.copy()

    for included, excluded in (
        ("Action", "NotAction"),
        ("Resource", "NotResource"),
    ):
        field_names = [key for key in (included, excluded) if key in statement]

        if len(field_names) != 1:
            raise PolicyInputError(
                f"Statement {index} must contain exactly one of "
                f"{included} or {excluded}."
            )

        key = field_names[0]
        normalized[key] = normalize_strings(statement[key], f"Statement {index} {key}")

    return normalized


def analyze_policy(policy: dict[str, Any]) -> list[Finding]:
    """Validate permission fields and run the implemented security checks."""
    statements = get_statements(policy)
    findings: list[Finding] = []

    for index, statement in enumerate(statements, start=1):
        normalized = normalize_statement(statement, index)
        for check in (
            check_admin_access,
            check_service_wildcard,
            check_allow_exclusions,
            check_passrole,
        ):
            finding = check(normalized, index)

            if finding is not None:
                findings.append(finding)

    return findings
