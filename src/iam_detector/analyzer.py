"""Read policy files for offline analysis."""

import json
from pathlib import Path
from typing import Any


class PolicyInputError(ValueError):
    """Raised when a policy file cannot be read or understood."""


def load_policy(path: str | Path) -> dict[str, Any]:
    """Read a JSON file and require a top-level JSON object."""
    policy_path = Path(path)

    try:
        text = policy_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PolicyInputError(
            f"Could not read policy file: {policy_path}"
        ) from error

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
        raise PolicyInputError(
            "Statement must be an object or a non-empty list."
        )

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            raise PolicyInputError(
                f"Statement {index} must be a JSON object."
            )

    return statements
