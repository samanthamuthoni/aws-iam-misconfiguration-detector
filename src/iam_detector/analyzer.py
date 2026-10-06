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