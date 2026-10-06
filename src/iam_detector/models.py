"""Structured security findings."""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Severity labels used in our reports."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


@dataclass(frozen=True)
class Finding:
    """One security concern and its recommended fix."""

    rule_id: str
    severity: Severity
    statement_index: int
    title: str
    description: str
    remediation: str
