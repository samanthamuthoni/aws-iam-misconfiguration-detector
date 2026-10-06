"""Command-line interface for offline IAM policy review."""

import argparse
import sys

from iam_detector.analyzer import PolicyInputError, analyze_policy, load_policy
from iam_detector.reporting import render_json, render_text


def main(argv: list[str] | None = None) -> int:
    """Read arguments, analyze a policy, and return an exit code."""
    parser = argparse.ArgumentParser(
        prog="python -m iam_detector.cli",
        description="Offline IAM policy review (early development).",
    )
    parser.add_argument(
        "policy",
        help="Path to a local IAM policy JSON file.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report format (default: text).",
    )
    args = parser.parse_args(argv)

    try:
        policy = load_policy(args.policy)
        findings = analyze_policy(policy)
    except PolicyInputError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        report = render_json(findings)
    else:
        report = render_text(findings)

    print(report)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
