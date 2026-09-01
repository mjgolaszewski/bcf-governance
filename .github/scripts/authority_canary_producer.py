"""Execute one deterministic, secretless authority-canary producer."""

from __future__ import annotations

import argparse


def outcome(producer: str, scenario: str) -> int:
    if scenario not in {"success", "producer-b-failure"}:
        return 64
    if producer == "a":
        return 0
    if producer == "b":
        return 86 if scenario == "producer-b-failure" else 0
    return 64


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--producer", choices=("a", "b"), required=True)
    parser.add_argument("--scenario", required=True)
    args = parser.parse_args()
    raise SystemExit(outcome(args.producer, args.scenario))


if __name__ == "__main__":
    main()
