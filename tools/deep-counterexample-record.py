#!/usr/bin/env python3
"""Record replayable deep-engine counterexamples.

Deep engines may produce many advisory leads. This tool writes the common
``deep_counterexample.v1`` artifact only when the operator can state the
target, invariant, violation, and either a replay command or a concrete reason
replay is impossible.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path


SCHEMA_VERSION = "auditooor.deep_counterexample.v1"
ENGINES = {
    "forge-fuzz",
    "medusa",
    "echidna",
    "halmos",
    "kontrol",
    "econ-sim",
    "math-model",
    "crypto-review",
}


def slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-") or "counterexample"


def validate(payload: dict[str, object]) -> list[str]:
    errors: list[str] = []
    required = ["engine", "target_function", "expected_invariant", "observed_violation"]
    for key in required:
        if not str(payload.get(key, "")).strip():
            errors.append(f"missing_{key}")
    if payload.get("engine") not in ENGINES:
        errors.append("invalid_engine")
    has_replay = bool(str(payload.get("replay_command", "")).strip())
    has_impossible = bool(str(payload.get("replay_impossible_reason", "")).strip())
    if not has_replay and not has_impossible:
        errors.append("missing_replay_command_or_impossible_reason")
    if has_replay and has_impossible:
        errors.append("ambiguous_replay_state")
    if has_replay and not str(payload.get("generated_forge_test_path", "")).strip():
        errors.append("missing_generated_forge_test_path")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--engine", required=True, choices=sorted(ENGINES))
    parser.add_argument("--target-function", required=True)
    parser.add_argument("--setup", default="")
    parser.add_argument("--input-sequence", default="")
    parser.add_argument("--expected-invariant", required=True)
    parser.add_argument("--observed-violation", required=True)
    parser.add_argument("--replay-command", default="")
    parser.add_argument("--generated-forge-test-path", default="")
    parser.add_argument("--replay-impossible-reason", default="")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[deep-counterexample] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    payload = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(ws),
        "engine": args.engine,
        "target_function": args.target_function,
        "setup": args.setup,
        "input_sequence": args.input_sequence,
        "expected_invariant": args.expected_invariant,
        "observed_violation": args.observed_violation,
        "replay_command": args.replay_command,
        "generated_forge_test_path": args.generated_forge_test_path,
        "replay_impossible_reason": args.replay_impossible_reason,
        "promotes_to_poc_work": bool(args.replay_command and args.generated_forge_test_path),
        "created_at_unix": int(time.time()),
    }
    errors = validate(payload)
    if errors:
        print(f"[deep-counterexample] ERR {', '.join(errors)}", file=sys.stderr)
        return 1
    out_json = args.out_json
    if out_json is None:
        safe = slug(f"{args.engine}-{args.target_function}")
        out_json = ws / "deep_counterexamples" / f"{safe}.deep_counterexample.v1.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[deep-counterexample] OK json={out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
