#!/usr/bin/env python3
"""Generate a Forge replay scaffold from deep_counterexample.v1.

This does not prove an exploit. It creates a deliberately skipped Forge test
with the counterexample metadata embedded inline so a harness author can wire
setup, actors, and calls without losing the original engine evidence.
"""
from __future__ import annotations

import argparse
import json
import re
import textwrap
from pathlib import Path
from typing import Any


EXPECTED_SCHEMA = "auditooor.deep_counterexample.v1"
HANDOFF_SCHEMA = "auditooor.deep_counterexample_replay_handoff.v1"


def slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "deep_counterexample"


def load_record(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"[deep-replay-scaffold] ERR {path}: expected JSON object")
    if data.get("schema_version") != EXPECTED_SCHEMA:
        raise SystemExit(
            f"[deep-replay-scaffold] ERR {path}: expected schema_version={EXPECTED_SCHEMA}"
        )
    return data


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def nonempty_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def impact_contract_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("contracts", "records", "rows", "impact_contracts"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def load_impact_contracts(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / ".auditooor" / "impact_contracts.json"
    if not path.exists():
        raise SystemExit(f"[deep-replay-scaffold] ERR blocked_missing_impact_contract: missing {path}")
    try:
        return impact_contract_rows(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"[deep-replay-scaffold] ERR blocked_missing_impact_contract: invalid {path}: {exc}") from exc


def selected_impact(row: dict[str, Any]) -> str:
    return nonempty_text(row.get("selected_impact")) or nonempty_text(row.get("listed_impact_selected"))


def severity(row: dict[str, Any]) -> str:
    return nonempty_text(row.get("severity")) or nonempty_text(row.get("raw_severity")) or nonempty_text(row.get("severity_implied"))


def locked_impact_contract(record: dict[str, Any], workspace: Path) -> dict[str, Any]:
    requested = nonempty_text(record.get("impact_contract_id"))
    if not requested:
        raise SystemExit(
            "[deep-replay-scaffold] ERR blocked_missing_impact_contract: "
            "deep replay scaffolds require record.impact_contract_id before PoC work"
        )
    rows = load_impact_contracts(workspace)
    row = next((item for item in rows if nonempty_text(item.get("impact_contract_id")) == requested), None)
    if not row:
        raise SystemExit(
            "[deep-replay-scaffold] ERR blocked_missing_impact_contract: "
            f"impact_contract_id {requested!r} not found in workspace impact contracts"
        )
    missing: list[str] = []
    if not selected_impact(row):
        missing.append("selected_impact")
    row_severity = severity(row)
    if not row_severity or row_severity.lower() == "none":
        missing.append("severity")
    if not truthy(row.get("listed_impact_proven")):
        missing.append("listed_impact_proven=true")
    if row.get("exact_impact_row") is False:
        missing.append("exact_impact_row")
    if missing:
        raise SystemExit(
            "[deep-replay-scaffold] ERR blocked_missing_impact_contract: "
            f"impact_contract_id {requested!r} is not locked ({', '.join(missing)})"
        )
    return {
        "impact_contract_id": requested,
        "selected_impact": selected_impact(row),
        "severity": row_severity,
        "listed_impact_proven": row.get("listed_impact_proven"),
        "exact_impact_row": row.get("exact_impact_row"),
    }


def solidity_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def split_args(raw: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    in_quote = False
    quote_char = ""
    escaped = False
    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if in_quote:
            current.append(char)
            if char == quote_char:
                in_quote = False
            continue
        if char in {'"', "'"}:
            in_quote = True
            quote_char = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            current.append(char)
            continue
        if char == "," and depth == 0:
            value = "".join(current).strip()
            if value:
                args.append(value)
            current = []
            continue
        current.append(char)
    value = "".join(current).strip()
    if value:
        args.append(value)
    return args


def infer_solidity_type(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"true|false", value, re.IGNORECASE):
        return "bool"
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
        return "address"
    if re.fullmatch(r"0x[a-fA-F0-9]{64}", value):
        return "bytes32"
    if re.fullmatch(r"0x[a-fA-F0-9]*", value):
        return "bytes"
    if re.fullmatch(r"\d+", value):
        return "uint256"
    if re.fullmatch(r"-\d+", value):
        return "int256"
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return "string"
    return "bytes"


def render_arg_expression(value: str) -> str:
    value = value.strip()
    typ = infer_solidity_type(value)
    if typ == "address":
        return f"address({value})"
    if typ == "bytes32":
        return f"bytes32({value})"
    if typ == "bytes":
        if re.fullmatch(r"0x[a-fA-F0-9]*", value):
            return f'hex"{value[2:]}"'
        return "bytes(\"\") /* TODO: replace opaque argument */"
    if typ == "string":
        if value.startswith("'") and value.endswith("'"):
            return f'"{solidity_string(value[1:-1])}"'
        return value
    return value


def normalize_trace_line(line: str) -> str:
    stripped = line.strip().rstrip(";")
    stripped = re.sub("^[|`\\\\/\\-+ ]*(?:\u251c\u2500|\u2514\u2500)?\\s*", "", stripped)
    stripped = re.sub(r"^\[\d+\]\s*", "", stripped)
    stripped = re.sub(r"^\d+[\).:-]\s*", "", stripped)
    stripped = re.sub(r"^[A-Za-z_][A-Za-z0-9_-]*\s*[:=]\s*", "", stripped)
    stripped = stripped.replace("::", ".")
    return stripped


def extract_call_steps(sequence: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for line in sequence.splitlines():
        stripped = normalize_trace_line(line)
        if not stripped or stripped.startswith(("#", "//")):
            continue
        match = re.search(r"(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$", stripped)
        if not match:
            continue
        fn = match.group(1)
        args = split_args(match.group(2))
        types = [infer_solidity_type(arg) for arg in args]
        if any(typ == "bytes" and not re.fullmatch(r"0x[a-fA-F0-9]*", arg.strip()) for typ, arg in zip(types, args)):
            # Keep opaque traces in comments instead of generating misleading code.
            continue
        steps.append(
            {
                "raw": stripped,
                "function": fn,
                "types": types,
                "args": args,
                "signature": f"{fn}({','.join(types)})",
            }
        )
    return steps


def render_synthesized_call_block(sequence: str) -> str:
    steps = extract_call_steps(sequence)
    if not steps:
        return textwrap.dedent(
            """\
                bool internal constant HAS_SYNTHESIZED_CALLS = false;

                function _replaySynthesizedCalls(address target) internal {
                    target;
                    // No simple Solidity-like calls were parsed from INPUT_SEQUENCE.
                    // Keep the original trace embedded above and wire calls manually.
                }
            """
        )

    lines = [
        "    bool internal constant HAS_SYNTHESIZED_CALLS = true;",
        "",
        "    function _replaySynthesizedCalls(address target) internal {",
        "        require(target != address(0), \"wire real target before replay\");",
    ]
    for idx, step in enumerate(steps, start=1):
        args = ", ".join(render_arg_expression(str(arg)) for arg in step["args"])
        suffix = f", {args}" if args else ""
        lines.extend(
            [
                f"        // Step {idx}: {step['raw']}",
                f"        (bool ok{idx}, ) = target.call(abi.encodeWithSignature(\"{step['signature']}\"{suffix}));",
                f"        require(ok{idx}, \"synthesized replay step {idx} failed\");",
            ]
        )
    lines.append("    }")
    return "\n".join(lines)


def render(record: dict[str, Any], record_path: Path) -> str:
    target = str(record.get("target_function") or "Unknown.target")
    engine = str(record.get("engine") or "unknown")
    test_name = f"test_replay_{slug(target)}_{slug(engine)}"
    expected = str(record.get("expected_invariant") or "")
    observed = str(record.get("observed_violation") or "")
    sequence = str(record.get("input_sequence") or "")
    replay = str(record.get("replay_command") or "")
    synthesized = textwrap.indent(render_synthesized_call_block(sequence), "        ")
    return textwrap.dedent(
        f"""\
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.13;

        import {{Test}} from "forge-std/Test.sol";

        /// @notice Generated from {record_path}.
        /// @dev SCAFFOLD ONLY. This test is skipped until setup/calls/assertions are wired.
        contract DeepCounterexampleReplayScaffold is Test {{
            string internal constant ENGINE = "{solidity_string(engine)}";
            string internal constant TARGET = "{solidity_string(target)}";
            string internal constant EXPECTED_INVARIANT = "{solidity_string(expected)}";
            string internal constant OBSERVED_VIOLATION = "{solidity_string(observed)}";
            string internal constant INPUT_SEQUENCE = "{solidity_string(sequence)}";
            string internal constant SOURCE_REPLAY_COMMAND = "{solidity_string(replay)}";

{synthesized}

            function {test_name}() public {{
                vm.skip(true);

                // TODO:
                // 1. Deploy or fork the real target system.
                // 2. Bind the real target and call _replaySynthesizedCalls(target) when HAS_SYNTHESIZED_CALLS is true.
                // 3. Assert OBSERVED_VIOLATION with value/state deltas, not just branch reachability.
                // 4. Only then record RESULT=proved IMPACT=exploit_impact with make poc-execution-record.
            }}
        }}
        """
    )


def handoff_path_for(scaffold_path: Path) -> Path:
    return scaffold_path.with_name(scaffold_path.name + ".handoff.json")


def render_handoff_manifest(
    record: dict[str, Any],
    record_path: Path,
    scaffold_path: Path,
    impact_contract: dict[str, Any],
) -> dict[str, Any]:
    sequence = str(record.get("input_sequence") or "")
    steps = extract_call_steps(sequence)
    has_synthesized = bool(steps)
    remaining_tasks = [
        "Deploy or fork the real target system; do not use mocks unless the finding scope explicitly allows them.",
        "Bind the real target address in the generated Forge test.",
    ]
    if has_synthesized:
        remaining_tasks.append("Call _replaySynthesizedCalls(target) and confirm every synthesized step maps to the intended production function.")
    else:
        remaining_tasks.append("Translate the original counterexample trace into concrete Forge calls manually; no safe call block was synthesized.")
    remaining_tasks.extend(
        [
            "Replace vm.skip(true) only after setup and replay calls are wired.",
            "Assert the observed violation with value/state deltas, not just branch reachability.",
            "Record the executed replay with make poc-execution-record RESULT=<proved|disproved|blocked_env|blocked_path|needs_human> IMPACT=<impact>.",
        ]
    )
    return {
        "schema_version": HANDOFF_SCHEMA,
        "record_path": str(record_path),
        "scaffold_path": str(scaffold_path),
        "engine": str(record.get("engine") or ""),
        "target_function": str(record.get("target_function") or ""),
        "source_replay_command": str(record.get("replay_command") or ""),
        "impact_contract": impact_contract,
        "has_synthesized_calls": has_synthesized,
        "synthesized_call_count": len(steps),
        "synthesized_calls": [
            {
                "step": idx,
                "raw": str(step["raw"]),
                "signature": str(step["signature"]),
                "types": list(step["types"]),
            }
            for idx, step in enumerate(steps, start=1)
        ],
        "remaining_tasks": remaining_tasks,
        "guardrails": [
            "This handoff manifest is not proof.",
            "Do not promote until the Forge replay executes and poc-execution-record captures exploit_impact.",
            "If setup requires privileged/admin/guardian/project-inaction behavior, run production-path and scope checks before severity claims.",
        ],
        "poc_execution_handoff": (
            "make poc-execution-record WS=<workspace> BRIEF=<brief.md> "
            "RESULT=<proved|disproved|blocked_env|blocked_path|needs_human> IMPACT=<impact>"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--print-path", action="store_true")
    args = parser.parse_args(argv)

    record_path = args.record.expanduser().resolve()
    record = load_record(record_path)
    if args.out:
        out = args.out.expanduser()
        ws = args.workspace.expanduser() if args.workspace else Path(str(record.get("workspace") or ".")).expanduser()
    else:
        ws = args.workspace.expanduser() if args.workspace else Path(str(record.get("workspace") or ".")).expanduser()
        out = ws / "poc-tests" / f"{slug(str(record.get('target_function') or record_path.stem))}_DeepCounterexampleReplay.t.sol"
    impact_contract = locked_impact_contract(record, ws.resolve())
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(record, record_path), encoding="utf-8")
    handoff_path = handoff_path_for(out)
    handoff_path.write_text(
        json.dumps(render_handoff_manifest(record, record_path, out, impact_contract), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.print_path:
        print(out)
    else:
        print(f"[deep-replay-scaffold] OK scaffold={out} handoff={handoff_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
