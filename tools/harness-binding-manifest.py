#!/usr/bin/env python3
"""Build a bounded local-only harness binding manifest from plan/report rows."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.harness_binding_manifest.v0"
EXECUTION_CONTRACT_SCHEMA = "auditooor.harness_execution_contract.v1"
_ENVELOPE_TOOL = Path(__file__).with_name("zero-day-proof-envelope-verify.py")


def _load_typed_envelope_tool() -> Any:
    """Reuse the canonical typed-proof validator instead of reconstructing it."""
    spec = importlib.util.spec_from_file_location("auditooor_typed_proof_envelope", _ENVELOPE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("typed_proof_envelope_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_TYPED_ENVELOPE = _load_typed_envelope_tool()
TYPED_ENVELOPE_SCHEMA = _TYPED_ENVELOPE.ENVELOPE_SCHEMA
ROW_KEYS = ("rows", "plans", "items", "results", "reductions", "units", "findings")
COMMAND_KEYS = (
    "compile_command",
    "next_command",
    "command",
    "run_command",
    "rerun_command",
    "scanner_command",
    "harness_command",
    "test_command",
)
GATING_KEYS = ("gating_test", "gate_command", "verification_command")
EXPLICIT_PATH_KEYS = ("generated_test_path", "test_path", "harness_path")
SOURCE_REF_KEYS = ("source_refs", "source_ref", "source_files", "source_file", "source_path")
WORKSPACE_BINDING_KEYS = ("workspace", "workspace_path", "source_workspace", "source_workspace_path")
ADVISORY_BOOL_KEYS = ("advisory_only", "provider_advisory_only", "row_is_advisory", "source_review_only")
ADVISORY_TEXT_KEYS = ("provenance", "source_provenance", "evidence_boundary", "proof_boundary", "submission_posture")
TARGET_KEYS = ("target_entrypoint", "entrypoint", "production_entrypoint")
SETUP_KEYS = ("actor_setup", "setup_template", "setup_path", "setup_steps", "setup")
IMPACT_KEYS = ("impact_contract_id",)
RUNNABLE_HARNESS_REQUIRED_INPUTS = (
    "harness_command",
    "gating_test",
    "source_refs",
    "target_entrypoint",
    "actor_setup",
    "fixture_source",
    "impact_contract_id",
    "generated_test_path",
)
RUNNABLE_STATUS_REFRESH_REQUIRED_INPUTS = RUNNABLE_HARNESS_REQUIRED_INPUTS
RUNNABLE_COMPOSED_CHAIN_REQUIRED_INPUTS = (
    "harness_command",
    "gating_test",
    "source_refs",
    "consumer_entrypoint",
    "producer_state_artifact",
    "fixture_source",
    "generated_test_path",
)
LOCAL_EXECUTABLES = {
    "python",
    "python3",
    "make",
    "forge",
    "cargo",
    "bash",
    "sh",
    "zsh",
    "pytest",
    "jq",
}
NETWORK_TOKENS = ("http://", "https://", "curl ", "wget ", "gh ", "git clone", "pip install ", "npm install ")
DISALLOWED_TOKENS = ("llm-dispatch", "semantic-provider-batch.py")
SUPPORTED_SHELL_TOKENS = {"&&", "||", ";"}
SHELL_EXECUTABLES = {"bash", "sh", "zsh"}
RELEVANCE_TOKENS = (
    "harness",
    "scanner",
    "rerun",
    "replay",
    "precision",
    "calibration",
    "scaffold",
    "live_check",
    "live-check",
    "forge test",
    "cargo test",
)
VAGUE_TOKENS = (
    "tbd",
    "todo",
    "needs_human",
    "manual review",
    "manual binding",
    "operator",
    "replace ",
    "expected:",
    "must emit",
    "should emit",
    "schema-valid blocked",
    "would have",
)
PLACEHOLDER_RE = re.compile(r"<[^>\n]+>")
ROW_SAFE_RE = re.compile(r"[^A-Za-z0-9_]")
LINE_SUFFIX_RE = re.compile(r":\d+(?::\d+)?$")
GITHUB_LINE_SUFFIX_RE = re.compile(r"#L\d+(?:-L?\d+)?$")
SOURCE_REF_PREFIXES = ("engage_report.json:", "engage_report.md:", "engage_report:", "workspace:")


def _read_json_or_jsonl(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        rows = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{lineno}: {exc}") from exc
        return rows
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at {path}: {exc}") from exc


def _path_inside_workspace(path: Path, workspace: Path) -> bool:
    try:
        resolved = path.expanduser().resolve(strict=False)
        root = workspace.expanduser().resolve(strict=False)
        return resolved == root or root in resolved.parents
    except OSError:
        return False


def _proof_file_from_exploit_row(row: dict[str, Any]) -> str | None:
    for key in ("proof_file", "proof_artifact_path", "poc_path", "test_path", "generated_test_path", "harness_path"):
        value = _nonempty_text(row.get(key))
        if value:
            return value
    proof_path = _nonempty_text(row.get("proof_path"))
    if proof_path and ("/" in proof_path or Path(proof_path).suffix):
        return proof_path
    return None


def _harness_family_from_exploit_row(row: dict[str, Any], proof_file: str | None) -> str:
    proof_path = _nonempty_text(row.get("proof_path")).lower()
    if proof_path == "foundry" or (proof_file and proof_file.endswith(".sol")):
        return "forge_invariant"
    if proof_path == "cosmos-production" or (proof_file and proof_file.endswith(".go")):
        return "go_test"
    if proof_path == "solana-program-test" or (proof_file and proof_file.endswith(".rs")):
        return "cargo_unit_test"
    return _nonempty_text(row.get("harness_family")) or "needs_human"


def _proof_file_exists_under_workspace(proof_file: str | None, workspace: Path | None) -> bool:
    if not proof_file:
        return False
    path = Path(proof_file).expanduser()
    if workspace is not None and not path.is_absolute():
        path = workspace / path
    if workspace is not None and not _path_inside_workspace(path, workspace):
        return False
    try:
        return path.resolve(strict=False).is_file()
    except OSError:
        return False


def _existing_workspace_file(path_text: str | None, workspace: Path | None) -> str | None:
    if not path_text or _is_vague(path_text):
        return None
    path = Path(path_text).expanduser()
    if workspace is not None and not path.is_absolute():
        path = workspace / path
    if workspace is not None and not _path_inside_workspace(path, workspace):
        return None
    try:
        return str(path) if path.resolve(strict=False).is_file() else None
    except OSError:
        return None


def _harness_command_from_proof_file(
    proof_file: str | None,
    harness_family: str,
    workspace: Path | None = None,
) -> str | None:
    if not _proof_file_exists_under_workspace(proof_file, workspace):
        return None
    quoted = shlex.quote(proof_file)
    path = Path(proof_file)
    if harness_family == "forge_invariant" or proof_file.endswith(".t.sol"):
        return f"forge test --match-path {quoted} -vv"
    if proof_file.endswith("_test.go"):
        stem = path.stem.removesuffix("_test")
        test_name = "Test" + re.sub(r"[^A-Za-z0-9]", "", stem.title())
        return f"go test ./... -run {shlex.quote(test_name)} -count=1 -v"
    if harness_family == "cargo_unit_test" or proof_file.endswith(".rs"):
        return "cargo test"
    return None


# Materialization: known harness families we can emit a runnable-but-TODO skeleton for.
# A skeleton is honestly NOT a proof - it imports/targets the cited source and carries a
# TODO body. Downstream conversion/proof must still RUN it to PASS (R80). The binding_status
# is 'materialized-skeleton', never 'ready'/'proven'.
MATERIALIZABLE_FORGE_FAMILIES = {"forge_invariant"}
MATERIALIZABLE_CARGO_FAMILIES = {"cargo_unit_test", "rust-cargo-test", "rust_cargo_test"}


def _first_inscope_source_ref(row: dict[str, Any], workspace: Path | None) -> tuple[str | None, str | None]:
    """Return (raw_ref, resolved_in_scope_path) for the first declared source_ref that
    resolves to a real file inside the workspace; (None, None) otherwise."""
    if workspace is None:
        return None, None
    for ref in _declared_source_refs(row):
        path_text, reason = _path_text_from_source_ref(ref)
        if reason or not path_text:
            continue
        path = Path(path_text).expanduser()
        candidate = path if path.is_absolute() else workspace / path
        if not _path_inside_workspace(candidate, workspace):
            continue
        try:
            if candidate.resolve(strict=False).is_file():
                return ref, str(candidate.resolve(strict=False))
        except OSError:
            continue
    return None, None


def _materialized_skeleton_path(row_id: str, harness_family: str, workspace: Path) -> Path | None:
    safe = _row_safe(row_id) or "exploit_row"
    base = workspace / "poc-tests" / f"{safe}-engine-harness"
    if harness_family in MATERIALIZABLE_FORGE_FAMILIES:
        return base / "test" / f"{_solidity_contract_name(row_id)}.t.sol"
    if harness_family in MATERIALIZABLE_CARGO_FAMILIES:
        return base / "tests" / f"{safe}_smoke.rs"
    return None


def _forge_skeleton_body(row_id: str, source_ref: str) -> str:
    contract = _solidity_contract_name(row_id)
    return (
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity >=0.8.0;\n\n"
        "// MATERIALIZED SKELETON - NOT A PROOF.\n"
        f"// Cited source: {source_ref}\n"
        "// TODO(materialized-skeleton): wire the cited entrypoint, attacker setup, and\n"
        "// before/after assertions, then run `forge test` to observe a real PASS.\n"
        'import {Test} from "forge-std/Test.sol";\n\n'
        f"contract {contract} is Test {{\n"
        "    function test_materialized_skeleton_TODO() public {\n"
        "        // TODO: instantiate the cited contract, drive the exploit path,\n"
        "        // and assert the impact. A skeleton body is not a passing PoC.\n"
        "        assertTrue(false, \"materialized-skeleton: TODO body, not yet proven\");\n"
        "    }\n"
        "}\n"
    )


def _cargo_skeleton_body(row_id: str, source_ref: str) -> str:
    return (
        "// MATERIALIZED SKELETON - NOT A PROOF.\n"
        f"// Cited source: {source_ref}\n"
        f"// Row: {row_id}\n"
        "// TODO(materialized-skeleton): import the cited module, drive the exploit path,\n"
        "// and assert the impact, then run `cargo test` to observe a real PASS.\n\n"
        "#[test]\n"
        "fn materialized_skeleton_todo() {\n"
        "    // TODO: a skeleton body is not a passing PoC.\n"
        "    panic!(\"materialized-skeleton: TODO body, not yet proven\");\n"
        "}\n"
    )


def _materialize_harness_skeleton(
    row_id: str,
    harness_family: str,
    source_ref: str,
    workspace: Path | None,
) -> tuple[str | None, str | None]:
    """Emit a minimal runnable-but-TODO harness stub that targets the cited source.

    Returns (generated_test_path, harness_command). The stub is honestly a skeleton:
    its body is a failing TODO, so it is materialized-skeleton, never proven. Returns
    (None, None) for families we cannot materialize or when no workspace is bound.
    """
    if workspace is None:
        return None, None
    target = _materialized_skeleton_path(row_id, harness_family, workspace)
    if target is None:
        return None, None
    try:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            if harness_family in MATERIALIZABLE_FORGE_FAMILIES:
                target.write_text(_forge_skeleton_body(row_id, source_ref), encoding="utf-8")
            else:
                target.write_text(_cargo_skeleton_body(row_id, source_ref), encoding="utf-8")
    except OSError:
        return None, None
    generated_test_path = str(target)
    if harness_family in MATERIALIZABLE_FORGE_FAMILIES:
        command = f"forge test --match-path {shlex.quote(generated_test_path)} -vv"
    else:
        command = "cargo test"
    return generated_test_path, command


def _target_entrypoint_from_exploit_row(row: dict[str, Any]) -> str | None:
    explicit = _binding_value(row, TARGET_KEYS)
    if explicit:
        return explicit
    refs = row.get("source_refs")
    if isinstance(refs, list):
        for ref in refs:
            text = _nonempty_text(ref)
            if text and not _is_vague(text):
                return text
    return None


def _exploit_queue_row_to_harness_row(
    row: dict[str, Any], workspace: Path | None = None, typed_envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    proof_file = _proof_file_from_exploit_row(row)
    harness_family = _harness_family_from_exploit_row(row, proof_file)
    explicit_harness_command = _nonempty_text(row.get("harness_command"))
    explicit_gating_test = _nonempty_text(row.get("gating_test"))
    proof_file_exists = _proof_file_exists_under_workspace(proof_file, workspace)
    explicit_command_allowed = bool(explicit_harness_command and proof_file_exists)
    command = (
        explicit_harness_command
        if explicit_command_allowed
        else _harness_command_from_proof_file(proof_file, harness_family, workspace)
    )

    # Materialization: exploit-queue rows carry proof_path (a harness KIND) + source_refs
    # + next_command, but NEVER a proof_file (0/3360 real rows), so the proof-file guard
    # above blocks every row. When a row declares NO proof_file yet has a valid in-scope
    # source_ref and a materializable harness_family, emit a runnable-but-TODO skeleton and
    # bind to it. HONESTY (R80): a TODO-body skeleton is NOT a proof - binding_status is
    # 'materialized-skeleton', and downstream conversion/proof must still RUN it to PASS.
    binding_status: str | None = None
    materialized_path: str | None = None
    if (
        proof_file is None
        and command is None
        and harness_family in (MATERIALIZABLE_FORGE_FAMILIES | MATERIALIZABLE_CARGO_FAMILIES)
    ):
        raw_ref, resolved_ref = _first_inscope_source_ref(row, workspace)
        if resolved_ref is not None:
            row_id_for_skel = _nonempty_text(row.get("lead_id")) or _nonempty_text(row.get("row_id")) or "exploit_row"
            materialized_path, materialized_command = _materialize_harness_skeleton(
                row_id_for_skel, harness_family, raw_ref or resolved_ref, workspace
            )
            if materialized_path and materialized_command:
                command = materialized_command
                binding_status = "materialized-skeleton"

    source_artifact = _nonempty_text(row.get("source_artifact_path"))
    source_refs = _declared_source_refs(row)
    generated_test_path = materialized_path or proof_file
    out: dict[str, Any] = {
        "row_id": _nonempty_text(row.get("lead_id")) or _nonempty_text(row.get("row_id")),
        "title": _nonempty_text(row.get("title")),
        "binding_scope": "harness",
        "harness_family": harness_family,
        "target_entrypoint": _target_entrypoint_from_exploit_row(row),
        "actor_setup": _nonempty_text(row.get("actor_setup")) or _nonempty_text(row.get("attacker_control")),
        "fixture_source": _nonempty_text(row.get("fixture_source")) or source_artifact or None,
        "impact_contract_id": _nonempty_text(row.get("impact_contract_id")),
        "generated_test_path": generated_test_path,
        "source_refs": source_refs,
        "proof_boundary": "Exploit-queue conversion row; runnable only when all harness bindings are present.",
        "expected_artifacts": [item for item in (generated_test_path, source_artifact) if item],
        "local_evidence": [item for item in (source_artifact,) if item],
    }
    if binding_status is not None:
        out["binding_status"] = binding_status
        out["proof_boundary"] = (
            "Materialized harness skeleton with a TODO body; NOT a proof. Downstream "
            "conversion/proof must run it to observe a real PASS (R80)."
        )
    if command:
        out["harness_command"] = command
        out["gating_test"] = explicit_gating_test if proof_file_exists and explicit_gating_test else command
    if typed_envelope is not None:
        out["zero_day_proof_envelope"] = copy.deepcopy(typed_envelope)
    return out


def load_rows(path: Path) -> list[dict[str, Any]]:
    payload = _read_json_or_jsonl(path)
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        if payload.get("schema") == "auditooor.exploit_queue.v1":
            workspace = path.parent.parent if path.parent.name == ".auditooor" else path.parent
            converted: list[dict[str, Any]] = []
            typed_entries: dict[str, dict[str, Any]] | None = None
            if "zero_day_proof_admission" in payload:
                envelope = _TYPED_ENVELOPE.build_envelope(payload)
                if payload.get("entries") not in (None, []):
                    raise ValueError("typed_proof_envelope_legacy_entries_present")
                typed_entries = {
                    entry["lead_id"]: entry
                    for entry in envelope["entries"]
                    if isinstance(entry, dict) and isinstance(entry.get("lead_id"), str)
                }
            for key in ("queue", "entries"):
                bucket = payload.get(key)
                if not isinstance(bucket, list):
                    continue
                for row in bucket:
                    if not isinstance(row, dict):
                        continue
                    lead_id = _nonempty_text(row.get("lead_id"))
                    if typed_entries is not None and lead_id not in typed_entries:
                        raise ValueError("typed_proof_envelope_row_missing")
                    converted.append(_exploit_queue_row_to_harness_row(
                        row, workspace, typed_entries.get(lead_id) if typed_entries is not None else None,
                    ))
            return [
                row for row in converted if isinstance(row, dict)
            ]
        for key in ROW_KEYS:
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return [payload]
    raise ValueError(f"input must be a JSON object, array, or JSONL rows: {path}")


def proof_ready_candidate_ids(packet_path: Path) -> set[str]:
    """Return only candidate IDs explicitly authorized for proof conversion.

    A judgment packet is a promotion boundary, not a status hint. Missing,
    malformed, or non-proof-ready packets fail closed so a downstream harness
    manifest cannot execute pre-judgment or blocked rows.
    """
    try:
        payload = _read_json_or_jsonl(packet_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return set()
    if not isinstance(payload, dict):
        return set()
    packets = payload.get("packets")
    if not isinstance(packets, list):
        return set()
    eligible: set[str] = set()
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        proof = packet.get("proof_readiness")
        if not isinstance(proof, dict) or str(proof.get("state") or "").strip().lower() != "proof_ready":
            continue
        candidate_id = _nonempty_text(packet.get("candidate_id"))
        if candidate_id:
            eligible.add(candidate_id)
    return eligible


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _iter_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_strings(child)


def _nonempty_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _list_texts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        out = []
        for item in value:
            text = _nonempty_text(item)
            if text:
                out.append(text)
        return out
    return []


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "advisory", "advisory_only"}
    return False


def _is_vague(value: Any) -> bool:
    text = _nonempty_text(value)
    if not text:
        return True
    lowered = text.lower()
    if PLACEHOLDER_RE.search(text):
        return True
    return any(token in lowered for token in VAGUE_TOKENS)


def _row_id(row: dict[str, Any], index: int) -> str:
    for key in ("row_id", "id", "candidate_id", "finding_id", "uuid", "slug"):
        value = _nonempty_text(row.get(key))
        if value:
            return value
    return f"row-{index:04d}"


def _row_title(row: dict[str, Any]) -> str:
    for key in ("title", "limitation", "summary", "name", "statement"):
        value = _nonempty_text(row.get(key))
        if value:
            return value
    return ""


def _row_text(row: dict[str, Any]) -> str:
    return "\n".join(_iter_strings(row)).lower()


def _is_relevant_row(row: dict[str, Any]) -> bool:
    if any(_nonempty_text(row.get(key)) for key in COMMAND_KEYS + GATING_KEYS):
        return True
    if _nonempty_text(row.get("harness_family")):
        return True
    text = _row_text(row)
    return any(token in text for token in RELEVANCE_TOKENS)


def _row_safe(row_id: str) -> str:
    return ROW_SAFE_RE.sub("_", row_id).strip("_").lower()


def _solidity_contract_name(row_id: str) -> str:
    return "Invariant_" + re.sub(r"[^A-Za-z0-9_]", "_", row_id)


def _generated_test_path(row: dict[str, Any], workspace: Path, row_id: str) -> str | None:
    for key in EXPLICIT_PATH_KEYS:
        value = _nonempty_text(row.get(key))
        if value and not _is_vague(value):
            path = Path(value)
            if not path.is_absolute():
                path = workspace / path
            return str(path)

    harness_target = _nonempty_text(row.get("harness_target"))
    if harness_target and not _is_vague(harness_target):
        path = Path(harness_target)
        if not path.is_absolute():
            path = workspace / path
        return str(path)

    harness_family = _nonempty_text(row.get("harness_family"))
    if not harness_family:
        return None

    safe = _row_safe(row_id)
    if harness_family == "forge_invariant":
        return str(workspace / f"poc-tests-{safe}" / "test" / f"{_solidity_contract_name(row_id)}.t.sol")
    if harness_family == "live_check":
        return str(workspace / "poc-tests" / safe / "live_check_spec.json")
    if harness_family in {"engine_api_in_process", "cargo_unit_test", "differential_fuzz"}:
        return str(workspace / "poc-tests" / safe / "tests" / f"{safe}_smoke.rs")
    return None


def _binding_value(row: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = row.get(key)
        if isinstance(value, list):
            items = [item for item in _list_texts(value) if not _is_vague(item)]
            if items:
                return items[0]
            continue
        text = _nonempty_text(value)
        if text and not _is_vague(text):
            return text
    return None


def _declared_source_refs(row: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in SOURCE_REF_KEYS:
        refs.extend(_list_texts(row.get(key)))
    return list(dict.fromkeys(refs))


def _path_text_from_source_ref(ref: str) -> tuple[str | None, str | None]:
    text = ref.strip().strip("`")
    if not text or _is_vague(text):
        return None, "source_ref_vague"
    if "://" in text:
        return None, "source_ref_not_local"
    for prefix in SOURCE_REF_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    text = GITHUB_LINE_SUFFIX_RE.sub("", text)
    text = LINE_SUFFIX_RE.sub("", text)
    if not text:
        return None, "source_ref_vague"
    return text, None


def _source_ref_assessment(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    declared = _declared_source_refs(row)
    valid_refs: list[str] = []
    blockers: list[str] = []
    missing_inputs: list[str] = []
    blocked_reasons: list[str] = []

    if not declared:
        return {
            "declared_refs": [],
            "valid_refs": [],
            "blockers": ["missing_source_refs"],
            "missing_inputs": ["source_refs"],
            "blocked_reasons": ["missing_source_refs"],
        }

    for ref in declared:
        path_text, reason = _path_text_from_source_ref(ref)
        if reason:
            blockers.append(reason)
            blocked_reasons.append(reason)
            continue
        assert path_text is not None
        path = Path(path_text).expanduser()
        candidate = path if path.is_absolute() else workspace / path
        if not _path_inside_workspace(candidate, workspace):
            blockers.append("source_ref_outside_workspace")
            blocked_reasons.append("stale_workspace_binding")
            continue
        if not candidate.resolve(strict=False).is_file():
            blockers.append("source_ref_missing")
            blocked_reasons.append("source_missing")
            continue
        valid_refs.append(str(candidate.resolve(strict=False)))

    if not valid_refs:
        missing_inputs.append("source_refs")

    return {
        "declared_refs": declared,
        "valid_refs": list(dict.fromkeys(valid_refs)),
        "blockers": list(dict.fromkeys(blockers)),
        "missing_inputs": missing_inputs,
        "blocked_reasons": list(dict.fromkeys(blocked_reasons)),
    }


def _workspace_binding_assessment(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    root = workspace.expanduser().resolve(strict=False)
    blockers: list[str] = []
    blocked_reasons: list[str] = []
    for key in WORKSPACE_BINDING_KEYS:
        text = _nonempty_text(row.get(key))
        if not text:
            continue
        bound = Path(text).expanduser().resolve(strict=False)
        if bound != root:
            blockers.append("stale_workspace_binding")
            blocked_reasons.append("stale_workspace_binding")
    return {
        "blockers": list(dict.fromkeys(blockers)),
        "blocked_reasons": list(dict.fromkeys(blocked_reasons)),
    }


def _advisory_provenance_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for key in ADVISORY_BOOL_KEYS:
        if _truthy(row.get(key)):
            blockers.append("advisory_only_provenance")
    for key in ADVISORY_TEXT_KEYS:
        text = _nonempty_text(row.get(key)).lower()
        if "advisory_only" in text or "advisory only" in text:
            blockers.append("advisory_only_provenance")
    return list(dict.fromkeys(blockers))


def _harness_path_assessment(binding_scope: str, bindings: dict[str, Any], workspace: Path) -> dict[str, Any]:
    if binding_scope not in {"harness", "composed_chain_harness"}:
        return {"valid_paths": [], "blockers": [], "missing_inputs": [], "blocked_reasons": []}

    path_text = _nonempty_text(bindings.get("generated_test_path"))
    if not path_text:
        return {
            "valid_paths": [],
            "blockers": ["missing_generated_test_path"],
            "missing_inputs": ["generated_test_path"],
            "blocked_reasons": ["missing_generated_test_path"],
        }

    path = Path(path_text).expanduser()
    candidate = path if path.is_absolute() else workspace / path
    if not _path_inside_workspace(candidate, workspace):
        return {
            "valid_paths": [],
            "blockers": ["generated_test_path_outside_workspace"],
            "missing_inputs": ["generated_test_path"],
            "blocked_reasons": ["stale_workspace_binding"],
        }
    if not candidate.resolve(strict=False).is_file():
        return {
            "valid_paths": [],
            "blockers": ["generated_test_path_missing"],
            "missing_inputs": ["generated_test_path"],
            "blocked_reasons": ["missing_harness_path"],
        }
    return {
        "valid_paths": [str(candidate.resolve(strict=False))],
        "blockers": [],
        "missing_inputs": [],
        "blocked_reasons": [],
    }


def _pathlike_artifacts(values: Any) -> list[str]:
    artifacts: list[str] = []
    for value in _list_texts(values):
        if value.startswith(("reports/", "docs/", "tools/", "agent_outputs/", ".")) or "/" in value:
            artifacts.append(value)
    return list(dict.fromkeys(artifacts))


def _row_expected_artifacts(row: dict[str, Any]) -> list[str]:
    artifacts = _pathlike_artifacts(row.get("expected_artifacts"))
    artifacts.extend(_pathlike_artifacts(row.get("local_evidence")))
    local_status_packet = _nonempty_text(row.get("local_status_packet"))
    if local_status_packet:
        artifacts.append(local_status_packet)
    return list(dict.fromkeys(artifacts))


def _row_proof_boundary(row: dict[str, Any], *, claim: str) -> str:
    boundary = _nonempty_text(row.get("proof_boundary"))
    if boundary:
        return boundary
    boundary = _nonempty_text(row.get("status_notes"))
    if boundary:
        return boundary
    if claim == "runnable_harness":
        return "Exact local command plus bounded local artifacts; not exploit proof, submission proof, or source-proof evidence."
    return "Status refresh or advisory evidence only; not runnable harness evidence."


def _fixture_source(row: dict[str, Any]) -> str | None:
    fixture = _binding_value(row, ("fixture_source", "fixture_kit_id"))
    if fixture:
        return fixture
    items = [item for item in _list_texts(row.get("required_fixtures")) if not _is_vague(item)]
    if items:
        return items[0]
    return None


def _binding_scope(row: dict[str, Any]) -> str:
    explicit = _nonempty_text(row.get("binding_scope"))
    if explicit in {"harness", "composed_chain_harness", "scanner_or_rerun", "status_refresh", "other"}:
        return explicit
    if _nonempty_text(row.get("harness_family")):
        return "harness"
    text = _row_text(row)
    if "harness" in text:
        return "harness"
    if "scanner" in text or "rerun" in text or "replay" in text:
        return "scanner_or_rerun"
    return "other"


def _producer_state_artifact(row: dict[str, Any]) -> str | None:
    return _binding_value(row, ("producer_state_artifact", "producer_artifact", "state_artifact"))


def _composed_generated_test_path(row: dict[str, Any], workspace: Path) -> str | None:
    for key in EXPLICIT_PATH_KEYS:
        value = _nonempty_text(row.get(key))
        existing = _existing_workspace_file(value, workspace)
        if existing:
            return existing
    return None


def _composed_fixture_source(row: dict[str, Any], workspace: Path) -> str | None:
    fixture = _fixture_source(row)
    producer_artifact = _producer_state_artifact(row)
    for candidate in (fixture, producer_artifact):
        existing = _existing_workspace_file(candidate, workspace)
        if existing:
            return existing
    return fixture


def _split_segments(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return [command.strip()] if command.strip() else []

    parts: list[str] = []
    current: list[str] = []
    for token in tokens:
        if token in SUPPORTED_SHELL_TOKENS:
            if current:
                parts.append(shlex.join(current))
                current = []
            continue
        current.append(token)
    if current:
        parts.append(shlex.join(current))
    return parts


def _unsupported_shell_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []

    unsupported = [token for token in tokens if set(token) <= set("|&<>") and token not in SUPPORTED_SHELL_TOKENS]
    return list(dict.fromkeys(unsupported))


def _skip_env_assignments(tokens: list[str]) -> list[str]:
    out = list(tokens)
    while out and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", out[0]):
        out.pop(0)
    return out


def _placeholder_inputs(text: str) -> list[str]:
    inputs = []
    for raw in PLACEHOLDER_RE.findall(text):
        name = raw[1:-1].strip().replace("-", "_").replace(" ", "_")
        if name:
            inputs.append(name.lower())
    return list(dict.fromkeys(inputs))


def _command_assessment(command: str | None) -> dict[str, Any]:
    if not command:
        return {"exact": False, "command": None, "blockers": ["missing_command"], "required_inputs": []}

    text = command.strip()
    lowered = text.lower()
    blockers: list[str] = []
    required_inputs = _placeholder_inputs(text)

    if any(token in lowered for token in DISALLOWED_TOKENS):
        blockers.append("disallowed_llm_dispatch")
    if any(token in lowered for token in NETWORK_TOKENS):
        blockers.append("network_access_not_allowed")
    if _is_vague(text):
        blockers.append("vague_command")
    if "\n" in text and not all(segment for segment in _split_segments(text)):
        blockers.append("unsupported_multiline_command")
    unsupported_shell_tokens = _unsupported_shell_tokens(text)
    if unsupported_shell_tokens:
        blockers.append("unsupported_shell_token:" + ",".join(unsupported_shell_tokens))

    segments = _split_segments(text)
    if not segments:
        blockers.append("missing_command")
    for segment in segments:
        try:
            tokens = shlex.split(segment)
        except ValueError:
            blockers.append("unparseable_command")
            continue
        tokens = _skip_env_assignments(tokens)
        if not tokens:
            blockers.append("missing_command")
            continue
        executable = tokens[0]
        if executable in SHELL_EXECUTABLES and "-c" in tokens[1:]:
            blockers.append("unsupported_shell_inline_command")
        if executable in LOCAL_EXECUTABLES:
            continue
        if executable.startswith("./") or executable.startswith("../") or executable.startswith("/"):
            continue
        if executable.endswith(".py") or executable.endswith(".sh"):
            continue
        blockers.append(f"unsupported_executable:{executable}")

    exact = not blockers
    return {
        "exact": exact,
        "command": text if exact else None,
        "blockers": blockers,
        "required_inputs": required_inputs,
    }


def _command_candidates(row: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in COMMAND_KEYS:
        value = _nonempty_text(row.get(key))
        if value:
            candidates.append(value)
    return list(dict.fromkeys(candidates))


def _best_command(row: dict[str, Any]) -> dict[str, Any]:
    candidates = _command_candidates(row)
    if not candidates:
        return {"exact": False, "command": None, "blockers": ["missing_command"], "required_inputs": []}
    assessed = [_command_assessment(candidate) for candidate in candidates]
    for item in assessed:
        if item["exact"]:
            return item
    best = min(assessed, key=lambda item: (len(item["blockers"]), len(item["required_inputs"])))
    return best


def _gating_test(row: dict[str, Any], command: dict[str, Any]) -> tuple[str | None, list[str], list[str]]:
    for key in GATING_KEYS:
        value = _nonempty_text(row.get(key))
        if not value:
            continue
        assessed = _command_assessment(value)
        if assessed["exact"]:
            return assessed["command"], [], assessed["required_inputs"]
        return None, assessed["blockers"], assessed["required_inputs"]
    if command["exact"]:
        return command["command"], [], []
    return None, ["missing_gating_test"], []


def analyze_row(row: dict[str, Any], *, index: int, workspace: Path) -> dict[str, Any]:
    row_id = _row_id(row, index)
    binding_scope = _binding_scope(row)
    command = _best_command(row)
    gating_test, gating_blockers, gating_inputs = _gating_test(row, command)

    consumer_entrypoint = _binding_value(row, ("consumer_entrypoint", "consumer_target_entrypoint", *TARGET_KEYS))
    producer_state_artifact = _producer_state_artifact(row)
    if binding_scope == "composed_chain_harness":
        generated_test_path = _composed_generated_test_path(row, workspace)
        fixture_source = _composed_fixture_source(row, workspace)
    else:
        generated_test_path = _generated_test_path(row, workspace, row_id)
        fixture_source = _fixture_source(row)

    bindings = {
        "source_refs": [],
        "declared_source_refs": [],
        "target_entrypoint": _binding_value(row, TARGET_KEYS),
        "consumer_entrypoint": consumer_entrypoint,
        "actor_setup": _binding_value(row, SETUP_KEYS),
        "fixture_source": fixture_source,
        "producer_state_artifact": producer_state_artifact,
        "impact_contract_id": _binding_value(row, IMPACT_KEYS),
        "generated_test_path": generated_test_path,
    }
    source_assessment = (
        _source_ref_assessment(row, workspace)
        if binding_scope in {"harness", "composed_chain_harness"}
        else {"declared_refs": [], "valid_refs": [], "blockers": [], "missing_inputs": [], "blocked_reasons": []}
    )
    workspace_assessment = (
        _workspace_binding_assessment(row, workspace)
        if binding_scope in {"harness", "composed_chain_harness"}
        else {"blockers": [], "blocked_reasons": []}
    )
    advisory_blockers = _advisory_provenance_blockers(row)
    bindings["source_refs"] = source_assessment["valid_refs"]
    bindings["declared_source_refs"] = source_assessment["declared_refs"]
    harness_path_assessment = _harness_path_assessment(binding_scope, bindings, workspace)

    missing_inputs: list[str] = []
    blockers = list(command["blockers"])
    blockers.extend(gating_blockers)
    blockers.extend(source_assessment["blockers"])
    blockers.extend(workspace_assessment["blockers"])
    blockers.extend(advisory_blockers)
    blockers.extend(harness_path_assessment["blockers"])
    blocked_reasons: list[str] = []
    blocked_reasons.extend(source_assessment["blocked_reasons"])
    blocked_reasons.extend(workspace_assessment["blocked_reasons"])
    blocked_reasons.extend(advisory_blockers)
    blocked_reasons.extend(harness_path_assessment["blocked_reasons"])

    if not command["exact"]:
        missing_inputs.append("harness_command")
    if gating_test is None:
        missing_inputs.append("gating_test")
    if binding_scope == "harness":
        for name in ("source_refs", "target_entrypoint", "actor_setup", "fixture_source", "impact_contract_id", "generated_test_path"):
            if not bindings[name]:
                missing_inputs.append(name)
    if binding_scope == "composed_chain_harness":
        for name in RUNNABLE_COMPOSED_CHAIN_REQUIRED_INPUTS:
            if name in {"harness_command", "gating_test"}:
                continue
            if not bindings.get(name):
                missing_inputs.append(name)
        if producer_state_artifact and not _existing_workspace_file(producer_state_artifact, workspace):
            blockers.append("producer_state_artifact_missing")
            if "producer_state_artifact" not in missing_inputs:
                missing_inputs.append("producer_state_artifact")
        if bindings.get("fixture_source") and not _existing_workspace_file(bindings["fixture_source"], workspace):
            blockers.append("fixture_source_not_local_file")
            if "fixture_source" not in missing_inputs:
                missing_inputs.append("fixture_source")
        explicit_test_path = _binding_value(row, EXPLICIT_PATH_KEYS)
        if explicit_test_path and not bindings.get("generated_test_path"):
            blockers.append("generated_test_path_missing")
            if "generated_test_path" not in missing_inputs:
                missing_inputs.append("generated_test_path")

    missing_inputs.extend(command["required_inputs"])
    missing_inputs.extend(gating_inputs)
    missing_inputs.extend(source_assessment["missing_inputs"])
    missing_inputs.extend(harness_path_assessment["missing_inputs"])
    missing_inputs = list(dict.fromkeys(missing_inputs))
    blocked_reasons = list(dict.fromkeys(blocked_reasons))

    source_binding_blockers = {
        "missing_source_refs",
        "source_ref_missing",
        "source_ref_outside_workspace",
        "source_ref_not_local",
        "source_ref_vague",
        "stale_workspace_binding",
    }
    source_only_missing = set(missing_inputs).issubset({"source_refs"})
    source_only_blockers = set(blockers).issubset(source_binding_blockers)

    if any(blocker in {"disallowed_llm_dispatch", "network_access_not_allowed"} for blocker in blockers):
        status = "blocked_disallowed_command"
    elif not command["exact"] and "vague_command" in blockers:
        status = "blocked_vague_plan"
    elif "advisory_only_provenance" in blockers:
        status = "blocked_advisory_provenance"
    elif any(blocker in source_binding_blockers for blocker in blockers) and source_only_missing and source_only_blockers:
        status = "blocked_source_binding"
    elif missing_inputs:
        status = "blocked_missing_inputs"
    else:
        status = "ready_executable_binding"

    required_inputs = {
        "harness_command": {"present": command["exact"], "value": command["command"]},
        "gating_test": {"present": gating_test is not None, "value": gating_test},
        "target_entrypoint": {"present": bindings["target_entrypoint"] is not None, "value": bindings["target_entrypoint"]},
        "consumer_entrypoint": {"present": bindings["consumer_entrypoint"] is not None, "value": bindings["consumer_entrypoint"]},
        "actor_setup": {"present": bindings["actor_setup"] is not None, "value": bindings["actor_setup"]},
        "fixture_source": {"present": bindings["fixture_source"] is not None, "value": bindings["fixture_source"]},
        "producer_state_artifact": {
            "present": bindings["producer_state_artifact"] is not None,
            "value": bindings["producer_state_artifact"],
        },
        "impact_contract_id": {"present": bindings["impact_contract_id"] is not None, "value": bindings["impact_contract_id"]},
        "generated_test_path": {"present": bindings["generated_test_path"] is not None, "value": bindings["generated_test_path"]},
        "source_refs": {"present": bool(bindings["source_refs"]), "value": bindings["source_refs"]},
    }

    analyzed = {
        "row_id": row_id,
        "title": _row_title(row),
        "binding_scope": binding_scope,
        "row_kind": "harness_plan" if _nonempty_text(row.get("harness_family")) else "report_row",
        "harness_family": _nonempty_text(row.get("harness_family")) or None,
        "verification_status": _nonempty_text(row.get("verification_status")) or None,
        "verification_commands": _list_texts(row.get("verification_commands")),
        "local_evidence": _list_texts(row.get("local_evidence")),
        "local_status_packet": _nonempty_text(row.get("local_status_packet")) or None,
        "status_notes": _nonempty_text(row.get("status_notes")) or None,
        "proof_boundary": _nonempty_text(row.get("proof_boundary")) or None,
        "status": status,
        "has_executable_harness_command": command["exact"],
        "harness_command": command["command"],
        "gating_test": gating_test,
        "binding_status": _nonempty_text(row.get("binding_status")) or None,
        "required_inputs": required_inputs,
        "missing_inputs": missing_inputs,
        "bindings": bindings,
        "blockers": sorted(set(blockers)),
        "blocked_reasons": blocked_reasons,
        "source_refs": bindings["source_refs"],
        "declared_source_refs": bindings["declared_source_refs"],
        "expected_artifacts": _row_expected_artifacts(row),
        "proof_boundary": _row_proof_boundary(
            row,
            claim=(
                "runnable_harness"
                if status == "ready_executable_binding" and binding_scope in {"harness", "composed_chain_harness"}
                else "blocked_harness"
            ),
        ),
    }
    typed_envelope = row.get("zero_day_proof_envelope")
    if isinstance(typed_envelope, dict):
        if typed_envelope.get("envelope_id") is None:
            raise ValueError("typed_proof_envelope_entry_invalid")
        analyzed["zero_day_proof_envelope"] = copy.deepcopy(typed_envelope)
    if binding_scope == "composed_chain_harness":
        for key in (
            "chain_id",
            "producer_lead_id",
            "consumer_lead_id",
            "bridging_state",
            "producer_source_artifact",
        ):
            value = row.get(key)
            if value not in (None, "", []):
                analyzed[key] = value
        analyzed["expected_artifacts"] = list(
            dict.fromkeys(
                [
                    *analyzed["expected_artifacts"],
                    *[
                        item
                        for item in (
                            bindings.get("producer_state_artifact"),
                            bindings.get("fixture_source"),
                            bindings.get("generated_test_path"),
                        )
                        if isinstance(item, str) and item.strip()
                    ],
                ]
            )
        )
    analyzed["execution_contract"] = _execution_contract(analyzed)
    return analyzed


def _execution_contract(row: dict[str, Any]) -> dict[str, Any]:
    """Build the explicit local execution contract consumed by queues/bundles.

    `status=ready_executable_binding` alone is intentionally not the runnable
    contract. Only harness-scope rows with every runnable-harness input present
    can claim `runnable_harness`; status-refresh/scanner rows remain
    `advisory_only` even when their local verification command is exact.
    """
    status = _nonempty_text(row.get("status"))
    binding_scope = _nonempty_text(row.get("binding_scope"))
    missing_inputs = [
        item for item in row.get("missing_inputs", [])
        if isinstance(item, str) and item.strip()
    ]
    blockers = [
        item for item in row.get("blockers", [])
        if isinstance(item, str) and item.strip()
    ]
    blocked_reasons = [
        item for item in row.get("blocked_reasons", [])
        if isinstance(item, str) and item.strip()
    ]
    commands = {
        "harness_command": row.get("harness_command"),
        "gating_test": row.get("gating_test"),
    }
    expected_artifacts = _row_expected_artifacts(row)
    proof_boundary = _row_proof_boundary(row, claim="blocked_harness")

    if binding_scope not in {"harness", "composed_chain_harness"}:
        claim = "advisory_only"
        runnable = False
        advisory_only = True
    elif status == "ready_executable_binding" and not missing_inputs and not blockers and not blocked_reasons:
        claim = "runnable_harness"
        runnable = True
        advisory_only = False
    else:
        claim = "blocked_harness"
        runnable = False
        advisory_only = False

    if claim == "runnable_harness":
        proof_boundary = _row_proof_boundary(row, claim=claim)

    if claim == "runnable_harness":
        required = list(RUNNABLE_HARNESS_REQUIRED_INPUTS)
        if binding_scope == "status_refresh":
            required = list(RUNNABLE_STATUS_REFRESH_REQUIRED_INPUTS)
        elif binding_scope == "composed_chain_harness":
            required = list(RUNNABLE_COMPOSED_CHAIN_REQUIRED_INPUTS)
        satisfied = list(required)
        missing_for_contract: list[str] = []
    elif claim == "blocked_harness":
        required = (
            list(RUNNABLE_COMPOSED_CHAIN_REQUIRED_INPUTS)
            if binding_scope == "composed_chain_harness"
            else list(RUNNABLE_HARNESS_REQUIRED_INPUTS)
        )
        satisfied = [item for item in required if item not in missing_inputs]
        missing_for_contract = missing_inputs
    else:
        required = ["local_verification_command"]
        satisfied = ["local_verification_command"] if row.get("has_executable_harness_command") else []
        missing_for_contract = []

    contract = {
        "schema": EXECUTION_CONTRACT_SCHEMA,
        "claim": claim,
        "runnable": runnable,
        "advisory_only": advisory_only,
        "fail_closed": True,
        "status_snapshot": status,
        "binding_scope": binding_scope,
        "required_for_runnable": required,
        "satisfied_inputs": satisfied,
        "missing_inputs": missing_for_contract,
        "blockers": blockers,
        "blocked_reasons": blocked_reasons,
        "commands": commands,
        "expected_artifacts": expected_artifacts,
        "source_refs": row.get("source_refs", []),
        "proof_boundary": proof_boundary,
        "evidence_boundary": (
            "exact local harness command plus bounded local artifacts"
            if claim == "runnable_harness"
            else "not runnable harness evidence"
        ),
    }
    if binding_scope == "composed_chain_harness":
        for key in (
            "chain_id",
            "producer_lead_id",
            "consumer_lead_id",
            "bridging_state",
            "producer_state_artifact",
            "producer_source_artifact",
            "consumer_entrypoint",
        ):
            value = row.get(key) or (row.get("bindings", {}) if isinstance(row.get("bindings"), dict) else {}).get(key)
            if value not in (None, "", []):
                contract[key] = value
    return contract


def build_manifest(
    rows: list[dict[str, Any]],
    *,
    workspace: Path | None = None,
    source_path: Path | None = None,
    candidate_judgment_path: Path | None = None,
) -> dict[str, Any]:
    base = workspace or Path(".")
    judgment_ids = None
    if candidate_judgment_path is not None:
        judgment_ids = proof_ready_candidate_ids(candidate_judgment_path)
    relevant_rows = [
        row
        for row in rows
        if _is_relevant_row(row)
        and (judgment_ids is None or _row_id(row, 0) in judgment_ids)
    ]
    manifest_rows = [analyze_row(row, index=index, workspace=base) for index, row in enumerate(relevant_rows, start=1)]
    blocker_counts = Counter(blocker for row in manifest_rows for blocker in row["blockers"])
    contract_counts = Counter(
        row.get("execution_contract", {}).get("claim", "missing_contract")
        for row in manifest_rows
    )
    return {
        "schema": SCHEMA,
        "execution_contract_schema": EXECUTION_CONTRACT_SCHEMA,
        "source_path": str(source_path) if source_path is not None else None,
        "candidate_judgment_path": str(candidate_judgment_path) if candidate_judgment_path is not None else None,
        "candidate_judgment_filter": (
            "proof_ready_only" if candidate_judgment_path is not None else "not_applied"
        ),
        "candidate_judgment_eligible_count": len(judgment_ids) if judgment_ids is not None else None,
        "input_row_count": len(rows),
        "workspace": str(base),
        "row_count": len(manifest_rows),
        "ready_count": sum(1 for row in manifest_rows if row["status"] == "ready_executable_binding"),
        "blocked_count": sum(1 for row in manifest_rows if row["status"] != "ready_executable_binding"),
        "executable_command_count": sum(1 for row in manifest_rows if row["has_executable_harness_command"]),
        "rows": sorted(manifest_rows, key=lambda row: row["row_id"]),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "contract_counts": dict(sorted(contract_counts.items())),
        "typed_proof_envelope_schema": TYPED_ENVELOPE_SCHEMA if any(
            isinstance(row.get("zero_day_proof_envelope"), dict) for row in manifest_rows
        ) else None,
        "typed_proof_envelope_entry_count": sum(
            1 for row in manifest_rows if isinstance(row.get("zero_day_proof_envelope"), dict)
        ),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Path to local JSON or JSONL plan/report rows.")
    parser.add_argument("--workspace", default=".", help="Workspace root used for derived harness paths.")
    parser.add_argument("--out", default=None, help="Optional output JSON path.")
    parser.add_argument(
        "--candidate-judgment-packet",
        default=None,
        help="Optional judgment packet; only proof_ready candidate rows enter the manifest.",
    )
    parser.add_argument("--print-json", action="store_true", help="Print JSON to stdout even when --out is used.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_path = Path(args.input).expanduser().resolve()
    workspace = Path(args.workspace).expanduser().resolve()
    rows = load_rows(input_path)
    judgment_path = (
        Path(args.candidate_judgment_packet).expanduser().resolve()
        if args.candidate_judgment_packet
        else None
    )
    manifest = build_manifest(
        rows,
        workspace=workspace,
        source_path=input_path,
        candidate_judgment_path=judgment_path,
    )
    payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"

    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload, encoding="utf-8")
    if args.print_json or not args.out:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
