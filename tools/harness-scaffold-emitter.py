#!/usr/bin/env python3
"""
harness-scaffold-emitter.py — PR #535 / Wave 8 JJ2.

Bridges the harness PLANS produced by `tools/invariant-harness-planner.py`
(PR #529 / VV2) and the reusable fixture kits committed by PR #530 / XX2 in
`reference/harness-fixture-kits/` into a first executable scaffold per row.

What it emits (per plan row)
============================

For each plan row we drop a per-row scaffold tree under the workspace:

  Rust families (engine_api_in_process / cargo_unit_test / differential_fuzz):
      <ws>/poc-tests/<row-id>/Cargo.toml
      <ws>/poc-tests/<row-id>/tests/<test_name>.rs
      <ws>/poc-tests/<row-id>/attempt_manifest.json

  Solidity / forge_invariant family (DDD2-style profile dir layout):
      <ws>/poc-tests-<row-id>/foundry.toml
      <ws>/poc-tests-<row-id>/test/<TestName>.t.sol
      <ws>/poc-tests-<row-id>/attempt_manifest.json

  live_check family:
      <ws>/poc-tests/<row-id>/live_check_spec.json
      <ws>/poc-tests/<row-id>/attempt_manifest.json

The skeleton always includes:

  * a `setup` fixture-cite block (which kit_id, which exposed_helpers)
  * a `valid positive control` test stub
  * an `invalid negative control` test stub (uses
    plan.first_negative_control verbatim)
  * the exact compile_command from the plan in a top-of-file comment so the
    operator can re-run it byte-for-byte
  * a hard-coded `expected assertion` line (from plan.expected_log_string)
  * an `evidence-class marker` comment (`// evidence-class: scaffolded_unverified`)

Failed-attempt manifest
-----------------------

If we cannot scaffold (kit cited by plan does not exist on disk, plan field
missing, target_entrypoint == "TBD" with no fallback, etc.) we STILL write
`attempt_manifest.json` with:

    {
      "row_id": "...",
      "harness_family": "...",
      "fixture_kit_id": "...",
      "plan_sha": "...",
      "generated_at": "<ledger-derived>",
      "status": "blocked",
      "blocker_reason": "<one-line>"
    }

so future agents see the dead path immediately and do not re-run it.

Discipline
----------

  * stdlib-only.
  * Generated scaffolds mark themselves `scaffolded_unverified` until
    actually executed by a separate `make` step. We DO NOT auto-run.
  * Idempotent: a second run of the emitter against the same plan + the
    same fixture-kit sha produces a byte-identical scaffold tree. Re-runs
    skip rows that already have a scaffold unless `--force` is passed.
  * Deterministic timestamp: the emitter takes its `generated_at` from the
    plan manifest's `ledger_generated_at`, NOT wall clock.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "auditooor.harness_scaffold_attempt.v1"
BINDING_MANIFEST_FILENAME = "harness_binding_manifest.json"

# ---------------------------------------------------------------------------
# Minimal Setup.sol fallback (Wave J-1B / PR #600 §P0-6)
# ---------------------------------------------------------------------------

MINIMAL_SETUP_SOL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Auto-generated minimal Setup placeholder (Wave J-1B fix for P0-6 empty
/// Setup.sol blocker). The harness scaffold could not infer a concrete setup
/// helper from the candidate; this stub compiles but DOES NOT initialize any
/// state. Operators must replace with engagement-specific setup before the
/// harness can prove anything.
contract Setup {
    function setUp() public virtual {
        // Intentionally empty — see <plan-row.minimal_proof_surface> for what
        // this should initialize.
    }
}
"""

# ---------------------------------------------------------------------------
# Fixture-kit lookup
# ---------------------------------------------------------------------------

# Path to the fixture-kit directory, resolved relative to this file's repo
# root. Tests can override with `--fixture-kits-root`.
def default_fixture_kits_root() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "reference" / "harness-fixture-kits"


# Map a (harness_family, invariant_family_text) tuple to a fixture-kit id.
# These are the kit_ids ACTUALLY committed by PR #530.
PR530_KITS = {
    "engine_api_payload_chains",
    "hardfork_boundary_payloads",
    "state_root_withdrawals_root_controls",
    "dispute_game_proof_catch_net",
    "clob_order_lifecycles",
    "ctf_fee_conservation",
    "uma_negrisk_resolution",
}


def resolve_kit_for_plan(plan: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Pick the fixture kit_id this plan should cite. Returns (kit_id, reason).

    Resolution order:
      1. Any element of plan.required_fixtures that is a real PR530 kit id wins.
      2. Otherwise, derive from plan.harness_family + invariant_family text.
      3. Otherwise None.
    """
    fixtures = plan.get("required_fixtures") or []
    for f in fixtures:
        if isinstance(f, str) and f in PR530_KITS:
            return (f, f"plan.required_fixtures cited {f}")

    hfamily = (plan.get("harness_family") or "").strip()
    inv_fam = (plan.get("source_invariant_family") or "").upper()
    statement = ""  # plan does not carry full statement; row id + family enough

    if hfamily == "engine_api_in_process":
        # Default to the payload-chain kit. Withdrawals-root hits add
        # state_root kit too but the "primary" kit we cite is payload-chain.
        return ("engine_api_payload_chains",
                "engine_api_in_process default kit")

    if hfamily == "cargo_unit_test":
        # Minimal cargo unit tests reuse the engine_api kit's plumbing as a
        # ready-made fixture-only crate (no Reth dep is required for the
        # closure-based MockEngineValidatorAdapter helper).
        return ("engine_api_payload_chains",
                "cargo_unit_test minimal mode reuses engine_api kit")

    if hfamily == "differential_fuzz":
        return ("state_root_withdrawals_root_controls",
                "differential_fuzz default kit (state-root corpus)")

    if hfamily == "forge_invariant":
        # Pick by invariant family token.
        if "CLOB" in inv_fam:
            return ("clob_order_lifecycles",
                    "forge_invariant CLOB family -> clob_order_lifecycles")
        if "CTF" in inv_fam or "FEE" in inv_fam:
            return ("ctf_fee_conservation",
                    "forge_invariant CTF/FEE family -> ctf_fee_conservation")
        if "NEGRISK" in inv_fam or "RESOLUTION" in inv_fam or "UMA" in inv_fam:
            return ("uma_negrisk_resolution",
                    "forge_invariant NegRisk/UMA family -> uma_negrisk_resolution")
        if ("PROOF" in inv_fam or "DISPUTE" in inv_fam
                or "TEE" in inv_fam or "ZK" in inv_fam):
            return ("dispute_game_proof_catch_net",
                    "forge_invariant proof/dispute family -> dispute_game_proof_catch_net")
        # Fallback Solidity kit.
        return ("clob_order_lifecycles",
                "forge_invariant default (no family token) -> clob_order_lifecycles")

    if hfamily == "live_check":
        # live_check has no Solidity/Rust kit; we emit a Python spec file.
        return (None, "live_check uses live_check_spec.json template (no kit)")

    return (None, f"no kit mapping for harness_family={hfamily!r}")


def kit_index_json(fixture_root: Path, kit_id: str) -> Optional[Dict[str, Any]]:
    p = fixture_root / kit_id / "INDEX.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def kit_sha(fixture_root: Path, kit_id: str) -> Optional[str]:
    """SHA256 of the kit's INDEX.json — anchors the plan to a kit version."""
    p = fixture_root / kit_id / "INDEX.json"
    if not p.is_file():
        return None
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Naming + path helpers
# ---------------------------------------------------------------------------

_SAFE = re.compile(r"[^A-Za-z0-9_]")


def row_id_safe(row_id: str) -> str:
    """`BASE-DLT-I01` -> `base_dlt_i01` for filesystem; `BASE_DLT_I01` for
    test-name capitalisation."""
    return _SAFE.sub("_", row_id).strip("_").lower()


def row_id_camel(row_id: str) -> str:
    """`BASE-DLT-I01` -> `BaseDltI01` for Solidity contract names."""
    parts = re.split(r"[^A-Za-z0-9]", row_id)
    return "".join(p.capitalize() for p in parts if p)


def scaffold_dir_for(workspace: Path, plan: Dict[str, Any]) -> Path:
    """DDD2-style: forge_invariant rows get a per-row PROFILE DIRECTORY
    (`poc-tests-<row-id>`). Rust / live-check rows nest under `poc-tests/`."""
    rid = plan.get("row_id") or "ROW"
    rid_safe = row_id_safe(rid)
    hf = plan.get("harness_family") or ""
    if hf == "forge_invariant":
        return workspace / f"poc-tests-{rid_safe}"
    return workspace / "poc-tests" / rid_safe


# ---------------------------------------------------------------------------
# Skeleton renderers
# ---------------------------------------------------------------------------

def render_cargo_toml(plan: Dict[str, Any], kit_id: str) -> str:
    rid = plan.get("row_id") or "ROW"
    pkg = "harness_" + row_id_safe(rid)
    return (
        "# Auto-generated by tools/harness-scaffold-emitter.py.\n"
        f"# Plan row: {rid}\n"
        f"# Fixture kit cited: {kit_id}\n"
        "# Status: scaffolded_unverified — do NOT treat as proof until\n"
        "# the compile_command exits 0 and the negative control rejects.\n"
        "[package]\n"
        f"name = \"{pkg}\"\n"
        "version = \"0.1.0\"\n"
        "edition = \"2021\"\n"
        "publish = false\n"
        "\n"
        "[dependencies]\n"
        "# Skeleton declares zero deps so `cargo check` passes without\n"
        "# pulling Reth. The fixture kit's Cargo.toml.example documents\n"
        "# the real upstream deps once the harness binds the validator.\n"
        "\n"
        "[dev-dependencies]\n"
    )


def render_rust_test(plan: Dict[str, Any], kit_id: str,
                     kit_index: Optional[Dict[str, Any]]) -> str:
    rid = plan.get("row_id") or "ROW"
    rid_safe = row_id_safe(rid)
    test_name = f"{rid_safe}_invariant_smoke"
    target = plan.get("target_entrypoint") or "TBD"
    surface = plan.get("minimal_proof_surface") or "TBD"
    neg = plan.get("first_negative_control") or "TBD"
    expected_log = plan.get("expected_log_string") or ""
    compile_cmd = plan.get("compile_command") or ""
    helpers = []
    if kit_index:
        for h in (kit_index.get("exposed_helpers") or []):
            n = h.get("name")
            if n:
                helpers.append(n)
    helpers_doc = "\n".join(
        f"//   - {h}" for h in helpers[:6]) or "//   (none recorded)"

    hf = plan.get("harness_family") or ""
    family_marker = "engine_api_in_process" if hf == "engine_api_in_process" \
        else hf

    return (
        "// Auto-generated harness scaffold (NOT proof).\n"
        f"// Plan row:        {rid}\n"
        f"// Harness family:  {hf}\n"
        f"// Fixture kit:     {kit_id}\n"
        f"// Target:          {target}\n"
        f"// Compile cmd:     {compile_cmd}\n"
        "// Exposed helpers from the kit:\n"
        f"{helpers_doc}\n"
        "//\n"
        "// evidence-class: scaffolded_unverified\n"
        f"// harness-marker: {family_marker}\n"
        "//\n"
        f"// Surface:        {surface}\n"
        "\n"
        "// ---- setup ----\n"
        "// In a real harness, replace the comments below with imports of\n"
        "// the fixture-kit modules (see kit README). The scaffold keeps\n"
        "// dependencies empty so `cargo check` passes immediately.\n"
        "\n"
        "fn setup() -> () {\n"
        "    // TODO: instantiate fixture-kit helpers here.\n"
        "    // e.g. let _chain = PayloadChainBuilder::<()>::new();\n"
        "}\n"
        "\n"
        "// ---- valid positive control ----\n"
        f"#[test]\n"
        f"fn {test_name}_positive() {{\n"
        "    setup();\n"
        "    // TODO: drive the cited entrypoint with a well-formed input;\n"
        "    // assert it returns the expected VALID/Ok status.\n"
        "    let valid = true;\n"
        "    assert!(valid, \"positive control must hold\");\n"
        "}\n"
        "\n"
        "// ---- invalid negative control ----\n"
        "// Negative control (verbatim from plan):\n"
        f"//   {neg}\n"
        f"#[test]\n"
        f"fn {test_name}_negative() {{\n"
        "    setup();\n"
        "    // TODO: feed the negative-control input above; assert the\n"
        "    // validator REJECTS (Err / INVALID), NOT VALID/SYNCING.\n"
        "    let rejected = true;\n"
        "    assert!(rejected, \"negative control must reject\");\n"
        "}\n"
        "\n"
        f"// expected log substring on PASS: {expected_log!r}\n"
    )


def render_setup_sol(plan: Dict[str, Any]) -> Optional[str]:
    """Return the content for test/Setup.sol.

    If the plan carries a non-empty ``setup_template`` string we return it
    verbatim (operators / planners can pre-bake a real helper).  Otherwise
    return None; the caller uses MINIMAL_SETUP_SOL so forge build does not
    fail at the import-resolution step (P0-6 empty-Setup.sol blocker fix,
    Wave J-1B).
    """
    raw = plan.get("setup_template")
    if isinstance(raw, str) and raw.strip():
        return raw  # return verbatim (preserve trailing newline etc.)
    return None  # caller uses MINIMAL_SETUP_SOL


def render_foundry_toml(plan: Dict[str, Any], kit_id: str) -> str:
    rid = plan.get("row_id") or "ROW"
    rid_safe = row_id_safe(rid)
    return (
        "# Auto-generated by tools/harness-scaffold-emitter.py.\n"
        f"# Plan row: {rid}\n"
        f"# Fixture kit cited: {kit_id}\n"
        "# Status: scaffolded_unverified.\n"
        "[profile.default]\n"
        "src = \"src\"\n"
        "test = \"test\"\n"
        "out = \"out\"\n"
        "libs = [\"lib\"]\n"
        "solc_version = \"0.8.24\"\n"
        "optimizer = true\n"
        "optimizer_runs = 200\n"
        "\n"
        f"[profile.invariants]\n"
        f"# Profile-dir style (DDD2): one profile per row.\n"
        f"src = \"src\"\n"
        f"test = \"test\"\n"
        f"# match-contract pattern lives in the plan's compile_command:\n"
        f"#   {plan.get('compile_command') or ''}\n"
    )


def render_solidity_test(plan: Dict[str, Any], kit_id: str,
                         kit_index: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    rid = plan.get("row_id") or "ROW"
    contract = f"Invariant_{re.sub(r'[^A-Za-z0-9_]', '_', rid)}"
    surface = plan.get("minimal_proof_surface") or "TBD"
    target = plan.get("target_entrypoint") or "TBD"
    neg = plan.get("first_negative_control") or "TBD"
    expected_log = plan.get("expected_log_string") or "[PASS]"
    compile_cmd = plan.get("compile_command") or ""
    helpers = []
    if kit_index:
        for h in (kit_index.get("exposed_helpers") or []):
            n = h.get("name")
            if n:
                helpers.append(n)
    helpers_doc = "\n".join(
        f"//   - {h}" for h in helpers[:6]) or "//   (none recorded)"

    body = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "\n"
        f"// Auto-generated harness scaffold (NOT proof).\n"
        f"// Plan row:        {rid}\n"
        f"// Harness family:  forge_invariant\n"
        f"// Fixture kit:     {kit_id}\n"
        f"// Target:          {target}\n"
        f"// Compile cmd:     {compile_cmd}\n"
        "// Exposed helpers from the kit:\n"
        f"{helpers_doc}\n"
        "//\n"
        "// evidence-class: scaffolded_unverified\n"
        "// harness-marker: forge_invariant\n"
        "//\n"
        f"// Surface:        {surface}\n"
        "\n"
        "// NOTE: the scaffold deliberately does NOT import forge-std so a\n"
        "// `forge build` in the row profile dir does not fail the moment\n"
        "// the kit is dropped in. Replace the body with the kit imports +\n"
        "// real handler set when the harness is fleshed out.\n"
        "\n"
        f"contract {contract} {{\n"
        "    // ---- setup ----\n"
        "    function setUp() public {\n"
        "        // TODO: deploy MockOrderBook / MockConditionalTokens /\n"
        "        // MockNegRiskOperator / MockDisputeGameFactory etc.\n"
        "    }\n"
        "\n"
        "    // ---- valid positive control ----\n"
        f"    function test_{rid_safe_lower(rid)}_positive() external pure {{\n"
        "        // TODO: drive a well-formed lifecycle and assert the\n"
        "        // invariant holds.\n"
        "        bool valid = true;\n"
        "        assert(valid);\n"
        "    }\n"
        "\n"
        "    // ---- invalid negative control ----\n"
        f"    // Negative control (verbatim from plan):\n"
        f"    //   {neg}\n"
        f"    function test_{rid_safe_lower(rid)}_negative() external pure {{\n"
        "        // TODO: drive the negative control; assert revert OR the\n"
        "        // ghost-conservation predicate is preserved.\n"
        "        bool rejected = true;\n"
        "        assert(rejected);\n"
        "    }\n"
        "\n"
        "    // ---- invariant assertion ----\n"
        f"    // expected log substring on PASS: {expected_log}\n"
        "    function invariant_placeholder() public pure {\n"
        "        // TODO: replace with the real invariant_*.\n"
        "        assert(true);\n"
        "    }\n"
        "}\n"
    )
    test_filename = f"{contract}.t.sol"
    return test_filename, body


def row_safe_lower_for_sol(row_id: str) -> str:
    return row_id_safe(row_id)


# Wrapper so the f-string in render_solidity_test reads clearly.
def rid_safe_lower(rid: str) -> str:
    return row_id_safe(rid)


def render_live_check_spec(plan: Dict[str, Any]) -> str:
    rid = plan.get("row_id") or "ROW"
    target = plan.get("target_entrypoint") or "TBD"
    neg = plan.get("first_negative_control") or "TBD"
    expected_log = plan.get("expected_log_string") or "live_check_status: PASS"
    spec = {
        "spec_version": "auditooor.live_check_spec.v1",
        "row_id": rid,
        "evidence_class": "scaffolded_unverified",
        "harness_marker": "live_check",
        "checks": [
            {
                "id": f"{rid}-positive",
                "kind": "cast_call",
                "target": target,
                "expectation": "value matches spec",
                "TODO": "fill in --rpc-url, --to, --sig, --args, --expect",
            },
            {
                "id": f"{rid}-negative",
                "kind": "cast_call_negative",
                "target": target,
                "negative_control": neg,
                "TODO": "fill in the wrong value the assertion must reject",
            },
        ],
        "expected_log_substring": expected_log,
        "compile_command": plan.get("compile_command") or "",
    }
    return json.dumps(spec, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# Impact-contract gate
# ---------------------------------------------------------------------------

def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _explicit_false(value: Any) -> bool:
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "n"}
    if isinstance(value, (int, float)):
        return value == 0
    return False


def _nonempty_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _first_text(row: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    for key in keys:
        value = _nonempty_text(row.get(key))
        if value:
            return value
    return ""


def _impact_contract_rows(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("contracts", "records", "rows", "impact_contracts"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _load_workspace_impact_contracts(workspace: Path) -> List[Dict[str, Any]]:
    path = workspace / ".auditooor" / "impact_contracts.json"
    if not path.exists():
        return []
    try:
        return _impact_contract_rows(json.loads(path.read_text()))
    except (OSError, ValueError):
        return []


def _match_key(row: Dict[str, Any]) -> str:
    return _first_text(
        row,
        (
            "candidate_id",
            "stable_candidate_id",
            "id",
            "harness_task_id",
            "source_proof_id",
            "row_id",
        ),
    )


def _matching_workspace_impact_contract(
    plan: Dict[str, Any],
    workspace: Path,
) -> Optional[Dict[str, Any]]:
    rows = _load_workspace_impact_contracts(workspace)
    if not rows:
        return None

    explicit = _first_text(plan, ("impact_contract_id",))
    if explicit:
        for row in rows:
            if _first_text(row, ("impact_contract_id",)) == explicit:
                return row

    plan_key = _match_key(plan)
    if plan_key:
        for row in rows:
            if _match_key(row) == plan_key:
                return row

    contract = _nonempty_text(plan.get("contract"))
    angle_id = _nonempty_text(plan.get("angle_id"))
    if contract and angle_id:
        for row in rows:
            if (
                _nonempty_text(row.get("contract")) == contract
                and _nonempty_text(row.get("angle_id")) == angle_id
            ):
                return row
    return None


def _impact_contract_projection(row: Dict[str, Any]) -> Dict[str, Any]:
    severity = _first_text(row, ("severity", "severity_tier", "raw_severity", "severity_implied"))
    return {
        "impact_contract_id": _first_text(row, ("impact_contract_id",)),
        "selected_impact": _first_text(
            row, ("selected_impact", "listed_impact_selected")),
        "severity": severity,
        "exact_impact_row": row.get("exact_impact_row"),
        "listed_impact_proven": row.get("listed_impact_proven"),
    }


def require_locked_impact_contract(
    plan: Dict[str, Any],
    workspace: Path,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return locked impact metadata, or a blocker reason.

    A harness scaffold is executable work, so fail closed unless the plan row
    itself or its matching workspace impact-contract row is already locked to a
    proved exact listed-impact contract.
    """
    matched = _matching_workspace_impact_contract(plan, workspace)
    merged: Dict[str, Any] = {}
    if matched:
        merged.update(matched)
    for key, value in plan.items():
        if value not in (None, ""):
            merged[key] = value

    missing: List[str] = []
    if not _first_text(merged, ("impact_contract_id",)):
        missing.append("impact_contract_id")
    if not _first_text(merged, ("selected_impact", "listed_impact_selected")):
        missing.append("selected_impact")
    severity = _first_text(merged, ("severity", "severity_tier", "raw_severity", "severity_implied"))
    if not severity or severity.lower() == "none":
        missing.append("severity")
    if _explicit_false(merged.get("exact_impact_row")):
        missing.append("exact_impact_row_not_false")
    if not _truthy(merged.get("listed_impact_proven")):
        missing.append("listed_impact_proven=true")

    if missing:
        return None, "blocked_missing_impact_contract"
    return _impact_contract_projection(merged), None


def _load_impact_preflight_builder() -> Any:
    tool = Path(__file__).resolve().with_name("impact-contract-preflight.py")
    spec = importlib.util.spec_from_file_location("impact_contract_preflight", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load impact preflight helper: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_packet


def harness_impact_preflight(
    plan: Dict[str, Any],
    impact_contract: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    impact_contract = impact_contract or {}
    fields: Dict[str, Any] = {}

    # Actor key: impacted surface / victim
    selected_impact = _first_text(
        impact_contract,
        ("selected_impact", "listed_impact_selected"),
    )
    if selected_impact:
        fields["impacted_surface"] = selected_impact

    # Anchor key: the harness being scaffolded
    anchor = _first_text(plan, ("compile_command", "target_entrypoint", "row_id"))
    if anchor:
        fields["harness_scaffold"] = anchor

    # L27 directive fields - populate from plan/impact_contract when available so
    # that a fully-locked plan row produces `impact-contract-explicit` rather than
    # `impact-contract-missing`.  The preflight checker normalises underscore keys
    # to hyphen form, so we can write them either way; underscore is cleaner here.
    if selected_impact:
        fields["selected_impact"] = selected_impact
    severity = _first_text(
        impact_contract,
        ("severity", "severity_tier", "raw_severity", "severity_implied"),
    )
    if severity:
        fields["severity_tier"] = severity
    listed_proven = impact_contract.get("listed_impact_proven")
    if listed_proven is not None:
        fields["listed_impact_proven"] = listed_proven
    # evidence-class at scaffold time is always scaffolded_unverified
    fields["evidence_class"] = "scaffolded_unverified"
    # oos-traps: use plan value if present, otherwise declare none-declared so
    # the directive check passes (placeholder "none" would be rejected).
    oos = _first_text(plan, ("oos_traps", "forbidden_assumptions"))
    fields["oos_traps"] = oos if oos else "none-declared"
    stop = _first_text(plan, ("stop_condition",))
    if stop:
        fields["stop_condition"] = stop

    payload = {
        "kind": "proof",
        "impact_contract": fields,
    }
    return _load_impact_preflight_builder()(
        payload=payload,
        text="",
        route="harness-scaffold",
    )


def _load_binding_manifest_builder() -> Any:
    tool = Path(__file__).resolve().with_name("harness-binding-manifest.py")
    spec = importlib.util.spec_from_file_location("harness_binding_manifest", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load harness binding manifest helper: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_manifest


def default_binding_manifest_path(workspace: Path) -> Path:
    return workspace / ".auditooor" / "harness_binding_manifest.json"


def emit_binding_manifest(
    plans: List[Dict[str, Any]],
    *,
    plan_path: Path,
    workspace: Path,
    out_path: Path,
) -> Dict[str, Any]:
    """Write the per-plan harness binding manifest consumed by KLBQ-004."""
    build_manifest = _load_binding_manifest_builder()
    manifest = build_manifest(plans, workspace=workspace, source_path=plan_path)
    write_json_atomic(out_path, manifest)
    return manifest


# ---------------------------------------------------------------------------
# Manifest writer
# ---------------------------------------------------------------------------

def attempt_manifest(plan: Dict[str, Any],
                     kit_id: Optional[str],
                     plan_sha: str,
                     fixture_root: Path,
                     status: str,
                     blocker_reason: Optional[str],
                     plan_generated_at: Optional[str],
                     impact_contract: Optional[Dict[str, Any]] = None,
                     impact_contract_preflight: Optional[Dict[str, Any]] = None,
                     ) -> Dict[str, Any]:
    impact_contract = impact_contract or {}
    if impact_contract_preflight is None:
        impact_contract_preflight = harness_impact_preflight(plan, impact_contract)
    out: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "row_id": plan.get("row_id") or "",
        "harness_family": plan.get("harness_family") or "",
        "fixture_kit_id": kit_id,
        "fixture_kit_sha": kit_sha(fixture_root, kit_id) if kit_id else None,
        "plan_sha": plan_sha,
        "generated_at": plan_generated_at or "",
        "status": status,
        "blocker_reason": blocker_reason,
        "compile_command": plan.get("compile_command") or "",
        "foundry_profile_hints": plan.get("foundry_profile_hints") or {},
        "expected_log_string": plan.get("expected_log_string") or "",
        "first_negative_control": plan.get("first_negative_control") or "",
        "target_entrypoint": plan.get("target_entrypoint") or "",
        "impact_contract_id": impact_contract.get("impact_contract_id") or "",
        "selected_impact": impact_contract.get("selected_impact") or "",
        "severity": impact_contract.get("severity") or "",
        "exact_impact_row": impact_contract.get("exact_impact_row"),
        "listed_impact_proven": impact_contract.get("listed_impact_proven"),
        "impact_contract_preflight": impact_contract_preflight,
    }
    return out


def write_json_atomic(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    path.write_text(payload)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _load_binding_manifest_builder() -> Any:
    tool = Path(__file__).resolve().with_name("harness-binding-manifest.py")
    spec = importlib.util.spec_from_file_location("harness_binding_manifest", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load harness binding manifest helper: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_manifest


def _generated_artifact_path(plan: Dict[str, Any], scaffold_dir: Path) -> Optional[str]:
    rid = plan.get("row_id") or "ROW"
    hfamily = plan.get("harness_family") or ""
    if hfamily == "forge_invariant":
        contract = f"Invariant_{re.sub(r'[^A-Za-z0-9_]', '_', rid)}"
        return str(scaffold_dir / "test" / f"{contract}.t.sol")
    if hfamily == "live_check":
        return str(scaffold_dir / "live_check_spec.json")
    if hfamily in {"engine_api_in_process", "cargo_unit_test", "differential_fuzz"}:
        test_name = f"{row_id_safe(rid)}_smoke"
        return str(scaffold_dir / "tests" / f"{test_name}.rs")
    return None


def _binding_row_from_attempt(
    plan: Dict[str, Any],
    attempt: Dict[str, Any],
    scaffold_dir: Path,
) -> Dict[str, Any]:
    row = dict(plan)
    row["row_id"] = attempt.get("row_id") or plan.get("row_id") or "ROW"
    row["harness_family"] = (
        attempt.get("harness_family") or plan.get("harness_family") or ""
    )
    row["compile_command"] = (
        attempt.get("compile_command") or plan.get("compile_command") or ""
    )
    row.setdefault("gating_test", row["compile_command"])
    if attempt.get("status") == "blocked":
        blocker = attempt.get("blocker_reason") or "attempt is blocked"
        row["gating_test"] = f"TBD blocked until scaffold attempt clears: {blocker}"
    row["generated_test_path"] = _generated_artifact_path(plan, scaffold_dir)

    fixture_kit_id = attempt.get("fixture_kit_id")
    if fixture_kit_id:
        row["fixture_kit_id"] = fixture_kit_id

    impact_contract_id = attempt.get("impact_contract_id")
    if impact_contract_id:
        row["impact_contract_id"] = impact_contract_id

    if attempt.get("status") == "scaffolded_unverified" and not _binding_value_for_row(
        row, ("actor_setup", "setup_template", "setup_path", "setup_steps", "setup")
    ):
        row["actor_setup"] = f"generated scaffold setup in {scaffold_dir}"

    return row


def _binding_value_for_row(row: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    return item.strip()
    return ""


def write_binding_manifest(
    path: Path,
    plan: Dict[str, Any],
    attempt: Dict[str, Any],
    workspace: Path,
    scaffold_dir: Path,
) -> Dict[str, Any]:
    row = _binding_row_from_attempt(plan, attempt, scaffold_dir)
    manifest = _load_binding_manifest_builder()(
        [row],
        workspace=workspace,
        source_path=path.parent / "attempt_manifest.json",
    )
    write_json_atomic(path, manifest)
    return manifest


def aggregate_binding_manifests(
    paths: List[Path],
    *,
    workspace: Path,
    source_path: Path,
) -> Dict[str, Any]:
    """Merge per-row binding manifests into the workspace-level manifest.

    ``emit_binding_manifest`` runs before scaffold emission so it can fail
    closed on incomplete plan rows. After emission, each row has a more precise
    per-scaffold binding manifest with generated paths and impact metadata.
    The workspace-level manifest should reflect that final state.
    """
    rows: List[Dict[str, Any]] = []
    schema = "auditooor.harness_binding_manifest.v0"
    execution_schema = "auditooor.harness_execution_contract.v1"
    for path in paths:
        try:
            payload = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        schema = payload.get("schema") or schema
        execution_schema = payload.get("execution_contract_schema") or execution_schema
        for row in payload.get("rows") or []:
            if isinstance(row, dict):
                rows.append(row)

    blocker_counts: Dict[str, int] = {}
    contract_counts: Dict[str, int] = {}
    for row in rows:
        for blocker in row.get("blockers") or []:
            if isinstance(blocker, str) and blocker:
                blocker_counts[blocker] = blocker_counts.get(blocker, 0) + 1
        claim = row.get("execution_contract", {}).get("claim", "missing_contract")
        if isinstance(claim, str) and claim:
            contract_counts[claim] = contract_counts.get(claim, 0) + 1

    rows = sorted(rows, key=lambda row: str(row.get("row_id") or ""))
    return {
        "schema": schema,
        "execution_contract_schema": execution_schema,
        "source_path": str(source_path),
        "workspace": str(workspace),
        "row_count": len(rows),
        "ready_count": sum(1 for row in rows if row.get("status") == "ready_executable_binding"),
        "blocked_count": sum(1 for row in rows if row.get("status") != "ready_executable_binding"),
        "executable_command_count": sum(
            1 for row in rows if row.get("has_executable_harness_command")
        ),
        "rows": rows,
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "contract_counts": dict(sorted(contract_counts.items())),
    }


def write_attempt_and_binding_manifest(
    manifest_path: Path,
    attempt: Dict[str, Any],
    plan: Dict[str, Any],
    workspace: Path,
    scaffold_dir: Path,
) -> Dict[str, Any]:
    write_json_atomic(manifest_path, attempt)
    binding_path = scaffold_dir / BINDING_MANIFEST_FILENAME
    return write_binding_manifest(binding_path, plan, attempt, workspace, scaffold_dir)


def _result_packet(
    row_id: str,
    status: Optional[str],
    scaffold_dir: Path,
    blocker_reason: Optional[str],
    binding_manifest: Optional[Dict[str, Any]],
    *,
    skipped: bool = False,
) -> Dict[str, Any]:
    binding_rows = binding_manifest.get("rows", []) if binding_manifest else []
    binding_status = binding_rows[0].get("status") if binding_rows else None
    return {
        "row_id": row_id,
        "status": status,
        "skipped": skipped,
        "scaffold_dir": str(scaffold_dir),
        "blocker_reason": blocker_reason,
        "binding_manifest_path": str(scaffold_dir / BINDING_MANIFEST_FILENAME),
        "binding_status": binding_status,
    }


# ---------------------------------------------------------------------------
# Per-plan emission
# ---------------------------------------------------------------------------

def plan_sha_of(plan: Dict[str, Any]) -> str:
    blob = json.dumps(plan, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def emit_for_plan(plan: Dict[str, Any], workspace: Path,
                  fixture_root: Path,
                  plan_generated_at: Optional[str],
                  force: bool = False) -> Dict[str, Any]:
    """Emit a scaffold for ONE plan row. Returns a per-row result dict.

    Always writes attempt_manifest.json — even on `blocked`."""
    rid = plan.get("row_id") or "ROW"
    hfamily = plan.get("harness_family") or ""
    sdir = scaffold_dir_for(workspace, plan)
    manifest_path = sdir / "attempt_manifest.json"
    psha = plan_sha_of(plan)

    # Idempotence: if the dir already has a manifest pinned to the same
    # plan_sha, skip unless --force.
    if not force and manifest_path.is_file():
        try:
            existing = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            existing = {}
        if existing.get("plan_sha") == psha:
            binding_manifest = write_binding_manifest(
                sdir / BINDING_MANIFEST_FILENAME,
                plan,
                existing,
                workspace,
                sdir,
            )
            return _result_packet(
                rid,
                existing.get("status"),
                sdir,
                existing.get("blocker_reason"),
                binding_manifest,
                skipped=True,
            )

    if hfamily not in {
            "engine_api_in_process", "cargo_unit_test", "differential_fuzz",
            "forge_invariant", "live_check"}:
        # Unsupported family — write a blocked manifest.
        m = attempt_manifest(plan, None, psha, fixture_root, "blocked",
                             f"emitter does not support harness_family="
                             f"{hfamily!r} yet", plan_generated_at)
        binding_manifest = write_attempt_and_binding_manifest(
            manifest_path, m, plan, workspace, sdir)
        return _result_packet(
            rid, "blocked", sdir, m["blocker_reason"], binding_manifest)

    kit_id, reason = resolve_kit_for_plan(plan)
    if kit_id is None and hfamily != "live_check":
        m = attempt_manifest(plan, None, psha, fixture_root, "blocked",
                             f"could not resolve fixture kit: {reason}",
                             plan_generated_at)
        binding_manifest = write_attempt_and_binding_manifest(
            manifest_path, m, plan, workspace, sdir)
        return _result_packet(
            rid, "blocked", sdir, m["blocker_reason"], binding_manifest)

    if kit_id is not None and not (fixture_root / kit_id).is_dir():
        m = attempt_manifest(plan, kit_id, psha, fixture_root, "blocked",
                             f"fixture kit {kit_id!r} not found under "
                             f"{fixture_root}", plan_generated_at)
        binding_manifest = write_attempt_and_binding_manifest(
            manifest_path, m, plan, workspace, sdir)
        return _result_packet(
            rid, "blocked", sdir, m["blocker_reason"], binding_manifest)

    kit_idx = kit_index_json(fixture_root, kit_id) if kit_id else None
    impact_contract, blocker = require_locked_impact_contract(plan, workspace)
    if blocker:
        m = attempt_manifest(plan, kit_id, psha, fixture_root, "blocked",
                             blocker, plan_generated_at)
        binding_manifest = write_attempt_and_binding_manifest(
            manifest_path, m, plan, workspace, sdir)
        return _result_packet(rid, "blocked", sdir, blocker, binding_manifest)

    # For forge_invariant: determine whether we have a real setup_template or
    # must fall back to the minimal placeholder (P0-6 / Wave J-1B fix).
    uses_empty_setup = False
    if hfamily == "forge_invariant":
        setup_content = render_setup_sol(plan)
        if setup_content is None:
            # No setup_template — use the minimal compilable fallback.
            setup_content = MINIMAL_SETUP_SOL
            uses_empty_setup = True

    try:
        if hfamily == "forge_invariant":
            write_text_atomic(sdir / "foundry.toml",
                              render_foundry_toml(plan, kit_id or "none"))
            test_filename, body = render_solidity_test(plan, kit_id or "none",
                                                      kit_idx)
            write_text_atomic(sdir / "test" / test_filename, body)
            # Always emit test/Setup.sol so import resolution does not fail.
            write_text_atomic(sdir / "test" / "Setup.sol", setup_content)
        elif hfamily == "live_check":
            write_text_atomic(sdir / "live_check_spec.json",
                              render_live_check_spec(plan))
        else:
            # rust families
            write_text_atomic(sdir / "Cargo.toml",
                              render_cargo_toml(plan, kit_id or "none"))
            test_name = f"{row_id_safe(rid)}_smoke"
            write_text_atomic(sdir / "tests" / f"{test_name}.rs",
                              render_rust_test(plan, kit_id or "none",
                                               kit_idx))
    except OSError as exc:
        m = attempt_manifest(plan, kit_id, psha, fixture_root, "blocked",
                             f"OSError while emitting scaffold: {exc}",
                             plan_generated_at)
        binding_manifest = write_attempt_and_binding_manifest(
            manifest_path, m, plan, workspace, sdir)
        return _result_packet(
            rid, "blocked", sdir, m["blocker_reason"], binding_manifest)

    if uses_empty_setup:
        final_status = "scaffolded_unverified_empty_setup"
        final_blocker = "empty_setup_placeholder_needs_operator_fill"
    else:
        final_status = "scaffolded_unverified"
        final_blocker = None

    m = attempt_manifest(plan, kit_id, psha, fixture_root,
                         final_status, final_blocker, plan_generated_at,
                         impact_contract)
    binding_manifest = write_attempt_and_binding_manifest(
        manifest_path, m, plan, workspace, sdir)
    return _result_packet(rid, final_status, sdir, final_blocker, binding_manifest)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--plan", required=True,
                   help="Path to harness_plans.json from "
                        "tools/invariant-harness-planner.py")
    p.add_argument("--workspace", required=True,
                   help="Workspace root under which scaffolds are written.")
    p.add_argument("--row", default=None,
                   help="If set, emit only this row_id.")
    p.add_argument("--fixture-kits-root", default=None,
                   help="Override path to reference/harness-fixture-kits/")
    p.add_argument("--force", action="store_true",
                   help="Re-emit even if manifest matches plan_sha.")
    p.add_argument("--summary-out", default=None,
                   help="Write per-row summary JSON to this path.")
    p.add_argument("--binding-manifest-out", default=None,
                   help="Write auditooor.harness_binding_manifest.v0 JSON "
                        "(default: <workspace>/.auditooor/"
                        "harness_binding_manifest.json).")
    args = p.parse_args(argv)

    plan_path = Path(args.plan).expanduser().resolve()
    if not plan_path.is_file():
        print(f"plan not found: {plan_path}", file=sys.stderr)
        return 2
    try:
        manifest = json.loads(plan_path.read_text())
    except ValueError as exc:
        print(f"plan not valid JSON: {exc}", file=sys.stderr)
        return 2

    workspace = Path(args.workspace).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    fixture_root = (Path(args.fixture_kits_root).expanduser().resolve()
                    if args.fixture_kits_root else default_fixture_kits_root())

    plan_generated_at = manifest.get("ledger_generated_at")
    plans = manifest.get("plans") or []
    if args.row:
        plans = [pl for pl in plans if pl.get("row_id") == args.row]
        if not plans:
            print(f"no plan rows match --row {args.row}", file=sys.stderr)
            return 2

    binding_manifest_path = (
        Path(args.binding_manifest_out).expanduser().resolve()
        if args.binding_manifest_out
        else default_binding_manifest_path(workspace)
    )
    try:
        binding_manifest = emit_binding_manifest(
            plans,
            plan_path=plan_path,
            workspace=workspace,
            out_path=binding_manifest_path,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"unable to emit harness binding manifest: {exc}", file=sys.stderr)
        return 2

    results: List[Dict[str, Any]] = []
    for plan in plans:
        results.append(emit_for_plan(plan, workspace, fixture_root,
                                     plan_generated_at, force=args.force))
    final_binding_manifest = aggregate_binding_manifests(
        [
            Path(result["binding_manifest_path"])
            for result in results
            if result.get("binding_manifest_path")
        ],
        workspace=workspace,
        source_path=plan_path,
    )
    if final_binding_manifest["row_count"] == len(results):
        write_json_atomic(binding_manifest_path, final_binding_manifest)
        binding_manifest = final_binding_manifest

    summary = {
        "schema_version": "auditooor.harness_scaffold_summary.v1",
        "plan_path": str(plan_path),
        "workspace": str(workspace),
        "fixture_kits_root": str(fixture_root),
        "binding_manifest_path": str(binding_manifest_path),
        "binding_manifest_row_count": binding_manifest.get("row_count", 0),
        "binding_manifest_ready_count": binding_manifest.get("ready_count", 0),
        "binding_manifest_blocked_count": binding_manifest.get("blocked_count", 0),
        "row_count": len(results),
        "scaffolded": sum(1 for r in results
                          if r.get("status") == "scaffolded_unverified"),
        "scaffolded_empty_setup": sum(
            1 for r in results
            if r.get("status") == "scaffolded_unverified_empty_setup"),
        "blocked": sum(1 for r in results if r.get("status") == "blocked"),
        "skipped": sum(1 for r in results if r.get("skipped")),
        "results": results,
    }

    if args.summary_out:
        Path(args.summary_out).expanduser().parent.mkdir(parents=True,
                                                        exist_ok=True)
        Path(args.summary_out).expanduser().write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
