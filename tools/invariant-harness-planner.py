#!/usr/bin/env python3
"""
invariant-harness-planner.py — PR #526 gap 3: invariant-to-harness planner.

Purpose
=======
The invariant ledger names properties; the planner says HOW to prove them.
Without a plan, agents waste cycles building harnesses against the wrong
surface (FN7: broad RPC service before the direct EngineApiTreeHandler).
The planner reads the workspace ledger, picks a harness family by heuristic
from `invariant_family` / `statement` / `id`, and emits a per-row plan with:

  - harness_family        forge_invariant | cargo_unit_test |
                          engine_api_in_process | live_check |
                          differential_fuzz | halmos_symbolic |
                          medusa_property | needs_human
  - required_fixtures     fixture-kit IDs (cross-ref TT's gap-4 kits when
                          present, otherwise "TBD:<kit-name>")
  - target_entrypoint     file:line citation (extracted from production_path)
  - minimal_proof_surface 2-3 line description of the smallest test
  - compile_command       exact cargo/forge invocation
  - first_negative_control smallest invalid input the test must reject
  - expected_log_string   substring to grep in run output to confirm pass
  - stop_condition        when to mark `executed_clean`

Outputs
-------
    <workspace>/.auditooor/harness_plans.json   machine-readable manifest
    <workspace>/.auditooor/harness_plans.md     human-readable sidecar

CLI
===
    python3 tools/invariant-harness-planner.py --workspace <ws>
    python3 tools/invariant-harness-planner.py --workspace <ws> --row BASE-DLT-I01
    python3 tools/invariant-harness-planner.py --workspace <ws> --out /tmp/plans.json

Discipline
----------
- stdlib-only.
- Heuristic, not magic. If `invariant_family` / `id` / `statement` matches
  no rule, emit `harness_family: needs_human` with a precise explanation.
- Idempotent: re-running on an unchanged ledger produces a byte-identical
  manifest (sorted keys, deterministic timestamp source = ledger row count
  rather than wall clock when --deterministic is set; default uses ledger
  generated_at when present).
- The planner emits PLANS, not code. Cargo/forge invocation happens
  elsewhere (chimera-ledger-scaffold, recon-fuzzer-runner, etc.).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.foundry_version import PLANNED_TARGET_VERSION, RECOMMENDED_PROFILES  # noqa: E402

SCHEMA_VERSION = "auditooor.harness_plans.v1"

# ---------------------------------------------------------------------------
# Heuristic dispatch table
# ---------------------------------------------------------------------------
#
# Each rule is (predicate_fn, harness_family, reason_template). The first
# match wins. Ordering matters: more specific rules first, then family
# prefixes, then generic fallbacks.

HARNESS_FAMILIES: Tuple[str, ...] = (
    "forge_invariant",
    "cargo_unit_test",
    "engine_api_in_process",
    "live_check",
    "differential_fuzz",
    "halmos_symbolic",
    "medusa_property",
    "needs_human",
)

# Token sets that drive the heuristic. Lowercased compare.
ENGINE_API_TOKENS = (
    "engine api",
    "engine_api",
    "newpayload",
    "new_payload",
    "fcu",
    "forkchoice",
    "fork_choice",
    "block payload",
    "withdrawals-root",
    "withdrawals_root",
    "withdrawalsroot",
)

DIFFERENTIAL_TOKENS = (
    "parity",
    "divergence",
    "agreement",
    "differential",
)

LIVE_TOKENS = (
    "deployment",
    "role",
    "config",
    "rpc",
    "live",
)

SYMBOLIC_TOKENS = (
    "halmos",
    "symbolic",
    "smt",
)

MEDUSA_TOKENS = (
    "medusa",
    "property test",
    "stateful fuzz",
)


def _id_prefix(row: Dict[str, Any]) -> str:
    """First segment of the row id, uppercased. e.g. BASE-DLT-I01 -> BASE."""
    rid = (row.get("id") or "").upper()
    if "-" in rid:
        return rid.split("-", 1)[0]
    return rid


def _id_segments(row: Dict[str, Any]) -> List[str]:
    """All segments of the row id, uppercased."""
    rid = (row.get("id") or "").upper()
    return [seg for seg in rid.split("-") if seg]


def _haystack(row: Dict[str, Any]) -> str:
    """Lowercased concatenation of fields used for keyword heuristics."""
    parts = []
    for f in ("invariant_family", "statement", "harness_target",
              "production_path", "negative_test", "required_engine"):
        v = row.get(f)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            parts.extend(str(x) for x in v)
    return " \n ".join(parts).lower()


def _has_any(text: str, tokens: Tuple[str, ...]) -> bool:
    return any(t in text for t in tokens)


def choose_harness_family(row: Dict[str, Any]) -> Tuple[str, str]:
    """Return (harness_family, reason).

    Order:
      1. *-DLT-* with engine-api / block payload tokens -> engine_api_in_process
      2. *-DLT-* mentioning a single function w/o engine-api -> cargo_unit_test
      3. *-LIVE-* -> live_check
      4. *-SC-* with proof_domain / tee_zk / forge target -> forge_invariant
      5. *-CLOB* / *-CTF* / *-NEGRISK* / *-FEE* / *-PAUSE* / *-SIGNATURE* -> forge_invariant
      6. statement contains parity/divergence/agreement -> differential_fuzz
      7. statement contains halmos/symbolic/smt -> halmos_symbolic
      8. statement contains medusa/property test/stateful fuzz -> medusa_property
      9. otherwise -> needs_human
    """
    segs = _id_segments(row)
    fam = (row.get("invariant_family") or "").upper()
    text = _haystack(row)

    # 1. DLT + engine-api signals
    if "DLT" in segs:
        if _has_any(text, ENGINE_API_TOKENS) or "WITHDRAWALS-ROOT" in fam \
                or "ENGINE-API" in fam or "PAYLOAD" in fam:
            return ("engine_api_in_process",
                    "DLT row references Engine API / payload / "
                    "withdrawals-root: prove against the in-process "
                    "EngineApiTreeHandler, not the outer RPC service.")
        # parity-shaped DLT row -> differential. Check before generic cargo.
        if _has_any(text, DIFFERENTIAL_TOKENS):
            return ("differential_fuzz",
                    "DLT row mentions parity/divergence/agreement: "
                    "differential oracle vs in-tree implementation.")
        # default DLT -> cargo unit test against a single function
        return ("cargo_unit_test",
                "DLT row without engine-api / parity tokens: "
                "narrow cargo unit test against the cited function.")

    # 3. LIVE rows
    if "LIVE" in segs:
        return ("live_check",
                "LIVE-* row: assert deployment/role/config truth via "
                "live-check-runner, not a unit test.")

    # 4. SC rows
    if "SC" in segs:
        # SC rows almost always want a Foundry invariant as the primary
        # surface. If the row's required_engine ALSO names halmos/medusa,
        # forge wins because the invariant assertion goes there first; the
        # symbolic/property layer is a follow-on. We only escalate to
        # halmos_symbolic / medusa_property when forge is NOT mentioned.
        req = (row.get("required_engine") or "").lower()
        forge_mentioned = "forge" in req or "foundry" in req
        if _has_any(text, SYMBOLIC_TOKENS) and not forge_mentioned:
            return ("halmos_symbolic",
                    "SC row mentions halmos/symbolic/SMT (no forge): "
                    "prove with halmos against the cited contract "
                    "function.")
        if _has_any(text, MEDUSA_TOKENS) and not forge_mentioned:
            return ("medusa_property",
                    "SC row mentions medusa/property/stateful fuzz "
                    "(no forge): Medusa property test.")
        return ("forge_invariant",
                "SC row (smart-contract domain): Foundry invariant "
                "harness against the cited contract entrypoint.")

    # 5. Solidity protocol families. Polymarket-style.
    sc_family_keywords = ("CLOB", "CTF", "NEGRISK", "FEE", "PAUSE",
                          "SIGNATURE", "AMM", "VAULT", "LENDING", "BRIDGE")
    if any(k in segs for k in sc_family_keywords) \
            or any(k.lower() in fam.lower() for k in sc_family_keywords):
        # parity in a Solidity row -> differential
        if _has_any(text, DIFFERENTIAL_TOKENS):
            return ("differential_fuzz",
                    "Solidity row mentions parity/divergence/agreement: "
                    "differential oracle harness.")
        if _has_any(text, SYMBOLIC_TOKENS):
            return ("halmos_symbolic",
                    "Solidity row mentions halmos/symbolic: halmos "
                    "harness against the cited contract function.")
        if _has_any(text, MEDUSA_TOKENS):
            return ("medusa_property",
                    "Solidity row mentions medusa/property/stateful fuzz: "
                    "Medusa property test.")
        return ("forge_invariant",
                "Solidity protocol-family row: Foundry invariant harness.")

    # 6/7/8 — fallbacks if id doesn't carry a family token
    if _has_any(text, DIFFERENTIAL_TOKENS):
        return ("differential_fuzz",
                "Statement mentions parity/divergence/agreement.")
    if _has_any(text, SYMBOLIC_TOKENS):
        return ("halmos_symbolic", "Statement mentions halmos/symbolic/SMT.")
    if _has_any(text, MEDUSA_TOKENS):
        return ("medusa_property", "Statement mentions medusa/property fuzz.")
    if _has_any(text, LIVE_TOKENS):
        return ("live_check", "Statement mentions deployment/role/config/rpc.")

    # 9 — required_engine fallback for bridge-promoted exploit-queue rows.
    # When the keyword heuristic yields no match AND the ledger row carries an
    # explicit `required_engine` field (set by exploit-queue-to-invariant-ledger.py),
    # use it as the authoritative family selector instead of falling back to
    # needs_human.  This unblocks EQ rows whose attack_class is outside the
    # keyword heuristic table.
    # Mapping: forge/forge_invariant/foundry -> forge_invariant
    #          go/go_test                    -> cargo_unit_test (DLT-family Go harness)
    #          cargo/cargo_unit_test         -> cargo_unit_test
    # Only fall back to needs_human when required_engine is absent, empty,
    # "manual", or an unrecognised token.
    req_engine = (row.get("required_engine") or "").strip().lower()
    if req_engine in ("forge", "forge_invariant", "foundry"):
        return ("forge_invariant",
                f"required_engine fallback: ledger row declares "
                f"required_engine={req_engine!r}; no id/keyword heuristic "
                f"matched — mapping to forge_invariant family.")
    if req_engine in ("go", "go_test"):
        return ("cargo_unit_test",
                f"required_engine fallback: ledger row declares "
                f"required_engine={req_engine!r}; no id/keyword heuristic "
                f"matched — mapping to cargo_unit_test (Go/DLT family).")
    if req_engine in ("cargo", "cargo_unit_test"):
        return ("cargo_unit_test",
                f"required_engine fallback: ledger row declares "
                f"required_engine={req_engine!r}; no id/keyword heuristic "
                f"matched — mapping to cargo_unit_test (Rust family).")

    return ("needs_human",
            "No id family segment, invariant_family token, statement keyword, "
            "or recognised required_engine matched the dispatch table — "
            "operator should pick the harness family explicitly.")


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

# Match `path/to/file.ext:LINE` or `path/to/file.ext` segments.
_FILE_LINE_RE = re.compile(
    r"""
    (?P<path>
        (?:[A-Za-z0-9_./-]+/)?
        [A-Za-z0-9_.-]+
        \.(?:rs|sol|toml|md|json|yml|yaml|t\.sol|sh|py)
    )
    (?:[:#](?P<line>\d+))?
    """,
    re.VERBOSE,
)


def extract_target_entrypoint(row: Dict[str, Any]) -> str:
    """Pull a `file:line` (or just `file`) hint from production_path /
    harness_target. Falls back to the first `function_name` shaped token,
    then to `production_path` raw, then to "TBD"."""
    for f in ("production_path", "harness_target", "negative_test"):
        v = row.get(f)
        if not isinstance(v, str):
            continue
        m = _FILE_LINE_RE.search(v)
        if m:
            path = m.group("path")
            line = m.group("line")
            return f"{path}:{line}" if line else path
    # Fallback: first arrow-separated token of production_path. e.g.
    # "engine_newPayloadV4 -> reth on_new_payload -> ..." -> first chunk.
    pp = row.get("production_path") or ""
    if isinstance(pp, str) and pp.strip():
        first = pp.split("->", 1)[0].strip()
        if first:
            return first
    return "TBD"


# Rough mapping from harness family + invariant family to fixture kit ID.
# When TT's gap-4 fixture kits are wired, each value here either
# already names a kit ID or is "TBD:<short-name>".
def fixture_kit_ids(row: Dict[str, Any], hfamily: str) -> List[str]:
    fam = (row.get("invariant_family") or "").upper()
    out: List[str] = []
    if hfamily == "engine_api_in_process":
        out.append("TBD:engine-api-payload-chain")
        if "WITHDRAWALS" in fam:
            out.append("TBD:withdrawals-root-vector")
        if "HARDFORK" in fam or "BOUNDARY" in fam:
            out.append("TBD:hardfork-boundary-payload")
        if "CL-EL" in fam or "PARITY" in fam:
            out.append("TBD:cl-el-block-pair")
    elif hfamily == "cargo_unit_test":
        out.append("TBD:rust-fixture-min")
    elif hfamily == "differential_fuzz":
        out.append("TBD:state-root-corpus")
        if "STATE-ROOT" in fam:
            out.append("TBD:revm-oracle")
    elif hfamily == "live_check":
        out.append("TBD:live-rpc-shim")
        if "ROLE" in fam or "DEPLOYMENT" in fam:
            out.append("TBD:role-config-truth")
    elif hfamily == "forge_invariant":
        out.append("TBD:forge-actor-handler")
        if "CTF" in fam:
            out.append("TBD:ctf-collateral-conservation-kit")
        if "CLOB" in fam:
            out.append("TBD:clob-order-lifecycle-kit")
        if "NEGRISK" in fam or "RESOLUTION" in fam:
            out.append("TBD:negrisk-resolution-kit")
        if "FEE" in fam or "FEE-MATH" in fam:
            out.append("TBD:fee-bounds-kit")
        if "TEE" in fam or "ZK" in fam or "PROOF" in fam:
            out.append("TBD:proof-domain-kit")
    elif hfamily == "halmos_symbolic":
        out.append("TBD:halmos-symbolic-shim")
    elif hfamily == "medusa_property":
        out.append("TBD:medusa-property-handlers")
    return out


# Compile-command templates. The planner does NOT shell out — these are
# strings the operator/agent will run elsewhere.
def compile_command(row: Dict[str, Any], hfamily: str,
                    workspace: Path) -> str:
    rid = row.get("id") or "ROW"
    if hfamily == "engine_api_in_process":
        return (f"cargo test --manifest-path "
                f"{workspace}/poc-tests/{rid.lower()}/Cargo.toml "
                f"-- --nocapture")
    if hfamily == "cargo_unit_test":
        return (f"cargo test --manifest-path "
                f"{workspace}/poc-tests/{rid.lower()}/Cargo.toml "
                f"-- --nocapture")
    if hfamily == "differential_fuzz":
        return (f"cargo run --manifest-path "
                f"{workspace}/differential_fuzz/{rid.lower()}/Cargo.toml "
                f"--release -- --corpus corpus/")
    if hfamily == "live_check":
        return (f"python3 tools/live-check-runner.py "
                f"--workspace {workspace} "
                f"--spec {workspace}/.auditooor/live_topology_checks.json "
                f"--row {rid}")
    if hfamily == "forge_invariant":
        return (f"FOUNDRY_PROFILE=invariants forge test "
                f"--match-contract Invariant_{rid.replace('-', '_')} "
                f"--fuzz-seed <explicit-seed> -vv")
    if hfamily == "halmos_symbolic":
        return f"halmos --match-contract Halmos_{rid.replace('-', '_')}"
    if hfamily == "medusa_property":
        return (f"medusa fuzz --config "
                f"{workspace}/medusa/{rid.lower()}.json")
    return ("# needs_human: operator must pick a harness family before "
            "a compile command can be emitted")


def expected_log_string(row: Dict[str, Any], hfamily: str) -> str:
    if hfamily == "engine_api_in_process":
        return "test result: ok"
    if hfamily == "cargo_unit_test":
        return "test result: ok"
    if hfamily == "differential_fuzz":
        return "no divergence"
    if hfamily == "live_check":
        return "live_check_status: PASS"
    if hfamily == "forge_invariant":
        return "[PASS]"
    if hfamily == "halmos_symbolic":
        return "[PASS]"
    if hfamily == "medusa_property":
        return "passing"
    return ""


def _row_obligation_context(row: Dict[str, Any]) -> Dict[str, Any]:
    """Read the typed bridge contract without trusting malformed metadata."""
    bridge_meta = row.get("bridge_meta")
    if not isinstance(bridge_meta, dict):
        return {}
    context = bridge_meta.get("obligation_context")
    return context if isinstance(context, dict) else {}


def first_negative_control(row: Dict[str, Any], hfamily: str) -> str:
    """Smallest invalid input the test must reject. Pulls from the row's
    `negative_test` field if non-empty; else emits a family-shaped default."""
    context = _row_obligation_context(row)
    nt = context.get("kill_condition") or row.get("negative_test")
    if isinstance(nt, str) and nt.strip():
        return nt.strip()
    if hfamily == "engine_api_in_process":
        return ("Submit a payload with an intentionally wrong "
                "withdrawals-root and assert the validator rejects it "
                "(INVALID status, not VALID/SYNCING).")
    if hfamily == "cargo_unit_test":
        return ("Construct a single invalid input for the cited function "
                "and assert it returns Err / panics in the documented way.")
    if hfamily == "differential_fuzz":
        return ("Feed a corpus block that the oracle accepts but the "
                "in-tree impl rejects (or vice versa); assert divergence "
                "halts the test.")
    if hfamily == "live_check":
        return ("Assert a critical role/owner/config value via cast call "
                "and fail closed if the on-chain value differs from spec.")
    if hfamily == "forge_invariant":
        return ("Drive an actor sequence that violates the stated "
                "invariant (e.g. burn that under-flows accounting); "
                "assert the invariant holds OR the call reverts.")
    if hfamily == "halmos_symbolic":
        return ("Encode the negation of the invariant as a symbolic "
                "post-condition and assert UNSAT.")
    if hfamily == "medusa_property":
        return ("Add a property handler that returns false on the "
                "invalid state; assert the corpus does not reach it.")
    return "TBD"


def minimal_proof_surface(row: Dict[str, Any], hfamily: str) -> str:
    """2-3 line description of the smallest test."""
    rid = row.get("id") or "ROW"
    fam = row.get("invariant_family") or ""
    context = _row_obligation_context(row)
    stmt = (context.get("expected_invariant") or row.get("statement") or "").strip()
    head = stmt.split(".")[0][:160] if stmt else fam
    if hfamily == "engine_api_in_process":
        return (f"Drive `{rid}` against the in-process EngineApiTreeHandler "
                f"(NOT the outer RPC service). Send a single newPayload with "
                f"the cited fixture; promote with FCU; assert the handler "
                f"returns INVALID for the negative control. Surface: {head}")
    if hfamily == "cargo_unit_test":
        return (f"Cargo unit test against the single function cited in "
                f"production_path. One positive call (well-formed input "
                f"-> expected output) and one negative call (invalid input "
                f"-> Err). Surface: {head}")
    if hfamily == "differential_fuzz":
        return (f"Differential driver: feed each corpus block to both the "
                f"oracle and the in-tree implementation; halt on the first "
                f"divergence and emit the offending block. Surface: {head}")
    if hfamily == "live_check":
        return (f"Single live-check spec entry: cast call the cited "
                f"contract function on the deployed network; assert the "
                f"returned value matches the spec/role expectation. "
                f"Surface: {head}")
    if hfamily == "forge_invariant":
        return (f"Foundry invariant: 1 actor, 1-3 handler functions wrapping "
                f"the cited entrypoint, one `invariant_*` assertion. "
                f"Surface: {head}")
    if hfamily == "halmos_symbolic":
        return (f"Halmos symbolic: a single check_* function wrapping the "
                f"cited entrypoint with symbolic args; one assert encoding "
                f"the invariant. Surface: {head}")
    if hfamily == "medusa_property":
        return (f"Medusa property: one property_* function returning the "
                f"invariant; minimal handler set covering the cited "
                f"production path. Surface: {head}")
    return f"needs_human: cannot synthesize a minimal proof surface for {rid}"


def stop_condition(row: Dict[str, Any], hfamily: str) -> str:
    if hfamily == "needs_human":
        return ("Operator picks a harness family, then re-runs the planner.")
    context = _row_obligation_context(row)
    if isinstance(context, dict) and isinstance(context.get("terminal_condition"), str) and context["terminal_condition"].strip():
        return context["terminal_condition"].strip()
    return ("Mark `executed_clean` once the compile command exits 0, the "
            "expected_log_string is present in the run output, AND the "
            "negative control was demonstrably rejected.")


def foundry_profile_hints(row: Dict[str, Any], hfamily: str) -> Dict[str, Any]:
    if hfamily != "forge_invariant":
        return {}
    text = _haystack(row)
    time_sensitive = any(tok in text for tok in ("timelock", "expiry", "deadline", "oracle", "finalization", "delay"))
    optimization_candidate = any(tok in text for tok in ("max ", "maximum", "loss", "drift", "insolvency", "rounding", "fee"))
    hints: Dict[str, Any] = {
        "planned_foundry_target": PLANNED_TARGET_VERSION,
        "proof_profile": "profile.invariants",
        "exploratory_profile": "profile.invariants_fast",
        "replay_profile": "profile.fuzz_repro",
        "required_metadata": [
            "foundry_version_inventory",
            "foundry_profile",
            "fuzz_seed",
            "hardfork_or_evm_version",
            "network_when_forked",
            "check_interval",
            "max_time_delay",
            "max_block_delay",
        ],
        "warnings": [
            "final proof runs must use an explicit fuzz seed",
            "final proof runs must pin hardfork/evm_version or network",
            "check_interval > 1 is exploratory unless the proof explains why transient violations cannot be missed",
        ],
        "recommended_profiles": RECOMMENDED_PROFILES,
    }
    if time_sensitive:
        hints["suggested_v1_7_controls"] = ["max_time_delay", "max_block_delay"]
    if optimization_candidate:
        hints.setdefault("suggested_v1_7_controls", []).append("invariant optimization mode")
    return hints


# ---------------------------------------------------------------------------
# Plan emission
# ---------------------------------------------------------------------------

def plan_for_row(row: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    hfamily, reason = choose_harness_family(row)
    plan: Dict[str, Any] = {
        "row_id": row.get("id") or "",
        "harness_family": hfamily,
        "reason": reason,
        "required_fixtures": fixture_kit_ids(row, hfamily),
        "target_entrypoint": extract_target_entrypoint(row),
        "minimal_proof_surface": minimal_proof_surface(row, hfamily),
        "compile_command": compile_command(row, hfamily, workspace),
        "first_negative_control": first_negative_control(row, hfamily),
        "expected_log_string": expected_log_string(row, hfamily),
        "stop_condition": stop_condition(row, hfamily),
        "source_row_status": row.get("status") or "",
        "source_invariant_family": row.get("invariant_family") or "",
        "foundry_profile_hints": foundry_profile_hints(row, hfamily),
    }
    return plan


def _row_needs_plan(row: Dict[str, Any]) -> bool:
    """A row needs a plan if it's `missing_harness` OR its harness_target is
    a planned `EXPECTED:...` (the operator hasn't written it yet)."""
    status = (row.get("status") or "").strip().lower()
    if status == "missing_harness":
        return True
    ht = row.get("harness_target") or ""
    if isinstance(ht, str) and ht.strip().upper().startswith("EXPECTED:"):
        return True
    return False


def build_manifest(ledger: Dict[str, Any], workspace: Path,
                   only_row: Optional[str] = None,
                   include_all: bool = False) -> Dict[str, Any]:
    rows = ledger.get("rows") or []
    plans: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for r in rows:
        rid = r.get("id") or ""
        if only_row and rid != only_row:
            continue
        if not include_all and not _row_needs_plan(r):
            skipped.append({"row_id": rid, "reason": "row already has "
                            "harness_target / not missing_harness"})
            continue
        plans.append(plan_for_row(r, workspace))
    plans.sort(key=lambda p: p["row_id"])
    skipped.sort(key=lambda s: s["row_id"])
    return {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "ledger_generated_at": ledger.get("generated_at"),
        "ledger_row_count": len(rows),
        "plan_count": len(plans),
        "plans": plans,
        "skipped": skipped,
    }


def render_markdown(manifest: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Workspace Harness Plans")
    lines.append("")
    lines.append("Generated by `tools/invariant-harness-planner.py` "
                 "(PR #526 gap 3).")
    lines.append("")
    lines.append(f"- workspace: `{manifest['workspace']}`")
    lines.append(f"- ledger rows: {manifest['ledger_row_count']}")
    lines.append(f"- plans emitted: {manifest['plan_count']}")
    lines.append(f"- ledger generated_at: "
                 f"{manifest.get('ledger_generated_at') or 'unknown'}")
    lines.append("")
    if not manifest["plans"]:
        lines.append("_No rows currently need a harness plan._")
        lines.append("")
    else:
        for p in manifest["plans"]:
            lines.append(f"## {p['row_id']}")
            lines.append("")
            lines.append(f"- harness_family: `{p['harness_family']}`")
            lines.append(f"- reason: {p['reason']}")
            fixtures = ", ".join(f"`{x}`" for x in p['required_fixtures']) \
                or "_none_"
            lines.append(f"- required_fixtures: {fixtures}")
            lines.append(f"- target_entrypoint: `{p['target_entrypoint']}`")
            lines.append(f"- minimal_proof_surface: {p['minimal_proof_surface']}")
            lines.append("- compile_command:")
            lines.append("")
            lines.append(f"  ```bash\n  {p['compile_command']}\n  ```")
            lines.append(f"- first_negative_control: "
                         f"{p['first_negative_control']}")
            lines.append(f"- expected_log_string: "
                         f"`{p['expected_log_string']}`")
            lines.append(f"- stop_condition: {p['stop_condition']}")
            hints = p.get("foundry_profile_hints") or {}
            if hints:
                lines.append(f"- planned_foundry_target: "
                             f"`{hints.get('planned_foundry_target')}`")
                lines.append(f"- proof_profile: `{hints.get('proof_profile')}`")
                lines.append(f"- replay_profile: `{hints.get('replay_profile')}`")
                for warning in hints.get("warnings", []):
                    lines.append(f"- foundry_warning: {warning}")
            lines.append("")
    if manifest["skipped"]:
        lines.append("## Skipped rows")
        lines.append("")
        for s in manifest["skipped"]:
            lines.append(f"- `{s['row_id']}` — {s['reason']}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_ledger(ws: Path) -> Dict[str, Any]:
    p = ws / ".auditooor" / "invariant_ledger.json"
    if not p.exists():
        sys.stderr.write(
            f"[invariant-harness-planner] ERROR: no ledger at {p}.\n"
            f"  run `make invariant-ledger WS={ws}` first.\n")
        sys.exit(2)
    with p.open() as f:
        return json.load(f)


def _write_outputs(manifest: Dict[str, Any], ws: Path,
                   out_path: Optional[Path] = None) -> Tuple[Path, Path]:
    json_path = out_path if out_path else (
        ws / ".auditooor" / "harness_plans.json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    md_path = ws / ".auditooor" / "harness_plans.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown(manifest))
    return json_path, md_path


_HIGH_IMPACT_SEVERITIES = {"Critical", "High", "critical", "high", "CRITICAL", "HIGH"}

_REQUIRED_IMPACT_CONTRACT_FIELDS = (
    "selected_impact",
    "severity_tier",
    "evidence_class",
    "oos_traps",
    "stop_condition",
)


def _load_impact_contracts(workspace: Path) -> Dict[str, Dict[str, Any]]:
    """Load impact_contracts.json keyed by row_id. Returns empty dict on
    missing file (callers should treat absent contracts as `blocked`)."""
    contracts_path = workspace / ".auditooor" / "impact_contracts.json"
    if not contracts_path.is_file():
        return {}
    try:
        data = json.loads(contracts_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    by_row: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("contracts") or []:
        # Accept any of these as the keying field — different lanes write the
        # contract with different names. ``candidate_id`` is the canonical
        # PR #535 field; ``row_id`` and ``id`` are used by older lanes.
        row_id = str(
            entry.get("candidate_id")
            or entry.get("row_id")
            or entry.get("id")
            or ""
        ).strip()
        if row_id:
            by_row[row_id] = entry
    return by_row


def _impact_contract_blocked(contract: Optional[Dict[str, Any]]) -> bool:
    """A contract is blocked if it's missing or any required field is empty."""
    if not isinstance(contract, dict):
        return True
    for key in _REQUIRED_IMPACT_CONTRACT_FIELDS:
        v = contract.get(key)
        if v is None:
            return True
        if isinstance(v, str) and not v.strip():
            return True
        if isinstance(v, (list, dict)) and not v:
            return True
    return False


def build_high_impact_queue(ledger: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    """Build a high-impact queue grouped by harness_family.

    Selects ledger rows where ``severity`` is High/Critical, attaches the
    matching impact-contract summary from
    ``<workspace>/.auditooor/impact_contracts.json`` (when present), and groups
    them by the harness family chosen by ``choose_harness_family``. Rows whose
    impact contract is missing or incomplete are flagged
    ``impact_contract_blocked=True`` so the
    ``high-impact-impact-contract-skeletons`` and
    ``high-impact-execution-bridge`` consumers can route them to the
    fail-closed skeleton lane instead of harness scaffolding.

    Schema: ``auditooor.high_impact_queue.v1`` with ``queue_items`` of
    ``{queue_item_id, harness_family, harness_kind, rows: [{row_id, severity,
    invariant_family, production_path, harness_target, impact_contract,
    impact_contract_blocked}]}``.
    """
    impact_contracts = _load_impact_contracts(workspace)
    rows = ledger.get("rows") or []
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        sev = str(r.get("severity") or "").strip()
        if sev not in _HIGH_IMPACT_SEVERITIES:
            continue
        rid = str(r.get("id") or "").strip()
        if not rid:
            continue
        family, kind = choose_harness_family(r)
        contract = impact_contracts.get(rid)
        blocked = _impact_contract_blocked(contract)
        grouped.setdefault((family, kind), []).append({
            "row_id": rid,
            "severity": sev,
            "invariant_family": str(r.get("invariant_family") or "").strip(),
            "production_path": str(r.get("production_path") or "").strip(),
            "harness_target": str(r.get("harness_target") or "").strip(),
            "impact_contract": contract,
            "impact_contract_blocked": blocked,
        })

    queue_items: List[Dict[str, Any]] = []
    for (family, kind), bucket in sorted(grouped.items()):
        bucket.sort(key=lambda r: r["row_id"])
        queue_items.append({
            "queue_item_id": family,
            "harness_family": family,
            "harness_kind": kind,
            "rows": bucket,
        })

    return {
        "schema_version": "auditooor.high_impact_queue.v1",
        "workspace": str(workspace),
        "ledger_generated_at": ledger.get("generated_at"),
        "ledger_row_count": len(rows),
        "queue_items": queue_items,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Emit per-row harness plans from a workspace's "
                    "invariant ledger (PR #526 gap 3).")
    ap.add_argument("--workspace", required=True,
                    help="Workspace directory containing "
                         ".auditooor/invariant_ledger.json")
    ap.add_argument("--row", default=None,
                    help="Plan only the named row id (e.g. BASE-DLT-I01).")
    ap.add_argument("--out", default=None,
                    help="JSON manifest path (default: "
                         "<ws>/.auditooor/harness_plans.json).")
    ap.add_argument("--all", action="store_true",
                    help="Plan every row (not only missing_harness / "
                         "EXPECTED:...).")
    ap.add_argument("--print-json", action="store_true",
                    help="Print the manifest to stdout in addition to "
                         "writing to disk.")
    ap.add_argument("--no-write", action="store_true",
                    help="Do not write to disk; useful for tests.")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    ledger = _load_ledger(ws)
    manifest = build_manifest(ledger, ws, only_row=args.row,
                              include_all=args.all)

    if not args.no_write:
        out_path = Path(args.out).resolve() if args.out else None
        json_path, md_path = _write_outputs(manifest, ws, out_path)
        sys.stdout.write(
            f"[invariant-harness-planner] OK: wrote {json_path} and "
            f"{md_path} ({manifest['plan_count']} plans, "
            f"{len(manifest['skipped'])} skipped)\n")
    if args.print_json:
        sys.stdout.write(json.dumps(manifest, indent=2, sort_keys=True))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
