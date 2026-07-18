#!/usr/bin/env python3
"""Workspace-level engine-harness proof check (PR4b adapter over PR4a's gate).

Reconciles the PR4 filename/interface split: PR4a built
``tools/engine-harness-proof-gate.py`` (file/dir-level ``classify_path`` with
verdicts ``pass-real-property-executed`` / ``fail-stub-or-ghost`` /
``fail-zero-executed-property``); PR4b's ``audit-completeness-check.py`` loader +
the ``make engine-proof-gate`` target both expect
``tools/engine-harness-proof-check.py`` exposing ``evaluate(ws)``.

This module is that workspace-level adapter. It discovers the workspace's engine
harnesses, classifies each via PR4a's gate, and returns the aggregate verdict
that ``audit-completeness-check.check_engine_harness`` consumes:

    {"verdict": "pass-engine-harness-proof" | "pass-no-engine-harness"
                | "fail-no-proven-harness" | "fail-unproven-harness",
     "proven": [<harness labels>], "unproven": [<harness labels>],
     "harnesses": [{"harness": <label>, "verdict": <gate verdict>}]}

CLI: ``engine-harness-proof-check.py <workspace> [--json]`` (rc 0 = pass, 1 = fail).
"""
from __future__ import annotations

import argparse
import glob as _glob
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.evm_engine_harness_proof.v1"
MANIFEST_REL = Path(".auditooor") / "evm_engine_proof" / "engine_harness_proof.json"
PER_FUNCTION_HALMOS_REL = Path(".audit_logs") / "solidity_per_function_halmos_manifest.json"


def _load_mutation_kill():
    """P0-d / P1-a / P1-b: load the shared kill-genuineness + stale-sidecar
    predicates from tools/lib/mutation_kill.py (and the producer's
    sidecar_harness_drifted from mutation-verify-coverage.py). The CONSUMER applies
    the same genuine-kill rule as the producer so a setUp-crash false-kill (mode 12)
    / panic-only equivalent-mutant (mode 9) is not credited here either."""
    out = {"kill": None, "drift": None}
    libp = Path(__file__).resolve().parent / "lib" / "mutation_kill.py"
    if libp.is_file():
        try:
            spec = importlib.util.spec_from_file_location("mutation_kill", str(libp))
            mod = importlib.util.module_from_spec(spec)
            sys.modules["mutation_kill"] = mod  # py3.14: register BEFORE exec
            spec.loader.exec_module(mod)
            out["kill"] = mod
        except Exception:  # noqa: BLE001
            pass
    mvcp = Path(__file__).resolve().parent / "mutation-verify-coverage.py"
    if mvcp.is_file():
        try:
            spec = importlib.util.spec_from_file_location("mutation_verify_coverage", str(mvcp))
            mod = importlib.util.module_from_spec(spec)
            sys.modules["mutation_verify_coverage"] = mod
            spec.loader.exec_module(mod)
            out["drift"] = getattr(mod, "sidecar_harness_drifted", None)
        except Exception:  # noqa: BLE001
            pass
    return out


_MK = _load_mutation_kill()


def _genuine_kill_tail(tail: str) -> bool:
    """True iff the failing output_tail is a genuine behaviour-changing kill (not a
    setUp-crash false-kill nor a panic-only equivalent-mutant). Fail-open True when
    the shared lib is unavailable (do not retroactively fail records on a missing lib)."""
    mod = _MK.get("kill")
    if mod is None:
        return True
    try:
        return bool(mod.is_behavior_changing_kill(tail))
    except Exception:  # noqa: BLE001
        return True


def _sidecar_drifted(rec: dict, ws: Path) -> bool:
    """True iff the sidecar's harness_source_sha256 no longer matches the on-disk
    harness (stale-sidecar guard, P1-b/mode 13). False when no recorded hash."""
    fn = _MK.get("drift")
    if fn is None:
        return False
    try:
        return bool(fn(rec, ws))
    except Exception:  # noqa: BLE001
        return False


def _load_gate():
    """Import PR4a's hyphenated tool by file path."""
    p = Path(__file__).resolve().with_name("engine-harness-proof-gate.py")
    if not p.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_engine_harness_proof_gate", p)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_engine_harness_proof_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


# Standard auto-authored / per-function harness locations across languages.
_HARNESS_GLOBS = [
    "poc-tests/**/*engine-harness*/**/*.sol",
    "poc-tests/**/*engine-harness*/**/*.rs",
    ".auditooor/**/*engine-harness*/**/*.sol",
    ".auditooor/**/*engine-harness*/**/*.rs",
    ".auditooor/halmos/**/*.sol",
    ".auditooor/medusa/**/*.sol",
    # medusa_ws is the canonical Step-2c invariant-fuzz workspace (the real-CUT
    # mutation-verified economic-invariant harnesses recorded in
    # broken_invariant_ids.json land at .auditooor/medusa_ws/harness/*.sol). The
    # ".auditooor/medusa/**" glob above misses the "_ws" variant, so genuine
    # mutation-verified harnesses (e.g. OptimismPortal2 no-double-spend) were
    # silently dropped -> false fail-no-proven-harness. classify_path still
    # validates each (a vacuous one still fails), so this only makes the genuine
    # harness VISIBLE - it cannot create a false-green.
    ".auditooor/medusa_ws/**/*.sol",
    ".auditooor/echidna/**/*.sol",
    "symbolic_runs/**/*.rs",
    "fuzz_runs/**/*.rs",
    # Canonical Recon/Chimera invariant harness (README Step 2c): a real-CUT
    # harness ships as test/recon/{Setup,TargetFunctions,Properties,CryticTester,
    # CryticToFoundry}.sol, NOT as a *engine-harness* dir. The proof lives in
    # Properties.sol + CryticToFoundry.sol. Discover those so a genuine real-CUT
    # harness (imports src/ + real machine-checkable invariants) is credited,
    # not silently dropped to "pass-no-engine-harness" -> L37 fail-hollow.
    # classify_path still validates each file, so a vacuous recon harness still
    # fails - this only makes the genuine one VISIBLE.
    "**/test/recon/*.sol",
    "chimera_harnesses/**/*.sol",
    "chimera_harnesses/**/*.rs",
]

# Recon structural files that are NOT standalone proof candidates. Setup.sol and
# TargetFunctions.sol are already filtered by _harness_shaped (no properties).
# CryticTester.sol is the echidna/medusa ENTRY whose echidna_* bodies delegate to
# Properties.sol. Properties.sol is the property-DEFINITIONS library: bare
# `property_*() returns (bool)` functions that the prover asserts - classify_path's
# tautology heuristic mis-reads guard-heavy-but-real definitions (many early
# `if (...) return true` clauses) as stub/ghost. In the Recon pattern the PROVER is
# CryticToFoundry.sol (foundry asserts + mutation tests) - judge the harness by
# THAT, not by the definitions library or the medusa entry. Both Properties.sol and
# CryticTester.sol are structural; CryticToFoundry.sol carries the proof. Mutation
# verification + fuzz execution are separately enforced by the invariant-fuzz gate,
# so excluding the definitions library here cannot create a false-green.
_RECON_STRUCTURAL_ENTRY_FILES = {"CryticTester.sol", "Properties.sol"}


def _is_advisory_generated_skeleton(path: Path, ws: Path) -> bool:
    """True for generated advisory scaffold files that are not proof artifacts."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if (
        "Auto-generated by tools/per-function-invariant-gen.py" in text
        and "This advisory scaffold is not proof" in text
    ):
        return True
    if (
        "CANDIDATE HARNESS - NOT PROOF" in text
        or "No file in this tree is proof" in text
        or "REVIEW CANDIDATE, not a finding" in text
    ):
        return True
    if "Auto-scaffolded by tools/gen-invariants.sh" in text and "TODO" in text and "assert(true)" in text:
        return True
    return False


def _discover(ws: Path, gate: Any | None = None) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for g in _HARNESS_GLOBS:
        try:
            for f in ws.glob(g):
                if f.is_file() and f not in seen and f.suffix in (".sol", ".rs"):
                    # Recon echidna-entry delegator (CryticTester.sol) is
                    # structural, not a standalone proof file - see
                    # _RECON_STRUCTURAL_ENTRY_FILES. The real proof is
                    # Properties.sol + CryticToFoundry.sol in the same dir.
                    if f.name in _RECON_STRUCTURAL_ENTRY_FILES:
                        continue
                    # Mutation-test FIXTURES are deliberately-broken copies used to
                    # PROVE a harness non-vacuous (the mutant must fail). They are
                    # NOT proof candidates themselves - counting them yields spurious
                    # fail-unproven-harness. The genuine harness is credited via the
                    # broken_invariant_ids mutation-verified feed (see evaluate()).
                    if f.name.startswith("Mutant") or "Mutant" in f.name or f.name == "MutantCheck.sol":
                        continue
                    # Engine OUTPUT / CORPUS dirs hold ENGINE-GENERATED .sol, not
                    # authored harnesses: echidna writes counterexample reproducers to
                    # <corpusDir>/foundry/Test.<hash>.sol and <corpusDir>/reproducers/;
                    # crytic-compile flattens sources into crytic-export/. Counting
                    # these yields spurious fail-unproven-harness (the LiqCtl echidna
                    # corpus produced a Test.<hash>.sol that was mis-scanned as a stub).
                    # Match by any path segment so it is depth-independent. Generic
                    # across medusa/echidna; cannot drop a genuine harness (authored
                    # harnesses never live under a *-corpus-*/crytic-export/reproducers
                    # segment).
                    if any(
                        part.startswith(("echidna-corpus", "medusa-corpus"))
                        or part in ("crytic-export", "reproducers", "build-info")
                        for part in f.parts
                    ):
                        continue
                    # r36-rebuttal: lane ENGINE-HARNESS-LIB-EXCLUDE registered
                    # Skip vendored/dependency test files (lib/forge-std/test/
                    # *.t.sol etc.) - the `**` glob otherwise recurses into a
                    # harness dir's lib/ and counts forge-std's own tautological
                    # library tests as project harnesses (spurious
                    # fail-unproven-harness). Generic across EVM/Rust/Go.
                    if gate is not None and hasattr(gate, "_is_dependency_path"):
                        try:
                            if gate._is_dependency_path(f):
                                continue
                        except Exception:
                            pass
                    if _is_advisory_generated_skeleton(f, ws):
                        continue
                    if gate is not None and hasattr(gate, "_harness_shaped"):
                        try:
                            if not gate._harness_shaped(f):
                                continue
                        except Exception:
                            pass
                    seen.add(f)
                    out.append(f)
        except (OSError, ValueError):
            continue
    return sorted(out)


def _int_field(obj: dict, key: str) -> int | None:
    value = obj.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _workspace_matches(declared: Any, ws: Path) -> bool:
    if not declared:
        return True
    try:
        return Path(str(declared)).expanduser().resolve() == ws.expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return str(declared) == str(ws)


def _per_function_halmos_row(ws: Path, gate: Any | None = None) -> dict | None:
    """Return a proof row for a fully executed and proof-validated Halmos manifest."""
    path = ws / PER_FUNCTION_HALMOS_REL
    if not path.is_file():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {
            "label": str(PER_FUNCTION_HALMOS_REL),
            "verdict": "fail-malformed-per-function-halmos-manifest",
            "reason": "manifest is unreadable or not JSON",
        }
    if not isinstance(obj, dict):
        return {
            "label": str(PER_FUNCTION_HALMOS_REL),
            "verdict": "fail-malformed-per-function-halmos-manifest",
            "reason": "manifest is not a JSON object",
        }
    if obj.get("schema") != "auditooor.solidity_per_function_halmos.v1":
        return {
            "label": str(PER_FUNCTION_HALMOS_REL),
            "verdict": "fail-malformed-per-function-halmos-manifest",
            "reason": "manifest schema is not auditooor.solidity_per_function_halmos.v1",
        }
    declared_workspace = obj.get("workspace")
    if not _workspace_matches(declared_workspace, ws):
        return {
            "label": str(PER_FUNCTION_HALMOS_REL),
            "verdict": "fail-per-function-halmos-incomplete",
            "reason": f"manifest workspace mismatch: {declared_workspace}",
        }
    status = str(obj.get("status") or "").strip().lower()
    expected = _int_field(obj, "expected_invocation_count")
    executed = _int_field(obj, "executed_invocation_count")
    ok = _int_field(obj, "ok_invocation_count")
    invocations = obj.get("invocations")
    bad_invocations: list[str] = []
    missing_harness_paths: list[str] = []
    unproven_harness_paths: list[str] = []
    # proven_real_invocations counts invocations that (a) executed successfully
    # AND (b) ran against a REAL, gate-proven harness (not an auto-generated
    # advisory `assert(true)` scaffold). This is the load-bearing tally for the
    # honest partial-execution path: it never credits advisory scaffolds, so a
    # workspace whose only "ok" runs are trivial `assert(true)` skeletons keeps
    # a proven_real count of 0 and cannot certify.
    proven_real_invocations: list[str] = []
    invocation_count = len(invocations) if isinstance(invocations, list) else None
    if isinstance(invocations, list):
        advisory_harness_paths: list[str] = []
        for row in invocations:
            if not isinstance(row, dict):
                bad_invocations.append("<non-object>")
                continue
            row_status = str(row.get("status") or "").strip().lower()
            row_ok = row_status in {"ok", "pass", "passed", "completed"}
            if not row_ok:
                bad_invocations.append(str(row.get("harness_contract") or row.get("selector") or row_status or "<unknown>"))
            harness_path = row.get("harness_path")
            if isinstance(harness_path, str) and harness_path.strip():
                hp = Path(harness_path)
                if not hp.is_absolute():
                    hp = ws / hp
                if not hp.is_file():
                    missing_harness_paths.append(str(row.get("harness_contract") or harness_path))
                elif _is_advisory_generated_skeleton(hp, ws):
                    label = str(row.get("harness_contract") or harness_path)
                    advisory_harness_paths.append(label)
                    unproven_harness_paths.append(label)
                elif gate is not None and hasattr(gate, "classify_path"):
                    try:
                        classified = gate.classify_path(hp)
                    except Exception:
                        classified = {"verdict": "error"}
                    if not str(classified.get("verdict") or "").startswith("pass"):
                        unproven_harness_paths.append(str(row.get("harness_contract") or harness_path))
                    elif row_ok:
                        # Real (non-advisory) harness, gate-proven, and the
                        # invocation executed successfully -> genuine evidence.
                        proven_real_invocations.append(str(row.get("harness_contract") or harness_path))
            else:
                missing_harness_paths.append(str(row.get("harness_contract") or row.get("selector") or "<missing-harness-path>"))
    else:
        advisory_harness_paths = []
    # Budget-blocked-by-timeout: halmos symbolic execution genuinely ATTEMPTED real
    # harnesses but every executed invocation hit the per-harness timeout, exhausting
    # the total budget (truncated_by_total_budget). This is a known halmos LIMITATION
    # (symbolic exec is slow/incomplete on loop/external-call-heavy contracts), NOT a
    # fraudulent skip and NOT a vacuous stub - a stub returns instantly, so a TIMEOUT
    # is itself evidence the harness carries real symbolic work. README STEP-4b
    # doctrine: "attempt halmos (honest timeout caveat OK)"; the engine proof comes
    # from the mutation-verified medusa/echidna fuzzing harnesses. Surface it as
    # ADVISORY so it does not veto the gate when genuine proven harnesses exist - but
    # it can NEVER create a false-green: evaluate()'s no-harness branch still fails
    # fail-no-proven-harness when the advisory halmos row is the only signal.
    inv_statuses = set()
    if isinstance(invocations, list):
        inv_statuses = {
            str(r.get("status") or "").strip().lower()
            for r in invocations if isinstance(r, dict)
        }
    # NOTE: a timeout invocation NATURALLY lands in bad_invocations (status!=ok),
    # unproven_harness_paths (classify_path flags an incomplete harness as not-pass),
    # and often advisory_harness_paths (the per-function arm is auto-generated
    # advisory scaffolding) - NONE of those are fraud, so none are required empty.
    # The honest disqualifiers are: a genuine completed proof (then it is not
    # "blocked-without-proof"), a MISSING harness file (a real gap), or any executed
    # invocation that is NOT a pure timeout (e.g. an "error"/"build-failed" status =
    # a real broken arm, not a slow one). Pure-timeout + budget-truncated + zero
    # genuine proof = an honest tool-limitation caveat, advisory not veto.
    budget_blocked_timeout = (
        status == "blocked"
        and bool(obj.get("truncated_by_total_budget"))
        and (ok or 0) == 0
        and len(proven_real_invocations) == 0
        and not missing_harness_paths
        and len(inv_statuses) > 0
        and inv_statuses.issubset({"timeout"})
    )
    good = (
        status in {"ok", "pass", "passed", "completed"}
        and expected is not None
        and executed is not None
        and ok is not None
        and expected > 0
        and executed == expected
        and ok == expected
        and invocation_count == expected
        and not bad_invocations
        and not missing_harness_paths
        and not unproven_harness_paths
    )
    label = f"solidity-per-function-halmos:{ok or 0}/{expected or 0}"
    if good:
        return {
            "label": label,
            "verdict": "pass-real-property-executed",
            "reason": f"{expected} per-function Halmos invocation(s) executed successfully",
            "manifest": str(path),
            "proven_real_invocation_count": len(proven_real_invocations),
        }
    # Honest partial-execution path: the full denominator did not complete (some
    # harnesses could not build, or the aggregate engine root failed to compile),
    # but a real, non-advisory, gate-proven floor of per-function symbolic
    # invocations DID execute successfully. That is genuine deep-engine evidence
    # and certifies as partial coverage. Advisory `assert(true)` scaffolds are
    # excluded by construction (proven_real_invocations never includes them), so
    # a workspace whose only "ok" runs are trivial skeletons stays at 0 here and
    # falls through to the honest fail below.
    try:
        partial_floor = int(os.environ.get("AUDITOOOR_PARTIAL_HALMOS_MIN_PROVEN", "1") or "1")
    except (TypeError, ValueError):
        partial_floor = 1
    if partial_floor < 1:
        partial_floor = 1
    if len(proven_real_invocations) >= partial_floor:
        return {
            "label": label,
            "verdict": "pass-real-property-executed-partial",
            "partial": True,
            "reason": (
                f"{len(proven_real_invocations)} real (non-advisory, gate-proven) "
                f"per-function Halmos invocation(s) executed successfully "
                f"(of {expected} expected; ok={ok}); full denominator not reached"
            ),
            "manifest": str(path),
            "proven_real_invocation_count": len(proven_real_invocations),
            "proven_real_invocations": proven_real_invocations[:10],
            "bad_invocations": bad_invocations[:10],
            "missing_harness_paths": missing_harness_paths[:10],
            "unproven_harness_paths": unproven_harness_paths[:10],
        }
    return {
        "label": label,
        "verdict": "fail-per-function-halmos-incomplete",
        "reason": (
            f"status={status or 'unknown'} expected={expected} executed={executed} ok={ok} "
            f"invocations={invocation_count} bad_invocations={len(bad_invocations)} "
            f"missing_harness_paths={len(missing_harness_paths)} "
            f"unproven_harness_paths={len(unproven_harness_paths)}"
        ),
        "manifest": str(path),
        "bad_invocations": bad_invocations[:10],
        "missing_harness_paths": missing_harness_paths[:10],
        "unproven_harness_paths": unproven_harness_paths[:10],
        "advisory_harness_paths": advisory_harness_paths[:10],
        "proven_real_invocation_count": len(proven_real_invocations),
        "advisory_only": budget_blocked_timeout or (
            expected is not None
            and expected > 0
            and len(advisory_harness_paths) == expected
            and not bad_invocations
            and not missing_harness_paths
        ),
        "budget_blocked_timeout": budget_blocked_timeout,
    }


def _record_is_nonvacuous(r: dict) -> bool:
    """True iff a mutation record proves its harness non-vacuous. Accepts the flat
    mutation_verify_coverage.v1 schema (verdict==non-vacuous) AND the durable
    mvc_sidecar CLUSTER schema (mutation_verified=True with mutants_killed>=1 or a
    FAIL mutation_detail row). Un-fakeable: a vacuous (0-kill) record returns False
    - mirrors core-coverage-completeness._record_is_kill so the two gates agree.

    caveat A (schema normalization): ALSO consults the CANONICAL shared predicate
    tools/lib/mutation_kill.sidecar_is_genuine so this reader agrees with the
    invariant-fuzz / audit-honesty readers on what a genuine sidecar is - a genuine
    record can never be missed because it lives in the other schema's field
    (serving-join). The canonical predicate is fail-closed (verdict=='non-vacuous'
    OR mutation_verified, AND >=1 real kill), so OR-ing it in can only ADD credit
    for a genuine record, never credit a vacuous one."""
    mod = _MK.get("kill")
    if mod is not None and hasattr(mod, "sidecar_is_genuine"):
        try:
            if mod.sidecar_is_genuine(r):
                return True
        except Exception:  # noqa: BLE001
            pass
    if str(r.get("verdict")) == "non-vacuous":
        return True
    if r.get("mutation_verified") is True:
        mk = r.get("mutants_killed")
        if isinstance(mk, int) and mk >= 1:
            return True
        md = r.get("mutation_detail")
        if isinstance(md, list):
            for m in md:
                if isinstance(m, dict):
                    rr = m.get("mutant_result") or m.get("result") or ""
                    if isinstance(rr, str) and rr.strip().lower() in (
                            "fail", "failed", "killed", "broken", "caught"):
                        return True
    # cluster-schema variant: the per-mutant ledger lives in a `mutation_verify`
    # ARRAY of {mutant_id, verdict: KILLED} rows (no top-level mutation_verified
    # bool / mutants_killed int). A KILLED row is the same un-fakeable ground truth
    # (a behaviour-changing mutant genuinely broke the property). Without this, an
    # mvc_sidecar that records its kills only as a mutation_verify array (e.g.
    # SSVEBAccounting) read as vacuous -> a genuine campaign uncredited.
    mv = r.get("mutation_verify")
    if isinstance(mv, list):
        for m in mv:
            if isinstance(m, dict):
                vv = m.get("verdict") or m.get("mutant_result") or m.get("result") or ""
                if isinstance(vv, str) and vv.strip().lower() in (
                        "killed", "fail", "failed", "broken", "caught"):
                    return True
    return False


def _campaign_sol_siblings(harness_file: Path) -> set:
    """Resolved paths of every *.sol under the Chimera/Recon CAMPAIGN root that owns
    ``harness_file`` (the ancestor dir whose parent is ``chimera_harnesses``; falls
    back to the harness file's own dir). A mutation-verified campaign's proof is
    distributed across harness + foundry test (.t.sol) + Properties/CryticToFoundry,
    so all its .sol files are part of the proven bundle - crediting only the one file
    the sidecar names leaves the sibling .t.sol mis-classified stub-or-ghost and
    vetoes a genuine non-vacuous campaign. False-green-safe: only reached for a real
    non-vacuous sidecar pointing INTO that exact campaign tree."""
    out: set = set()
    try:
        rf = harness_file.resolve()
    except Exception:
        rf = harness_file
    root = rf.parent
    for anc in rf.parents:
        if anc.parent is not None and anc.parent.name == "chimera_harnesses":
            root = anc
            break
    try:
        for f in root.rglob("*.sol"):
            if f.is_file():
                out.add(str(f.resolve()))
    except Exception:
        pass
    if not out:
        out.add(str(rf))
    return out


def _resolve_sidecar_harness_file(rec: dict, ws: Path) -> Path | None:
    """Resolve the on-disk harness file a mutation record proves.

    Two sidecar schemas reach this consumer:
      - the durable mvc_sidecar CLUSTER schema stores ``harness_path`` (ws-relative
        or absolute);
      - the flat ``mutation_verify_coverage.v1`` schema (per-fn + chimera campaign
        records) has NO ``harness_path`` - it stores the harness as a runner
        COMMAND, ``cd <DIR> && forge test --match-path '<REL>'`` (+ ``runner_cwd``).

    The old loop read ONLY ``harness_path`` and ``continue``d when it was absent, so
    every genuinely non-vacuous v1 record was silently dropped (serving-join false-red
    -> the campaign read ``fail-stub-or-ghost``). Strata 2026-07-01 witness:
    AprPairFeedBounds (7/11 behaviour-changing kills) and TrancheDepositorConservation
    (4/13) were uncredited next to the already-credited TrancheNoValueCreation (1/1) -
    weaker evidence proven, stronger evidence dropped, purely on schema shape.

    False-green-safe: the CALLER has already confirmed the record is non-vacuous and
    not drifted; this only LOCATES the file, and the returned path must exist on disk
    (a bare marker resolves to None). Returns the resolved harness Path or None."""
    import re as _re
    import glob as _g
    hp = rec.get("harness_path")
    if hp:
        p = Path(str(hp))
        if not p.is_absolute():
            p = ws / p
        return p if p.is_file() else None
    cmd = rec.get("harness") or rec.get("runner_command") or ""
    if not isinstance(cmd, str) or not cmd:
        return None
    mp = _re.search(r"--match-path\s+(['\"])(.+?)\1", cmd)
    rel = mp.group(2) if mp else None
    if rel is None:
        mp2 = _re.search(r"--match-path\s+(\S+)", cmd)
        rel = mp2.group(1) if mp2 else None
    if not rel:
        # NO --match-path but a --match-contract <Name> (mutation-verify-coverage.py
        # accepts either): locate the harness .sol that DEFINES that contract. The kill
        # was proven against exactly that test contract, so its file is the proven harness.
        mc = _re.search(r"--match-contract\s+(['\"]?)([A-Za-z_]\w+)\1", cmd)
        if mc:
            name = mc.group(2)
            cdm0 = _re.search(r"\bcd\s+(\S+)", cmd)
            roots = []
            if cdm0 and Path(cdm0.group(1)).is_dir():
                roots.append(Path(cdm0.group(1)))
            roots += [ws / "chimera_harnesses", ws]
            pat = _re.compile(r"\bcontract\s+" + _re.escape(name) + r"\b")
            for root in roots:
                if not root.is_dir():
                    continue
                for h in _g.glob(str(root / "**" / "*.sol"), recursive=True):
                    hp2 = Path(h)
                    if "/out/" in h or not hp2.is_file():
                        continue
                    try:
                        if pat.search(hp2.read_text(encoding="utf-8", errors="replace")):
                            return hp2
                    except OSError:
                        continue
        return None
    # match-path is relative to the `cd <DIR>` the command runs in; fall back to
    # runner_cwd then the workspace root.
    cdm = _re.search(r"\bcd\s+(\S+)", cmd)
    base: Path | None = Path(cdm.group(1)) if cdm else None
    if base is None or not base.is_dir():
        rc = rec.get("runner_cwd")
        base = Path(str(rc)) if rc else ws
    cand = base / rel
    if cand.is_file():
        return cand
    hits = [Path(h) for h in _g.glob(str(base / rel)) if Path(h).is_file()]
    return hits[0] if hits else None


def _mutation_verified_harnesses(ws: Path) -> set:
    """Harness file paths PROVEN non-vacuous by mutation-verification (the
    broken_invariant_ids.json feed: the MUTANT genuinely broke the property). A
    tautology survives mutation, so a mutant-broken property is provably NOT
    tautological - this ground truth overrides classify_path's STATIC tautology
    heuristic (which mis-flags guard-heavy real invariant properties as stub/ghost).
    UN-FAKEABLE: requires mutation_verified=True AND the harness file AND the medusa
    evidence_path to exist on disk - a hand-written marker without a real medusa run
    cannot pass."""
    out: set = set()
    try:
        d = json.loads((ws / ".auditooor" / "broken_invariant_ids.json").read_text(encoding="utf-8"))
    except Exception:
        d = {}  # no broken_invariant_ids feed -> skip it, but STILL scan the
                # premade-mutant records below (do not early-return).
    for b in d.get("broken_invariant_ids", []):
        if b.get("mutation_verified") is not True:
            continue
        hp, ep = b.get("harness"), b.get("evidence_path")
        if not hp or not Path(hp).is_file():
            continue
        if not ep or not Path(ep).is_file():
            continue  # demand real on-disk medusa evidence, not just a marker
        try:
            out.add(str(Path(hp).resolve()))
        except Exception:
            out.add(str(hp))

    # ALSO credit premade-mutant-harness records (mutation-verify-coverage.py
    # --mutant-harness): a non-vacuous verdict means the BASELINE harness passed on
    # the real CUT AND the pre-made MUTANT harness failed - a genuine mutant-kill,
    # the same un-fakeable ground truth as broken_invariant_ids.json. These records
    # key on the CUT (source_file) and carry the proven harness file in harness_path,
    # which the broken_invariant_ids feed above does not see. UN-FAKEABLE: require
    # verdict==non-vacuous AND the recorded harness_path to exist on disk.
    import glob as _glob
    for _d in (".auditooor/cross-function-coverage", ".auditooor/mvc_sidecar"):
        # Glob ALL *.json (not just mutation*.json): mutation-verify-coverage.py
        # --out lets the operator name the record anything (e.g.
        # liqctl_mint_premade_mutant.json), and the old mutation*.json glob silently
        # dropped any record not so named -> a genuinely mutant-killed harness read
        # as fail-stub-or-ghost. The verdict==non-vacuous + harness_path-on-disk
        # check below is the un-fakeable gate, so widening the glob cannot create a
        # false-green (a random json without those fields is skipped).
        for _p in _glob.glob(str(ws / _d / "*.json")):
            try:
                _r = json.loads(Path(_p).read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(_r, dict):
                continue
            # Accept BOTH schemas: the flat mutation_verify_coverage.v1 record
            # (verdict==non-vacuous) AND the durable mvc_sidecar CLUSTER schema
            # (mutation_verified=True + mutants_killed>=1 / a FAIL mutation_detail
            # row). The cluster schema uses result/mutants_killed instead of verdict,
            # so the verdict-only check silently dropped genuine >=1M-call cluster
            # harnesses (same serving-join gap fixed in core-coverage-completeness).
            if not _record_is_nonvacuous(_r):
                continue
            # P1-b (mode 13): drop a STALE sidecar whose harness was clobbered.
            if _sidecar_drifted(_r, ws):
                continue
            # Resolve the proven harness file. Cluster schema -> harness_path; flat
            # mutation_verify_coverage.v1 schema -> derived from the --match-path
            # runner command (no harness_path key). A bare marker with no on-disk
            # file resolves to None and is dropped.
            _hpp = _resolve_sidecar_harness_file(_r, ws)
            if _hpp is None:
                continue
            # Credit the whole campaign bundle (harness + sibling .t.sol/Properties).
            out |= _campaign_sol_siblings(_hpp)
    return out


def _drifted_campaign_files(ws: Path) -> set:
    """Resolved *.sol paths in campaigns whose mvc_sidecar is NON-VACUOUS (a real
    mutation-verified harness) but DRIFTED - harness_source_sha256 no longer matches
    the on-disk harness (e.g. a sibling cross-function/closeout edit additively
    changed the baseline invariant handler AFTER the kill was recorded).

    These files are NOT fake/tautological stubs: the mutation proof is GENUINE but
    STALE, and the honest fix is a re-verify (re-run mutation-verify-coverage so the
    sidecar hash is refreshed), NOT authoring a real harness from scratch. Surfaced
    PURELY for diagnostics so the FAIL message can say 'stale/drifted sidecar
    (re-verify)' instead of mislabeling a real, mutation-verified harness a
    'fake/tautological stub' (which sends the operator down the wrong debug path).
    Never credited as proven - a drifted sidecar stays uncredited until re-verified;
    this set only RECLASSIFIES the diagnostic, so it cannot create a false-green."""
    out: set = set()
    import glob as _glob
    for _d in (".auditooor/cross-function-coverage", ".auditooor/mvc_sidecar"):
        for _p in _glob.glob(str(ws / _d / "*.json")):
            try:
                _r = json.loads(Path(_p).read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(_r, dict) or not _record_is_nonvacuous(_r):
                continue
            if not _sidecar_drifted(_r, ws):
                continue
            _hp = _r.get("harness_path")
            if not _hp:
                continue
            _hpp = Path(_hp)
            if not _hpp.is_absolute():
                _hpp = ws / _hpp
            try:
                out |= _campaign_sol_siblings(_hpp)
            except Exception:
                pass
    return out


# An auto-authored harness that SELF-DECLARES it is not a proof: the
# evm-engine-harness-author "CANDIDATE HARNESS - NOT PROOF" banner, or the
# materialized-skeleton "MATERIALIZED SKELETON - NOT A PROOF" / TODO stub. These
# are advisory leads awaiting promotion to a real-CUT harness, NOT failed proofs.
_NONPROOF_BANNER_RE = re.compile(
    r"NOT\s+A\s+PROOF|NOT\s+PROOF|MATERIALIZED\s+SKELETON|CANDIDATE\s+HARNESS|"
    r"no file in this tree is proof|materialized-skeleton",
    re.IGNORECASE,
)


def _is_advisory_scaffold(path: Path) -> bool:
    """True iff the harness file self-declares it is a non-proof scaffold. Such a
    scaffold must NOT veto the engine-harness proof gate (it is advisory, exactly
    like the per-function-halmos advisory_harness_paths). A genuine proven /
    mutation-verified harness is still REQUIRED to pass (evaluate()'s
    `not proven -> fail-no-proven-harness`), so treating scaffolds as advisory can
    never create a false-green - it only stops a self-declared TODO skeleton from
    masking a workspace that DOES carry a real proof."""
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return False
    return bool(_NONPROOF_BANNER_RE.search(head))


# A thin Foundry invariant-mode ENTRYPOINT whose `invariant_*()` bodies do nothing
# but delegate to a Handler it instantiates (e.g. `function invariant_cap() public {
# handler.invariant_cap(); }`). The PROPERTY logic lives in that Handler, not here -
# exactly the CryticTester.sol/Properties.sol structural-entry split already handled
# by _RECON_STRUCTURAL_ENTRY_FILES, but for the foundry `forge test` arm instead of
# the echidna/medusa arm. classify_path's static tautology heuristic reads such an
# entrypoint as fail-stub-or-ghost (its own body carries no assertion), vetoing a
# campaign whose Handler IS proven. This detector + the proven-sibling guard below
# lift it to a structural-entry pass. False-green-safe: it is credited ONLY when a
# same-directory sibling .sol is itself genuinely proven (byte-hash-inherited or
# mutation-verified) - so a delegating entry alone, with no proven handler beside it,
# still gets no credit.
_INVARIANT_DELEGATE_RE = re.compile(
    r"function\s+invariant_\w+\s*\([^)]*\)\s*(?:public|external)[^{]*\{\s*"
    r"(\w+)\s*\.\s*invariant_\w+\s*\([^)]*\)\s*;\s*\}",
)


def _is_foundry_invariant_entry_delegator(path: Path) -> bool:
    """True iff `path` is a thin Foundry invariant-mode entry that ONLY delegates its
    invariant_* bodies to a handler (no inline assert/require/property of its own).
    Structural, like CryticTester.sol - the proof is the handler it drives. Caller
    MUST still require a genuinely-proven same-dir sibling before crediting."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    # Must be a foundry invariant runner (extends Test, registers a target contract).
    if "is Test" not in text and "Test," not in text:
        return False
    if "targetContract" not in text and "targetSelector" not in text:
        return False
    # Find every invariant_* body; ALL must be pure delegations (no inline asserts).
    inv_bodies = re.findall(
        r"function\s+invariant_\w+\s*\([^)]*\)[^{]*\{(.*?)\}", text, re.DOTALL
    )
    if not inv_bodies:
        return False
    for body in inv_bodies:
        b = body.strip()
        # A pure delegation body is exactly one `x.invariant_*( ... );` statement.
        if not re.fullmatch(r"\w+\s*\.\s*invariant_\w+\s*\([^)]*\)\s*;", b):
            return False
        # Defense-in-depth: a delegating entry must carry NO inline property of its own.
        if re.search(r"\b(assert|assertEq|assertLe|assertGe|assertTrue|require)\b", b):
            return False
    return True


def _has_proven_sibling(path: Path, proven_resolved: set) -> bool:
    """True iff a *.sol in the SAME directory as `path` (other than `path` itself) is
    already credited proven (its resolved path is in `proven_resolved`)."""
    try:
        d = path.resolve().parent
        self_r = path.resolve()
    except Exception:
        return False
    for sib in d.glob("*.sol"):
        try:
            sr = sib.resolve()
        except Exception:
            continue
        if sr == self_r:
            continue
        if str(sr) in proven_resolved:
            return True
    return False


def _mvc_named_harness_paths(ws: Path) -> set:
    """Resolved paths of the harness FILES explicitly named by a genuine
    non-vacuous mvc_sidecar / mutation record (the harness_path itself, NOT the
    campaign siblings). Each is an un-fakeable proof file: a >=1-mutant-kill record
    pointing at an on-disk harness. _discover only globs a FIXED set of harness
    locations (chimera_harnesses/, poc-tests/, .auditooor/medusa_ws/, ...); when an
    mvc_sidecar harness_path points elsewhere - e.g. the real src/.../test/echidna
    tree - the genuine harness is never discovered, so classify_path's STATIC
    tautology heuristic mis-reads the chimera COPY (byte-identical, at a different
    path) as fail-stub-or-ghost and the campaign is uncredited. Injecting these
    directly fixes that path-mismatch. False-green-safe: requires a non-vacuous
    record (_record_is_nonvacuous) AND the named file on disk."""
    import glob as _g
    out: set = set()
    for rel in ("cross-function-coverage", "mvc_sidecar"):
        for p in _g.glob(str(ws / ".auditooor" / rel / "*.json")):
            try:
                r = json.loads(Path(p).read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(r, dict) or not _record_is_nonvacuous(r):
                continue
            # P1-b (mode 13): drop a STALE sidecar whose harness was clobbered.
            if _sidecar_drifted(r, ws):
                continue
            hp = r.get("harness_path")
            if not hp:
                continue
            hpp = Path(hp)
            if not hpp.is_absolute():
                hpp = ws / hpp  # cluster sidecars store a ws-relative harness_path
            if hpp.is_file():
                try:
                    out.add(str(hpp.resolve()))
                except Exception:
                    out.add(str(hpp))
    return out


def _mutation_verified_records(ws: Path) -> list[dict]:
    """Proven-harness entries from canonical mutation-verify-coverage.py records
    (schema ``auditooor.mutation_verify_coverage.v1``). Those records key on the
    CUT (``source_file``) + a runner COMMAND rather than a discoverable harness
    FILE, so ``_discover`` never sees them and ``_mutation_verified_harnesses``
    (which demands a ``harness_path``) skips them - a genuinely mutation-verified
    harness over the real CUT (e.g. the ProtocolFee core invariant) was therefore
    never credited (producer/consumer schema drift). A ``non-vacuous`` record =
    the BASELINE passed on the real CUT AND >=1 behaviour-changing MUTANT was
    KILLED: the same un-fakeable mutation ground truth the broken_invariant_ids
    feed trusts. Require the CUT ``source_file`` on disk so a bare marker cannot
    pass. Returns ``[{label, source_file}]``."""
    out: list[dict] = []
    seen: set[str] = set()
    candidates: list[str] = []
    for rel in ("cross-function-coverage", "mvc_sidecar"):
        candidates += _glob.glob(str(ws / ".auditooor" / rel / "*.json"))
    candidates += _glob.glob(str(ws / ".auditooor" / "mvc_sidecar*.json"))
    for p in candidates:
        try:
            rec = json.loads(Path(p).read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        if str(rec.get("schema")) != "auditooor.mutation_verify_coverage.v1":
            continue
        if str(rec.get("verdict")) != "non-vacuous":
            continue
        # P1-b (mode 13): reject a STALE sidecar whose harness was clobbered after
        # the kills were banked (the recorded source-hash no longer matches disk).
        if _sidecar_drifted(rec, ws):
            continue
        base = rec.get("baseline") if isinstance(rec.get("baseline"), dict) else {}
        if str(base.get("status")) not in ("pass", "passed", "ok"):
            continue
        # P0-d / P1-a: a kill counts only when it is a GENUINE behaviour-changing
        # kill (its output_tail names a real invariant/property assertion frame, not
        # a setUp-crash false-kill nor a panic-only equivalent-mutant). Records with
        # no output_tail keep the legacy `killed` truth (fail-open) so pre-existing
        # cluster sidecars are not retroactively dropped.
        killed = any(
            isinstance(m, dict) and m.get("killed")
            and (m.get("kill_kind") in (None, "behavior-changing")
                 or "output_tail" not in m)
            and (("output_tail" not in m) or _genuine_kill_tail(str(m.get("output_tail") or "")))
            for m in (rec.get("mutant_results") or [])
        )
        if not killed:
            continue
        src = str(rec.get("source_file") or "").strip()
        if not src or not Path(src).is_file():
            continue
        fn = str(rec.get("function") or "").strip()
        label = f"mutation-verified:{Path(src).name}" + (f"::{fn}" if fn else "")
        if label in seen:
            continue
        seen.add(label)
        out.append({"label": label, "source_file": src})
    return out


def evaluate(ws: Any) -> dict:
    """Workspace-level proof verdict consumed by audit-completeness-check."""
    ws = Path(ws)
    gate = _load_gate()
    if gate is None or not hasattr(gate, "classify_path"):
        return {
            "verdict": "error",
            "proven": [],
            "unproven": [],
            "harnesses": [],
            "reason": "PR4a engine-harness-proof-gate.py not loadable",
        }
    harnesses = _discover(ws, gate)
    # This row is emitted only after the per-function harness proof gate passes.
    per_function_halmos = _per_function_halmos_row(ws, gate)
    # Canonical mutation-verify-coverage.v1 records are CUT-keyed (no discoverable
    # harness file), so they certify proof even when _discover finds nothing.
    _mvc_records = _mutation_verified_records(ws)
    if not harnesses:
        # A mutation-verified harness whose harness_path lies OUTSIDE the _discover
        # globs (e.g. src/.../test/echidna) certifies proof even when discovery is
        # empty. Same un-fakeable ground truth as _mvc_records; gated by a
        # non-vacuous record + on-disk file.
        _named_only = _mvc_named_harness_paths(ws)
        if _named_only:
            rows = []
            proven_labels = []
            for _hp in sorted(_named_only):
                p = Path(_hp)
                try:
                    lbl = str(p.relative_to(ws))
                except ValueError:
                    lbl = _hp
                rows.append({"harness": lbl, "verdict": "pass-mutation-verified-invariant",
                             "mutation_verified": True})
                proven_labels.append(lbl)
            for rec in _mvc_records:
                if rec["label"] not in proven_labels:
                    rows.append({"harness": rec["label"],
                                 "verdict": "pass-mutation-verified-invariant",
                                 "mutation_verified": True, "source_file": rec["source_file"]})
                    proven_labels.append(rec["label"])
            return {
                "verdict": "pass-engine-harness-proof",
                "proven": proven_labels,
                "unproven": [],
                "harnesses": rows,
                "reason": f"{len(proven_labels)} mutation-verified harness(es) (named harness_path on disk)",
            }
        if _mvc_records:
            rows = [{"harness": rec["label"],
                     "verdict": "pass-mutation-verified-invariant",
                     "mutation_verified": True, "source_file": rec["source_file"]}
                    for rec in _mvc_records]
            return {
                "verdict": "pass-engine-harness-proof",
                "proven": [rec["label"] for rec in _mvc_records],
                "unproven": [],
                "harnesses": rows,
                "reason": f"{len(_mvc_records)} mutation-verified harness(es) over the real CUT",
            }
        if per_function_halmos is not None:
            row = {
                "harness": per_function_halmos["label"],
                "verdict": per_function_halmos["verdict"],
                "reason": per_function_halmos.get("reason", ""),
            }
            if str(per_function_halmos["verdict"]).startswith("pass"):
                result = {
                    "verdict": "pass-engine-harness-proof",
                    "proven": [per_function_halmos["label"]],
                    "unproven": [],
                    "harnesses": [row],
                    "reason": per_function_halmos.get("reason", ""),
                }
                if per_function_halmos.get("partial"):
                    result["partial"] = True
                    row["partial"] = True
                return result
            return {
                "verdict": "fail-no-proven-harness",
                "proven": [],
                "unproven": [per_function_halmos["label"]],
                "harnesses": [row],
                "reason": per_function_halmos.get("reason", ""),
                "advisory_only": bool(per_function_halmos.get("advisory_only")),
            }
        return {
            "verdict": "pass-no-engine-harness",
            "proven": [],
            "unproven": [],
            "harnesses": [],
            "reason": "no engine harness files discovered (live-engines signal governs presence)",
        }
    proven: list[str] = []
    unproven: list[str] = []
    rows: list[dict] = []
    partial_proof = False
    if per_function_halmos is not None:
        label = per_function_halmos["label"]
        v = str(per_function_halmos["verdict"])
        row = {"harness": label, "verdict": v, "reason": per_function_halmos.get("reason", "")}
        if per_function_halmos.get("advisory_only"):
            row["advisory_only"] = True
        else:
            (proven if v.startswith("pass") else unproven).append(label)
            if v.startswith("pass") and per_function_halmos.get("partial"):
                partial_proof = True
                row["partial"] = True
        rows.append(row)
    _mut_verified = _mutation_verified_harnesses(ws)

    def _sha(fp: str) -> str | None:
        try:
            return hashlib.sha256(Path(fp).read_bytes()).hexdigest()
        except Exception:
            return None
    # Content-hashes of every mutation-verified harness file, so a byte-identical
    # COPY discovered at a different path (e.g. chimera_harnesses/ vs the real
    # src/.../test/echidna proof the mvc_sidecar names) inherits proven status
    # instead of being vetoed as fail-stub-or-ghost by the static tautology
    # heuristic. False-green-safe: the hash must equal a genuinely mutation-verified
    # harness's content - a stub cannot collide with a non-vacuous proof.
    _mv_hashes = {h for h in (_sha(p) for p in _mut_verified) if h}
    advisory: list[str] = []
    _delegator_candidates: list[tuple[str, Path]] = []
    for h in harnesses:
        try:
            label = str(h.relative_to(ws))
        except ValueError:
            label = str(h)
        # Mutation-verified ground truth overrides the static tautology heuristic.
        try:
            _hr = str(h.resolve())
        except Exception:
            _hr = str(h)
        if (_hr in _mut_verified or str(h) in _mut_verified
                or (_mv_hashes and _sha(_hr) in _mv_hashes)):
            rows.append({"harness": label, "verdict": "pass-mutation-verified-invariant", "mutation_verified": True})
            proven.append(label)
            continue
        # A self-declared non-proof scaffold ("CANDIDATE HARNESS - NOT PROOF" /
        # "MATERIALIZED SKELETON - NOT A PROOF" / TODO skeleton) is ADVISORY: it
        # neither certifies nor vetoes (mirrors per-function-halmos advisory
        # handling). A genuine proven harness is still required below, so this
        # cannot create a false-green.
        if _is_advisory_scaffold(h):
            rows.append({"harness": label, "verdict": "advisory-candidate-scaffold",
                         "advisory_only": True})
            advisory.append(label)
            continue
        try:
            c = gate.classify_path(h)
            v = str(c.get("verdict", "") if isinstance(c, dict) else c)
        except Exception as exc:  # pragma: no cover (defensive)
            v = f"error:{exc}"
        rows.append({"harness": label, "verdict": v})
        (proven if v.startswith("pass") else unproven).append(label)
        # Record stub/ghost-flagged delegating-entry candidates for the post-pass
        # structural-entry fixup below (needs the fully-populated proven set first).
        if not v.startswith("pass") and _is_foundry_invariant_entry_delegator(h):
            _delegator_candidates.append((label, h))
    # Inject mutation-verified harnesses _discover did NOT find by path. The
    # mvc_sidecar harness_path may name the real src/.../test/echidna harness while
    # _discover only globs the chimera_harnesses/ COPY (byte-identical, different
    # path) - the two never matched, so classify_path's static heuristic vetoed a
    # genuine mutation-verified campaign as fail-stub-or-ghost. Gated by a
    # non-vacuous record + the named file on disk: cannot create a false-green.
    _named_mv = _mvc_named_harness_paths(ws)
    if _named_mv:
        _proven_resolved = set()
        for lbl in proven:
            try:
                _proven_resolved.add(str((ws / lbl).resolve()))
            except Exception:
                pass
        for _hp in sorted(_named_mv):
            if _hp in _proven_resolved:
                continue
            p = Path(_hp)
            try:
                label = str(p.relative_to(ws))
            except ValueError:
                label = _hp
            if label in proven:
                continue
            # if _discover already classified this exact path as unproven, lift it.
            if label in unproven:
                unproven.remove(label)
            rows.append({"harness": label,
                         "verdict": "pass-mutation-verified-invariant",
                         "mutation_verified": True})
            proven.append(label)
    # Inject canonical mutation-verify-coverage.v1 proven harnesses (CUT-keyed,
    # outside the discovery globs) - the un-fakeable mutation ground truth that
    # the schema drift previously dropped.
    for rec in _mvc_records:
        if rec["label"] in proven:
            continue
        rows.append({"harness": rec["label"], "verdict": "pass-mutation-verified-invariant",
                     "mutation_verified": True, "source_file": rec["source_file"]})
        proven.append(rec["label"])
    # Structural-entry fixup: a thin Foundry invariant entrypoint whose invariant_*
    # bodies only delegate to a same-dir Handler is structural (like CryticTester.sol),
    # not a standalone proof. classify_path flagged it stub/ghost above because its own
    # body has no assertion - but the PROPERTY lives in the Handler it drives. Lift it
    # to a structural-entry pass IFF a same-directory sibling .sol is ALREADY credited
    # proven (the now-fully-populated `proven` set). False-green-safe: a delegating
    # entry with no proven handler beside it gets no credit; the handler itself still
    # had to pass on its own merits (byte-hash-inherited from a real mvc/mutation proof).
    if _delegator_candidates:
        _proven_resolved2 = set()
        for lbl in proven:
            try:
                _proven_resolved2.add(str((ws / lbl).resolve()))
            except Exception:
                pass
        for label, h in _delegator_candidates:
            if label in proven:
                continue
            if not _has_proven_sibling(h, _proven_resolved2):
                continue
            if label in unproven:
                unproven.remove(label)
            for r in rows:
                if r.get("harness") == label:
                    r["verdict"] = "pass-structural-invariant-entry-delegator"
                    r["structural_entry"] = True
                    break
            proven.append(label)
    if proven and not unproven:
        verdict = "pass-engine-harness-proof"
    elif not proven:
        verdict = "fail-no-proven-harness"
    else:
        verdict = "fail-unproven-harness"
    out: dict = {"verdict": verdict, "proven": proven, "unproven": unproven,
                 "harnesses": rows}
    # Diagnostic-only: split the unproven list into genuinely-tautological vs
    # drifted-but-real (a sibling edit staled an otherwise non-vacuous sidecar).
    # Does NOT change the verdict - a drifted sidecar stays uncredited - it only
    # tells the operator which fix applies (re-verify vs author a real harness).
    if unproven:
        try:
            _drifted = _drifted_campaign_files(ws)
        except Exception:
            _drifted = set()
        if _drifted:
            drifted_unproven = []
            for label in unproven:
                try:
                    rp = str((ws / label).resolve())
                except Exception:
                    rp = str(ws / label)
                if rp in _drifted:
                    drifted_unproven.append(label)
            if drifted_unproven:
                out["drifted_unproven"] = drifted_unproven
    if advisory:
        out["advisory"] = advisory
    if partial_proof and verdict == "pass-engine-harness-proof":
        out["partial"] = True
    return out


def write_manifest(ws: Any, result: dict) -> Path:
    """Persist the proof-check verdict for strict audit-completeness runs."""
    ws = Path(ws)
    path = ws / MANIFEST_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA_VERSION,
        **result,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Workspace engine-harness proof check (PR4b adapter).")
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--no-write-manifest",
        action="store_true",
        help="do not write .auditooor/evm_engine_proof/engine_harness_proof.json",
    )
    a = ap.parse_args()
    ws = Path(a.workspace)
    if not ws.is_dir():
        print(f"ERR workspace not found or not a directory: {ws}", file=sys.stderr)
        return 2
    r = evaluate(ws)
    manifest_path = None
    if not a.no_write_manifest:
        manifest_path = write_manifest(ws, r)
    if a.json:
        out = dict(r)
        if manifest_path is not None:
            out["manifest_path"] = str(manifest_path)
        print(json.dumps(out, indent=2))
    else:
        suffix = f" | manifest={manifest_path}" if manifest_path is not None else ""
        print(f"{r['verdict']} | proven={len(r['proven'])} unproven={len(r['unproven'])} | {r.get('reason','')}{suffix}")
    return 0 if r["verdict"].startswith("pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
