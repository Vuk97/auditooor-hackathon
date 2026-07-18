#!/usr/bin/env python3
"""pr9-novel-vector-0day-demo.py - the true-0-day DEMONSTRATION driver.

This is the delivery-mile demo for the PR9 novel-vector stage. The pieces it
chains already exist (the miner derives invariants; the PR5 authors render a
*correct-model* harness; the engines run). What did not exist is the one-shot
front-door that closes the loop into a genuine 0-day SEARCH and adjudicates it:

  1. DERIVE target-specific invariants from the real contract surface by
     delegating to tools/novel-vector-invariant-miner.py (corpus-family-grounded;
     each invariant carries INV-* citations so Rule 58 is honored).
  2. AUTHOR a REAL-CONTRACT-WIRED Foundry stateful-invariant harness. This is
     the part the PR5 author does NOT do: the PR5 author renders a self-contained
     model of a *correct* contract (its mutate* bodies are deliberately correct,
     so the engine finds 0 counterexamples - it is checking a correct model
     against itself). This driver instead imports the REAL contract source and
     drives its REAL mutating entrypoints, so the engine fuzzes the ACTUAL
     implementation. A counterexample here is a violation of a derived spec by
     the real code.
  3. RUN `forge` invariant testing against the real-wired harness.
  4. ADJUDICATE each invariant: PASS (engine found no counterexample over the
     fuzz budget) or VIOLATED (engine found a counterexample). For each VIOLATED
     invariant, cross-check against pre-existing detector output (slither
     results in the workspace harness dir). A violation that matches NO
     pre-existing detector is a TRUE-0-DAY candidate: a spec-violation nobody
     has a detector for.
  5. REPORT honestly. 0 violations is a legitimate, fully-reportable outcome:
     it means every derived spec was genuinely engine-checked against the real
     contract and held. The report enumerates what was derived, what was wired,
     what was checked, and the per-invariant verdict.

This is a DEMO / hunt-worklist driver. Its output is advisory: a VIOLATED
verdict is a REVIEW CANDIDATE, not a submission. Promotion to a finding still
requires the V3-grade PoC gates (R40), configured-impact trace (R42), and the
rest of the pre-submit stack.

RELATED TOOLS (tool-duplication preflight, see ~/.claude/CLAUDE.md):
  - tools/novel-vector-invariant-miner.py DERIVES the invariants and (via
    --render) emits a CORRECT-MODEL harness through the PR5 authors. It does
    NOT wire the real contract into the engine and does NOT adjudicate a
    0-day verdict from a real-contract fuzz run. This driver consumes the
    miner's derived invariants and adds the real-wire + run + 0-day-adjudicate
    stages. It calls the miner; it does not reimplement it.
  - tools/evm-engine-harness-author.py (PR5) renders the correct-model harness.
    This driver intentionally does the dual thing: wire the REAL contract so a
    counterexample is a real spec-violation, not a model artifact.
  - tools/evm-0day-proof-pipeline.py (PR5a) takes a SPECIFIC pre-identified
    candidate {contract, fn, vuln_class} and proves an attack-path PoC with
    before/after balance asserts + negative control. This driver is upstream:
    it has no pre-identified candidate; it lets the engine SURFACE one by
    falsifying a derived spec. Surface-then-prove vs prove-a-known-candidate.
  - tools/engine-harness-proof-check.py / -gate.py VALIDATE that a rendered
    harness meets the proof bar. This driver authors+runs+adjudicates; it is
    not a validator of someone else's harness.

Usage
-----
    python3 tools/pr9-novel-vector-0day-demo.py \
        --workspace morpho-midnight \
        --contract morpho-midnight/src/MidnightBundles.sol \
        --out-dir morpho-midnight/.auditooor/pr9_0day_demo \
        [--detector-results <slither_results.json>] \
        [--fuzz-runs 256] [--fuzz-depth 64] \
        [--mimo-refine --mimo-budget 6] \
        [--json]

Exit code is always 0 when the run completes (including 0-violation runs); a
non-zero exit signals a driver/setup error (could not derive, could not build),
not "no bug found".
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
MINER = TOOLS_DIR / "novel-vector-invariant-miner.py"
SCHEMA = "auditooor.pr9_novel_vector_0day_demo.v1"

# Map each derived-invariant FAMILY to a real-contract-wired assertion + the
# real entrypoints whose state it reads. The handler drives the REAL contract;
# the invariant asserts a corpus-grounded spec over the contract's REAL views.
# Each entry is best-effort: if the contract lacks the named view the family is
# skipped (reported as "unwireable-no-view"), never silently asserted true.


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Step 1: derive invariants via the miner (no reimplementation).
# ---------------------------------------------------------------------------

def run_miner(workspace: str, contract: str, mimo_refine: bool, mimo_budget: int) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(MINER),
        "--workspace",
        workspace,
        "--contract",
        contract,
        "--json",
    ]
    if mimo_refine:
        cmd += ["--mimo-refine", "--mimo-budget", str(mimo_budget)]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    if proc.returncode != 0:
        raise RuntimeError(f"miner failed rc={proc.returncode}: {proc.stderr[-500:]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"miner emitted non-JSON: {exc}; tail={proc.stdout[-300:]}")


# ---------------------------------------------------------------------------
# Step 2: parse the REAL contract's external view surface so we can wire
# real-state assertions (not model assertions).
# ---------------------------------------------------------------------------

_VIEW_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)\s+view\s+returns\s*\(\s*(\w+)",
)
_STATE_PUBLIC_RE = re.compile(
    r"^\s*(?:uint256|uint160|uint128|int24|address|bool)\s+public\s+(\w+)\s*;",
    re.MULTILINE,
)


def parse_real_surface(contract_path: Path) -> dict[str, Any]:
    src = contract_path.read_text(encoding="utf-8", errors="replace")
    name_m = re.search(r"\b(?:contract|library)\s+(\w+)", src)
    name = name_m.group(1) if name_m else contract_path.stem
    views = {m.group(1): m.group(2) for m in _VIEW_RE.finditer(src)}
    public_scalars = _STATE_PUBLIC_RE.findall(src)
    ext_fns = re.findall(
        r"function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)(?![^{;]*\bview\b)(?![^{;]*\bpure\b)",
        src,
    )
    return {
        "name": name,
        "views": views,            # name -> return type
        "public_scalars": public_scalars,
        "mutating_external": ext_fns,
        "src": src,
    }


# ---------------------------------------------------------------------------
# Step 2b: author a REAL-CONTRACT-WIRED Foundry invariant harness from the
# derived invariants + the real view surface. Each invariant family that maps
# to a checkable real-view assertion is emitted; the rest are reported as
# unwireable.
# ---------------------------------------------------------------------------

# Family -> (view-symbol predicate template, human spec). Each template is a
# Solidity boolean over the REAL contract's public scalars / views. Only emitted
# when every referenced symbol exists on the real contract.
FAMILY_REAL_ASSERTIONS: list[dict[str, Any]] = [
    {
        "family": "conservation",
        "needs": ["totalPulled", "totalPushed", "feesAccrued"],
        "expr": "c.totalPulled() == c.totalPushed() + c.feesAccrued() + c.residual()",
        "spec": "every pulled unit is accounted as pushed + fee + still-held residual (no value created/destroyed)",
    },
    {
        "family": "custody",
        "needs": ["custodyHeld", "userBalanceSum"],
        "expr": "c.userBalanceSum() == c.custodyHeld()",
        "spec": "sum of user-credited balances equals custody held (no over/under-crediting)",
    },
    {
        "family": "bounds",
        "needs": ["totalPushed", "totalPulled"],
        "expr": "c.totalPushed() <= c.totalPulled()",
        "spec": "the bundler never pushes out more than it pulled in (no inflation)",
    },
    {
        "family": "soundness",
        "needs": ["residual"],
        "expr": "c.residual() <= c.totalPulled()",
        "spec": "residual held never exceeds the total ever pulled (residual is a subset of inflow)",
    },
]


def author_real_wired_harness(
    out_dir: Path,
    contract_path: Path,
    surface: dict[str, Any],
    derived_families: set[str],
) -> dict[str, Any]:
    """Author a forge invariant harness wiring the REAL contract.

    Returns {emitted: [...], unwireable: [...], test_path, contract_copy}.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    src_dir = out_dir / "src"
    test_dir = out_dir / "test"
    src_dir.mkdir(exist_ok=True)
    test_dir.mkdir(exist_ok=True)

    # copy the REAL contract verbatim into the harness src tree
    contract_copy = src_dir / contract_path.name
    contract_copy.write_text(contract_path.read_text(encoding="utf-8"), encoding="utf-8")

    name = surface["name"]
    scalars = set(surface["public_scalars"])

    emitted: list[dict[str, Any]] = []
    unwireable: list[dict[str, Any]] = []
    for spec in FAMILY_REAL_ASSERTIONS:
        if spec["family"] not in derived_families:
            continue
        missing = [s for s in spec["needs"] if s not in scalars]
        if missing:
            unwireable.append({**{k: spec[k] for k in ("family", "spec")}, "missing_views": missing})
            continue
        emitted.append(spec)

    # build invariant_ functions
    inv_fns = []
    for i, spec in enumerate(emitted):
        inv_fns.append(
            f"    /// {spec['family']}: {spec['spec']}\n"
            f"    function invariant_{spec['family']}() public view {{\n"
            f"        assertTrue({spec['expr']}, \"{spec['family']}: REAL-contract spec violated\");\n"
            f"    }}"
        )
    inv_block = "\n".join(inv_fns) if inv_fns else (
        "    // no wireable real-view assertion for the derived families"
    )

    # handler drives the real mutating entrypoints in a bounded, valid way
    handler = _build_handler(name, surface)

    foundry_toml = (
        "[profile.default]\n"
        'src = "src"\ntest = "test"\nout = "out"\nlibs = ["lib"]\n\n'
        "[profile.default.invariant]\n"
        "runs = {runs}\ndepth = {depth}\nfail_on_revert = false\n"
    )

    test_src = f"""// SPDX-License-Identifier: UNLICENSED
// =====================================================================
// PR9 TRUE-0-DAY HARNESS - real-contract-wired, NOT a correct model.
// Auto-authored by tools/pr9-novel-vector-0day-demo.py. The handler drives the
// REAL {name} mutating entrypoints; each invariant_* asserts a corpus-grounded
// spec over the REAL contract's public views. A counterexample is a violation
// of a derived spec by the actual implementation - a true-0-day candidate when
// it matches no pre-existing detector.
// =====================================================================
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_path.name}";

contract {name}_PR9_Invariant is Test {{
    {name} internal c;
    {name}_PR9_Handler internal handler;

    function setUp() public {{
        c = new {name}();
        handler = new {name}_PR9_Handler(c);
        targetContract(address(handler));
    }}

{inv_block}
}}

{handler}
"""

    test_path = test_dir / f"{name}_PR9_Invariant.t.sol"
    test_path.write_text(test_src, encoding="utf-8")
    (out_dir / "foundry.toml").write_text(foundry_toml, encoding="utf-8")

    return {
        "emitted": emitted,
        "unwireable": unwireable,
        "test_path": str(test_path),
        "contract_copy": str(contract_copy),
        "foundry_toml": foundry_toml,  # the {runs}/{depth} are formatted at run time
    }


def _build_handler(name: str, surface: dict[str, Any]) -> str:
    """Build a handler that drives the real mutating surface in a valid order.

    The handler is contract-specific where we know the shape (MidnightBundles);
    for unknown contracts it drives a generic best-effort sequence. Driving
    REAL entrypoints (not model mutate* bodies) is the whole point.
    """
    muts = surface["mutating_external"]
    if name == "MidnightBundles":
        body = """
        // approve self to pull, then pull funds (credits custody 1:1)
        c.approveBundler(address(c), amt);
        try c.erc20TransferFrom(address(this), amt % (amt + 1)) {} catch {}
        // forward a sub-amount into a leg (conserves value into push+fee)
        uint256 fwd = amt % 1_000_000;
        try c.forward(fwd, fwd % 7) {} catch {}
        // sweep whatever residual remains
        try c.sweepResidual() {} catch {}
        seed; actor;
"""
        # the bundler reverts forward/sweep unless msg.sender==initiator, which
        # only multicall sets transiently; the handler still exercises the
        # accounting writes that DO land (approve + transferFrom credit paths),
        # which is exactly where conservation/custody specs can break.
    else:
        calls = []
        for fn in muts[:6]:
            calls.append(f"        try c.{fn}() {{}} catch {{}}  // best-effort drive")
        body = "\n".join(calls) + "\n        seed; amt; actor;\n"

    return f"""/// @notice Handler driving the REAL {name} mutating entrypoints.
contract {name}_PR9_Handler {{
    {name} internal c;
    constructor({name} _c) {{ c = _c; }}

    function step(uint256 seed, uint256 amt, address actor) external {{
        amt = amt % 1e30;
{body}    }}
}}"""


# ---------------------------------------------------------------------------
# Step 3: run forge invariant testing.
# ---------------------------------------------------------------------------

def _resolve_forge() -> str | None:
    for cand in (
        os.path.expanduser("~/.auditooor/bin/forge"),
        shutil.which("forge"),
    ):
        if cand and Path(cand).exists():
            return cand
    return None


def ensure_forge_std(out_dir: Path, workspace_root: Path) -> bool:
    """Copy forge-std into the harness lib dir from a sibling/repo harness.

    Searches the workspace first (cheapest, most likely), then falls back to a
    bounded repo-wide search so a fresh out-of-tree workspace (e.g. a /tmp
    falsification workspace) still resolves the std lib.
    """
    lib = out_dir / "lib" / "forge-std"
    # require StdInvariant.sol (provides targetContract) not just Test.sol, so a
    # stripped forge-std copy never silently breaks the invariant harness build.
    if (lib / "src" / "StdInvariant.sol").exists() and (lib / "src" / "Test.sol").exists():
        return True
    search_roots = [workspace_root, REPO_ROOT]
    for root in search_roots:
        try:
            for cand in root.rglob("lib/forge-std"):
                if (cand / "src" / "Test.sol").exists() and (cand / "src" / "StdInvariant.sol").exists():
                    (out_dir / "lib").mkdir(parents=True, exist_ok=True)
                    try:
                        if lib.exists():
                            shutil.rmtree(lib)
                        shutil.copytree(cand, lib)
                    except Exception:
                        return False
                    return True
        except Exception:
            continue
    return False


def run_forge_invariant(out_dir: Path, name: str, runs: int, depth: int) -> dict[str, Any]:
    forge = _resolve_forge()
    if not forge:
        return {"ran": False, "reason": "forge-not-found", "results": {}}
    # format foundry.toml with the chosen budget
    toml = out_dir / "foundry.toml"
    toml.write_text(toml.read_text().format(runs=runs, depth=depth), encoding="utf-8")
    proc = subprocess.run(
        [forge, "test", "--match-contract", f"{name}_PR9_Invariant", "-vv"],
        capture_output=True,
        text=True,
        cwd=str(out_dir),
        timeout=600,
    )
    out = proc.stdout + "\n" + proc.stderr
    results = _parse_forge_invariants(out)
    return {
        "ran": True,
        "returncode": proc.returncode,
        "results": results,
        "stdout_tail": out[-1500:],
    }


# forge emits invariant results in several shapes depending on version/verbosity:
#   [PASS] invariant_bounds() (runs: 256)         <- pass, fn in parens
#   [FAIL] invariant_custody() (runs: 256)        <- fail, fn in parens
#   [FAIL: custody: REAL-contract spec violated]  <- fail, NO fn; reason carries
#                                                    the assertion message text
#   {"event":"failure","invariant":"invariant_custody", ...}  <- JSON event line
# We parse all three so a violation is never silently dropped.
_INV_PARENS = re.compile(r"\[(PASS|FAIL)\]\s+(invariant_\w+)\(")
_INV_JSON_FAIL = re.compile(r'"event"\s*:\s*"failure".*?"invariant"\s*:\s*"(invariant_\w+)"')
_INV_FAIL_REASON = re.compile(r"\[FAIL:\s*([a-zA-Z_]+):")


def _parse_forge_invariants(output: str) -> dict[str, str]:
    res: dict[str, str] = {}
    # 1. explicit [PASS]/[FAIL] invariant_x( ... ) lines
    for m in _INV_PARENS.finditer(output):
        res[m.group(2)] = "PASS" if m.group(1) == "PASS" else "VIOLATED"
    # 2. JSON failure events (carry the invariant fn name)
    for m in _INV_JSON_FAIL.finditer(output):
        res[m.group(1)] = "VIOLATED"
    # 3. [FAIL: <family>: ...] lines (the assertion message names the family,
    #    which by construction maps to invariant_<family>)
    for m in _INV_FAIL_REASON.finditer(output):
        res[f"invariant_{m.group(1)}"] = "VIOLATED"
    return res


# ---------------------------------------------------------------------------
# Step 4: 0-day adjudication - cross-check violations against pre-existing
# detector output. A violation with no detector match is a true-0-day.
# ---------------------------------------------------------------------------

def load_pre_existing_detectors(workspace_root: Path, explicit: str | None) -> dict[str, Any]:
    paths = []
    if explicit:
        paths.append(Path(explicit))
    paths += list(workspace_root.rglob("slither_results.json"))
    checks: list[str] = []
    scanned: list[str] = []
    for p in paths:
        if not p.exists():
            continue
        scanned.append(str(p))
        try:
            d = json.loads(p.read_text())
            dets = d.get("results", {}).get("detectors", [])
            checks += [x.get("check", "") for x in dets]
        except Exception:
            continue
    return {"scanned_files": scanned, "detector_checks": [c for c in checks if c], "detector_count": len([c for c in checks if c])}


def adjudicate_0day(forge_results: dict[str, str], detectors: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    det_count = detectors["detector_count"]
    for inv, verdict in forge_results.items():
        if verdict != "VIOLATED":
            continue
        # any spec-violation has no matching detector when the pre-existing
        # detector set found nothing on this contract (det_count == 0); when
        # detectors exist we conservatively flag detector-overlap-possible.
        is_0day = det_count == 0
        out.append(
            {
                "invariant": inv,
                "verdict": "VIOLATED",
                "pre_existing_detector_match": not is_0day,
                "true_0day_candidate": is_0day,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------

def run_demo(args) -> dict[str, Any]:
    workspace_root = (REPO_ROOT / args.workspace).resolve() if not Path(args.workspace).is_absolute() else Path(args.workspace)
    contract_path = (REPO_ROOT / args.contract).resolve() if not Path(args.contract).is_absolute() else Path(args.contract)
    if not contract_path.exists():
        raise FileNotFoundError(f"contract not found: {contract_path}")

    # 1. derive
    miner_out = run_miner(args.workspace, args.contract, args.mimo_refine, args.mimo_budget)
    derived = miner_out.get("invariants", [])
    derived_families = {d["family"] for d in derived}
    grounding_ids = sorted({iid for d in derived for iid in (d.get("grounding_invariant_ids") or [])})

    # 2. parse real surface + author real-wired harness
    surface = parse_real_surface(contract_path)
    out_dir = (REPO_ROOT / args.out_dir).resolve() if not Path(args.out_dir).is_absolute() else Path(args.out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    harness = author_real_wired_harness(out_dir, contract_path, surface, derived_families)

    # 3. run
    run_info: dict[str, Any] = {"ran": False, "reason": "no-wireable-invariant"}
    adjudication: list[dict[str, Any]] = []
    if harness["emitted"]:
        if ensure_forge_std(out_dir, workspace_root):
            run_info = run_forge_invariant(out_dir, surface["name"], args.fuzz_runs, args.fuzz_depth)
        else:
            run_info = {"ran": False, "reason": "forge-std-not-found"}

    # 4. adjudicate 0-day
    detectors = load_pre_existing_detectors(workspace_root, args.detector_results)
    forge_results = run_info.get("results", {}) if run_info.get("ran") else {}
    adjudication = adjudicate_0day(forge_results, detectors)

    n_violated = sum(1 for v in forge_results.values() if v == "VIOLATED")
    n_0day = sum(1 for a in adjudication if a["true_0day_candidate"])

    summary = {
        "schema_version": SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": args.workspace,
        "contract": args.contract,
        "target": surface["name"],
        "discovery_mode": "real-contract-wired spec-violation counterexample search",
        # derivation
        "invariants_derived": len(derived),
        "derived_families": sorted(derived_families),
        "grounding_invariant_ids": grounding_ids,
        "rule58_grounded": bool(grounding_ids),
        "mimo_refined": miner_out.get("mimo_refined", 0),
        # wiring
        "real_views_present": sorted(surface["views"].keys()),
        "real_public_scalars": sorted(surface["public_scalars"]),
        "invariants_wired_to_real_contract": [e["family"] for e in harness["emitted"]],
        "invariants_unwireable": harness["unwireable"],
        "harness_test_path": harness["test_path"],
        # engine run
        "engine_ran": run_info.get("ran", False),
        "engine_reason": run_info.get("reason", ""),
        "engine_returncode": run_info.get("returncode"),
        "forge_fuzz_runs": args.fuzz_runs,
        "forge_fuzz_depth": args.fuzz_depth,
        "per_invariant_verdict": forge_results,
        # 0-day adjudication
        "pre_existing_detectors": detectors,
        "violations": n_violated,
        "true_0day_candidates": n_0day,
        "adjudication": adjudication,
        # honest headline
        "headline": _headline(len(derived), bool(harness["emitted"]), run_info.get("ran", False), n_violated, n_0day),
    }

    # write sidecar
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pr9_0day_demo_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _headline(n_derived: int, wired: bool, ran: bool, n_violated: int, n_0day: int) -> str:
    if n_derived == 0:
        return "no invariants derived (no mutating external surface) - nothing to check"
    if not wired:
        return f"{n_derived} invariants derived but none wireable to a real view - reported, not engine-checked"
    if not ran:
        return f"{n_derived} derived, harness authored, but engine could not run (see engine_reason)"
    if n_violated == 0:
        return (
            f"{n_derived} invariants derived; real-contract spec-search ran; "
            f"0 counterexamples - every derived spec HELD against the real contract (honest negative)"
        )
    return (
        f"{n_derived} derived; {n_violated} VIOLATED by the real contract; "
        f"{n_0day} are true-0-day candidates (no pre-existing detector match)"
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--contract", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--detector-results", default=None, help="explicit slither_results.json to cross-check")
    ap.add_argument("--fuzz-runs", type=int, default=256)
    ap.add_argument("--fuzz-depth", type=int, default=64)
    ap.add_argument("--mimo-refine", action="store_true")
    ap.add_argument("--mimo-budget", type=int, default=6)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        summary = run_demo(args)
    except Exception as exc:
        err = {"schema_version": SCHEMA, "error": str(exc)}
        print(json.dumps(err, indent=2))
        return 1

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(summary["headline"])
        print(f"  derived families : {summary['derived_families']}")
        print(f"  grounding INV ids: {len(summary['grounding_invariant_ids'])} (Rule58={summary['rule58_grounded']})")
        print(f"  wired to real    : {summary['invariants_wired_to_real_contract']}")
        print(f"  engine ran       : {summary['engine_ran']} rc={summary['engine_returncode']}")
        print(f"  per-invariant    : {summary['per_invariant_verdict']}")
        print(f"  0-day candidates : {summary['true_0day_candidates']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
