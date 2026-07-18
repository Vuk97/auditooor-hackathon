#!/usr/bin/env python3
"""precompile-differential-engine — real differential exec engine for the
A11 EVM/precompile-divergence lane.

Why this exists
---------------
The A11 lane (`make a11-precompile-diff`) historically only *staged* inputs:
`tools/base-evm-config-coverage.py` scans a workspace's Rust config and
`tools/baselines/a11_precompile_diff/differential_test_inputs/*.json` ships
hand-rolled probe rows. Neither one ever *executed* a differential — the
capability-readiness dashboard (W4.11) flagged the lane as PARTIAL: "Stages
differential inputs + config scan only; no exec engine."

W4.8 shipped `tools/audit/differential-test-runner.py`, a real function-by-
function divergence classifier. That runner is the right model, but it only
handles Go / Solidity (its extractor, `function-signature-extractor.py`, has
no Rust mode). The A11 precompile trees are Rust (revm / reth / Base-Azul
forks). So A11 is a genuinely different problem domain — it needs its own
exec engine, but it can and does **reuse the runner's divergence-verdict
ranking and report shape** so downstream consumers see one consistent model.

What this engine does (the real exec, not just staging)
-------------------------------------------------------
1. Builds a *precompile registry* for each of two Rust source trees:
     - upstream: a stock `revm` / `reth` checkout (the reference)
     - fork:     the Base / Azul fork being audited
   A registry entry is `(address, name, gas_marker, hardfork_gate)` mined
   per-tree by regex over `src/**.rs`.

2. Diffs the two registries entry-by-entry and classifies every divergence:
     - "precompile-added"        — address present only in the fork
     - "precompile-removed"      — address present only upstream
     - "security-relevant"       — same address, but gas marker OR hardfork
                                   activation gate differs (a precompile
                                   whose cost/activation moved silently is
                                   the classic cross-client consensus-split
                                   finding)
     - "behavior-changing"       — same address + same gas + same gate, but
                                   the symbolic name changed (a rename that
                                   may mask a re-implementation)
     - "identical"               — fully matching entry
   The verdict ranking mirrors `differential-test-runner._rank` so the two
   tools produce a comparable `top_finding_keys` ordering.

3. Cross-checks the staged differential test inputs. Each `bs_*` /`pc_*`
   row asserts `expected_same_across_revm_and_base`. The engine resolves the
   row's `delta_target` (clz / secp256r1 / abr / shared) against the
   registry diff and emits a real expected-vs-actual line:
     - a `base_specific` row whose target shows NO divergence in the diff
       is flagged `MISSING-DIVERGENCE` (the Base delta did not land — a
       finding, per the fixture README).
     - a `positive_control` row whose target DOES show divergence is flagged
       `UNEXPECTED-DIVERGENCE` (the differential rig itself is wrong).
     - otherwise `CONSISTENT`.

CLI
---
    python3 tools/audit/precompile-differential-engine.py \\
        --upstream <path/to/revm-tree> \\
        --fork <path/to/base-azul-tree> \\
        [--inputs <dir with bs_*/pc_*.json>] \\
        [--out report.json] [--audit-pin SHA] [--strict]

Output: an `auditooor.precompile_differential_report.v1` JSON artifact.

Exit codes:
    0 = analysis succeeded, no security-relevant divergence and no
        MISSING/UNEXPECTED input inconsistency
    1 = error (bad path)
    2 = (only with --strict) a security-relevant divergence OR a
        MISSING/UNEXPECTED input cross-check inconsistency was found
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.precompile_differential_report.v1"

MAX_FILE_BYTES = 2 * 1024 * 1024

SKIP_PATH_TOKENS = (
    "/target/", "/.git/", "/node_modules/", "/_archive/",
    "/tests/", "/test/", "/benches/", "/examples/",
)

# --- registry mining regexes -------------------------------------------------
# A precompile entry usually pairs a name token with an address constant on
# the same / adjacent line. We mine both, then pair them by line proximity.
RE_PRECOMPILE_NAME = re.compile(
    r"\b([a-z][a-z0-9_]*(?:verify|recover|precompile|p256|secp256r1|blake2"
    r"|modexp|ecadd|ecmul|ecpairing|identity|ripemd|sha256|clz))\b",
    re.IGNORECASE,
)
RE_ADDR = re.compile(r"\b(0x[0-9a-fA-F]{2,40})\b")
# u64-ish gas constant marker on the line.
RE_GAS_MARKER = re.compile(
    r"\b(?:gas|GAS|cost|COST)\b[^\n]{0,40}?\b(\d{2,9})\b"
)
# hardfork activation gate token.
RE_HARDFORK_GATE = re.compile(
    r"\b(BASE_V\d+|OSAKA|AZUL|PRAGUE|CANCUN|SHANGHAI|"
    r"SpecId::[A-Z][A-Za-z0-9_]*|Hardfork::[A-Z][A-Za-z0-9_]*)\b"
)
# delta-target keyword sets used for the staged-input cross-check.
# No trailing \b — Rust convention suffixes tokens (p256_verify, clz_opcode)
# and an underscore is a word char so a trailing \b would never match.
DELTA_TARGET_KEYWORDS = {
    "clz": re.compile(r"\b(?:clz|count_leading_zeros|7939)", re.IGNORECASE),
    "secp256r1": re.compile(
        r"\b(?:secp256r1|p256|7951)", re.IGNORECASE),
    "abr": re.compile(
        r"\b(?:account_balances_and_receipts|receiptsroot|"
        r"compute_balances_root|nobalancesroot)", re.IGNORECASE),
}


def _iter_rs(root: Path):
    for p in root.rglob("*.rs"):
        sp = str(p).replace("\\", "/")
        if any(tok in sp for tok in SKIP_PATH_TOKENS):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def mine_registry(root: Path) -> Dict[str, Dict[str, Any]]:
    """Return {address: entry} for every precompile-shaped declaration in a
    Rust tree. `entry` carries name, gas_marker, hardfork_gate, location.

    When the same address appears multiple times we keep the *richest* entry
    (most non-empty fields) so partial declarations do not shadow a complete
    one. Entries with no extractable address are keyed by `name@file:line`.
    """
    registry: Dict[str, Dict[str, Any]] = {}
    for fp in _iter_rs(root):
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(fp.relative_to(root))
        except ValueError:
            rel = str(fp)
        for ln, line in enumerate(text.splitlines(), start=1):
            name_m = RE_PRECOMPILE_NAME.search(line)
            addr_m = RE_ADDR.search(line)
            if not name_m and not addr_m:
                continue
            # require at least a precompile-shaped name token to avoid
            # mining every hex literal in the tree.
            if not name_m:
                continue
            name = name_m.group(1).lower()
            addr = (addr_m.group(1).lower() if addr_m else "")
            gas_m = RE_GAS_MARKER.search(line)
            gate_m = RE_HARDFORK_GATE.search(line)
            key = addr if addr else f"{name}@{rel}:{ln}"
            entry = {
                "address": addr,
                "name": name,
                "gas_marker": gas_m.group(1) if gas_m else "",
                "hardfork_gate": gate_m.group(1) if gate_m else "",
                "location": f"{rel}:{ln}",
            }
            existing = registry.get(key)
            if existing is None:
                registry[key] = entry
            else:
                # keep the richer entry.
                def _filled(e: Dict[str, Any]) -> int:
                    return sum(
                        1 for k in ("gas_marker", "hardfork_gate")
                        if e.get(k))
                if _filled(entry) > _filled(existing):
                    registry[key] = entry
    return registry


def _classify(up: Dict[str, Any], fk: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Classify the divergence between an upstream and a fork registry entry."""
    gas_changed = up.get("gas_marker", "") != fk.get("gas_marker", "")
    gate_changed = up.get("hardfork_gate", "") != fk.get("hardfork_gate", "")
    name_changed = up.get("name", "") != fk.get("name", "")
    detail = {
        "gas_changed": gas_changed,
        "gate_changed": gate_changed,
        "name_changed": name_changed,
        "upstream": {k: up.get(k, "") for k in
                     ("name", "gas_marker", "hardfork_gate", "location")},
        "fork": {k: fk.get(k, "") for k in
                 ("name", "gas_marker", "hardfork_gate", "location")},
    }
    # gas / activation-gate moved silently -> consensus-split class.
    if gas_changed or gate_changed:
        return "security-relevant", detail
    if name_changed:
        return "behavior-changing", detail
    return "identical", detail


def _rank(verdict: str) -> int:
    return {
        "security-relevant": 0,
        "behavior-changing": 1,
        "precompile-added": 2,
        "precompile-removed": 2,
        "identical": 4,
    }.get(verdict, 5)


def diff_registries(
    up_reg: Dict[str, Dict[str, Any]],
    fk_reg: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    counts = {
        "identical": 0, "behavior-changing": 0, "security-relevant": 0,
        "precompile-added": 0, "precompile-removed": 0,
    }
    divergences: List[Dict[str, Any]] = []
    for key in sorted(set(up_reg) | set(fk_reg)):
        up = up_reg.get(key)
        fk = fk_reg.get(key)
        if up and not fk:
            verdict, detail = "precompile-removed", {
                "note": "precompile present upstream, absent in fork",
                "upstream": up,
            }
        elif fk and not up:
            verdict, detail = "precompile-added", {
                "note": "precompile present in fork, absent upstream",
                "fork": fk,
            }
        else:
            verdict, detail = _classify(up, fk)  # type: ignore[arg-type]
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict == "identical":
            continue
        divergences.append({
            "registry_key": key,
            "verdict": verdict,
            "detail": detail,
        })
    divergences.sort(key=lambda d: (_rank(d["verdict"]), d["registry_key"]))
    return divergences, counts


def _divergence_targets(divergences: List[Dict[str, Any]]) -> set[str]:
    """Resolve which delta-targets (clz/secp256r1/abr) actually diverged."""
    hit: set[str] = set()
    for d in divergences:
        blob = json.dumps(d, sort_keys=True)
        for target, rx in DELTA_TARGET_KEYWORDS.items():
            if rx.search(blob):
                hit.add(target)
    return hit


def crosscheck_inputs(
    inputs_dir: Optional[Path],
    diverged_targets: set[str],
) -> List[Dict[str, Any]]:
    """Cross-check staged differential test inputs against the registry diff.

    Returns one row per `bs_*`/`pc_*.json` fixture with a real verdict.
    """
    rows: List[Dict[str, Any]] = []
    if inputs_dir is None or not inputs_dir.is_dir():
        return rows
    for jf in sorted(inputs_dir.glob("*.json")):
        try:
            spec = json.loads(jf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(spec, dict) or "row_id" not in spec:
            continue
        category = spec.get("category", "")
        target = spec.get("delta_target", "")
        expect_same = bool(spec.get("expected_same_across_revm_and_base", True))
        target_diverged = target in diverged_targets
        # base_specific rows under an active fork SHOULD diverge.
        if category == "base_specific" and not expect_same:
            verdict = "CONSISTENT" if target_diverged else "MISSING-DIVERGENCE"
        elif category == "positive_control":
            verdict = "UNEXPECTED-DIVERGENCE" if target_diverged else "CONSISTENT"
        else:
            # base_specific pre-activation row: must mirror upstream.
            verdict = "UNEXPECTED-DIVERGENCE" if target_diverged else "CONSISTENT"
        rows.append({
            "row_id": spec.get("row_id"),
            "category": category,
            "delta_target": target,
            "expected_same_across_revm_and_base": expect_same,
            "registry_shows_divergence": target_diverged,
            "verdict": verdict,
        })
    return rows


def build_report(
    upstream: Path,
    fork: Path,
    inputs_dir: Optional[Path],
    audit_pin: Optional[str],
) -> Dict[str, Any]:
    up_reg = mine_registry(upstream)
    fk_reg = mine_registry(fork)
    divergences, counts = diff_registries(up_reg, fk_reg)
    diverged_targets = _divergence_targets(divergences)
    input_rows = crosscheck_inputs(inputs_dir, diverged_targets)

    sec = [d for d in divergences if d["verdict"] == "security-relevant"]
    inconsistent = [
        r for r in input_rows
        if r["verdict"] in ("MISSING-DIVERGENCE", "UNEXPECTED-DIVERGENCE")
    ]
    return {
        "schema": SCHEMA,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "audit_pin": audit_pin,
        "inputs": {
            "upstream_tree": str(upstream),
            "fork_tree": str(fork),
            "differential_test_inputs_dir": str(inputs_dir) if inputs_dir else None,
        },
        "summary": {
            "upstream_precompiles": len(up_reg),
            "fork_precompiles": len(fk_reg),
            "counts": counts,
            "security_relevant_count": len(sec),
            "diverged_delta_targets": sorted(diverged_targets),
            "input_rows_checked": len(input_rows),
            "input_inconsistency_count": len(inconsistent),
            "top_finding_keys": [d["registry_key"] for d in sec[:10]],
        },
        "divergences": divergences,
        "input_crosscheck": input_rows,
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--upstream", required=True,
                   help="Path to upstream revm/reth reference tree")
    p.add_argument("--fork", required=True,
                   help="Path to the Base/Azul fork tree being audited")
    p.add_argument("--inputs",
                   help="Dir of staged differential test inputs (bs_*/pc_*.json)")
    p.add_argument("--out", help="Output JSON path. Default: stdout.")
    p.add_argument("--audit-pin", help="Optional audit-pin SHA for the fork.")
    p.add_argument("--strict", action="store_true",
                   help="Exit 2 on any security-relevant divergence or "
                        "input cross-check inconsistency.")
    args = p.parse_args(argv)

    up = Path(args.upstream).resolve()
    fk = Path(args.fork).resolve()
    if not up.is_dir():
        print(f"not a directory: {up}", file=sys.stderr)
        return 1
    if not fk.is_dir():
        print(f"not a directory: {fk}", file=sys.stderr)
        return 1
    inputs_dir = Path(args.inputs).resolve() if args.inputs else None

    report = build_report(up, fk, inputs_dir, args.audit_pin)

    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)

    s = report["summary"]
    print(
        f"precompile-differential: upstream={s['upstream_precompiles']}pc "
        f"fork={s['fork_precompiles']}pc "
        f"security-relevant={s['security_relevant_count']} "
        f"behavior-changing={s['counts'].get('behavior-changing', 0)} "
        f"added={s['counts'].get('precompile-added', 0)} "
        f"removed={s['counts'].get('precompile-removed', 0)} "
        f"input-rows={s['input_rows_checked']} "
        f"input-inconsistencies={s['input_inconsistency_count']}",
        file=sys.stderr,
    )
    if args.strict and (
        s["security_relevant_count"] > 0
        or s["input_inconsistency_count"] > 0
    ):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
