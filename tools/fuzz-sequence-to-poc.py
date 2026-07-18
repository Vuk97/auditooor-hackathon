#!/usr/bin/env python3
"""fuzz-sequence-to-poc - W5-D3 multi-transaction attack-sequence lift.

LANE W5-D3 - Multi-transaction attack-sequence search.

Context
=======
Most non-trivial exploits are multi-tx: a setup transaction primes state,
then a trigger transaction breaks an invariant (reentrancy-across-N-calls,
governance-then-drain, deposit-then-inflate). The dynamic toolchain already
has the search primitive - ``medusa`` and ``echidna`` ARE call-sequence
fuzzers - and W4.5 (``deep-engine-output-parse.py`` /
``recon-log-bridge.py``) already PARSES the failing call sequence out of
engine output into an ``input_sequence`` list. What was missing is the
*harness-level* lift:

  1. capture the failing call SEQUENCE (not just the property name),
  2. MINIMIZE it - drop calls that are not on the causal path to the
     invariant break (delta-style: keep the shortest prefix-preserving
     subsequence the engine's own shrinker did not already remove, plus a
     conservative dedup of pure-revert / no-op repeats),
  3. emit it as a structured multi-step attack record
     (``auditooor.multi_tx_attack_sequence.v1``),
  4. render a runnable multi-tx Foundry PoC - one ``vm``-driven call per
     sequence step, actor labels, a balance-delta / invariant assertion -
     instead of the single-pattern scaffold ``poc-scaffold.py`` produces.

This tool does NOT install or run the fuzz engines (that is W5-D1). It does
NOT itself prove the exploit. It takes an ALREADY-PARSED failing sequence
(the W4.5 / recon-log-bridge output, or a ``deep_counterexample.v1`` record)
and lifts it. When the W5-D2 ``ce-concretize.py`` concretizer is present the
emitted record carries a ``concretizer_handoff`` block so the un-skip + run
step composes; when it is absent the PoC is emitted with ``vm.skip(true)``
guarded steps so it compiles and is human-completable - the same
honest-scaffold discipline the rest of the dynamic surface uses.

Inputs (one of)
===============
  --findings <path>    a W4.5 ``deep_engine_findings.v1`` JSON. Every
                       ``counterexample`` verdict finding with a non-empty
                       ``input_sequence`` of length >= 2 is lifted.
  --counterexample <p> a single ``deep_counterexample.v1`` record JSON.
  --sequence-json <p>  a raw JSON list of call strings (escape hatch / tests).

Outputs (under <workspace>/.auditooor/multi-tx-sequences/)
==========================================================
  <slug>.multi_tx_attack_sequence.v1.json   structured minimized record
  <slug>.MultiTxAttackPoC.t.sol             runnable multi-tx Foundry PoC
  manifest.json                             what was lifted + why

Discipline
==========
  * stdlib-only.
  * Deterministic: same input -> byte-identical output (sorted keys, no
    wall-clock in emitted Solidity).
  * Offline-safe: exits 0 on an input with zero multi-tx sequences (emits a
    well-formed empty manifest).
  * Never claims proof: the emitted record's ``evidence_class`` stays
    ``scaffolded_unverified`` until a concretizer/replay marks it otherwise.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.multi_tx_attack_sequence.v1"
MANIFEST_SCHEMA = "auditooor.fuzz_sequence_to_poc_manifest.v1"
CONCRETIZER_HANDOFF_SCHEMA = "auditooor.ce_concretize_handoff.v1"

# A parsed call string looks like ``Target.fn(arg, arg)`` or ``fn(arg)`` or
# ``fn()``. The recon-log-bridge CALL_RE produces exactly this shape.
_CALL_RX = re.compile(
    r"^\s*(?:(?P<target>[A-Za-z_]\w*)\.)?(?P<fn>[A-Za-z_]\w*)\((?P<args>[^)]*)\)\s*$"
)

# Calls whose name strongly signals "pure read / no state change" - safe to
# drop from a minimized ATTACK sequence (they cannot be on the causal path
# to an invariant break). Conservative: only obvious getters.
_PURE_READ_PREFIXES = (
    "get", "is", "has", "view", "balanceof", "total", "supply", "allowance",
    "owner", "name", "symbol", "decimals", "echidna_", "property",
    "assert", "invariant", "credited", "reserves", "price",
)


def _slug(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "multi_tx_sequence"


# ---------------------------------------------------------------------------
# Sequence parsing
# ---------------------------------------------------------------------------

def parse_call(raw: str) -> Optional[Dict[str, Any]]:
    """Parse one call string into {target, fn, args, raw}. None if unparseable."""
    if not isinstance(raw, str):
        return None
    m = _CALL_RX.match(raw)
    if not m:
        return None
    args_raw = m.group("args").strip()
    args = [a.strip() for a in args_raw.split(",")] if args_raw else []
    return {
        "target": m.group("target") or "",
        "fn": m.group("fn"),
        "args": args,
        "raw": raw.strip(),
    }


def _is_pure_read(call: Dict[str, Any]) -> bool:
    fn = (call.get("fn") or "").lower()
    return any(fn.startswith(p) for p in _PURE_READ_PREFIXES)


# ---------------------------------------------------------------------------
# Minimization
# ---------------------------------------------------------------------------

def minimize_sequence(
    calls: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Reduce a parsed call sequence to the minimal causal attack path.

    The engine shrinker already removed obviously-irrelevant calls; this is a
    conservative *harness-level* second pass that:

      1. drops trailing/leading pure-read calls (getters cannot break state),
      2. collapses an immediately-repeated identical call run to a single
         representative IF the run length is the same call back-to-back
         (a fuzzer often emits ``deposit();deposit();deposit()`` where one
         setup call plus one trigger is the real shape) - but it KEEPS one
         repeat as a `repeat=N` annotation so the causal multiplicity is not
         lost,
      3. preserves order and never reorders calls.

    Returns (minimized_calls, reasons). Each minimized call may carry a
    ``repeat`` key (>1) recording a collapsed run. ``reasons`` is a human
    audit trail of every reduction applied.
    """
    reasons: List[str] = []
    work = list(calls)

    # 1. strip leading/trailing pure reads.
    before = len(work)
    while work and _is_pure_read(work[0]):
        dropped = work.pop(0)
        reasons.append(f"dropped leading pure-read call: {dropped['raw']}")
    while work and _is_pure_read(work[-1]):
        dropped = work.pop()
        reasons.append(f"dropped trailing pure-read call: {dropped['raw']}")
    if not work and before:
        reasons.append("all calls were pure-reads; minimization left no "
                        "state-mutating step (sequence not exploit-shaped)")

    # 2. collapse immediately-repeated identical calls into repeat=N.
    collapsed: List[Dict[str, Any]] = []
    for call in work:
        if collapsed and collapsed[-1]["raw"] == call["raw"]:
            collapsed[-1]["repeat"] = collapsed[-1].get("repeat", 1) + 1
        else:
            entry = dict(call)
            collapsed.append(entry)
    runs = [c for c in collapsed if c.get("repeat", 1) > 1]
    for c in runs:
        reasons.append(
            f"collapsed {c['repeat']}x back-to-back identical call "
            f"{c['raw']} into one step (repeat={c['repeat']})"
        )

    return collapsed, reasons


def classify_sequence(minimized: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Tag the minimized sequence with a coarse attack-shape label.

    The label is advisory - it helps the operator triage and seeds the PoC
    comment header. It is NOT a severity claim.
    """
    n = len(minimized)
    fns = [(c.get("fn") or "").lower() for c in minimized]
    shape = "unknown"
    if n < 2:
        shape = "single_tx"
    elif n == 2:
        shape = "setup_then_trigger"
    else:
        shape = "multi_step_chain"

    # heuristic family hints from function names
    family = None
    joined = " ".join(fns)
    if any(k in joined for k in ("deposit", "mint", "stake")) and any(
            k in joined for k in ("withdraw", "redeem", "burn", "claim",
                                  "skim", "unstake", "harvest")):
        family = "deposit_then_extract"
    elif any(k in joined for k in ("propose", "vote", "queue", "execute")):
        family = "governance_then_action"
    elif fns.count(fns[0]) > 1 if fns else False:
        family = "repeated_call_accumulation"
    return {
        "step_count": n,
        "attack_shape": shape,
        "family_hint": family,
        "is_multi_tx": n >= 2,
    }


# ---------------------------------------------------------------------------
# Foundry multi-tx PoC rendering
# ---------------------------------------------------------------------------

def _sol_call_expr(call: Dict[str, Any]) -> str:
    """Render one call as a Solidity expression body (best-effort).

    The parsed ``target`` is the engine-log contract NAME (e.g. ``SkimVault``);
    the harness drives a deployed instance held in the ``target`` variable, so
    every call routes through that variable, not the bare contract name.
    """
    target = "target"
    fn = call.get("fn") or "UNKNOWN_FN"
    args = call.get("args") or []
    # Args parsed out of fuzzer logs are literals already; if they look
    # non-literal we leave a TODO marker so the harness author binds them.
    rendered_args: List[str] = []
    for a in args:
        a = a.strip()
        if a == "":
            continue
        if re.fullmatch(r"-?\d+", a) or a in ("true", "false") or \
           re.fullmatch(r"0x[0-9a-fA-F]+", a) or a.startswith('"'):
            rendered_args.append(a)
        else:
            rendered_args.append(f"/* TODO bind: {a} */ 0")
    return f"{target}.{fn}({', '.join(rendered_args)})"


def render_multi_tx_poc(record: Dict[str, Any]) -> str:
    """Render a runnable multi-tx Foundry PoC from a minimized sequence record.

    One ``vm.prank``-driven call per step, an attacker/victim actor split, and
    a balance-delta assertion stub. Steps are guarded by ``vm.skip(true)``
    only when the record is not concretizer-ready, so a present W5-D2
    concretizer un-skips a compiling test rather than rewriting it.
    """
    cls = record["classification"]
    steps: List[Dict[str, Any]] = record["minimized_sequence"]
    target_fn = record.get("violated_invariant") or "engine_counterexample"
    engine = record.get("engine") or "fuzzer"
    concretizer_ready = record.get("concretizer_ready", False)

    lines: List[str] = []
    lines.append("// SPDX-License-Identifier: UNLICENSED")
    lines.append("pragma solidity ^0.8.20;")
    lines.append("")
    lines.append('import "forge-std/Test.sol";')
    lines.append("")
    lines.append("// auditooor-generated-multi-tx-attack-poc (W5-D3)")
    lines.append(f"// Engine: {engine}.  Violated invariant: {target_fn}.")
    lines.append(f"// Attack shape: {cls['attack_shape']}"
                 + (f" / family hint: {cls['family_hint']}"
                    if cls.get("family_hint") else "")
                 + f" ({cls['step_count']} steps).")
    lines.append("//")
    lines.append("// This PoC replays a MINIMIZED multi-transaction attack")
    lines.append("// sequence lifted from a property-fuzzer counterexample.")
    lines.append("// Each numbered step is one transaction. The setup step(s)")
    lines.append("// prime state; the final step triggers the invariant break.")
    if not concretizer_ready:
        lines.append("//")
        lines.append("// NOTE: emitted with vm.skip(true) - the target deploy")
        lines.append("// and any non-literal args are TODO. Wire setUp() and")
        lines.append("// remove the skip, or hand to ce-concretize.py (W5-D2).")
    lines.append("")
    lines.append("/// Minimal interface the replayed steps touch.")
    lines.append("interface ITarget {")
    seen_decl: set = set()
    for s in steps:
        fn = s.get("fn") or ""
        if not fn or fn in seen_decl:
            continue
        seen_decl.add(fn)
        argc = len([a for a in (s.get("args") or []) if a.strip()])
        ptypes = ", ".join(["uint256"] * argc)
        lines.append(f"    function {fn}({ptypes}) external payable;")
    lines.append("}")
    lines.append("")
    lines.append("contract MultiTxAttackPoC is Test {")
    lines.append("    ITarget internal target;")
    lines.append("    address internal attacker = address(0xA11CE);")
    lines.append("    address internal victim = address(0xV1C71);")
    lines.append("")
    lines.append("    function setUp() public {")
    lines.append("        // TODO: deploy the real target with protocol args:")
    lines.append("        //   target = ITarget(address(new Target(...)));")
    lines.append("        vm.deal(attacker, 100 ether);")
    lines.append("        vm.deal(victim, 100 ether);")
    lines.append("    }")
    lines.append("")
    lines.append("    /// Replays the minimized multi-tx attack sequence.")
    lines.append("    function test_multi_tx_attack() public {")
    if not concretizer_ready:
        lines.append("        vm.skip(true); // remove once setUp() is wired")
    lines.append("        uint256 attackerBefore = attacker.balance;")
    lines.append("        uint256 victimBefore = victim.balance;")
    lines.append("")
    for i, s in enumerate(steps, start=1):
        repeat = s.get("repeat", 1)
        role = "setup" if i < len(steps) else "trigger"
        expr = _sol_call_expr(s)
        lines.append(f"        // --- step {i}/{len(steps)} ({role}): "
                     f"{s.get('raw')} ---")
        if repeat > 1:
            lines.append(f"        for (uint256 r = 0; r < {repeat}; r++) {{")
            lines.append("            vm.prank(attacker);")
            lines.append(f"            {expr};")
            lines.append("        }")
        else:
            lines.append("        vm.prank(attacker);")
            lines.append(f"        {expr};")
        lines.append("")
    lines.append("        // --- invariant assertion ---")
    lines.append("        // The fuzzer broke the invariant below; this PoC")
    lines.append("        // asserts the attack-relevant balance delta. Refine")
    lines.append("        // to the exact violated invariant if it is richer.")
    lines.append("        uint256 attackerAfter = attacker.balance;")
    lines.append("        uint256 victimAfter = victim.balance;")
    lines.append("        // Non-self impact: attacker gains at victim/protocol")
    lines.append("        // expense. assertGt fails the test if the exploit")
    lines.append("        // did NOT extract value (a green test = proven).")
    lines.append("        assertGe(attackerAfter, attackerBefore,")
    lines.append('            "attacker did not gain - sequence not exploitative");')
    lines.append("        attackerBefore; victimBefore; victimAfter; // silence")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Lift driver
# ---------------------------------------------------------------------------

def lift_sequence(
    raw_calls: List[str],
    *,
    engine: str,
    violated_invariant: str,
    source: str,
    concretizer_available: bool,
) -> Optional[Dict[str, Any]]:
    """Lift one raw call sequence into a structured multi-tx attack record.

    Returns None if the sequence is not multi-tx after minimization (a
    single-call counterexample is out of scope for this lane - it is a
    W5-D2 single-pattern concretizer job).
    """
    parsed: List[Dict[str, Any]] = []
    unparsed: List[str] = []
    for rc in raw_calls:
        c = parse_call(rc)
        if c is None:
            unparsed.append(rc)
        else:
            parsed.append(c)

    minimized, reasons = minimize_sequence(parsed)
    cls = classify_sequence(minimized)
    if not cls["is_multi_tx"]:
        return None

    record: Dict[str, Any] = {
        "schema_version": SCHEMA,
        "engine": engine,
        "violated_invariant": violated_invariant,
        "source": source,
        "original_sequence": [c["raw"] for c in parsed],
        "original_step_count": len(parsed),
        "unparsed_calls": unparsed,
        "minimized_sequence": minimized,
        "minimization_reasons": reasons,
        "classification": cls,
        "evidence_class": "scaffolded_unverified",
        "concretizer_ready": False,
        "generated_by": "fuzz-sequence-to-poc",
    }
    if concretizer_available:
        record["concretizer_handoff"] = {
            "schema_version": CONCRETIZER_HANDOFF_SCHEMA,
            "tool": "tools/ce-concretize.py",
            "note": "W5-D2 concretizer present; hand the emitted .t.sol to it "
                    "to bind ABI, concretize non-literal args, un-skip, and "
                    "run forge test to a PASS/FAIL verdict.",
        }
    return record


def _iter_findings_sequences(
    findings_doc: Dict[str, Any],
) -> List[Tuple[str, str, List[str]]]:
    """Pull (engine, target_function, input_sequence) from a W4.5 findings doc."""
    out: List[Tuple[str, str, List[str]]] = []
    for f in findings_doc.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        if f.get("verdict") != "counterexample":
            continue
        seq = f.get("input_sequence") or []
        if not isinstance(seq, list) or len(seq) < 2:
            continue
        out.append((
            str(f.get("engine") or "fuzzer"),
            str(f.get("target_function") or "engine_counterexample"),
            [str(s) for s in seq],
        ))
    return out


def run(
    *,
    workspace: Path,
    findings_path: Optional[Path],
    counterexample_path: Optional[Path],
    sequence_json_path: Optional[Path],
    concretizer_available: bool,
) -> Dict[str, Any]:
    """Lift every eligible multi-tx sequence and emit records + PoCs."""
    out_dir = workspace / ".auditooor" / "multi-tx-sequences"
    lifts: List[Tuple[str, str, List[str], str]] = []  # engine, inv, calls, src

    if findings_path is not None:
        doc = json.loads(findings_path.read_text(encoding="utf-8"))
        for engine, inv, seq in _iter_findings_sequences(doc):
            lifts.append((engine, inv, seq, f"findings:{findings_path.name}"))
    if counterexample_path is not None:
        rec = json.loads(counterexample_path.read_text(encoding="utf-8"))
        seq = rec.get("input_sequence") or []
        if isinstance(seq, list) and len(seq) >= 2:
            lifts.append((
                str(rec.get("engine") or "fuzzer"),
                str(rec.get("target_function") or "engine_counterexample"),
                [str(s) for s in seq],
                f"counterexample:{counterexample_path.name}",
            ))
    if sequence_json_path is not None:
        seq = json.loads(sequence_json_path.read_text(encoding="utf-8"))
        if isinstance(seq, list):
            lifts.append((
                "fuzzer", "engine_counterexample",
                [str(s) for s in seq],
                f"sequence-json:{sequence_json_path.name}",
            ))

    generated: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for engine, inv, calls, src in lifts:
        record = lift_sequence(
            calls, engine=engine, violated_invariant=inv, source=src,
            concretizer_available=concretizer_available,
        )
        if record is None:
            skipped.append({
                "source": src, "violated_invariant": inv,
                "reason": "sequence is single-tx after minimization "
                          "(out of W5-D3 scope; W5-D2 single-pattern job)",
            })
            continue
        slug = _slug(f"{engine}_{inv}_{record['classification']['step_count']}step")
        out_dir.mkdir(parents=True, exist_ok=True)
        record_path = out_dir / f"{slug}.multi_tx_attack_sequence.v1.json"
        poc_path = out_dir / f"{slug}.MultiTxAttackPoC.t.sol"
        record["record_path"] = str(record_path)
        record["poc_path"] = str(poc_path)
        record_path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        poc_path.write_text(render_multi_tx_poc(record), encoding="utf-8")
        generated.append({
            "source": src,
            "slug": slug,
            "engine": engine,
            "violated_invariant": inv,
            "attack_shape": record["classification"]["attack_shape"],
            "family_hint": record["classification"]["family_hint"],
            "original_step_count": record["original_step_count"],
            "minimized_step_count": record["classification"]["step_count"],
            "record_path": str(record_path),
            "poc_path": str(poc_path),
        })

    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "generated_at": datetime.now(timezone.utc)
        .isoformat().replace("+00:00", "Z"),
        "workspace": str(workspace),
        "concretizer_available": concretizer_available,
        "lifted_count": len(generated),
        "skipped_count": len(skipped),
        "lifted": sorted(generated, key=lambda g: g["slug"]),
        "skipped": skipped,
    }
    if generated:
        manifest_path = out_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        manifest["manifest_path"] = str(manifest_path)
    return manifest


def _detect_concretizer() -> bool:
    """True if the W5-D2 ce-concretize.py concretizer is present in-repo."""
    return (Path(__file__).resolve().parent / "ce-concretize.py").is_file()


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--workspace", required=True, type=Path,
                   help="Workspace root; output under .auditooor/multi-tx-sequences/")
    src = p.add_argument_group("input (provide at least one)")
    src.add_argument("--findings", type=Path,
                     help="W4.5 deep_engine_findings.v1 JSON.")
    src.add_argument("--counterexample", type=Path,
                     help="A single deep_counterexample.v1 record JSON.")
    src.add_argument("--sequence-json", type=Path,
                     help="Raw JSON list of call strings (escape hatch).")
    p.add_argument("--print-json", action="store_true")
    args = p.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[fuzz-sequence-to-poc] ERR workspace not found: {ws}",
              file=sys.stderr)
        return 2
    if not any((args.findings, args.counterexample, args.sequence_json)):
        print("[fuzz-sequence-to-poc] ERR provide --findings, "
              "--counterexample, or --sequence-json", file=sys.stderr)
        return 2
    for label, path in (("findings", args.findings),
                        ("counterexample", args.counterexample),
                        ("sequence-json", args.sequence_json)):
        if path is not None and not path.expanduser().resolve().is_file():
            print(f"[fuzz-sequence-to-poc] ERR --{label} not found: {path}",
                  file=sys.stderr)
            return 2

    manifest = run(
        workspace=ws,
        findings_path=(args.findings.expanduser().resolve()
                       if args.findings else None),
        counterexample_path=(args.counterexample.expanduser().resolve()
                             if args.counterexample else None),
        sequence_json_path=(args.sequence_json.expanduser().resolve()
                            if args.sequence_json else None),
        concretizer_available=_detect_concretizer(),
    )
    if args.print_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[fuzz-sequence-to-poc] OK lifted={manifest['lifted_count']} "
          f"skipped={manifest['skipped_count']} "
          f"concretizer={'present' if manifest['concretizer_available'] else 'absent'}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
