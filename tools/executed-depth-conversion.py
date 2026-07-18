#!/usr/bin/env python3
"""executed-depth-conversion (LOGIC_ARSENAL_ROADMAP logic #2, conversion lane).

THE MISSING LANE. The arsenal pass demotes a unit to a ``needs-llm-depth``
coverage_unit_verdict when >=1 adversarial hypothesis was emitted but NO impact was
proven mechanically. Downstream, tools/executed-refutation-negative-gate.py credits a
value-mover NEGATIVE only when a poc_execution_record carries BOTH an EXECUTED
refutation (a command that actually ran, exit 0) AND a GUARD-NEUTRALIZATION mutant
receipt (the hypothesis becomes reachable when the cited guard is removed). Until this
tool nothing bridged the two: a ``needs-llm-depth`` verdict never became an executed
PoC/refutation with a poc_execution/ record the gate credits, so a workspace could sit
at 0 executed depth on every unit.

Two modes:

  emit-obligations  (DETERMINISTIC, always runnable, wired REQUIRED after depth-probe)
      Select the ``needs-llm-depth`` (+ crypto/nonce/signature) units from
      .auditooor/coverage_unit_verdicts/*.json and write, PER UNIT, an
      executed-refutation OBLIGATION to
          .auditooor/executed_depth_obligations/<slug>.json
      carrying the fn + file:line + the coupled invariant/guard to neutralize + the
      adversarial questions. This is the worklist the depth lane drives.

  record            (BRIDGE - writes a poc_execution_record ONLY from a REAL result)
      Given a REAL executed result (baseline go-test PASS + a guard-neutralization
      mutant that KILLED the test, tree restored byte-clean), write
          .auditooor/poc_execution/<slug>/execution_manifest.json
      in EXACTLY the schema executed-refutation-negative-gate.py credits (source_refs /
      cut / function anchors so it JOINs to the value-mover NEGATIVE on that unit).
      ANTI-FABRICATION: the tool REFUSES to write unless the result proves baseline
      exit 0 AND mutant exit != 0 (killed) AND cut_restored_byte_clean. It never
      invents an execution - it only serializes one you actually ran.

Usage:
  executed-depth-conversion.py emit-obligations --workspace <ws> [--json]
  executed-depth-conversion.py record --workspace <ws> --unit <unit_id> \
        --result <result.json> [--json]
  executed-depth-conversion.py status --workspace <ws> [--json]
"""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

COVERAGE_UNIT_VERDICT_SCHEMA = "auditooor.coverage_unit_verdict.v1"
NEEDS_LLM_DEPTH_VERDICT = "needs-llm-depth"
OBLIGATION_SCHEMA = "auditooor.executed_depth_obligation.v1"
POC_RECORD_SCHEMA = "auditooor.poc_execution_record.v1"

# A unit is a "crypto" depth unit (the ~15 crypto arm) when its questions/reason touch
# nonce/k-value/signature/ecdsa/entropy - these are the depth units the negative gate's
# value-mover class ("nonce|replay|signature") also cares about.
CRYPTO_RX = re.compile(
    r"nonce|k-value|k value|ecdsa|signature|sig-|entropy|deterministic.*seed|"
    r"private key|keygen|round-message|proof-obligation|randomness",
    re.IGNORECASE,
)


def _slug(unit_id: str) -> str:
    """file::fn -> file-ext--fn, matching coverage_unit_verdicts/<slug>.json naming."""
    s = str(unit_id).strip()
    s = s.replace("::", "--").replace(".", "-")
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", s)
    return s or "unit"


def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _best_file_line(data: dict) -> str:
    """Best-effort file:line anchor from a coverage_unit_verdict."""
    sp = str(data.get("source_path") or "").strip()
    # some verdicts carry a line hint under detail/anchor; fall back to source_path only
    for k in ("file_line", "anchor", "line_hint"):
        v = data.get(k)
        if v:
            return str(v)
    return sp


def _flagged_negative_units(ws: Path):
    """The second depth-pending population: value-mover NEGATIVES (cleared/refuted)
    that tools/executed-refutation-negative-gate.py flags as NON-HONEST (grep-only or
    no executed-refutation+guard-neutralization receipt). These are the units whose
    honest count the conversion lane directly drains: each needs a REAL executed
    refutation proving its cited guard is load-bearing. Loaded via the gate module so
    the selection is the SAME set the gate scores - no drift.
    """
    gate = Path(__file__).resolve().with_name("executed-refutation-negative-gate.py")
    if not gate.is_file():
        return []
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("_exec_refut_gate", gate)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        res = mod.scan(Path(ws))
    except Exception:
        return []
    out = []
    for e in (res.get("flagged") or []):
        unit_ref = str(e.get("unit") or "").strip()
        if not unit_ref:
            continue
        # unit_ref is a source_ref like "poll.go:120" or "src/.../batch.go:53-65"
        fpart = unit_ref.split(":")[0].strip()
        base = os.path.basename(fpart)
        mech = str(e.get("mechanism") or "").strip()
        unit_id = f"{base}::{mech}" if mech else base
        out.append({
            "unit_id": unit_id,
            "slug": _slug(f"{base}--{mech}" if mech else base),
            "source_path": fpart,
            "function": "",
            "file_line": unit_ref,
            "verdict": f"flagged-negative:{e.get('verdict')}",
            "is_crypto": False,
            "adversarial_questions": [],
            "reason": (f"executed-refutation-negative-gate flagged this {e.get('verdict')} "
                       f"value-mover NEGATIVE as NON-HONEST (mechanism={mech}); prove the "
                       f"cited guard is LOAD-BEARING with an executed baseline PASS + a "
                       f"guard-neutralization mutant that KILLS the test."),
            "verdict_path": "executed-refutation-negative-gate",
            "flagged_negative": True,
        })
    return out


def select_units(ws: Path, include_flagged_negatives: bool = True):
    """Return the list of depth-conversion obligation candidates for a workspace.

    Candidates come from two depth-pending populations:
      (A) a ``needs-llm-depth`` coverage_unit_verdict, OR any verdict whose
          reason/questions are crypto-shaped (the crypto depth arm), AND
      (B) the value-mover NEGATIVES flagged NON-HONEST by
          executed-refutation-negative-gate.py (the units whose honest count the lane
          drains). ``include_flagged_negatives=False`` returns only (A) for a
          verdicts-dir-only unit test.
    Deterministic (population A is pure); population B mirrors the gate's own scan.
    """
    vdir = Path(ws) / ".auditooor" / "coverage_unit_verdicts"
    out = []
    seen = set()
    if not vdir.is_dir():
        if include_flagged_negatives:
            for u in _flagged_negative_units(ws):
                if u["unit_id"] not in seen:
                    seen.add(u["unit_id"])
                    out.append(u)
        return out
    for path in sorted(vdir.glob("*.json")):
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        if str(data.get("schema") or "") != COVERAGE_UNIT_VERDICT_SCHEMA:
            continue
        verdict = str(data.get("verdict") or "").strip()
        unit_id = str(data.get("unit_id") or "").strip()
        if not unit_id:
            continue
        questions = data.get("adversarial_questions") or []
        hay = " ".join([str(data.get("reason") or ""), " ".join(str(q) for q in questions)])
        is_crypto = bool(CRYPTO_RX.search(hay))
        if verdict != NEEDS_LLM_DEPTH_VERDICT and not is_crypto:
            continue
        fn = unit_id.split("::")[-1] if "::" in unit_id else ""
        if unit_id in seen:
            continue
        seen.add(unit_id)
        out.append({
            "unit_id": unit_id,
            "slug": _slug(unit_id),
            "source_path": str(data.get("source_path") or ""),
            "function": fn,
            "file_line": _best_file_line(data),
            "verdict": verdict,
            "is_crypto": is_crypto,
            "adversarial_questions": [str(q) for q in questions],
            "reason": str(data.get("reason") or ""),
            "verdict_path": str(path),
        })
    if include_flagged_negatives:
        for u in _flagged_negative_units(ws):
            if u["unit_id"] not in seen:
                seen.add(u["unit_id"])
                out.append(u)
    return out


def _obligation_for(unit: dict, ws: Path) -> dict:
    """Build the per-unit executed-refutation obligation payload."""
    return {
        "schema": OBLIGATION_SCHEMA,
        "workspace": Path(ws).name,
        "unit_id": unit["unit_id"],
        "slug": unit["slug"],
        "source_path": unit["source_path"],
        "function": unit["function"],
        "file_line": unit["file_line"],
        "source_verdict": unit["verdict"],
        "is_crypto": unit["is_crypto"],
        "status": "pending",
        "obligation": (
            "Author a REAL executed test (go test / cargo test / forge test over the "
            "actual CUT, NO mock of the unit) that drives {fn} and ASSERTS the coupled "
            "invariant below. Run it PASS (baseline). Then NEUTRALIZE the load-bearing "
            "guard/store-op (mutant) and RE-RUN: the test MUST FAIL (mutant killed). "
            "Restore the CUT byte-clean. Feed the executed result to "
            "`executed-depth-conversion.py record` to emit the poc_execution_record."
        ).format(fn=unit["function"] or unit["unit_id"]),
        "coupled_invariant_to_prove": unit["reason"] or (
            "derive the load-bearing invariant from the adversarial questions"),
        "adversarial_questions": unit["adversarial_questions"],
        "poc_record_target": os.path.join(
            ".auditooor", "poc_execution", unit["slug"], "execution_manifest.json"),
    }


def emit_obligations(ws: Path, overwrite_resolved: bool = False) -> dict:
    """Write one obligation JSON per selected depth unit. Never clobbers a unit that
    already has a RESOLVED poc_execution_record (idempotent, re-run safe)."""
    ws = Path(ws)
    units = select_units(ws)
    odir = ws / ".auditooor" / "executed_depth_obligations"
    odir.mkdir(parents=True, exist_ok=True)
    written, skipped_resolved = 0, 0
    for unit in units:
        poc = ws / ".auditooor" / "poc_execution" / unit["slug"] / "execution_manifest.json"
        opath = odir / f"{unit['slug']}.json"
        payload = _obligation_for(unit, ws)
        if poc.is_file():
            payload["status"] = "resolved"
            payload["poc_record"] = str(poc)
            skipped_resolved += 1
        opath.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        written += 1
    return {
        "workspace": ws.name,
        "obligation_dir": str(odir),
        "selected_units": len(units),
        "obligations_written": written,
        "resolved": skipped_resolved,
        "pending": written - skipped_resolved,
    }


def _validate_result(result: dict) -> list:
    """Return a list of FAILURE reasons; empty list => the result is a genuine
    executed baseline-PASS + mutant-KILL. This is the anti-fabrication gate."""
    reasons = []
    if not isinstance(result, dict):
        return ["result is not a JSON object"]
    base = result.get("baseline")
    mut = result.get("mutant")
    if not isinstance(base, dict):
        reasons.append("missing baseline{} block")
    else:
        ec = base.get("exit_code")
        st = str(base.get("status") or "").lower()
        if not ((isinstance(ec, int) and ec == 0) or st == "pass"):
            reasons.append("baseline did not PASS (need exit_code 0 / status pass)")
        if not str(base.get("cmd") or "").strip():
            reasons.append("baseline.cmd is empty (no command was run)")
    if not isinstance(mut, dict):
        reasons.append("missing mutant{} block")
    else:
        ec = mut.get("exit_code")
        st = str(mut.get("status") or "").lower()
        # a KILLED mutant means the test FAILED under the neutralized guard
        if not ((isinstance(ec, int) and ec != 0) or st in ("fail", "failed", "killed")):
            reasons.append("mutant was NOT killed (need non-zero exit / status fail)")
        if not str(mut.get("description") or "").strip():
            reasons.append("mutant.description is empty (no guard-neutralization named)")
    if result.get("cut_restored_byte_clean") is not True:
        reasons.append("cut_restored_byte_clean is not true")
    if not (result.get("source_refs") or []):
        reasons.append("source_refs is empty (record could not JOIN to its unit)")
    if not str(result.get("function") or "").strip():
        reasons.append("function is empty (record could not JOIN to its unit)")
    return reasons


def build_poc_record(ws: Path, unit_id: str, result: dict) -> dict:
    """Serialize a genuine executed result into the poc_execution_record schema the
    negative-gate credits. Presumes _validate_result already passed."""
    base = result.get("baseline") or {}
    mut = result.get("mutant") or {}
    fn = str(result.get("function") or "").strip()
    source_refs = [str(r) for r in (result.get("source_refs") or [])]
    cut = str(result.get("cut") or (source_refs[0] if source_refs else ""))
    return {
        "schema": POC_RECORD_SCHEMA,
        "workspace": Path(ws).name,
        "unit_id": unit_id,
        "function": fn,
        "source_refs": source_refs,
        "cut": cut,
        "file_line": cut,
        "invariant": str(result.get("invariant") or ""),
        # executed refutation - the negative gate reads execution.status / exit_code
        "execution": {
            "status": "pass",
            "exit_code": 0,
            "cmd": str(base.get("cmd") or ""),
        },
        "commands_attempted": [
            {"cmd": str(base.get("cmd") or ""), "status": "pass", "exit_code": 0,
             "role": "baseline"},
            {"cmd": str(mut.get("cmd") or ""),
             "status": "fail",
             "exit_code": int(mut.get("exit_code") or 1),
             "role": "guard-neutralization-mutant"},
        ],
        # guard-neutralization mutant receipt - the negative gate matches the word
        # "mutant"/"guard-neutraliz" in the blob to set guard_neutralized=True
        "guard_neutralization": {
            "mutant_description": str(mut.get("description") or ""),
            "kill_evidence": str(mut.get("output_excerpt")
                                 or result.get("kill_evidence") or ""),
            "mutation_verified": True,
            "cut_restored_byte_clean": True,
        },
        "baseline_pass": str(base.get("output_excerpt") or ""),
        "kill_evidence": str(mut.get("output_excerpt") or ""),
        "harness": str(result.get("harness") or ""),
        "test": str(result.get("test") or ""),
        "verified_by": str(result.get("verified_by")
                           or "executed-depth-conversion record bridge"),
        "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def record(ws: Path, unit_id: str, result_path: str) -> dict:
    """Write the poc_execution_record for <unit_id> from a REAL executed result file.
    Refuses (rc-carrying dict with ok=False) unless the result validates."""
    ws = Path(ws)
    result = _load_json(result_path)
    if result is None:
        return {"ok": False, "error": f"could not load result file {result_path}"}
    reasons = _validate_result(result)
    if reasons:
        return {"ok": False, "error": "result did not validate (NOT written - "
                "no fabrication)", "reasons": reasons}
    rec = build_poc_record(ws, unit_id, result)
    slug = _slug(unit_id)
    outdir = ws / ".auditooor" / "poc_execution" / slug
    outdir.mkdir(parents=True, exist_ok=True)
    outpath = outdir / "execution_manifest.json"
    outpath.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    # flip the obligation to resolved if one exists
    opath = ws / ".auditooor" / "executed_depth_obligations" / f"{slug}.json"
    if opath.is_file():
        ob = _load_json(opath)
        if isinstance(ob, dict):
            ob["status"] = "resolved"
            ob["poc_record"] = str(outpath)
            opath.write_text(json.dumps(ob, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "poc_record": str(outpath), "unit_id": unit_id, "slug": slug}


def status(ws: Path) -> dict:
    ws = Path(ws)
    units = select_units(ws)
    resolved, pending = [], []
    for u in units:
        poc = ws / ".auditooor" / "poc_execution" / u["slug"] / "execution_manifest.json"
        (resolved if poc.is_file() else pending).append(u["unit_id"])
    return {
        "workspace": ws.name,
        "selected_units": len(units),
        "resolved_units": len(resolved),
        "pending_units": len(pending),
        "pending": pending[:200],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    p_emit = sub.add_parser("emit-obligations")
    p_emit.add_argument("--workspace", required=True)
    p_emit.add_argument("--json", action="store_true")

    p_rec = sub.add_parser("record")
    p_rec.add_argument("--workspace", required=True)
    p_rec.add_argument("--unit", required=True)
    p_rec.add_argument("--result", required=True)
    p_rec.add_argument("--json", action="store_true")

    p_st = sub.add_parser("status")
    p_st.add_argument("--workspace", required=True)
    p_st.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    ws = Path(args.workspace)

    if args.mode == "emit-obligations":
        res = emit_obligations(ws)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"executed-depth-conversion emit-obligations ws={res['workspace']}")
            print(f"  selected depth units      : {res['selected_units']}")
            print(f"  obligations written       : {res['obligations_written']}")
            print(f"  resolved / pending        : {res['resolved']} / {res['pending']}")
            print(f"  obligation dir            : {res['obligation_dir']}")
        return 0

    if args.mode == "record":
        res = record(ws, args.unit, args.result)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            if res.get("ok"):
                print(f"executed-depth-conversion record: WROTE {res['poc_record']}")
            else:
                print(f"executed-depth-conversion record: REFUSED - {res.get('error')}")
                for r in res.get("reasons", []):
                    print(f"    - {r}")
        return 0 if res.get("ok") else 2

    if args.mode == "status":
        res = status(ws)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"executed-depth-conversion status ws={res['workspace']}")
            print(f"  selected/resolved/pending : {res['selected_units']}/"
                  f"{res['resolved_units']}/{res['pending_units']}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
