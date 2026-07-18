#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-mined-landed-producer registered via agent-pathspec-register.py -->
"""mined-landed-parity-build.py - canonical producer for mined_landed_parity.json.

GENERIC FUNNEL FIX. The audit-completeness-check mined-landed signal (i2)
requires ``<ws>/.auditooor/mined_landed_parity.json`` asserting that every
mined hunt-finding sidecar's outcome is durably LANDED in the workspace
learning ledger (no un-landed LEARNING_DEBT). No canonical step produced that
ledger - it was hand-maintained per-workspace and went stale (its declared
count drifted from the live ``hunt_findings_sidecars/*.json`` count, and the
candidate_id namespace diverged across regenerations). This tool produces the
ledger from REAL artifacts, idempotently, on ANY workspace.

LANDING (honest, not faked): each genuine finding-sidecar file's outcome is
recorded into a durable workspace learning ledger -
  - refuted / FP / by-design / OOS / no-exploit / informational -> known_dead_ends.jsonl
  - confirmed / holds / finding / real-attack                    -> learning_staged.jsonl
A sidecar is counted LANDED only once such a record exists for it (keyed by a
stable record id derived from the sidecar file path, so re-runs do not
duplicate). A sidecar whose verdict/disposition cannot be determined is
reported UNACCOUNTED - the ledger then honestly shows landed < mined and the
gate stays failed, rather than inventing parity.

Counting reuses audit-completeness-check.py's own ``_is_finding_sidecar`` /
``_count_sidecars`` so the producer's ``sidecar_count`` is IDENTICAL to the
number the gate checks (they can never silently diverge).

USAGE
    python3 tools/mined-landed-parity-build.py --workspace <ws> [--check] [--json]

``--check`` computes and prints the parity WITHOUT writing the ledger or
appending learning records (exit 0 if parity would hold, 1 otherwise).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# r36-rebuttal: lane-mined-landed-producer
# Refuted-class = any verdict meaning "no finding here" (FP, by-design,
# defended, OOS, hunt produced no/insufficient evidence, hallucinated pattern
# not present in source, negative survivor sweep). These ARE landable outcomes
# (the finding's negative result is durable learning). NOT in this set: a
# verdict that is empty/None/undecided -> that sidecar is genuinely un-landed
# debt and must stay UNACCOUNTED (never invent a disposition).
_REFUTED_MARKERS = {
    "refuted", "fp", "false-positive", "false_positive", "by-design",
    "by_design", "oos", "out-of-scope", "out_of_scope", "no-exploit",
    "no_exploit", "ruled-out", "ruled_out", "informational", "drop",
    "dropped", "no-finding", "no_finding", "not-exploitable", "invalid",
    "wont-fix", "duplicate", "dupe",
    # hunt outcomes that mean "no finding established"
    "insufficient", "not_in_source", "not-in-source", "negative",
    "protected", "defended", "standard", "no-survivor", "no_survivor",
    "zero net-new", "net-new survivors",
}
_CONFIRMED_MARKERS = {
    "confirmed", "holds", "finding", "real-attack", "real_attack",
    "exploitable", "valid", "true-positive", "true_positive",
}


def _load_gate_helpers():
    """Reuse audit-completeness-check.py's finding-sidecar predicate so the
    producer counts EXACTLY what the gate counts (no divergence)."""
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        "acc_for_parity", str(here / "audit-completeness-check.py")
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["acc_for_parity"] = mod
    spec.loader.exec_module(mod)
    return mod


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _record_id(ws: Path, sidecar: Path) -> str:
    rel = str(sidecar.relative_to(ws)) if sidecar.is_relative_to(ws) else sidecar.name
    return "mlp-" + hashlib.sha1(rel.encode("utf-8")).hexdigest()[:16]


def _verdict_bucket(obj: dict) -> str | None:
    """refuted | confirmed | None (undeterminable)."""
    blob = " ".join(
        str(obj.get(k) or "")
        for k in ("verdict", "disposition", "outcome", "kill_verdict",
                  "status", "result")
    ).lower()
    # Confirmed wins if explicitly present (a real finding must not be filed
    # as a dead-end).
    for m in _CONFIRMED_MARKERS:
        if m in blob:
            return "confirmed"
    for m in _REFUTED_MARKERS:
        if m in blob:
            return "refuted"
    # r36-rebuttal: lane FIX-MINED-LANDED-APPLIES registered in .auditooor/agent_pathspec.json
    # The per-function / MIMO hunt sidecar schema records its verdict in
    # `applies_to_target` ("no" = examined + ruled out = refuted; "yes" = the
    # hypothesis applies = a real candidate, never a dead-end), NOT in
    # verdict/disposition. Without this, an adjudicated FP sidecar is scored
    # "no determinable verdict" -> permanent un-landed LEARNING_DEBT (the
    # morpho-midnight mined-landed false-red). Confirmed markers above still win.
    ann = str(obj.get("applies_to_target") or "").strip().lower()
    if ann in ("yes", "true", "y"):
        return "confirmed"
    if ann in ("no", "false", "n"):
        return "refuted"
    return None


def _load_landed_ids(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.is_file():
        return out
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            rid = rec.get("record_id") or rec.get("mlp_record_id")
            if rid:
                out.add(str(rid))
    except OSError:
        pass
    return out


def build(ws: Path, *, check: bool = False) -> dict[str, Any]:
    ws = ws.expanduser().resolve()
    acc = _load_gate_helpers()
    side_dir = ws / "hunt_findings_sidecars"

    # Enumerate the SAME genuine finding-sidecar files the gate counts.
    sidecar_files: list[Path] = []
    if side_dir.is_dir():
        for c in sorted(side_dir.glob("*.json")):
            if c.is_file() and not c.name.startswith(".") and acc._is_finding_sidecar(c):
                sidecar_files.append(c)
    mined = len(sidecar_files)

    a = ws / ".auditooor"
    dead_ends = a / "known_dead_ends.jsonl"
    staged = a / "learning_staged.jsonl"
    already = _load_landed_ids(dead_ends) | _load_landed_ids(staged)

    new_dead: list[str] = []
    new_staged: list[str] = []
    accounted: list[str] = []
    unaccounted: list[dict] = []

    for sc in sidecar_files:
        try:
            obj = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError, ValueError):
            unaccounted.append({"sidecar": sc.name, "reason": "unparseable"})
            continue
        if not isinstance(obj, dict):
            unaccounted.append({"sidecar": sc.name, "reason": "non-object"})
            continue
        bucket = _verdict_bucket(obj)
        if bucket is None:
            unaccounted.append({"sidecar": sc.name,
                                "reason": "no determinable verdict/disposition"})
            continue
        rid = _record_id(ws, sc)
        accounted.append(rid)
        if rid in already:
            continue  # idempotent: already landed
        rec = {
            "schema_version": "auditooor.mined_landed_record.v1",
            "record_id": rid,
            "candidate_id": obj.get("candidate_id"),
            "workspace": ws.name,
            "outcome_bucket": bucket,
            "kill_verdict": obj.get("verdict") or obj.get("disposition"),
            "evidence_file_line": obj.get("file_line"),
            "kill_reason": (str(obj.get("hypothesis") or obj.get("analysis") or "")[:280]),
            "negative_control": obj.get("negative_control"),
            "poc_result": obj.get("poc_result") or obj.get("poc"),
            "source_artifact": str(sc.relative_to(ws)) if sc.is_relative_to(ws) else sc.name,
            "generated_by": "mined-landed-parity-build.py",
            "promoted_at_utc": _now(),
        }
        (new_staged if bucket == "confirmed" else new_dead).append(json.dumps(rec, sort_keys=True))

    # landed = finding-sidecar files with a derivable+recorded outcome (new or
    # already-present). r36-rebuttal: lane-mined-landed-producer
    landed = len(accounted)

    parity_ok = (mined > 0 and landed >= mined) or mined == 0
    result = {
        "schema": "auditooor.mined_landed_parity.v1",
        "workspace": str(ws),
        "sidecar_count": mined,
        "mined_count": mined,
        "landed_count": landed,
        "sidecars_accounted": landed,
        "corpus_record_count": landed,
        "unaccounted_count": len(unaccounted),
        "unaccounted": unaccounted[:50],
        "parity_ok": parity_ok,
        "generated_at": _now(),
        "generated_by": "mined-landed-parity-build.py",
        "note": (
            "Canonical producer: each genuine finding-sidecar's outcome landed "
            "in the workspace learning ledger (refuted->known_dead_ends.jsonl, "
            "confirmed->learning_staged.jsonl). landed_count counts sidecar "
            "files with a derivable outcome; unaccounted sidecars are reported "
            "honestly (parity_ok=false) rather than faked."
        ),
    }

    if check:
        return result

    # Append new learning records (idempotent) then write the parity ledger.
    a.mkdir(parents=True, exist_ok=True)  # r36-rebuttal: lane-mined-landed-producer
    if new_dead:
        with dead_ends.open("a", encoding="utf-8") as fh:
            for line in new_dead:
                fh.write(line + "\n")
    if new_staged:
        with staged.open("a", encoding="utf-8") as fh:
            for line in new_staged:
                fh.write(line + "\n")
    a.mkdir(parents=True, exist_ok=True)
    (a / "mined_landed_parity.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    result["landed_records_appended"] = len(new_dead) + len(new_staged)
    result["ledger_written"] = str(a / "mined_landed_parity.json")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--check", action="store_true",
                    help="Compute parity without writing the ledger or landing records.")
    ap.add_argument("--json", action="store_true", help="Print the result as JSON.")
    args = ap.parse_args(argv)

    if not args.workspace.is_dir():
        print(f"[mined-landed-parity-build] ERR workspace not found: {args.workspace}",
              file=sys.stderr)
        return 2

    result = build(args.workspace, check=args.check)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[mined-landed-parity-build] sidecar_count={result['sidecar_count']} "
              f"landed_count={result['landed_count']} "
              f"unaccounted={result['unaccounted_count']} "
              f"parity_ok={result['parity_ok']}"
              + ("" if args.check else f" -> {result.get('ledger_written','')}"))
    return 0 if result["parity_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
