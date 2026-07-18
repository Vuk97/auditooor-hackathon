#!/usr/bin/env python3
"""ETL per-workspace DEPTH ledgers into the shared hackerman corpus (S9-depth-crossws).

The depth stage (make audit-depth) writes two per-workspace ledgers that today are
reused only INTRA-workspace (per-fn-mimo-batch-gen reads them) and discarded at the
workspace boundary, so every new workspace re-derives the same deposit/withdraw,
propose/execute pair taxonomy + which guard shapes most often go missing. This ETL
banks the genuine gaps into audit/corpus_tags/tags/depth_ledgers/ so the next
workspace's sibling-path-guard-diff + negative-space probe are primed cross-workspace.

Sources (real schemas, R76):
  <ws>/.auditooor/negative_space_gaps.jsonl  (auditooor.negative_space_gap.v1)
     -> gap_found == True rows ingest as CANDIDATE depth-gap records (corpus).
     -> gap_found == False rows with a substantive ruled_out_reason AND a
        guard_id/file_line are NOT dropped: they bank as DEAD-END records
        (auditooor.known_dead_end.v1, verdict="ruled-out") into
        reports/known_dead_ends.jsonl (read by vault_known_dead_ends), so the
        next workspace's negative-space probe does not re-chase the same dead
        ends. They do NOT enter the candidate-finding / invariant corpus.
        A gap_found==False row with no reason (or no anchor) is still dropped
        (anti-stub). ~1610 ruled-out reasons/run were previously discarded.
  <ws>/.auditooor/sibling_guard_asymmetries.jsonl  (auditooor.sibling_path_guard_diff.v1)
     -> ingest rows where a guard is present on one arm but MISSING on the sibling
        (guard_on_a_missing_on_b or guard_on_b_missing_on_a non-empty).

Schema validity is delegated to the prior-audit ETL build_record (one source of
truth) then provenance/tier are overridden, mirroring hackerman-etl-from-our-submissions.py.
Idempotent: record_id is keyed on workspace + the row's stable gap id, so re-runs
overwrite in place rather than duplicating.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ETL = _HERE / "hackerman-etl-from-prior-audits.py"
_spec = importlib.util.spec_from_file_location("prior_audit_etl", _ETL)
_pa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pa)  # reuse build_record + slugify + yaml_dump (one source of truth)

SCHEMA = "auditooor.hackerman_record.v1.1"
DEFAULT_OUT = _HERE.parent / "audit" / "corpus_tags" / "tags" / "depth_ledgers"
TIER = "tier-3-source-cited"  # depth gaps are source-cited candidates, not proven exploits

# Dead-end sink: ruled-out (gap_found==false) negative-space rows are banked here in the
# canonical auditooor.known_dead_end.v1 schema (same path + shape as triage-kill-promoter.py
# and hackerman-etl-from-finding-sidecars.py, the canonical KDE writers) so the two corpora
# stay unified and vault_known_dead_ends reads them. Env-overridable for test isolation.
KDE_SCHEMA = "auditooor.known_dead_end.v1"
KDE_PATH = Path(os.environ.get(
    "AUDITOOOR_KDE_PATH",
    str(_HERE.parent / "reports" / "known_dead_ends.jsonl")))

NEG_SPACE_LEDGER = "negative_space_gaps.jsonl"
SIBLING_LEDGER = "sibling_guard_asymmetries.jsonl"


def _ts_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_jsonl(path: Path):
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _override(rec: dict, *, ws_name: str, source_ref: str, gap_id: str,
              bug_class: str, attack_class: str, title: str) -> dict:
    digest = hashlib.sha256(f"{source_ref}\n{gap_id}".encode("utf-8")).hexdigest()[:12]
    rec["source_audit_ref"] = source_ref
    rec["record_id"] = (
        f"depth-gap:{_pa.slugify(ws_name, max_len=32)}:"
        f"{_pa.slugify(gap_id, max_len=72)}:{digest}"
    )
    rec["schema_version"] = SCHEMA
    rec["verification_tier"] = TIER
    rec["record_tier"] = "depth-ledger-derived"
    rec["bug_class"] = bug_class[:160]
    rec["attack_class"] = attack_class[:160]
    ext = rec.setdefault("record_extensions", {})
    ext["finding_title"] = title[:300]
    ext["origin_workspace"] = ws_name
    ext["depth_ledger_gap"] = True
    return rec


def _record_from_negspace(ws_name: str, row: dict) -> dict | None:
    if not row.get("gap_found"):
        return None
    guard_id = str(row.get("guard_id") or "").strip()
    file_line = str(row.get("file_line") or "").strip()
    if not guard_id and not file_line:
        return None
    reason = str(row.get("ruled_out_reason") or "").strip()
    title = f"Negative-space guard gap at {file_line or guard_id}"
    body = f"{title}\n\nProbed gap (gap_found=true) at {file_line}. Context: {reason}"[:6000]
    doc = _pa.SourceDoc(workspace=Path(ws_name), audit_kind="depth_negative_space",
                        path=Path(file_line or guard_id), rel_path=Path(file_line or guard_id))
    seg = _pa.FindingSegment(title=title, body=body, heading_line=1, ordinal=0)
    rec = _pa.build_record(doc, seg)
    return _override(rec, ws_name=ws_name,
                     source_ref=f"depth-negative-space:{ws_name}:{file_line or guard_id}",
                     gap_id=guard_id or file_line,
                     bug_class="missing-guard-negative-space",
                     attack_class="missing-guard-bypass",
                     title=title)


def _kde_from_negspace(ws_name: str, ws_path: str, row: dict,
                       target_pin: str | None = None) -> dict | None:
    """Bank a ruled-out (gap_found==false) negative-space row as a DEAD-END.

    A ruled-out probe is genuine signal (the gap was checked and is NOT a gap), so
    we record WHY it was ruled out rather than discarding it - the next workspace's
    negative-space probe should not re-chase it. This is a known_dead_end.v1 record
    (verdict="ruled-out"), NOT a candidate finding: it goes to KDE_PATH only.

    Anti-stub: requires a substantive ruled_out_reason AND at least one source anchor
    (guard_id or file_line). A reasonless row carries no signal and is dropped.
    Idempotent: dead_end_id = sha1(file_line|reason)[:16].
    """
    if row.get("gap_found"):
        return None  # gap_found==true keeps its candidate path
    guard_id = str(row.get("guard_id") or "").strip()
    file_line = str(row.get("file_line") or "").strip()
    reason = str(row.get("ruled_out_reason") or "").strip()
    if not reason:
        return None  # anti-stub: no reason => no signal
    if not guard_id and not file_line:
        return None  # anti-stub: no anchor
    anchor = file_line or guard_id
    dead_end_id = hashlib.sha1(f"{anchor}|{reason}".encode("utf-8")).hexdigest()[:16]
    decided_by = str(row.get("decided_by") or row.get("decided_by_model")
                     or row.get("model") or "depth-negative-space-probe").strip()
    code_excerpt = str(row.get("code_excerpt") or row.get("guard_excerpt") or "").strip()
    rec = {
        "schema_version": KDE_SCHEMA,
        "record_id": f"{ws_name}:depth-negspace:{dead_end_id}",
        "dead_end_id": dead_end_id,
        "workspace": ws_name,
        "workspace_path": ws_path,
        "candidate_id": guard_id or file_line,
        "kill_verdict": "ruled-out",
        "verdict": "ruled-out",
        "drop_class": "negative-space-ruled-out",
        "kill_reason": reason[:500],
        "attack_class": "missing-guard-bypass",
        "bug_class": "missing-guard-negative-space",
        "evidence_file_line": file_line[:200],
        "file_line": file_line[:200],
        "evidence_code_excerpt": code_excerpt[:500],
        "code_excerpt": code_excerpt[:500],
        "decided_by": decided_by[:120] or "depth-negative-space-probe",
        "source_artifact": f"depth-negative-space:{ws_name}:{anchor}",
        "promoted_at_utc": _ts_utc(),
        "generated_by": "hackerman-etl-from-depth-ledgers",
    }
    if target_pin:
        rec["target_pin"] = str(target_pin)[:80]
    return rec


def _record_from_sibling(ws_name: str, row: dict) -> dict | None:
    miss_a = row.get("guard_on_a_missing_on_b") or []
    miss_b = row.get("guard_on_b_missing_on_a") or []
    if not miss_a and not miss_b:
        return None
    gap_id = str(row.get("candidate_gap_id") or "").strip()
    pair = str(row.get("pair") or "").strip()
    file_lines = row.get("file_lines") or []
    hint = str(row.get("shared_invariant_hint") or "").strip()
    if not gap_id:
        return None
    missing = sorted(set(map(str, miss_a)) | set(map(str, miss_b)))
    title = f"Sibling-path guard asymmetry on '{pair}' (missing: {', '.join(missing[:6])})"
    body = (
        f"{title}\n\nPaths: {file_lines}. "
        f"Guards present on one arm but missing on the sibling: {missing}. "
        f"Shared invariant: {hint}"
    )[:6000]
    site = file_lines[0] if file_lines else pair
    doc = _pa.SourceDoc(workspace=Path(ws_name), audit_kind="depth_sibling_asymmetry",
                        path=Path(site), rel_path=Path(site))
    seg = _pa.FindingSegment(title=title, body=body, heading_line=1, ordinal=0)
    rec = _pa.build_record(doc, seg)
    return _override(rec, ws_name=ws_name,
                     source_ref=f"depth-sibling-asymmetry:{ws_name}:{gap_id}",
                     gap_id=gap_id,
                     bug_class="guard-asymmetry-sibling-path",
                     attack_class="missing-guard-bypass",
                     title=title)


def _resolve_target_pin(aud: Path) -> str | None:
    """Best-effort: the captured audit pin, so a dead-end is anchored to a commit.
    Reads <ws>/.auditooor/audit_pin_monitor.json (auditooor.audit_pin_monitor.v1).
    Degrades to None (loudly absent, never a fabricated pin)."""
    mon = aud / "audit_pin_monitor.json"
    if not mon.is_file():
        return None
    try:
        data = json.loads(mon.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return None
    assets = data.get("assets") if isinstance(data, dict) else None
    if isinstance(assets, list):
        for a in assets:
            if isinstance(a, dict):
                pin = a.get("captured_pin") or a.get("pin")
                if pin:
                    return str(pin)
    if isinstance(data, dict):
        pin = data.get("captured_pin") or data.get("pin")
        if pin:
            return str(pin)
    return None


def _load_existing_kde() -> dict:
    out: dict = {}
    if not KDE_PATH.is_file():
        return out
    for line in KDE_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = r.get("record_id")
        if rid:
            out[rid] = r
    return out


def process_workspace(ws_root: Path, out_dir: Path, dry_run: bool):
    ws_name = ws_root.name
    ws_path = str(ws_root)
    aud = ws_root / ".auditooor"
    target_pin = _resolve_target_pin(aud)
    written = []
    dead_ends = []
    for row in _read_jsonl(aud / NEG_SPACE_LEDGER):
        rec = _record_from_negspace(ws_name, row)
        if rec:
            written.append(_emit(rec, out_dir, dry_run, ws_name, "negative_space"))
            continue
        # gap_found==false: bank the ruled-out reason as a DEAD-END (not a candidate).
        kde = _kde_from_negspace(ws_name, ws_path, row, target_pin)
        if kde:
            dead_ends.append(kde)
    for row in _read_jsonl(aud / SIBLING_LEDGER):
        rec = _record_from_sibling(ws_name, row)
        if rec:
            written.append(_emit(rec, out_dir, dry_run, ws_name, "sibling_asymmetry"))
    _emit_dead_ends(dead_ends, dry_run)
    written.extend(dead_ends)
    return written


def _emit_dead_ends(dead_ends: list, dry_run: bool) -> int:
    """Append new dead-end records to KDE_PATH, idempotent by record_id."""
    if not dead_ends:
        return 0
    existing = _load_existing_kde()
    to_add = [r for r in dead_ends if r["record_id"] not in existing]
    if not to_add or dry_run:
        return len(to_add)
    KDE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with KDE_PATH.open("a", encoding="utf-8") as fh:
        for r in to_add:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    return len(to_add)


def _emit(rec: dict, out_dir: Path, dry_run: bool, ws_name: str, kind: str) -> dict:
    fname = f"{_pa.slugify(rec['record_id'], max_len=100)}.yaml"
    target = out_dir / fname
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        target.write_text(_pa.yaml_dump(rec), encoding="utf-8")
    return {"workspace": ws_name, "kind": kind, "bug_class": rec.get("bug_class", ""),
            "record_id": rec["record_id"], "out": str(target)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", help="single workspace root (e.g. ~/audits/optimism)")
    ap.add_argument("--audits-root", help="scan every workspace under this root")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json-summary", action="store_true")
    args = ap.parse_args(argv)

    out_dir = Path(os.path.expanduser(args.out_dir))
    roots = []
    if args.workspace:
        roots.append(Path(os.path.expanduser(args.workspace)))
    if args.audits_root:
        root = Path(os.path.expanduser(args.audits_root))
        if root.is_dir():
            roots.extend(sorted(p for p in root.iterdir() if (p / ".auditooor").is_dir()))
    if not roots:
        ap.error("provide --workspace or --audits-root")

    all_written = []
    for ws in roots:
        all_written.extend(process_workspace(ws, out_dir, args.dry_run))

    dead_ends = [r for r in all_written
                 if r.get("schema_version") == KDE_SCHEMA]
    candidates = [r for r in all_written if r not in dead_ends]

    summary = {
        "schema": "auditooor.hackerman_depth_ledger_etl.summary.v1",
        "records": len(candidates),
        "candidate_records": len(candidates),
        "dead_end_records": len(dead_ends),
        "workspaces_scanned": len(roots),
        "out_dir": str(out_dir),
        "kde_path": str(KDE_PATH),
        "dry_run": args.dry_run,
    }
    if args.json_summary:
        print(json.dumps(summary, indent=2))
    else:
        print(f"depth-ledger ETL: {len(candidates)} candidate records + "
              f"{len(dead_ends)} dead-ends from {len(roots)} workspace(s) "
              f"-> {out_dir}{' (dry-run)' if args.dry_run else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
