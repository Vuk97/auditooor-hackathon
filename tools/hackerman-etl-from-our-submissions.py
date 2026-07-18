#!/usr/bin/env python3
"""Ingest OUR OWN confirmed findings (submissions/) into the cross-workspace
hackerman corpus as tier-1 records.

THE MISSING FEEDER. Every other corpus source (prior-audits, solodit, github,
agent-artifact) has an ETL; our own PoC-confirmed findings - the highest-trust
signal we produce - had none. A Critical found in workspace A never primed the
hunt / dedup / originality gates in workspace B. This closes that loop.

It reuses the inference helpers from hackerman-etl-from-prior-audits.py (one
source of truth for bug/attack/language/domain/component/signature inference and
the v1.1 record shape) but stamps:
  - verification_tier: tier-1-own-poc-confirmed  (our highest trust tier)
  - source_audit_ref:  own-finding:<ws>:<relpath>  (honest provenance)
  - provenance.kind:   own-confirmed-finding

R76 honesty: only ingests files that are GENUINE confirmed findings - those under
filed/ , paste_ready/ , packaged/ with a real severity. It SKIPS readmes, OOS /
rejected / superseded / staging dirs, dupe-review notes, and severity-less docs.
Stdlib-only. Dry-run by default-safe via --dry-run; validate with `make
validate-hackerman` before trusting the output.

Usage:
    python3 tools/hackerman-etl-from-our-submissions.py --workspace ~/audits/mezo --dry-run --json-summary
    python3 tools/hackerman-etl-from-our-submissions.py --audits-root ~/audits --out-dir audit/corpus_tags/tags/auditooor_own_findings
"""
import argparse
import hashlib
import importlib.util
import os
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ETL = _HERE / "hackerman-etl-from-prior-audits.py"
_spec = importlib.util.spec_from_file_location("prior_audit_etl", _ETL)
_pa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pa)  # reuse the inference helpers + yaml_dump (one source of truth)

TIER = "tier-1-self-poc-confirmed"
SCHEMA = "auditooor.hackerman_record.v1.1"
DEFAULT_OUT = _HERE.parent / "audit" / "corpus_tags" / "tags" / "auditooor_own_findings"

# Directories under submissions/ whose contents are CONFIRMED findings.
CONFIRMED_DIRS = ("filed", "paste_ready", "packaged")
# Path fragments that mark a doc as NOT a confirmed finding -> skip.
SKIP_FRAGMENTS = (
    "_oos", "oos_", "_rejected", "_superseded", "/staging/", "/draft",
    "dupe_review", "dupe-review", "readme", "submissions.md", "oos_check",
    "_archive", "/notes", "template",
)
# Sub-doc basenames that live ALONGSIDE a finding but are not the finding itself.
SKIP_BASENAMES = (
    "evidence_matrix", "manifest", "checklist", "index", "summary",
    "_matrix", "_notes", "paste_hash", "metadata", "scope", "severity",
    "submit_packet", "_packet", "submit-packet",
)
# A confirmed finding carries the program severity in its FILENAME (our paste-ready
# naming convention: ...-CRITICAL.md / ...-MEDIUM.md). Body-only severity is too
# weak a signal and pulls in evidence sub-docs -> corpus noise.
FILENAME_SEV_RE = re.compile(r"(?i)(?:^|[-_])(critical|high|medium|low)(?:[-_.]|$)")
SEV_RE = FILENAME_SEV_RE
POC_RE = re.compile(r"\b(poc|proof[- ]of[- ]concept|--- PASS|^ok\b|forge test|exploit|test_|halmos|medusa|echidna)\b", re.IGNORECASE)


def is_confirmed_finding(path: Path) -> bool:
    p = path.as_posix().lower()
    if not p.endswith(".md"):
        return False
    if not any(f"/{d}/" in p or p.rsplit("/", 2)[-2:][0] == d for d in CONFIRMED_DIRS) and "/submissions/" not in p:
        return False
    if not any(seg in p for seg in (f"/{d}/" for d in CONFIRMED_DIRS)):
        return False
    if any(s in p for s in SKIP_FRAGMENTS):
        return False
    base = path.stem.lower()
    if any(b in base for b in SKIP_BASENAMES):
        return False
    # The finding's severity must be in the FILENAME (paste-ready convention).
    if not FILENAME_SEV_RE.search(path.name):
        return False
    return True


def extract_title(path: Path, text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            t = line.lstrip("#").strip()
            if len(t) > 4:
                return t[:200]
    stem = re.sub(r"[-_]+", " ", path.stem)
    return stem[:200]


def build_own_record(ws_name: str, rel_path: str, title: str, body: str,
                     filename_severity: str = "", filed: bool = False) -> dict:
    """Delegate to the prior-audit ETL's build_record (guaranteed schema-valid field
    set) then override provenance + tier for our own confirmed findings."""
    doc = _pa.SourceDoc(workspace=Path(ws_name), audit_kind="own_submission",
                        path=Path(rel_path), rel_path=Path(rel_path))
    seg = _pa.FindingSegment(title=title, body=body, heading_line=1, ordinal=0)
    rec = _pa.build_record(doc, seg)  # valid v1 record, all allowed fields
    # honest own-finding provenance
    source_ref = f"own-finding:{ws_name}:{rel_path}"
    digest = hashlib.sha256(f"{source_ref}\n{title}".encode("utf-8")).hexdigest()[:12]
    rec["source_audit_ref"] = source_ref
    rec["record_id"] = f"own-finding:{_pa.slugify(ws_name, max_len=32)}:{_pa.slugify(rel_path, max_len=72)}:{digest}"
    rec["schema_version"] = SCHEMA
    rec["verification_tier"] = "tier-1-officially-disclosed" if filed else TIER
    rec["record_tier"] = "submission-derived"
    if filename_severity:
        sev = filename_severity.lower()
        if sev in ("critical", "high", "medium", "low"):
            rec["severity_at_finding"] = sev
    ext = rec.setdefault("record_extensions", {})
    ext["finding_title"] = title[:300]
    ext["origin_workspace"] = ws_name
    ext["confirmed_finding"] = True
    return rec


def discover(ws_root: Path):
    sub = ws_root / "submissions"
    if not sub.is_dir():
        return []
    out = []
    for path in sub.rglob("*.md"):
        if is_confirmed_finding(path):
            out.append(path)
    return out


def process_workspace(ws_root: Path, out_dir: Path, dry_run: bool):
    ws_name = ws_root.name
    written, skipped_no_sev = [], 0
    for path in discover(ws_root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not FILENAME_SEV_RE.search(path.name):
            skipped_no_sev += 1
            continue
        title = extract_title(path, text)
        rel = path.relative_to(ws_root).as_posix()
        fm = FILENAME_SEV_RE.search(path.name)
        rec = build_own_record(ws_name, rel, title, text[:6000],
                               filename_severity=fm.group(1) if fm else "",
                               filed="filed" in rel.lower())
        fname = f"{_pa.slugify(rec['record_id'], max_len=100)}.yaml"
        target = out_dir / fname
        if not dry_run:
            out_dir.mkdir(parents=True, exist_ok=True)
            target.write_text(_pa.yaml_dump(rec), encoding="utf-8")
        written.append({"workspace": ws_name, "rel_path": rel,
                        "severity": rec.get("severity_at_finding", ""),
                        "bug_class": rec.get("bug_class", ""), "record_id": rec["record_id"], "out": str(target)})
    return written, skipped_no_sev


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", help="single workspace root (e.g. ~/audits/mezo)")
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
        r = Path(os.path.expanduser(args.audits_root))
        roots += [p for p in sorted(r.iterdir()) if p.is_dir()] if r.is_dir() else []
    if not roots:
        ap.error("provide --workspace or --audits-root")

    all_written, total_skipped = [], 0
    per_ws = {}
    for ws in roots:
        w, s = process_workspace(ws, out_dir, args.dry_run)
        if w or s:
            per_ws[ws.name] = {"ingested": len(w), "skipped_no_severity": s}
        all_written += w
        total_skipped += s

    summary = {
        "tool": "hackerman-etl-from-our-submissions",
        "verification_tier": TIER,
        "dry_run": args.dry_run,
        "out_dir": str(out_dir),
        "total_ingested": len(all_written),
        "total_skipped_no_severity": total_skipped,
        "per_workspace": per_ws,
    }
    if args.json_summary:
        import json
        print(json.dumps(summary, indent=2))
    else:
        print(f"[own-findings-etl] tier={TIER} dry_run={args.dry_run} ingested={len(all_written)} "
              f"skipped_no_sev={total_skipped} out={out_dir}")
        for ws, c in sorted(per_ws.items()):
            print(f"  {ws}: ingested={c['ingested']} skipped={c['skipped_no_severity']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
