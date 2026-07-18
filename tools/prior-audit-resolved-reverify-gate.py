#!/usr/bin/env python3
"""prior-audit-resolved-reverify-gate: reconcile prior audit history before promotion.

Every prior item touching an in-scope file gets an explicit disposition. Known,
acknowledged, risk-accepted, wont-fix, planned-remediation, OOS, and unknown items are
promotion blockers. Fixed/resolved items require current-code re-verification so a
reported fix cannot silently be treated as a duplicate.
at the current HEAD - a "reported-fixed but we-found-not-fixed" incomplete/reverted-fix is
one of the highest-value finding types and must not be skipped.

Why this exists (Strata 2026, operator-caught): prior_audits/INGESTED_FINDINGS.md marked
the UnstakeCooldown proxy-reuse class (M-4/M-09) "Resolved / COVERED", but at the new HEAD
the guard `require(pending==false)` was present in MidasCooldownRequestImpl but MISSING in
sUSDe/sNUSD impls - a genuine incomplete fix. The audit ran the LLM hunt BEFORE any prior-
findings dedup / re-verify, so the dupe-vs-incomplete-fix distinction was discovered late.
The dir-exists check on prior_audits/ (step-0d) is NOT enough: it must be PROVEN that each
resolved in-scope finding was re-checked at HEAD.

Contract: parse the ingested prior findings and require a per-finding re-verification
artifact under <ws>/.auditooor/prior_resolved_reverify/*.json for fixed/resolved rows
(verdict: still-fixed | incomplete-fix | reverted-fix | not-applicable, with a cite).
Under --strict, FAIL (rc 1) for any promotion blocker. Advisory (rc 0 + WARN) otherwise.
Emits the obligation worklist so the loop knows exactly what to drive.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import hashlib
from pathlib import Path

_FILE_ANCHOR = re.compile(r"([A-Za-z_][A-Za-z0-9_]*\.sol)(?::(\d+(?:-\d+)?))?")
_SEV = re.compile(r"\b(critical|high|medium|low|info(?:rmational)?)\b", re.I)

_DISPOSITION_PATTERNS = (
    ("oos", re.compile(r"\b(out[ -]?of[ -]?scope|oos)\b", re.I)),
    ("risk-accepted", re.compile(r"\brisk[ -]?accepted\b", re.I)),
    ("wont-fix", re.compile(r"\b(?:won['’]?t|will[ -]?not)[ -]?fix\b", re.I)),
    ("planned-remediation", re.compile(
        r"\b(todo|planned|plan(?:ned)?[ -]?remediation|to[ -]?be[ -]?fixed|backlog)\b", re.I)),
    ("acknowledged", re.compile(r"\backnowledged\b", re.I)),
    ("known", re.compile(r"\bknown(?:[ -]issue)?\b|team[ -]?aware|covered", re.I)),
    ("fixed-resolved", re.compile(r"\b(resolved|fixed)\b", re.I)),
)

_FINDING_RECORD_MARKERS = re.compile(
    r"(?:\bfinding\b|\bissue\b|\bvulnerability\b|\bseverity\b|"
    r"\bstatus\b|\b(out[ -]?of[ -]?scope|oos)\b|\brisk[ -]?accepted\b|"
    r"\b(?:won['’]?t|will[ -]?not)[ -]?fix\b|\b(?:acknowledged|known|covered)\b|"
    r"\b(?:resolved|fixed)\b|\b(?:todo|planned|backlog|to[ -]?be[ -]?fixed|unreviewed)\b)",
    re.I,
)
_FINDING_ID_PREFIX = re.compile(
    r"^\s*(?:[#*_-]*\s*)?(?:[CHM]-?\d+|\d+(?:\.\d+){1,3})(?:\b|\s*[-:|])",
    re.I,
)


def _prior_audit_documents(ws: Path) -> list[Path]:
    paths: list[Path] = []
    prior = ws / "prior_audits"
    if not prior.is_dir():
        return paths
    for path in sorted(prior.rglob("*")):
        if path.is_file() and path.suffix.lower() in {".md", ".txt", ".json"}:
            paths.append(path)
    # A human-readable DIGEST_<report>.md is a derived canonical view of the
    # paired raw <report>.txt. Queueing both creates a false pending-agent
    # obligation even when the raw report was already reviewed. Prefer the
    # digest while retaining the raw source as an analysis alias below.
    digest_sources = {
        path.parent / f"{path.stem.removeprefix('DIGEST_')}.txt"
        for path in paths
        if path.name.startswith("DIGEST_") and path.suffix.lower() == ".md"
    }
    return [path for path in paths if path not in digest_sources]


def context_review_gate(ws: Path) -> tuple[int, dict]:
    """Queue complete prior-audit text for agent reading and validate imports."""
    documents = _prior_audit_documents(ws)
    if not documents:
        return 0, {"verdict": "pass-no-prior-audit", "documents": 0, "pending": 0}
    rows = []
    for path in documents:
        text = path.read_text(encoding="utf-8", errors="replace")
        rows.append({
            "document_id": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
            "source_file": str(path),
            "content": text,
            "analysis_status": "pending-agent-analysis",
        })
    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    queue_path = out_dir / "prior_audit_context_review_queue.json"
    queue_path.write_text(json.dumps({
        "schema_version": "auditooor.prior_audit_context_review_queue.v1",
        "workspace": str(ws),
        "documents": rows,
        "policy": "Prior audit text is read in context by an agent; status words alone do not decide scope.",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    analysis_path = out_dir / "prior_audit_context_analysis.json"
    try:
        analysis = json.loads(analysis_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        analysis = {}
    analyzed = {
        str(row.get("document_id")): row
        for row in analysis.get("documents", [])
        if isinstance(row, dict) and row.get("document_id")
    } if isinstance(analysis, dict) else {}
    analyzed_source_status = {
        Path(str(row.get("source_file"))).resolve(): str(row.get("status", ""))
        for row in analysis.get("documents", [])
        if isinstance(row, dict) and row.get("source_file")
    } if isinstance(analysis, dict) else {}
    pending = []
    for row in rows:
        status = analyzed.get(row["document_id"], {}).get("status")
        if status == "complete":
            continue
        source = Path(str(row["source_file"])).resolve()
        if source.name.startswith("DIGEST_") and source.suffix.lower() == ".md":
            raw = source.parent / f"{source.stem.removeprefix('DIGEST_')}.txt"
            if analyzed_source_status.get(raw) == "complete":
                continue
            try:
                raw_id = hashlib.sha256(raw.read_text(
                    encoding="utf-8", errors="replace"
                ).encode("utf-8")).hexdigest()[:16]
            except OSError:
                raw_id = ""
            if analyzed.get(raw_id, {}).get("status") == "complete":
                continue
        pending.append(row["document_id"])
    result = {
        "verdict": "pass-prior-audit-context-reviewed" if not pending else "pending-agent-analysis",
        "documents": len(rows),
        "pending": len(pending),
        "pending_document_ids": pending,
        "queue_path": str(queue_path),
        "analysis_path": str(analysis_path),
    }
    evidence_path = out_dir / "prior_audit_context_reconciliation.json"
    evidence_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return (0 if not pending else 1), result


def _looks_like_finding_record(raw: str) -> bool:
    """Reject scope/architecture prose that merely names an in-scope file."""
    line = raw.strip().strip("|").strip()
    return bool(_FINDING_RECORD_MARKERS.search(line) or _FINDING_ID_PREFIX.search(line))


def _in_scope_files(ws: Path) -> set:
    """Basenames of the in-scope .sol files (from inscope_units.jsonl, else SCOPE.md)."""
    files = set()
    iu = ws / ".auditooor" / "inscope_units.jsonl"
    if iu.is_file():
        for line in iu.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                f = json.loads(line).get("file", "")
            except (json.JSONDecodeError, ValueError):
                continue
            if f.endswith(".sol"):
                files.add(os.path.basename(f))
    scope = ws / "SCOPE.md"
    if scope.is_file():
        for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*\.sol)", scope.read_text(errors="ignore")):
            files.add(m.group(1))
    return files


def _disposition(raw: str) -> str:
    for name, pattern in _DISPOSITION_PATTERNS:
        if pattern.search(raw):
            return name
    return "unknown"


def _disposition_with_context(lines: list[str], index: int) -> str:
    """Classify a wrapped finding row using its nearby explicit status marker.

    Extracted PDF text commonly wraps a finding heading over several lines, for
    example ``5.16 ... TrustToken.sol`` followed by ``Points Fixed`` on the
    next line.  The marker is still semantic report context, not a filename or
    architecture keyword.  Keep the lookahead narrow and require an explicit
    disposition token so ordinary prose cannot silently classify a finding.
    """
    direct = _disposition(lines[index])
    if direct != "unknown":
        return direct
    for nearby in lines[index + 1:index + 5]:
        candidate = _disposition(nearby)
        if candidate != "unknown":
            return candidate
    return "unknown"


def _parse_prior_resolved(ws: Path, in_scope: set) -> list:
    """Return explicitly classified prior items whose file anchor is in scope."""
    out = []
    sources = (glob.glob(str(ws / "prior_audits" / "*.md")) +
               glob.glob(str(ws / "prior_audits" / "*.json")) +
               glob.glob(str(ws / "prior_audits" / "*.txt")))
    for p in sources:
        text = Path(p).read_text(errors="ignore")
        lines = text.splitlines()
        for line_index, raw in enumerate(lines):
            anchors = _FILE_ANCHOR.findall(raw)
            hit = [(f, ln) for (f, ln) in anchors if f in in_scope]
            if not hit or not _looks_like_finding_record(raw):
                continue
            sev_m = _SEV.search(raw)
            title = raw.strip().strip("|").strip()[:200]
            for f, ln in hit:
                item = {
                    "title": title,
                    "severity": (sev_m.group(1).title() if sev_m else "?"),
                    "file": f,
                    "line": ln or "",
                    "source": os.path.basename(p),
                    "disposition": _disposition_with_context(lines, line_index),
                }
                item["finding_id"] = hashlib.sha256(
                    json.dumps(item, sort_keys=True).encode("utf-8")
                ).hexdigest()[:16]
                item["candidate_promotion"] = (
                    "requires-current-code-reverification"
                    if item["disposition"] == "fixed-resolved" else "blocked-known-or-oos"
                )
                out.append(item)
    # dedup by (file,line,severity,title-prefix)
    seen, dedup = set(), []
    for o in out:
        k = (o["file"], o["line"], o["severity"], o["title"][:60])
        if k not in seen:
            seen.add(k)
            dedup.append(o)
    return dedup


def _reverified_keys(ws: Path) -> tuple[set, set]:
    """Return (finding IDs, legacy file-only artifacts) with valid evidence."""
    ids, files = set(), set()
    d = ws / ".auditooor" / "prior_resolved_reverify"
    for p in glob.glob(str(d / "*.json")):
        try:
            j = json.loads(Path(p).read_text(errors="ignore"))
        except (json.JSONDecodeError, ValueError):
            continue
        recs = j if isinstance(j, list) else [j]
        for r in recs:
            if not isinstance(r, dict):
                continue
            v = str(r.get("verdict", "")).lower().replace("_", "-")
            f = os.path.basename(str(r.get("file", "")))
            if (f and r.get("cite") and
                    v in ("still-fixed", "incomplete-fix", "reverted-fix", "not-applicable")):
                if r.get("finding_id"):
                    ids.add(str(r["finding_id"]))
                else:
                    files.add(f)
    return ids, files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("--strict", action="store_true",
                    help="FAIL (rc 1) if any in-scope prior-Resolved finding is unverified")
    ap.add_argument("--context-review", action="store_true",
                    help="extract complete prior-audit documents and require agent analysis")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    ws = Path(args.workspace).resolve()

    if args.context_review:
        rc, res = context_review_gate(ws)
        print(json.dumps(res, indent=2) if args.json else
              f"[prior-audit-context] {res['verdict']}: documents={res['documents']} pending={res['pending']}")
        return rc

    if not (ws / "prior_audits").is_dir():
        # No prior audit => nothing to re-verify (fresh target). PASS.
        res = {"gate": "prior-audit-resolved-reverify", "verdict": "pass-no-prior-audit",
               "obligations": [], "reverified_files": []}
        print(json.dumps(res) if args.json else "[prior-resolved-reverify] pass-no-prior-audit")
        return 0

    in_scope = _in_scope_files(ws)
    obligations = _parse_prior_resolved(ws, in_scope)
    reverified_ids, legacy_files = _reverified_keys(ws)
    fixed_by_file = {}
    for item in obligations:
        if item["disposition"] == "fixed-resolved":
            fixed_by_file[item["file"]] = fixed_by_file.get(item["file"], 0) + 1
    unmet = [o for o in obligations if o["disposition"] == "fixed-resolved" and
             o["finding_id"] not in reverified_ids and
             not (o["file"] in legacy_files and fixed_by_file[o["file"]] == 1)]
    blockers = [o for o in obligations if o["disposition"] != "fixed-resolved"]
    reverified = sorted(set(legacy_files) | {o["file"] for o in obligations if o["finding_id"] in reverified_ids})

    verdict = "pass-no-relevant-prior-items" if not obligations else (
        "pass-all-fixed-reverified" if not unmet and not blockers else
        "fail-prior-history-reconciliation")
    res = {
        "gate": "prior-audit-resolved-reverify",
        "verdict": verdict,
        "in_scope_files": sorted(in_scope),
        "prior_resolved_in_scope": len([o for o in obligations if o["disposition"] == "fixed-resolved"]),
        "prior_items_in_scope": len(obligations),
        "dispositions": {d: sum(o["disposition"] == d for o in obligations)
                         for d in sorted({o["disposition"] for o in obligations})},
        "reverified_files": reverified,
        "blocking_items": blockers,
        "unmet": unmet,
        "reason": (f"{len(blockers)} prior item(s) are known/OOS or otherwise unresolved for "
                   f"candidate promotion; {len(unmet)} fixed/resolved item(s) lack current-code "
                   f"re-verification. Resolve the disposition or provide a finding_id-scoped "
                   f"artifact with {{file,verdict,cite}}."
                   if (unmet or blockers) else "no relevant prior items require reconciliation"),
    }
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[prior-resolved-reverify] {verdict}: {len(obligations)} in-scope prior items, "
              f"{len(reverified)} re-verified files, {len(blockers)} BLOCKING, {len(unmet)} UNMET")
        for o in blockers[:25]:
            print(f"   BLOCKING [{o['disposition']}] {o['file']} - {o['title'][:80]}")
        for o in unmet[:25]:
            print(f"   UNMET [{o['severity']}] {o['file']}{':'+o['line'] if o['line'] else ''} - {o['title'][:80]}")
    if args.strict and (unmet or blockers):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
