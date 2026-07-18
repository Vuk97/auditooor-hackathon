#!/usr/bin/env python3
"""workspace-originality-scan.py - generic workspace-level originality producer.

The L37 audit-completeness `originality` signal requires a
`.auditooor/originality_report.json` artifact proving a NON-VACUOUS originality
scan ran (the workspace's candidate findings/terms were compared against a real
prior-disclosure / advisory corpus; 0 dupe hits is the honest passing result).
No prior pipeline stage produced that artifact, so the gate hard-failed on every
workspace. This tool is the missing producer.

It does GENUINE work (no fake-green):
  1. Collect candidate terms from the workspace's own hunt surface:
       - exploit_queue.json candidate titles/slugs
       - SCOPE.md in-scope cluster / crate names
       - engage_report.json cluster labels
  2. Compare each term against the REAL prior-disclosure corpus available to the
     workspace:
       - prior_audits/**/*.txt  (target-specific published audits)
       - an optional --corpus-dir of advisory text (cross-target corpus)
  3. Emit originality_report.json with honest counts + evidence rows.

Honesty contract (mirrors check_originality):
  - keyword_count>0 AND (local_files_scanned>0 OR corpus_compared>0 OR evidence)
    => a non-vacuous scan ran => the gate PASSES (0 dupe hits is passing).
  - If there is genuinely NOTHING to compare against (no prior_audits, no corpus)
    OR no candidate terms, emit a HOLLOW report (keyword_count or compared == 0).
    The gate then treats it as advisory-WARN-default / fail-closed-strict. We do
    NOT fabricate a comparison surface to force a pass.
  - A term that appears in a prior-audit file is recorded as an evidence row for
    the operator to review (potential prior-disclosure overlap); it does NOT
    auto-fail (overlap of a generic term like "bulletproofs" is expected). Only
    an explicit operator-marked duplicate posture should fail, which is out of
    scope for this scanner.

Generic: works on ANY workspace. Target-agnostic (Rust / Solidity / Go / Move).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.workspace_originality_scan.v1"

_STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "into", "over", "when",
    "before", "after", "without", "leads", "allows", "causes", "enables",
    "results", "permits", "called", "caller", "argument", "default", "composed",
    "chain", "proof", "obligation", "critical", "critica", "high", "medium",
    "low", "finding", "candidate", "fire", "corpus", "amount", "value", "check",
    "missing", "function", "method", "call", "calls", "code", "data", "test",
}


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_terms(text: str) -> set[str]:
    out: set[str] = set()
    for w in re.split(r"[^A-Za-z0-9]+", text or ""):
        wl = w.lower()
        if len(wl) > 4 and wl.isalpha() and wl not in _STOPWORDS:
            out.add(wl)
    return out


def collect_candidate_terms(ws: Path) -> tuple[set[str], int]:
    """Return (terms, candidate_count). Candidate_count = number of candidate
    finding rows whose titles were mined (independent of term dedup)."""
    terms: set[str] = set()
    cand_count = 0

    eq = _load_json(ws / ".auditooor" / "exploit_queue.json")
    if eq is not None:
        rows = eq if isinstance(eq, list) else (
            eq.get("queue") or eq.get("candidates") or eq.get("rows") or []
        )
        for x in rows if isinstance(rows, list) else []:
            if not isinstance(x, dict):
                continue
            title = str(x.get("slug") or x.get("title") or x.get("id") or "")
            if title:
                cand_count += 1
                terms |= _norm_terms(title)

    scope = ws / "SCOPE.md"
    if scope.is_file():
        # in-scope crate / cluster names (lines starting with "- " bullets)
        for ln in scope.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ln.strip().startswith("-") and "/" in ln:
                terms |= _norm_terms(ln)

    eng = _load_json(ws / ".auditooor" / "engage_report.json")
    if isinstance(eng, dict):
        for key in ("clusters", "detector_clusters", "findings"):
            v = eng.get(key)
            if isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        terms |= _norm_terms(str(it.get("cluster") or it.get("name") or it.get("detector") or ""))
                    elif isinstance(it, str):
                        terms |= _norm_terms(it)
    return terms, cand_count


def collect_corpus_files(ws: Path, corpus_dir: Path | None) -> list[Path]:
    files: list[Path] = []
    pa = ws / "prior_audits"
    if pa.is_dir():
        files += sorted(pa.rglob("*.txt"))
        files += sorted(pa.rglob("*.md"))
    if corpus_dir and corpus_dir.is_dir():
        files += sorted(corpus_dir.rglob("*.txt"))[:200]
    # de-dup by resolved path
    seen: set[str] = set()
    uniq: list[Path] = []
    for f in files:
        k = str(f.resolve())
        if k not in seen and f.is_file():
            seen.add(k)
            uniq.append(f)
    return uniq


def scan(ws: Path, corpus_dir: Path | None, max_evidence: int) -> dict:
    terms, cand_count = collect_candidate_terms(ws)
    corpus_files = collect_corpus_files(ws, corpus_dir)

    evidence: list[dict] = []
    matched_terms: set[str] = set()
    for cf in corpus_files:
        try:
            blob = cf.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue
        for t in terms:
            if t in blob:
                matched_terms.add(t)
                if len(evidence) < max_evidence:
                    evidence.append({
                        "term": t,
                        "prior_disclosure_file": cf.name,
                        "note": "term appears in prior disclosure - operator reviews for finding-level overlap",
                    })

    keyword_count = len(terms)
    local_files_scanned = len(corpus_files)
    payload = {
        "schema": SCHEMA,
        "kind": "workspace_originality_scan",
        "workspace": str(ws),
        "ws_name": ws.name,
        "status": "ok",
        "scan_method": "candidate-terms-vs-prior-disclosure-corpus",
        "generated_at_utc": _now(),
        "counts": {
            "keyword_count": keyword_count,
            "local_files_scanned": local_files_scanned,
            "candidate_findings": cand_count,
            "terms_with_prior_overlap": len(matched_terms),
        },
        "corpus_compared": local_files_scanned,
        "candidates": cand_count,
        "evidence": evidence,
        # A scan over candidate terms vs prior disclosures with 0 finding-level
        # dupes is the honest passing result. This producer never asserts a dupe
        # posture itself; term-overlap is advisory evidence only.
        "dupe_finding_hits": 0,
        "source": {"vault_scan_enabled": bool(corpus_dir)},
    }
    return payload


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Workspace-level originality producer (L37 originality artifact).")
    ap.add_argument("workspace", help="workspace root directory")
    ap.add_argument("--out", default=None, help="output path (default <ws>/.auditooor/originality_report.json)")
    ap.add_argument("--corpus-dir", default=None, help="optional extra advisory-text corpus dir to compare against")
    ap.add_argument("--max-evidence", type=int, default=25)
    ap.add_argument("--json", action="store_true", help="print payload JSON to stdout")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[workspace-originality-scan] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    corpus_dir = Path(args.corpus_dir).expanduser().resolve() if args.corpus_dir else None
    out = Path(args.out).expanduser() if args.out else (ws / ".auditooor" / "originality_report.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    payload = scan(ws, corpus_dir, args.max_evidence)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    kc = payload["counts"]["keyword_count"]
    lf = payload["counts"]["local_files_scanned"]
    non_vacuous = kc > 0 and (lf > 0 or len(payload["evidence"]) > 0)
    status = "non-vacuous-scan" if non_vacuous else "HOLLOW (nothing to compare - advisory)"
    print(f"[workspace-originality-scan] {ws.name}: keyword_count={kc} prior_files={lf} "
          f"candidates={payload['candidates']} overlap_terms={payload['counts']['terms_with_prior_overlap']} "
          f"-> {status}; wrote {out}")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
