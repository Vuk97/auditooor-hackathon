#!/usr/bin/env python3
"""paste-ready-triage.py

Classify every paste-ready row in a VALIDATION_WORKLIST_<ts>.json into:

    SUBMIT-READY        — 0 gate failures
    HOLD-FIXABLE        — only CONTENT failures (sections missing,
                          OOS rebuttal needed, title-schema, $ phrasing)
    HOLD-OPERATOR-AUTH  — passes all gates BUT operator filing freeze
                          per Master Mandate § 0.4
    HOLD-EXTERNAL       — disposition pins it on external info
                          (public-fix list, deployment timing, etc.)
    KILL-RECOMMENDED    — STRUCTURAL failures (mock-PoC contamination
                          not faithfully modeled, severity rubric
                          mismatch, novel-class-not-proven, etc.)
    DUPLICATE           — title or content matches an existing
                          SUBMIT_ or KILL_ artifact in
                          <workspace>/submissions/final_dispositions/

The tool is read-only. It does not file or commit.

Inputs:
    --worklist PATH   default: latest VALIDATION_WORKLIST_*.json under
                      /Users/wolf/audits/_worklist/

Outputs:
    /Users/wolf/audits/_worklist/PASTE_READY_TRIAGE_<ts>.md
    /Users/wolf/audits/_worklist/PASTE_READY_TRIAGE_<ts>.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

WORKLIST_DIR = Path("/Users/wolf/audits/_worklist")

# Pre-submit-check rule classifiers. KEY = rule number string.
#   bucket = which content/structural class it falls in.
#       'content'    — operator can fix (add section, cite, rephrase)
#       'structural' — bug-shape problem (novel-not-proven, mock contamination,
#                       severity-rubric mismatch). Push toward KILL.
#       'external'   — needs external info (live-proof row IDs, public-fix list)
RULE_BUCKETS: dict[str, str] = {
    "1": "content",   # rubric citation
    "2": "content",   # dollar impact phrasing
    "3": "content",   # OOS/exclusion clause
    "11": "content",  # scope-review artifact missing
    "16": "structural",  # variant/incomplete-fix without novel class proof
    "21": "external",    # live-state dependent, no exact row IDs
    "22": "content",     # source-only justification / fork_replay citation
    "25": "content",     # in-scope trigger / root cause section
    "27": "content",     # production-path
    "29": "content",     # per-finding OOS clause matched
    "34": "content",     # title-schema
}

# Per-finding-OOS gate is content (operator writes a rebuttal section).
# poc-stub-coverage MISSING is content. But if the stub IS the entire PoC
# (mock-only contamination), that's structural. We detect this by
# counting MISSING entries vs OK entries.
# upstream-equivalent FAIL is content (cite upstream commit / explain delta).


def latest_worklist() -> Path:
    cands = sorted(glob.glob(str(WORKLIST_DIR / "VALIDATION_WORKLIST_*.json")))
    if not cands:
        sys.exit(f"no VALIDATION_WORKLIST_*.json under {WORKLIST_DIR}")
    return Path(cands[-1])


def parse_pre_submit_failed_rules(gate: dict[str, Any]) -> list[tuple[str, str]]:
    """Return [(rule_no, line)] for ❌-marked items in pre-submit-check."""
    out: list[tuple[str, str]] = []
    txt = (gate.get("summary", "") or "") + "\n" + (gate.get("excerpt", "") or "")
    for line in txt.splitlines():
        m = re.search(r"❌\s*(\d+)\.\s*(.{1,200})", line)
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return out


def classify_poc_stub(gate: dict[str, Any]) -> str:
    """Return 'content' or 'structural' for poc-stub-coverage failures."""
    txt = gate.get("summary", "") + "\n" + gate.get("excerpt", "")
    missing = len(re.findall(r"\bMISSING\b", txt))
    ok = len(re.findall(r"\bOK\b\s+\w+", txt))
    # If MISSING outnumbers OK 2:1 or there is no OK at all, the PoC is
    # mock-dominated and may be structurally unfaithful.
    if missing >= 2 and ok == 0:
        return "structural"
    return "content"


def gate_failure_reasons(row: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    """Bucket every gate failure by class.

    Returns:
        { 'content':   [...],
          'structural': [...],
          'external':  [...],
          'unknown':   [...] }
    """
    buckets: dict[str, list[dict[str, str]]] = {
        "content": [],
        "structural": [],
        "external": [],
        "unknown": [],
    }
    for g in row.get("gates", []):
        if g.get("status") != "fail":
            continue
        gname = g.get("gate", "")
        if gname == "pre-submit-check":
            for rule_no, line in parse_pre_submit_failed_rules(g):
                bucket = RULE_BUCKETS.get(rule_no, "unknown")
                buckets[bucket].append(
                    {"gate": gname, "rule": rule_no, "line": line}
                )
        elif gname == "per-finding-oos":
            buckets["content"].append(
                {"gate": gname, "rule": "oos", "line": g.get("summary", "")[:200]}
            )
        elif gname == "upstream-equivalent":
            buckets["content"].append(
                {"gate": gname, "rule": "upstream", "line": "upstream-equivalent gate fail (cite upstream commit / explain delta)"}
            )
        elif gname == "poc-stub-coverage":
            cls = classify_poc_stub(g)
            buckets[cls].append(
                {"gate": gname, "rule": "stub-coverage", "line": g.get("summary", "").splitlines()[0][:200]}
            )
        else:
            buckets["unknown"].append(
                {"gate": gname, "rule": "?", "line": g.get("summary", "")[:200]}
            )
    return buckets


def per_gate_summary(row: dict[str, Any]) -> list[str]:
    """One-line summary per gate (pass/fail/skip + first-fail-line)."""
    lines: list[str] = []
    for g in row.get("gates", []):
        gname = g.get("gate", "")
        st = g.get("status", "")
        if st == "fail":
            first = (g.get("summary", "") or "").splitlines()[0][:160]
            lines.append(f"  - {gname}: FAIL — {first}")
        elif st == "pass":
            lines.append(f"  - {gname}: pass")
        elif st == "skipped":
            lines.append(f"  - {gname}: skipped — {g.get('summary','')[:120]}")
        else:
            lines.append(f"  - {gname}: {st}")
    return lines


def slugify(name: str) -> str:
    s = name.lower().replace(".md", "")
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s


def find_dispositions(workspace: str) -> dict[str, str]:
    """Return {disposition_filename: full_path} for the workspace."""
    out: dict[str, str] = {}
    fd = Path(workspace) / "submissions" / "final_dispositions"
    if not fd.is_dir():
        return out
    for p in fd.iterdir():
        if p.is_file() and p.suffix == ".md":
            out[p.name] = str(p)
    return out


def find_disposition_match(name: str, dispositions: dict[str, str]) -> tuple[str, str] | None:
    """Heuristic: match a paste-ready name against disposition filenames.

    e.g. FN7_CRITICAL_FINAL_PASTE.md  -> SUBMIT_FN7_*.md or KILL_FN7_*.md.
    Strategy: extract leading FN<n> or R<n>-<n> token, look for prefix match.
    """
    base = name.replace(".md", "")
    # Token candidates
    tokens: list[str] = []
    m = re.match(r"^(FN\d+)\b", base, re.I)
    if m:
        tokens.append(m.group(1).upper())
    m = re.match(r"^([RW]\d+[-_]?\w*)", base, re.I)
    if m:
        tokens.append(m.group(1).upper().replace("_", "-"))
    # Also try "G_V01", "P256", "SNAPPY", "SWIVAL", "H2B", "KZG", "CACHE_PREFIX"
    for kw in (
        "G_V01", "P256", "SNAPPY", "SWIVAL", "H2B", "KZG",
        "CACHE_PREFIX", "BASE_LIVE", "AMP", "DYNAMIC_FEE",
    ):
        if kw.replace("_", "").lower() in base.replace("_", "").lower():
            tokens.append(kw)
    for tok in tokens:
        for fname, fpath in dispositions.items():
            up = fname.upper()
            if tok in up:
                if up.startswith("SUBMIT"):
                    return ("SUBMIT", fpath)
                if up.startswith("KILL"):
                    return ("KILL", fpath)
                if up.startswith("HOLD"):
                    return ("HOLD", fpath)
    return None


def classify_row(row: dict[str, Any], dispositions: dict[str, str]) -> dict[str, Any]:
    """Apply the triage decision tree."""
    fail_count = row.get("fail_count", 0)
    buckets = gate_failure_reasons(row)
    n_struct = len(buckets["structural"])
    n_ext = len(buckets["external"])
    n_content = len(buckets["content"])
    n_unknown = len(buckets["unknown"])

    # 1. Disposition discrepancy detection (does NOT change classification by
    #    itself — the discrepancy is reported separately).
    disp = find_disposition_match(row["name"], dispositions)
    discrepancy: str | None = None
    if disp is not None:
        kind, _ = disp
        if kind == "KILL":
            discrepancy = (
                "DISCREPANCY: paste-ready exists but final_disposition says KILL"
            )
        elif kind == "SUBMIT":
            discrepancy = (
                "INFO: final_disposition says already SUBMITTED — likely DUPLICATE"
            )
        elif kind == "HOLD":
            discrepancy = (
                "INFO: final_disposition says HOLD — operator has not authorized filing"
            )

    # 2. Triage classification
    bucket: str
    rationale: list[str]

    if disp is not None and disp[0] == "SUBMIT":
        bucket = "DUPLICATE"
        rationale = [
            f"Workspace final_disposition file `{Path(disp[1]).name}` marks this "
            "candidate as already filed/escalated.",
            "Filing again would duplicate operator-confirmed submission.",
            "Operator action: confirm and archive paste-ready, or supersede with new evidence.",
        ]
    elif disp is not None and disp[0] == "KILL":
        bucket = "KILL-RECOMMENDED"
        rationale = [
            f"Workspace final_disposition file `{Path(disp[1]).name}` marks this candidate as KILLED.",
            "Paste-ready predates the kill decision OR was regenerated automatically.",
            f"Open gate failures: {fail_count} (structural={n_struct}, content={n_content}, external={n_ext}).",
            "Operator action: archive the paste-ready unless fresh evidence promotes it.",
        ]
    elif fail_count == 0:
        # All gates clean. Master Mandate § 0.4 freeze still applies.
        if disp is not None and disp[0] == "HOLD":
            bucket = "HOLD-OPERATOR-AUTH"
            rationale = [
                "All 4 gates pass.",
                f"final_disposition `{Path(disp[1]).name}` records a HOLD posture.",
                "Submission is mechanically ready; operator filing freeze keeps it on hold.",
            ]
        else:
            bucket = "HOLD-OPERATOR-AUTH"
            rationale = [
                "All 4 gates pass.",
                "No final_disposition pin found, but Master Mandate § 0.4 filing freeze applies by default.",
                "Operator action: explicit filing approval required before submission.",
            ]
    elif n_struct > 0:
        bucket = "KILL-RECOMMENDED"
        struct_lines = "; ".join(b["line"][:80] for b in buckets["structural"][:3])
        rationale = [
            f"Structural gate failures detected ({n_struct}): {struct_lines}",
            "These indicate bug-shape defects (novel-class-not-proven, mock-PoC dominance, severity-rubric mismatch).",
            f"Other failures: content={n_content}, external={n_ext}.",
            "No viable rewrite path without re-proving the underlying claim.",
        ]
    elif n_ext > 0:
        bucket = "HOLD-EXTERNAL"
        ext_lines = "; ".join(b["line"][:80] for b in buckets["external"][:3])
        rationale = [
            f"External-info-blocker failures ({n_ext}): {ext_lines}",
            "Cannot be fixed by content edits alone — needs deployment data, public-fix list, or live-proof row IDs.",
            f"Other failures: content={n_content}.",
        ]
    elif n_content > 0 or n_unknown > 0:
        bucket = "HOLD-FIXABLE"
        rationale = [
            f"Content-only failures ({n_content + n_unknown}). Operator can fix with section additions / phrasing / citations.",
        ]
        # Build a minimum-effort fix plan
    else:  # pragma: no cover  — paranoia branch
        bucket = "HOLD-FIXABLE"
        rationale = ["Failures present but unclassified; review gate output manually."]

    # 3. Minimum-effort fix plan for HOLD-FIXABLE
    fix_plan: list[str] = []
    if bucket == "HOLD-FIXABLE":
        # Deterministic ordering: rubric/dollar/OOS/section first, then upstream/title.
        priority = ["1", "2", "3", "11", "25", "27", "22", "29", "34", "16"]
        ordered: list[dict[str, str]] = []
        seen: set[str] = set()
        for p in priority:
            for b in buckets["content"]:
                if b.get("rule") == p and id(b) not in seen:
                    ordered.append(b)
                    seen.add(id(b))
        # Append non-pre-submit content rows
        for b in buckets["content"] + buckets["unknown"]:
            if id(b) not in seen:
                ordered.append(b)
                seen.add(id(b))
        for i, b in enumerate(ordered[:5], 1):
            gate = b.get("gate", "?")
            rule = b.get("rule", "?")
            line = b.get("line", "")[:120]
            fix_plan.append(f"  {i}. [{gate} #{rule}] {line}")

    # 4. KILL justification
    kill_just: list[str] = []
    if bucket == "KILL-RECOMMENDED":
        for b in buckets["structural"][:5]:
            kill_just.append(f"  - [{b['gate']} #{b['rule']}] {b['line'][:140]}")
        if disp is not None and disp[0] == "KILL":
            kill_just.append(f"  - operator final_disposition: KILL ({Path(disp[1]).name})")

    return {
        "name": row["name"],
        "path": row["path"],
        "workspace": row["workspace"],
        "kind": row["kind"],
        "severity": row.get("severity"),
        "fail_count": fail_count,
        "bucket": bucket,
        "rationale": rationale,
        "gate_lines": per_gate_summary(row),
        "fix_plan": fix_plan,
        "kill_justification": kill_just,
        "discrepancy": discrepancy,
        "disposition_match": (
            {"kind": disp[0], "path": disp[1]} if disp is not None else None
        ),
        "buckets_count": {
            "content": n_content,
            "structural": n_struct,
            "external": n_ext,
            "unknown": n_unknown,
        },
    }


def render_md(results: list[dict[str, Any]], worklist_path: Path, ts: str) -> str:
    by_bucket: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        by_bucket.setdefault(r["bucket"], []).append(r)

    bucket_order = [
        "SUBMIT-READY",
        "HOLD-FIXABLE",
        "HOLD-OPERATOR-AUTH",
        "HOLD-EXTERNAL",
        "KILL-RECOMMENDED",
        "DUPLICATE",
    ]

    lines: list[str] = []
    lines.append(f"# Paste-Ready Triage — {ts}")
    lines.append("")
    lines.append(f"Source: `{worklist_path}`")
    lines.append(f"Total rows triaged: **{len(results)}**")
    lines.append("")
    lines.append("## Bucket counts")
    lines.append("")
    lines.append("| Bucket | Count |")
    lines.append("|---|---|")
    for b in bucket_order:
        lines.append(f"| {b} | {len(by_bucket.get(b, []))} |")
    lines.append("")

    # Discrepancy section
    discreps = [r for r in results if r.get("discrepancy")]
    if discreps:
        lines.append("## Discrepancies vs final_dispositions")
        lines.append("")
        lines.append(f"{len(discreps)} paste-ready(s) conflict with workspace final_disposition pins:")
        lines.append("")
        for r in discreps:
            lines.append(f"- **{r['name']}** ({r['workspace']})")
            lines.append(f"  - {r['discrepancy']}")
            if r["disposition_match"]:
                lines.append(f"  - disposition file: `{Path(r['disposition_match']['path']).name}`")
            lines.append(f"  - triage bucket: {r['bucket']}")
        lines.append("")

    for b in bucket_order:
        rows = by_bucket.get(b, [])
        lines.append(f"## {b} ({len(rows)})")
        lines.append("")
        if not rows:
            lines.append("_(empty)_")
            lines.append("")
            continue
        for r in rows:
            ws_short = r["workspace"].rsplit("/", 1)[-1]
            lines.append(f"### {r['name']}  ({ws_short}, {r['severity']}, fail={r['fail_count']})")
            lines.append(f"- path: `{r['path']}`")
            lines.append("- per-gate summary:")
            for gl in r["gate_lines"]:
                lines.append(gl)
            lines.append("- rationale:")
            for rl in r["rationale"]:
                lines.append(f"  - {rl}")
            if r["fix_plan"]:
                lines.append("- minimum-effort fix plan:")
                lines.extend(r["fix_plan"])
            if r["kill_justification"]:
                lines.append("- kill justification:")
                lines.extend(r["kill_justification"])
            if r["discrepancy"]:
                lines.append(f"- discrepancy: **{r['discrepancy']}**")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Generated by `tools/paste-ready-triage.py`. Operator-readable only.")
    lines.append("This file does not authorize filing.")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--worklist", type=str, default=None)
    p.add_argument("--out-dir", type=str, default=str(WORKLIST_DIR))
    args = p.parse_args()

    worklist = Path(args.worklist) if args.worklist else latest_worklist()
    with worklist.open() as f:
        wl = json.load(f)

    # Cache disposition lookups per workspace
    disp_cache: dict[str, dict[str, str]] = {}

    results: list[dict[str, Any]] = []
    for row in wl["rows"]:
        ws = row["workspace"]
        if ws not in disp_cache:
            disp_cache[ws] = find_dispositions(ws)
        results.append(classify_row(row, disp_cache[ws]))

    ts = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_md = Path(args.out_dir) / f"PASTE_READY_TRIAGE_{ts}.md"
    out_json = Path(args.out_dir) / f"PASTE_READY_TRIAGE_{ts}.json"

    out_md.write_text(render_md(results, worklist, ts))

    summary_counts: dict[str, int] = {}
    for r in results:
        summary_counts[r["bucket"]] = summary_counts.get(r["bucket"], 0) + 1
    out_json.write_text(json.dumps(
        {
            "schema": "auditooor.paste_ready_triage.v1",
            "generated_at": ts,
            "source_worklist": str(worklist),
            "total_rows": len(results),
            "bucket_counts": summary_counts,
            "rows": results,
        },
        indent=2,
    ))

    print(f"[paste-ready-triage] wrote {out_md}")
    print(f"[paste-ready-triage] wrote {out_json}")
    print(f"[paste-ready-triage] bucket counts: {summary_counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
