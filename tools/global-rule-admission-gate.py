#!/usr/bin/env python3
"""global-rule-admission-gate - BLOCK a new global rule that has not been
admitted across >= N workspaces (the reverse-evolution enforcement).

The admission gate (review_attribution.admit) decides whether a repeating
cross-workspace pattern justifies a GLOBAL change. This gate ENFORCES it at the
point a global rule is actually ADDED: a newly-added R##/L## rule line in
CLAUDE.md or docs/CODIFIED_RULES_INDEX.md, or a new audit-complete L37 signal,
must EITHER pass admission (>= threshold distinct workspaces attributed to the
same subject) OR carry an explicit inline admission marker
`<!-- admitted: <subject> | <class> -->` (operator-approved, audit-logged).

This is the direct defense against reverse evolution: one workspace miss can no
longer silently spawn one permanent global rule. A single/few-workspace lesson
must be fixed LOCALLY.

Modes:
  --added-lines-file <f>   newline-delimited ADDED diff lines (e.g. from
                           `git diff --cached -U0 | grep '^+'`); the gate scans
                           them for new-rule markers.
  --subject <s> --class <c>  check ONE subject directly.

Exit 0 = admitted / no new global rule / marker present; 1 = a new global rule
is NOT admitted (block). Language- and platform-agnostic.
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# A newly-added GLOBAL rule looks like a new R##/L## definition line, or a new
# L37 signal tuple, or a new pre-submit Check #. We only flag ADDED lines.
# A genuine NEW rule definition looks like the CODIFIED_RULES_INDEX.md bullet
# shape: `- **R99 some-title**`. A bare prose MENTION of an existing rule (e.g.
# a code comment "the L37 signal" or "matches R76 hallucination") must NOT
# match - that is not a new rule being added (loop-caught 2026-07-01: this
# over-broad regex false-fired on a code comment merely referencing L37).
_NEW_RULE_RE = re.compile(r"^\s*[-*]\s*\*\*([RL]\d{1,3})(?:/[RL]\d{1,3})?\s+[a-z]", re.I)
_NEW_SIGNAL_RE = re.compile(r'_l37_gate_strict\(\s*["\']([A-Z_]+)["\']')
_ADMITTED_MARKER_RE = re.compile(r"<!--\s*admitted:\s*([^|]+?)\s*(?:\|\s*([a-z-]+)\s*)?-->", re.I)


def _review_attribution():
    spec = importlib.util.spec_from_file_location("review_attribution", _HERE / "review_attribution.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _strip_diff_marker(ln: str) -> str:
    """Strip a leading `git diff` '+' add-marker (but not a '+++ b/file' file
    header) so the bullet-shape regex sees the actual source-line content,
    matching how `git diff --cached -U0 | grep '^+'` lines are structured."""
    if ln.startswith("+++"):
        return ""
    if ln.startswith("+"):
        return ln[1:]
    return ln


def scan_added_lines(lines: list[str], *, threshold: int = 3) -> dict:
    """Find new global-rule markers in ADDED lines; each must be admitted or
    carry an inline admitted marker."""
    ra = _review_attribution()
    led = getattr(ra, "LEDGER", None)
    text = "\n".join(lines)
    admitted_markers = {m.group(1).strip() for m in _ADMITTED_MARKER_RE.finditer(text)}
    violations = []
    subjects = []
    for raw_ln in lines:
        ln = _strip_diff_marker(raw_ln)
        for m in _NEW_RULE_RE.finditer(ln):
            subjects.append(("rule:" + m.group(1).upper(), ln.strip()[:100]))
        for m in _NEW_SIGNAL_RE.finditer(ln):
            subjects.append(("signal:" + m.group(1), ln.strip()[:100]))
    seen = set()
    for subject, ctx in subjects:
        if subject in seen:
            continue
        seen.add(subject)
        if subject in admitted_markers:
            continue  # explicit operator-approved admission marker present
        # any attribution class counts toward admission for this subject
        best = None
        for klass in ra.ATTRIBUTION_CLASSES:
            v = ra.admit(subject, klass, threshold=threshold, ledger=led)
            if v["distinct_workspaces"] > (best["distinct_workspaces"] if best else -1):
                best = v
        if not best or not best["verdict"].startswith("pass-"):
            violations.append({"subject": subject, "context": ctx,
                               "distinct_workspaces": best["distinct_workspaces"] if best else 0,
                               "threshold": threshold})
    return {"verdict": "fail-unadmitted-global-rule" if violations else "pass-admitted",
            "violations": violations, "new_rule_subjects": [s for s, _ in subjects]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--added-lines-file")
    ap.add_argument("--subject")
    ap.add_argument("--class", dest="klass")
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.subject:
        ra = _review_attribution()
        klass = args.klass or "reasoning"
        v = ra.admit(args.subject, klass, threshold=args.threshold)
        ok = v["verdict"].startswith("pass-")
        print(v if args.json else f"[global-rule-admission] {v['verdict']}: {v['reason']}")
        return 0 if ok else 1

    lines = []
    if args.added_lines_file:
        try:
            lines = Path(args.added_lines_file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            print("[global-rule-admission] added-lines-file unreadable; pass (nothing to check)")
            return 0
    rep = scan_added_lines(lines, threshold=args.threshold)
    if args.json:
        import json
        print(json.dumps(rep, indent=2))
    else:
        print(f"[global-rule-admission] {rep['verdict']}")
        for v in rep["violations"]:
            print(f"  BLOCKED new global rule {v['subject']} - only {v['distinct_workspaces']}/"
                  f"{v['threshold']} distinct workspaces attributed. Fix locally, or add "
                  f"`<!-- admitted: {v['subject']} -->` with operator approval. ({v['context']})")
    return 0 if rep["verdict"].startswith("pass-") else 1


if __name__ == "__main__":
    sys.exit(main())
