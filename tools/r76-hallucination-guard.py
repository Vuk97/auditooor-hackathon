#!/usr/bin/env python3
"""R76 hallucination-guard gate (pre-submit + MIMO-output validator).

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

Empirical anchor: hb-pallet-ismp-claim 2026-05-27. MIMO returned
VERDICT=CONFIRMED HIGH with file_line='N/A conceptual pattern'. Real
source grep showed the vulnerable pattern MIMO described
(keccak256(abi.encodePacked(recipient, amount))) does NOT exist;
real Hyperbridge code uses proper Leaf::Request enum encoding.

This gate refuses to promote any draft / MIMO candidate where:
  (a) verdict is CONFIRMED / PROMOTE / REAL-BUG-PROMOTE
  (b) AND any of:
      - file_line is empty / 'N/A' / contains 'conceptual'|'pattern'|
        'typical'|'illustrative'|'hypothetical'
      - code_excerpt string does NOT appear via grep in the workspace
        source (when --workspace is provided)

USAGE:
  # Single draft:
  python3 tools/r76-hallucination-guard.py <draft.md> [--workspace <ws>] [--json]

  # MIMO sidecar batch (READ-ONLY by default - emits a verdict report, writes
  # NO triage feedback / anti-pattern files):
  python3 tools/r76-hallucination-guard.py --scan-mimo-dir audit/corpus_tags/derived/mega5

  # MIMO sidecar batch WITH feedback persistence (the legacy write behavior):
  python3 tools/r76-hallucination-guard.py --scan-mimo-dir <dir> --write-feedback

PR2b (2026-05-29): --scan-mimo-dir is READ-ONLY by default so a scan can never
silently mutate triage feedback / corpus state. Pass --write-feedback to restore
the prior feedback-writing behavior. --strict-promotion makes a CONFIRMED
candidate fail unless it ships a non-empty code_excerpt that grep-hits the
--workspace source (a CONFIRMED row with no excerpt is no longer admissible).

Override: <!-- r76-rebuttal: <reason 200 chars> -->

Exit 0 = pass, 1 = fail (hallucination detected), 2 = error.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.r76_hallucination_guard.v1"
RULE_ID = "R76-HALLUCINATION-GUARD"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent

CONFIRMED_RE = re.compile(
    r"\b(CONFIRMED|PROMOTE|REAL[\s_-]?BUG[\s_-]?PROMOTE|VERIFIED)\b",
    re.IGNORECASE,
)

# Phrases that signal MIMO synthesized a "conceptual pattern" rather than
# reading real source.
HALLUCINATION_PHRASE_RE = re.compile(
    r"\b(N/?A|conceptual|illustrative|hypothetical|typical|"
    r"vulnerable\s+pattern|generic\s+pattern|sample\s+code)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(
    r"<!--\s*r76-rebuttal:\s*(.{1,200}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)


# Source-file extensions the R76 excerpt-grep scans. Mainstream + the DSL /
# non-mainstream languages that appear across ~/audits/* workspaces. A verbatim
# source line in ANY of these must be grep-findable, or a CONFIRMED finding is
# wrongly auto-downgraded to MAYBE at emit time. Obyte 2026-07-09: .oscript/.aa
# (Obyte Autonomous Agents) findings were ALWAYS downgraded because the list was
# .sol/.rs/.go/.ts/.py only - and .js (ocore, the Obyte core, is in scope) was
# also missing. Adding an extension can only ADD real matches; it never
# false-matches a Solidity ws (those files simply do not exist there).
_R76_SOURCE_EXTS = (
    "sol", "rs", "go", "ts", "py", "js",          # mainstream
    "oscript", "aa",                               # Obyte Autonomous Agents
    "cairo", "move", "vy", "circom", "clar", "nr", "zok",  # other DSLs seen in ~/audits/*
)


# A line that is only whitespace / punctuation / brackets carries no verbatim
# signal (a bare ``});`` matches everywhere), so it is not required to grep-match.
_PUNCT_ONLY_LINE_RE = re.compile(r"^[\s{}()\[\];,.:+\-*/&|!<>=?%^~`'\"]*$")
_SUBSTANTIVE_MIN = 6


def _substantive_excerpt_lines(excerpt: str) -> list[str]:
    """Whitespace-normalized substantive (>= 6 chars, not punctuation-only) lines."""
    out: list[str] = []
    for raw in excerpt.split("\n"):
        s = re.sub(r"\s+", " ", raw).strip()
        if len(s) < _SUBSTANTIVE_MIN:
            continue
        if _PUNCT_ONLY_LINE_RE.match(s):
            continue
        out.append(s)
    return out


def _grep_needle(workspace: Path, needle: str) -> bool:
    try:
        includes = [f"--include=*.{ext}" for ext in _R76_SOURCE_EXTS]
        r = subprocess.run(
            ["grep", "-rqF", *includes, needle, str(workspace)],
            timeout=30, capture_output=True,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return True  # If grep fails, don't false-fail


def grep_excerpt(workspace: Path, excerpt: str, min_chars: int = 30) -> bool:
    """Return True if the excerpt appears (substring match) in workspace source.

    MULTILINE-AWARE (2026-07-10): for a multiline excerpt (>= 2 substantive lines)
    EVERY substantive line must grep-hit the source, not just the single longest
    line. This closes the R76 hole where one verbatim line credited a block with
    fabricated lines. Behavior-preserving for a single substantive line (original
    longest-line needle). Brace/punctuation-only and tiny lines are ignored.
    """
    if not workspace or not workspace.is_dir():
        return True  # No workspace = skip the check (warn-only)
    excerpt = excerpt.strip()
    if len(excerpt) < min_chars:
        return True  # Too short to grep meaningfully
    subs = _substantive_excerpt_lines(excerpt)
    if not subs:
        return True

    # MULTILINE path: every substantive line must be present in source.
    if len(subs) >= 2:
        for line in subs:
            if not _grep_needle(workspace, line[:200]):
                return False
        return True

    # SINGLE substantive line: preserve the original longest-line needle behavior.
    lines = [l.strip() for l in excerpt.split("\n") if len(l.strip()) >= min_chars]
    if not lines:
        return True
    needle = max(lines, key=len)[:120]  # cap needle to 120 chars
    needle = re.sub(r"\s+", " ", needle).strip()
    if len(needle) < min_chars:
        return True
    return _grep_needle(workspace, needle)


def check_candidate(verdict: str, file_line: str, code_excerpt: str,
                    workspace: Path | None, strict_promotion: bool = False) -> dict:
    """Apply R76 rules to a single candidate. Returns verdict dict.

    strict_promotion=True (PR2b): a CONFIRMED candidate MUST ship a non-empty
    code_excerpt, and that excerpt must grep-hit the workspace source. A
    CONFIRMED row with no excerpt (or one that cannot be grep-verified against
    a supplied workspace) is no longer admissible for promotion - it fails with
    fail-no-code-excerpt / fail-code-excerpt-not-in-workspace instead of
    silently passing.
    """
    out = {
        "schema_version": SCHEMA, "rule_id": RULE_ID,
        "input_verdict": verdict, "input_file_line": file_line[:200],
        "strict_promotion": bool(strict_promotion),
    }
    if not CONFIRMED_RE.search(verdict or ""):
        out["verdict"] = "pass-not-confirmed"
        out["reason"] = "verdict is not CONFIRMED/PROMOTE; gate not applicable"
        return out
    # CONFIRMED path - apply hallucination checks
    if not file_line or not file_line.strip() or file_line.strip().upper() == "NULL":
        out["verdict"] = "fail-no-file-line"
        out["reason"] = "verdict=CONFIRMED but file_line is empty"
        return out
    if HALLUCINATION_PHRASE_RE.search(file_line):
        out["verdict"] = "fail-conceptual-file-line"
        out["reason"] = (f"verdict=CONFIRMED but file_line='{file_line[:80]}' "
                         f"contains hallucination signal")
        return out
    excerpt_clean = (code_excerpt or "").strip()
    if strict_promotion and not excerpt_clean:
        out["verdict"] = "fail-no-code-excerpt"
        out["reason"] = ("strict-promotion: verdict=CONFIRMED but no code_excerpt "
                         "supplied; a promotable record must cite real source")
        return out
    if excerpt_clean and workspace:
        if not grep_excerpt(workspace, excerpt_clean):
            out["verdict"] = "fail-code-excerpt-not-in-workspace"
            out["reason"] = (f"verdict=CONFIRMED but code_excerpt does NOT "
                             f"appear in workspace source via grep")
            out["excerpt_needle"] = excerpt_clean[:200]
            return out
    if strict_promotion and excerpt_clean and not workspace:
        out["verdict"] = "fail-strict-no-workspace"
        out["reason"] = ("strict-promotion requires --workspace to grep-verify "
                         "the code_excerpt; none supplied")
        return out
    out["verdict"] = "pass-verified"
    out["reason"] = "verdict=CONFIRMED with valid file_line + grepable code_excerpt"
    return out


def check_draft(draft_path: Path, workspace: Path | None,
                strict_promotion: bool = False) -> dict:
    try:
        text = draft_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return {
            "schema_version": SCHEMA, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "error",
            "reason": f"draft not found: {draft_path}",
        }
    rb = REBUTTAL_RE.search(text)
    if rb and rb.group(1).strip():
        return {
            "schema_version": SCHEMA, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "ok-rebuttal",
            "reason": f"r76-rebuttal accepted: {rb.group(1).strip()[:200]}",
        }
    # Extract any verdict / file_line / code_excerpt patterns from the draft
    verdict_match = re.search(r"verdict[:\s]+([A-Z][A-Z_-]+)", text, re.IGNORECASE)
    file_line_match = re.search(r"file[_\s]?line[:\s]+([^\n]{1,200})", text, re.IGNORECASE)
    excerpt_match = re.search(r"code[_\s]?excerpt[:\s]+(.{30,500})", text, re.IGNORECASE | re.DOTALL)
    verdict = verdict_match.group(1) if verdict_match else ""
    file_line = file_line_match.group(1).strip() if file_line_match else ""
    excerpt = excerpt_match.group(1).strip() if excerpt_match else ""
    res = check_candidate(verdict, file_line, excerpt, workspace,
                          strict_promotion=strict_promotion)
    res["draft"] = str(draft_path)
    return res


def scan_mimo_dir(scan_dir: Path, workspace: Path | None,
                  strict_promotion: bool = False) -> list[dict]:
    """Apply R76 to every MIMO sidecar in a dir; emit list of fail reports."""
    out = []
    for f in sorted(glob.glob(str(scan_dir / "*.json"))):
        try:
            d = json.loads(Path(f).read_text())
        except Exception:
            continue
        r = d.get("result", "")
        if not isinstance(r, str) or not r.strip():
            continue
        body = r.strip().strip("`").lstrip("json").strip()
        try:
            j = json.loads(body)
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict):
            continue
        # r36-rebuttal: lane R76-FIX-MIMO-SCHEMA registered.
        # GAP-5 fix: MIMO sidecars produce `applies_to_target` (yes/no/maybe)
        # not `verdict` (CONFIRMED/...). Map applies=yes (or maybe + medium+
        # confidence) to CONFIRMED so we can hallucination-scan the 3158+
        # existing sidecars produced by background MIMO dispatchers.
        verdict = str(j.get("verdict", "") or "")
        applies = str(j.get("applies_to_target", "") or "").strip().lower()
        confidence = str(j.get("confidence", "") or "").strip().lower()
        if not verdict:
            if applies == "yes":
                verdict = "CONFIRMED"
            elif applies == "maybe" and confidence in ("high", "medium"):
                verdict = "CONFIRMED"
        file_line = str(j.get("file_line", "") or "")
        excerpt = str(j.get("code_excerpt", "") or "")
        res = check_candidate(verdict, file_line, excerpt, workspace,
                              strict_promotion=strict_promotion)
        res["applies_to_target"] = applies
        res["confidence"] = confidence
        res["source_artifact"] = f
        res["task_id"] = d.get("task_id", "")
        res["workspace"] = d.get("workspace") or ""
        if not res["verdict"].startswith("pass"):
            out.append(res)
    return out


def persist_feedback(report: dict) -> dict:
    """Send R76 fail report to triage-verdict-feedback.py consumers."""
    if not report.get("fails"):
        return {"attempted": False, "reason": "no_fails"}
    if os.environ.get("AUDITOOOR_R76_FEEDBACK_DISABLE") == "1":
        return {"attempted": False, "reason": "disabled_by_env"}

    derived = Path(os.environ.get("AUDITOOOR_DERIVED_DIR") or AUDITOOOR_ROOT / "audit/corpus_tags/derived")
    derived.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(str(report.get("scan_dir") or "scan")).name)
    report_path = derived / f"r76_hallucination_feedback_{safe_name}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    cmd = [
        sys.executable,
        str(AUDITOOOR_ROOT / "tools" / "triage-verdict-feedback.py"),
        "--r76-report",
        str(report_path),
        "--kill-class",
        "KILL-R76-HALLUCINATION",
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    out: dict = {
        "attempted": True,
        "report_path": str(report_path),
        "returncode": proc.returncode,
        "stderr": proc.stderr[-1000:],
    }
    try:
        out["summary"] = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        out["stdout"] = proc.stdout[-1000:]
    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="R76 hallucination guard")
    p.add_argument("draft", nargs="?", help="Path to draft.md")
    p.add_argument("--workspace", help="Workspace root for grep verification")
    p.add_argument("--scan-mimo-dir", help="Scan a MIMO sidecar dir; emit fail report (READ-ONLY by default)")
    p.add_argument("--write-feedback", action="store_true",
                   help="Persist scan failures to triage feedback consumers "
                        "(legacy write behavior; OFF by default in PR2b).")
    p.add_argument("--no-feedback", action="store_true",
                   help="(deprecated, now the default) Do not write triage feedback.")
    p.add_argument("--strict-promotion", action="store_true",
                   help="A CONFIRMED candidate must ship a code_excerpt that "
                        "grep-hits --workspace source, else it fails.")
    p.add_argument("--strict", action="store_true",
                   help="Hard fail on warnings")
    p.add_argument("--json", action="store_true", help="JSON output")
    args = p.parse_args(argv)

    ws = Path(args.workspace) if args.workspace else None

    if args.scan_mimo_dir:
        fails = scan_mimo_dir(Path(args.scan_mimo_dir), ws,
                              strict_promotion=args.strict_promotion)
        report = {
            "schema_version": SCHEMA, "rule_id": RULE_ID,
            "scan_dir": args.scan_mimo_dir,
            "read_only": not args.write_feedback,
            "hallucination_count": len(fails),
            "fails": fails,
        }
        # PR2b: read-only by default. Feedback is written ONLY when the operator
        # passes --write-feedback (and not --no-feedback, kept as an explicit
        # belt-and-suspenders opt-out).
        if args.write_feedback and not args.no_feedback:
            report["feedback"] = persist_feedback(report)
        else:
            report["feedback"] = {"attempted": False, "reason": "read_only_default"}
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"[R76] scanned {args.scan_mimo_dir}: {len(fails)} hallucinations detected")
            for r in fails:
                print(f"  - {r.get('task_id','?')}: {r['verdict']}: {r['reason'][:120]}")
        return 1 if fails else 0

    if not args.draft:
        p.print_help()
        return 2

    res = check_draft(Path(args.draft), ws, strict_promotion=args.strict_promotion)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[R76] {res['verdict']}: {res['reason']}")

    v = res.get("verdict", "")
    if v.startswith("pass") or v == "ok-rebuttal":
        return 0
    if v == "error":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
