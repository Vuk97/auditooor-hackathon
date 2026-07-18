#!/usr/bin/env python3
"""trust-gauge.py — pre-Immunefi-paste trust gauge (PR #127, Codex-revised plan).

Composes the existing originality / scope / pre-submit stack into a single
fail-closed verdict before the operator pastes a finding to Immunefi.

Per docs/PLAN_TRUST_GAUGE.md (Codex revision absorbed 2026-04-25):

  Stage A — hard blockers (any failure ⇒ BLOCK, short-circuit allowed):
    1. tools/pre-submit-check.sh <draft>  with SCOPE_REASONER_FAIL_MODE=block
       - Check #25 (in-scope prerequisite)        — fail ⇒ BLOCK
       - Check #26 (mock-PoC / cited-PoC)         — fail ⇒ BLOCK
    2. tools/scope-reasoner.py --draft <draft> in block-mode
       - risk_level == "likely-OOS"               — fail ⇒ BLOCK

  Stage B — soft signals (informational; cannot upgrade BLOCK to READY):
    3. tools/originality-grep.sh                  — green / yellow / red
    4. tools/variant-detector.py                  — green / yellow / red
    5. tools/pattern-dedupe.py                    — green / yellow / red
    6. severity-defensibility heuristic on draft  — green / yellow / red

Verdict states:
    READY  — every Stage A pass AND every Stage B green
    REVIEW — every Stage A pass AND one or more Stage B yellow/red
    BLOCK  — any Stage A fail (Stage B is irrelevant for the verdict)

Exit codes:
    0   READY
    1   REVIEW
    2   BLOCK
    >=64 wrapper / tooling error (kept distinct from a gate's negative verdict)

JSON sidecar schema (also printed to stdout):
    {
      "verdict": "READY" | "REVIEW" | "BLOCK",
      "hard_blockers": {
        "check_25_in_scope":         "pass" | "fail",
        "check_26_poc_integrity":    "pass" | "fail",
        "scope_reasoner_block_mode": "pass" | "fail",
        "pre_submit_all_checks":     "pass" | "fail"
      },
      "soft_signals": {
        "originality_grep":       "green" | "yellow" | "red",
        "variant_detector":       "green" | "yellow" | "red",
        "pattern_dedupe":         "green" | "yellow" | "red",
        "severity_defensibility": "green" | "yellow" | "red"
      },
      "log_paths":  { ...   per-tool stdout/stderr capture paths ... },
      "raw_outputs_preserved": true
    }

`--bundle` semantics:
    READY  → emit  paste-ready.txt   (Immunefi paste block)
    REVIEW → emit  review-manifest.txt (NOT paste-ready)
    BLOCK  → emit  review-manifest.txt (NOT paste-ready)

`--include-scope-verdict` re-includes scope-reasoner JSON inside the Immunefi
paste block.  Default is OFF — Immunefi triagers should not see internal
boilerplate.

This tool MUST NOT auto-paste / clipboard / network anywhere.  It writes
files to disk and prints the verdict + paths.  Operator pastes by hand.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"

PRE_SUBMIT     = TOOLS / "pre-submit-check.sh"
SCOPE_REASONER = TOOLS / "scope-reasoner.py"
ORIGINALITY    = TOOLS / "originality-grep.sh"
VARIANT        = TOOLS / "variant-detector.py"
PATTERN_DEDUPE = TOOLS / "pattern-dedupe.py"


# Wrapper / tooling error exit codes (must be >=64 per plan)
EXIT_TOOL_MISSING       = 64
EXIT_DRAFT_MISSING      = 65
EXIT_PRE_SUBMIT_CRASH   = 66
EXIT_SCOPE_CRASH        = 67
EXIT_INTERNAL           = 70


# --------------------------------------------------------------------------
# subprocess helpers
# --------------------------------------------------------------------------

def _run(cmd: List[str], env: Optional[Dict[str, str]] = None,
         log_dir: Optional[Path] = None, name: str = "cmd",
         timeout: int = 600) -> Tuple[int, str, str, Optional[Path]]:
    """Run `cmd`, capture stdout/stderr; persist combined log to disk if asked.

    Returns (returncode, stdout, stderr, log_path_or_None).
    """
    proc = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    log_path: Optional[Path] = None
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{name}.log"
        with log_path.open("w", encoding="utf-8") as fh:
            fh.write(f"# cmd: {' '.join(cmd)}\n")
            fh.write(f"# returncode: {proc.returncode}\n")
            fh.write("# --- stdout ---\n")
            fh.write(proc.stdout or "")
            fh.write("\n# --- stderr ---\n")
            fh.write(proc.stderr or "")
    return proc.returncode, proc.stdout or "", proc.stderr or "", log_path


# --------------------------------------------------------------------------
# Stage A — hard blockers
# --------------------------------------------------------------------------

# Lines emitted by pre-submit-check.sh, e.g.
#   "  ✅ 25. OOS prerequisite gate: ..."
#   "  ❌ 25. oos-prerequisite-root-cause-missing: ..."
#   "  ✅ 26. Mock-PoC contamination gate: ..."
#   "  ❌ 26. mock-poc-contamination: ..."
#   "  ❌ 23. scope-reasoner-likely-oos: ..."
_CHECK_LINE = re.compile(r"^\s*([✅❌⚠️])\s*(\d+)\.")


def parse_pre_submit_output(stdout: str) -> Dict[int, str]:
    """Return {check_number: 'pass' | 'fail' | 'warn'} from pre-submit output.

    Last verdict line for a given check wins (matches pre-submit's own
    overall-fail accounting which only counts ❌ as a failure).
    """
    verdicts: Dict[int, str] = {}
    for line in stdout.splitlines():
        m = _CHECK_LINE.match(line)
        if not m:
            continue
        symbol, number = m.group(1), int(m.group(2))
        if symbol == "✅":
            verdicts[number] = "pass"
        elif symbol == "❌":
            verdicts[number] = "fail"
        elif symbol == "⚠":
            # leading-warning glyph rendered as ⚠ alone — treat as warn
            verdicts[number] = "warn"
    return verdicts


def run_pre_submit(draft: Path, log_dir: Path) -> Dict[str, Any]:
    """Run pre-submit-check.sh in strict block-mode and parse Check 25 / 26."""
    if not PRE_SUBMIT.exists():
        return {"error": f"missing tool: {PRE_SUBMIT}", "errno": EXIT_TOOL_MISSING}
    env = os.environ.copy()
    env["SCOPE_REASONER_FAIL_MODE"] = "block"
    try:
        rc, out, err, log = _run(
            ["bash", str(PRE_SUBMIT), str(draft)],
            env=env, log_dir=log_dir, name="pre-submit",
        )
    except subprocess.TimeoutExpired as exc:
        return {"error": f"pre-submit timeout: {exc}", "errno": EXIT_PRE_SUBMIT_CRASH}
    except FileNotFoundError as exc:
        return {"error": f"pre-submit launch failure: {exc}", "errno": EXIT_PRE_SUBMIT_CRASH}

    verdicts = parse_pre_submit_output(out)
    return {
        "returncode": rc,
        "stdout": out,
        "stderr": err,
        "log": log,
        "check_25": verdicts.get(25, "missing"),
        "check_26": verdicts.get(26, "missing"),
        "check_23": verdicts.get(23, "missing"),
    }


def run_scope_reasoner_block(draft: Path, log_dir: Path) -> Dict[str, Any]:
    """Run scope-reasoner.py and treat risk_level == 'likely-OOS' as fail."""
    if not SCOPE_REASONER.exists():
        return {"error": f"missing tool: {SCOPE_REASONER}", "errno": EXIT_TOOL_MISSING}
    try:
        rc, out, err, log = _run(
            [sys.executable, str(SCOPE_REASONER), "--draft", str(draft)],
            log_dir=log_dir, name="scope-reasoner",
        )
    except subprocess.TimeoutExpired as exc:
        return {"error": f"scope-reasoner timeout: {exc}", "errno": EXIT_SCOPE_CRASH}
    except FileNotFoundError as exc:
        return {"error": f"scope-reasoner launch failure: {exc}", "errno": EXIT_SCOPE_CRASH}

    risk_level = "unknown"
    parsed: Dict[str, Any] = {}
    try:
        parsed = json.loads(out) if out.strip() else {}
        risk_level = parsed.get("risk_level", "unknown")
    except json.JSONDecodeError:
        # Tool failed to emit JSON. Default to "fail" — we are fail-closed.
        return {
            "returncode": rc, "stdout": out, "stderr": err, "log": log,
            "risk_level": "unknown", "verdict": "fail",
            "error": "scope-reasoner did not emit JSON",
            "errno": EXIT_SCOPE_CRASH,
        }

    # Block-mode semantics: only "likely-OOS" is a hard block.
    # "advisory" / "common-OOS" / "medium-OOS" / "none" are NOT block-mode fails.
    verdict = "fail" if risk_level == "likely-OOS" else "pass"
    return {
        "returncode": rc, "stdout": out, "stderr": err, "log": log,
        "risk_level": risk_level, "parsed": parsed, "verdict": verdict,
    }


# --------------------------------------------------------------------------
# Stage B — soft signals
# --------------------------------------------------------------------------

def run_originality_grep(draft: Path, log_dir: Path) -> Dict[str, Any]:
    """Use originality-grep.sh on a couple of keywords lifted from the draft.

    Mature integration would lift named entities (contract / function names);
    for the v1 wrapper we extract a deterministic keyword set from the title /
    first heading and grep across the corpora.  Soft signal only.
    """
    if not ORIGINALITY.exists():
        return {"error": f"missing tool: {ORIGINALITY}", "errno": EXIT_TOOL_MISSING}

    keyword = _extract_originality_keyword(draft)
    if not keyword:
        return {"verdict": "yellow", "reason": "no-keyword-extractable", "log": None}

    try:
        rc, out, err, log = _run(
            ["bash", str(ORIGINALITY), keyword],
            log_dir=log_dir, name="originality-grep",
        )
    except subprocess.TimeoutExpired as exc:
        return {"verdict": "yellow", "reason": f"timeout: {exc}", "log": None}
    except FileNotFoundError as exc:
        return {"error": f"originality launch failure: {exc}", "errno": EXIT_TOOL_MISSING}

    # originality-grep exits 0 when ANY hits found, 1 when CLEAN.
    # For a novel finding we WANT exit 1 (no prior corpus match) → green.
    if rc == 1:
        verdict = "green"
    elif rc == 0:
        verdict = "yellow"  # prior hits found — operator should inspect
    else:
        verdict = "yellow"
    return {"verdict": verdict, "returncode": rc, "stdout": out, "stderr": err,
            "log": log, "keyword": keyword}


def _extract_originality_keyword(draft: Path) -> str:
    """Best-effort keyword: first H1 stripped of severity/scope tags, else stem."""
    try:
        text = draft.read_text(errors="ignore")
    except OSError:
        return draft.stem
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("# "):
            kw = line.lstrip("# ").strip()
            kw = re.sub(r"\[[^\]]+\]", "", kw).strip()
            kw = re.sub(r"\s+", " ", kw)
            if kw:
                # originality-grep uses extended regex; grab the longest
                # alphanumeric run so we don't accidentally inject regex meta.
                tokens = re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", kw)
                if tokens:
                    # Pick the first three tokens as a phrase.
                    return " ".join(tokens[:3])
                return kw
    return draft.stem


def run_variant_detector(draft: Path, workspace: Optional[Path],
                         log_dir: Path) -> Dict[str, Any]:
    if not VARIANT.exists():
        return {"error": f"missing tool: {VARIANT}", "errno": EXIT_TOOL_MISSING}
    if workspace is None:
        # Walk up from draft until we hit a dir that looks like a workspace.
        workspace = _guess_workspace(draft)
    if workspace is None or not workspace.exists():
        return {"verdict": "yellow",
                "reason": "no-workspace-resolvable", "log": None}

    try:
        rc, out, err, log = _run(
            [sys.executable, str(VARIANT), str(workspace), str(draft), "--json"],
            log_dir=log_dir, name="variant-detector",
        )
    except subprocess.TimeoutExpired as exc:
        return {"verdict": "yellow", "reason": f"timeout: {exc}", "log": None}
    except FileNotFoundError as exc:
        return {"error": f"variant launch failure: {exc}", "errno": EXIT_TOOL_MISSING}

    # variant-detector exit codes: 0 low / 1 medium / 2 high.
    if rc == 0:
        verdict = "green"
    elif rc == 1:
        verdict = "yellow"
    elif rc == 2:
        verdict = "red"
    else:
        verdict = "yellow"
    return {"verdict": verdict, "returncode": rc, "stdout": out, "stderr": err,
            "log": log, "workspace": str(workspace)}


def _guess_workspace(draft: Path) -> Optional[Path]:
    cur = draft.resolve().parent
    for _ in range(8):
        if (cur / "submissions").exists() or (cur / "SCOPE.md").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def run_pattern_dedupe(log_dir: Path) -> Dict[str, Any]:
    """Pattern-dedupe operates on the DSL pattern library, not on a draft.

    For trust-gauge we treat exit 0 as green (no near-duplicate patterns
    flagged).  Any non-zero or import error → yellow.  This is a soft
    signal only (per Codex Stage B).
    """
    if not PATTERN_DEDUPE.exists():
        return {"error": f"missing tool: {PATTERN_DEDUPE}", "errno": EXIT_TOOL_MISSING}
    try:
        rc, out, err, log = _run(
            [sys.executable, str(PATTERN_DEDUPE), "--threshold", "0.95"],
            log_dir=log_dir, name="pattern-dedupe",
        )
    except subprocess.TimeoutExpired as exc:
        return {"verdict": "yellow", "reason": f"timeout: {exc}", "log": None}
    except FileNotFoundError as exc:
        return {"error": f"pattern-dedupe launch failure: {exc}", "errno": EXIT_TOOL_MISSING}

    verdict = "green" if rc == 0 else "yellow"
    return {"verdict": verdict, "returncode": rc, "stdout": out, "stderr": err,
            "log": log}


def assess_severity_defensibility(draft: Path) -> Dict[str, Any]:
    """Heuristic: rubric citation + dollar-impact + cited tier example.

    Returns green if all three present, yellow if 1-2, red if 0.
    """
    try:
        text = draft.read_text(errors="ignore").lower()
    except OSError:
        return {"verdict": "red", "reason": "draft-unreadable"}

    has_rubric = bool(re.search(r"rubric|severity rubric|immunefi rubric", text))
    has_dollar = bool(re.search(r"\$\s?\d|usd|impact[:\s].*\d", text))
    has_tier_example = bool(re.search(
        r"(see|cited|previous|reference|similar to)\s+(poly|morpho|snow|cap|finding|submission)-",
        text,
    ))

    score = sum([has_rubric, has_dollar, has_tier_example])
    if score == 3:
        verdict = "green"
    elif score >= 1:
        verdict = "yellow"
    else:
        verdict = "red"
    return {
        "verdict": verdict,
        "has_rubric_citation": has_rubric,
        "has_dollar_impact": has_dollar,
        "has_tier_example": has_tier_example,
    }


# --------------------------------------------------------------------------
# verdict assembly
# --------------------------------------------------------------------------

def compute_verdict(hard: Dict[str, str], soft: Dict[str, str]) -> str:
    if any(v != "pass" for v in hard.values()):
        return "BLOCK"
    if all(v == "green" for v in soft.values()):
        return "READY"
    return "REVIEW"


def assemble_report(draft: Path, log_dir: Path, workspace: Optional[Path],
                    runners: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run every gate and assemble the JSON report.

    `runners` injection point is for tests — pass a dict of callables to
    short-circuit any subprocess hit (hermetic mocking).  In production it
    stays None and we exec the real tools.
    """
    runners = runners or {}

    pre_submit = (runners.get("pre_submit") or run_pre_submit)(draft, log_dir)
    if pre_submit.get("errno"):
        return {"_tooling_error": True, "_errno": pre_submit["errno"],
                "_detail": pre_submit.get("error"), "log_dir": str(log_dir)}

    scope = (runners.get("scope_reasoner") or run_scope_reasoner_block)(draft, log_dir)
    if scope.get("errno"):
        return {"_tooling_error": True, "_errno": scope["errno"],
                "_detail": scope.get("error"), "log_dir": str(log_dir)}

    # Codex 15:52Z aggregate-blocker fix (PR #127):
    # Treat the pre-submit gate's overall returncode as a hard blocker.  Even
    # if Check #25 and Check #26 individually parsed as pass, a non-zero
    # returncode means *some other* check (e.g. live-proof / dollar-impact /
    # PoC compile) failed and the operator must NOT paste.
    #
    # Conservative v1: any pre_submit returncode != 0 ⇒ BLOCK.  A future
    # follow-up may safely classify warnings-only failures by parsing the
    # final summary block — until then we fail closed.
    pre_submit_rc = pre_submit.get("returncode")
    pre_submit_aggregate = "pass" if pre_submit_rc == 0 else "fail"

    hard_blockers = {
        "check_25_in_scope":         "pass" if pre_submit["check_25"] == "pass" else "fail",
        "check_26_poc_integrity":    "pass" if pre_submit["check_26"] == "pass" else "fail",
        "scope_reasoner_block_mode": "pass" if scope["verdict"] == "pass" else "fail",
        "pre_submit_all_checks":     pre_submit_aggregate,
    }

    # Stage B — even if Stage A failed, we still record signals for diagnostic
    # context (per plan: "Stage B may still run for diagnostic context, but its
    # results MUST NOT upgrade the verdict").
    originality = (runners.get("originality") or run_originality_grep)(draft, log_dir)
    if originality.get("errno"):
        return {"_tooling_error": True, "_errno": originality["errno"],
                "_detail": originality.get("error"), "log_dir": str(log_dir)}

    variant = (runners.get("variant") or run_variant_detector)(draft, workspace, log_dir)
    if variant.get("errno"):
        return {"_tooling_error": True, "_errno": variant["errno"],
                "_detail": variant.get("error"), "log_dir": str(log_dir)}

    pattern = (runners.get("pattern_dedupe") or run_pattern_dedupe)(log_dir)
    if pattern.get("errno"):
        return {"_tooling_error": True, "_errno": pattern["errno"],
                "_detail": pattern.get("error"), "log_dir": str(log_dir)}

    severity = (runners.get("severity") or assess_severity_defensibility)(draft)

    soft_signals = {
        "originality_grep":       originality["verdict"],
        "variant_detector":       variant["verdict"],
        "pattern_dedupe":         pattern["verdict"],
        "severity_defensibility": severity["verdict"],
    }

    verdict = compute_verdict(hard_blockers, soft_signals)

    log_paths = {
        "pre_submit":       _path_or_none(pre_submit.get("log")),
        "scope_reasoner":   _path_or_none(scope.get("log")),
        "originality_grep": _path_or_none(originality.get("log")),
        "variant_detector": _path_or_none(variant.get("log")),
        "pattern_dedupe":   _path_or_none(pattern.get("log")),
    }

    return {
        "verdict": verdict,
        "hard_blockers": hard_blockers,
        "soft_signals": soft_signals,
        "log_paths": log_paths,
        "raw_outputs_preserved": True,
        "draft": str(draft),
        "log_dir": str(log_dir),
        "details": {
            "pre_submit_returncode": pre_submit.get("returncode"),
            "pre_submit_aggregate_reason": (
                "pass: returncode==0"
                if pre_submit_rc == 0
                else f"fail: pre-submit returncode={pre_submit_rc} "
                     f"(aggregate gate failure; see pre-submit log)"
            ),
            "scope_reasoner_risk_level": scope.get("risk_level"),
            "variant_detector_returncode": variant.get("returncode"),
            "originality_returncode": originality.get("returncode"),
            "pattern_dedupe_returncode": pattern.get("returncode"),
            "severity_signals": {
                k: v for k, v in severity.items() if k != "verdict"
            },
        },
    }


def _path_or_none(p: Any) -> Optional[str]:
    if p is None:
        return None
    return str(p)


# --------------------------------------------------------------------------
# bundle emission
# --------------------------------------------------------------------------

def emit_bundle(report: Dict[str, Any], draft: Path, out_dir: Path,
                include_scope_verdict: bool = False) -> Path:
    """Emit paste-ready.txt for READY, review-manifest.txt otherwise."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if report["verdict"] == "READY":
        path = out_dir / "paste-ready.txt"
        path.write_text(_render_paste_ready(draft, report, include_scope_verdict))
    else:
        path = out_dir / "review-manifest.txt"
        path.write_text(_render_review_manifest(draft, report))
    return path


def _render_paste_ready(draft: Path, report: Dict[str, Any],
                        include_scope_verdict: bool) -> str:
    body = draft.read_text(errors="ignore")
    parts = [body.rstrip(), ""]
    if include_scope_verdict:
        parts.append("---")
        parts.append("# Internal scope-reasoner verdict (operator-included)")
        parts.append(json.dumps(report.get("hard_blockers", {}), indent=2))
        parts.append("scope_reasoner_risk_level: " +
                     str(report.get("details", {}).get("scope_reasoner_risk_level")))
        parts.append("")
    parts.append("<!-- trust-gauge verdict: READY -->")
    return "\n".join(parts) + "\n"


def _render_review_manifest(draft: Path, report: Dict[str, Any]) -> str:
    lines = [
        f"# Trust-gauge review manifest — verdict: {report['verdict']}",
        f"draft: {draft}",
        "",
        "## Hard blockers",
    ]
    for k, v in report["hard_blockers"].items():
        marker = "PASS" if v == "pass" else "FAIL"
        lines.append(f"  [{marker}] {k}")
    lines.append("")
    lines.append("## Soft signals")
    for k, v in report["soft_signals"].items():
        lines.append(f"  [{v.upper():6s}] {k}")
    lines.append("")
    lines.append("## Log paths (raw outputs preserved on disk)")
    for k, v in report["log_paths"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    if report["verdict"] == "BLOCK":
        lines.append("## Remediation")
        for k, v in report["hard_blockers"].items():
            if v != "pass":
                lines.append(f"  - {k} failed; inspect log path above.")
    elif report["verdict"] == "REVIEW":
        lines.append("## Remediation")
        for k, v in report["soft_signals"].items():
            if v != "green":
                lines.append(f"  - {k} ({v}); operator inspection required "
                             f"before paste.")
    lines.append("")
    lines.append("# NOT paste-ready. Operator must address the items above.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None,
         runners: Optional[Dict[str, Any]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Pre-Immunefi-paste trust gauge (READY / REVIEW / BLOCK).",
    )
    p.add_argument("draft", help="Submission file to evaluate.")
    p.add_argument("--workspace", help="Workspace dir (auto-detected if absent).")
    p.add_argument("--bundle", action="store_true",
                   help="Emit paste-ready.txt (READY) or review-manifest.txt "
                        "(REVIEW/BLOCK) into --out-dir.")
    p.add_argument("--out-dir", default=None,
                   help="Where to write logs and bundle. Default: tempdir.")
    p.add_argument("--include-scope-verdict", action="store_true",
                   help="Append scope-reasoner verdict to paste-ready text "
                        "(READY only).")
    p.add_argument("--json-only", action="store_true",
                   help="Print JSON only (suppress human summary).")
    args = p.parse_args(argv)

    draft = Path(args.draft).expanduser()
    if not draft.exists():
        print(f"trust-gauge: draft not found: {draft}", file=sys.stderr)
        return EXIT_DRAFT_MISSING

    out_dir = Path(args.out_dir).expanduser() if args.out_dir else Path(
        tempfile.mkdtemp(prefix="trust-gauge-"))
    log_dir = out_dir / "logs"
    workspace = Path(args.workspace).expanduser() if args.workspace else None

    try:
        report = assemble_report(draft, log_dir, workspace, runners=runners)
    except Exception as exc:  # noqa: BLE001 — surface as tooling error
        print(f"trust-gauge: internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    if report.get("_tooling_error"):
        errno = int(report.get("_errno", EXIT_INTERNAL))
        print(json.dumps({"_tooling_error": True,
                          "_errno": errno,
                          "_detail": report.get("_detail"),
                          "log_dir": report.get("log_dir")}, indent=2))
        return errno

    bundle_path: Optional[Path] = None
    if args.bundle:
        bundle_path = emit_bundle(report, draft, out_dir,
                                  include_scope_verdict=args.include_scope_verdict)
        report["bundle_path"] = str(bundle_path)

    print(json.dumps(report, indent=2))
    if not args.json_only:
        print(f"# verdict: {report['verdict']}", file=sys.stderr)
        if bundle_path is not None:
            print(f"# bundle: {bundle_path}", file=sys.stderr)
        print(f"# logs:   {log_dir}", file=sys.stderr)

    if report["verdict"] == "READY":
        return 0
    if report["verdict"] == "REVIEW":
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
