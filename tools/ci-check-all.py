#!/usr/bin/env python3
"""ci-check-all.py — Run every CI gate and emit a PR-ready markdown summary.

Runs each underlying tool script directly (not via `make`) so we don't
double-run anything. Classifies gates into BLOCKING (test, parity, compile,
lint) and ADVISORY (cross-link, coverage-matrix, freshness, gaps-smoke,
detector-dedupe). Exits 0 iff all blocking gates pass.

Report is written to docs/CI_STATUS.md and is ready to paste as a PR comment.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
DOCS = ROOT / "docs"
REPORT = DOCS / "CI_STATUS.md"
AUDITS_ROOT = Path.home() / "audits"

# (slug, category, cmd, cwd)   category in {"blocking","advisory"}
# A `cmd` of a callable means "run a custom aggregator that walks ~/audits/* and
# returns (rc, out)" (see Phase 41 self-enforcement gates below).
GATES = [
    ("test",            "blocking", ["bash", str(ROOT / "detectors/rust_wave1/test_fixtures/test_detectors.sh")], ROOT),
    ("parity",          "blocking", [sys.executable, str(TOOLS / "parity-report.py")], ROOT),
    ("compile",         "blocking", [sys.executable, str(TOOLS / "pattern-compile.py"), "--all"], ROOT),
    ("lint",            "blocking", [sys.executable, str(TOOLS / "detector-lint.py")], ROOT),
    ("exploit-regression", "blocking", [sys.executable, str(TOOLS / "exploit-anchor-regression.py")], ROOT),
    ("outcome-telemetry", "blocking", [sys.executable, str(TOOLS / "tests" / "test_outcome_telemetry.py")], ROOT),
    ("fork-replay", "blocking", [sys.executable, str(TOOLS / "tests" / "test_fork_replay_cli.py")], ROOT),
    # Phase 41 self-enforcement gates: registered as BLOCKING per the megaplan
    # but downgraded to ADVISORY here while the cross-workspace baseline catches
    # up (Phase 36/39 cleanup hasn't shipped on every workspace yet, and forge
    # availability is environment-dependent). Promote to "blocking" once every
    # ~/audits/* workspace passes locally; existing flow auto-downgrades a
    # blocking FAIL to ADVISORY only if explicitly marked here, so flipping the
    # category is the one-line cutover.
    ("submissions-lint", "blocking", "_run_submissions_lint", ROOT),  # Phase 41 (BLOCKING — enforces triager-clean)
    # Phase 46: pre-submit gate aggregator. Promoted from advisory → BLOCKING
    # after 8/8 Polymarket clean drafts pass via the submission-render.py
    # metadata-block injection. Walks every ~/audits/* workspace, runs
    # tools/pre-submit-check.sh on every submissions/clean/*.md (skipping
    # INDEX.md), and fails if any draft fails. Env-only forge failures
    # (missing solc) are downgraded to warnings inside pre-submit-check.sh.
    ("pre-submit",      "blocking", "_run_pre_submit", ROOT),         # Phase 46
    ("verify-pocs",     "blocking", "_run_verify_pocs", ROOT),         # Phase 47c — PROMOTED ADVISORY → BLOCKING. SKILL_ISSUE #218 resolved by adding solc-version retry logic to verify-pocs.sh: when forge auto-detect fails ("Encountered invalid solc version"), the script extracts the pragma version from the error and retries with `--use 0.8.X` (satisfied by solc-select-installed binaries). Polymarket: PASS=9 FAIL=0 SKIP=0.
    ("cross-link",      "advisory", [sys.executable, str(TOOLS / "cross-link-validator.py"), "--fix-suggestions", "--scope", "repo-only"], ROOT),
    ("coverage-matrix", "advisory", [sys.executable, str(TOOLS / "detector-coverage-matrix.py")], ROOT),
    ("freshness",       "advisory", [sys.executable, str(TOOLS / "pattern-freshness-audit.py")], ROOT),
    ("gaps-smoke",      "advisory", [sys.executable, str(TOOLS / "gap-analyzer.py"), "--smoke", "--out", "/tmp/auditooor_ci_gap_analysis_smoke.md"], ROOT),
    ("detector-dedupe", "advisory", [sys.executable, str(TOOLS / "detector-dedupe.py")], ROOT),
    ("flow-gate",       "advisory", "_run_flow_gate", ROOT),           # Phase 41
]


# ---------------------------------------------------------------------------
# Phase 41 — self-enforcement aggregators that walk ~/audits/*.
# Each returns (rc, combined_out, elapsed_seconds).  rc=0 → all workspaces
# passed.  rc=2 → SKIPPED (no audits/ dir).  Otherwise the count of failed
# workspaces (capped at 99 for sanity).
# ---------------------------------------------------------------------------

def _list_workspaces():
    if not AUDITS_ROOT.is_dir():
        return None
    out = []
    for p in sorted(AUDITS_ROOT.iterdir()):
        if not p.is_dir():
            continue
        if (p / ".auditooor_skip").exists():
            continue
        out.append(p)
    return out


def _run_workspace_cmd(ws, cmd, timeout=300):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s", time.time() - t0
    except FileNotFoundError as e:
        return 127, f"MISSING: {e}", time.time() - t0


def _run_submissions_lint():
    t0 = time.time()
    workspaces = _list_workspaces()
    if workspaces is None:
        return 2, f"SKIPPED: {AUDITS_ROOT} does not exist", time.time() - t0
    # Phase 41 promotion: gate enforces TRIAGER-CLEAN output under
    # <ws>/submissions/clean/ (+ engage_candidates/clean/), NOT the internal
    # authoring SUBMISSIONS.md. The internal doc is the source; the clean/
    # renders are what a triager actually sees. This lets submissions-lint
    # be BLOCKING without forcing us to rewrite the internal authoring format.
    eligible = [w for w in workspaces if (w / "submissions" / "clean").exists() or (w / "submissions" / "engage_candidates" / "clean").exists()]
    if not eligible:
        return 2, (
            "SKIPPED: no workspace has rendered triager-clean outputs "
            "(run `make clean-submissions` from an up-to-date nested "
            "submissions/SUBMISSIONS.md ledger, or `make clean-engage-candidates` "
            "for engage-candidate renders)"
        ), time.time() - t0
    fails = 0
    lines = [f"submissions-lint (triager-clean) over {len(eligible)} workspace(s):"]
    for ws in eligible:
        rc, out, _ = _run_workspace_cmd(ws, [sys.executable, str(TOOLS / "submissions-lint.py"), str(ws), "--triager-clean", "--clean-glob", "--strict"], timeout=120)
        tag = "PASS" if rc == 0 else f"FAIL(rc={rc})"
        lines.append(f"  {tag}  {ws.name}")
        if rc != 0:
            fails += 1
            tail = "\n".join(out.splitlines()[-5:])
            lines.append(f"    {tail}")
    summary = f"PASS={len(eligible)-fails} FAIL={fails} TOTAL={len(eligible)}"
    lines.append(summary)
    return (0 if fails == 0 else min(fails, 99)), "\n".join(lines), time.time() - t0


def _run_verify_pocs():
    t0 = time.time()
    workspaces = _list_workspaces()
    if workspaces is None:
        return 2, f"SKIPPED: {AUDITS_ROOT} does not exist", time.time() - t0
    eligible = []
    for w in workspaces:
        # foundry.toml may be at workspace root or nested one level (pocs/, etc.)
        if (w / "foundry.toml").exists() or list(w.glob("*/foundry.toml")):
            eligible.append(w)
    if not eligible:
        return 2, "SKIPPED: no workspace has foundry.toml", time.time() - t0
    fails = 0
    lines = [f"verify-pocs over {len(eligible)} workspace(s):"]
    for ws in eligible:
        rc, out, _ = _run_workspace_cmd(ws, ["bash", str(TOOLS / "verify-pocs.sh"), str(ws), "--strict"], timeout=600)
        tag = "PASS" if rc == 0 else f"FAIL(rc={rc})"
        lines.append(f"  {tag}  {ws.name}")
        if rc != 0:
            fails += 1
            tail = "\n".join(out.splitlines()[-5:])
            lines.append(f"    {tail}")
    summary = f"PASS={len(eligible)-fails} FAIL={fails} TOTAL={len(eligible)}"
    lines.append(summary)
    return (0 if fails == 0 else min(fails, 99)), "\n".join(lines), time.time() - t0


def _run_flow_gate():
    t0 = time.time()
    workspaces = _list_workspaces()
    if workspaces is None:
        return 2, f"SKIPPED: {AUDITS_ROOT} does not exist", time.time() - t0
    if not workspaces:
        return 2, "SKIPPED: no workspaces", time.time() - t0
    fails = 0
    lines = [f"flow-gate over {len(workspaces)} workspace(s) (advisory — per-engagement):"]
    for ws in workspaces:
        rc, out, _ = _run_workspace_cmd(ws, ["bash", str(TOOLS / "flow-gate.sh"), str(ws)], timeout=180)
        if rc == 0:
            tag = "PASS"
        elif rc == 2:
            tag = "WARN(soft)"
        else:
            tag = f"FAIL(rc={rc})"
            fails += 1
        lines.append(f"  {tag}  {ws.name}")
    summary = f"PASS={len(workspaces)-fails} FAIL={fails} TOTAL={len(workspaces)}"
    lines.append(summary)
    return (0 if fails == 0 else min(fails, 99)), "\n".join(lines), time.time() - t0


def _run_pre_submit():
    """Phase 46: aggregate pre-submit-check.sh across every ~/audits/*
    workspace's submissions/clean/*.md (skipping INDEX.md). Fails if any
    draft fails. Env-only forge/solc failures are warns inside the gate
    script, so this can be safely BLOCKING."""
    t0 = time.time()
    workspaces = _list_workspaces()
    if workspaces is None:
        return 2, f"SKIPPED: {AUDITS_ROOT} does not exist", time.time() - t0
    eligible = [w for w in workspaces if (w / "submissions" / "clean").exists()]
    if not eligible:
        return 2, (
            "SKIPPED: no workspace has triager-clean submissions/clean/ output "
            "(render via `make clean-submissions` from a nested "
            "submissions/SUBMISSIONS.md ledger first)"
        ), time.time() - t0
    fails = 0
    total = 0
    lines = [f"pre-submit over {len(eligible)} workspace(s):"]
    for ws in eligible:
        clean_dir = ws / "submissions" / "clean"
        drafts = sorted(p for p in clean_dir.glob("*.md") if p.name != "INDEX.md")
        ws_pass = 0
        ws_fail = 0
        for d in drafts:
            total += 1
            rc, _out, _ = _run_workspace_cmd(ws, ["bash", str(TOOLS / "pre-submit-check.sh"), str(d)], timeout=300)
            if rc == 0:
                ws_pass += 1
            else:
                ws_fail += 1
                fails += 1
        lines.append(f"  {ws.name}: PASS={ws_pass} FAIL={ws_fail}")
    summary = f"PASS={total-fails} FAIL={fails} TOTAL={total}"
    lines.append(summary)
    return (0 if fails == 0 else min(fails, 99)), "\n".join(lines), time.time() - t0


# Map slug → callable for Phase 41 aggregator gates
_AGGREGATORS = {
    "_run_submissions_lint": _run_submissions_lint,
    "_run_verify_pocs":      _run_verify_pocs,
    "_run_flow_gate":        _run_flow_gate,
    "_run_pre_submit":       _run_pre_submit,
}


def run(cmd, cwd):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=900)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT after 900s", time.time() - t0
    except FileNotFoundError as e:
        return 127, f"MISSING: {e}", time.time() - t0


def classify(slug: str, rc: int, out: str):
    """Return (status, headline).  status in {PASS,FAIL,SKIPPED,ADVISORY}."""
    if slug == "test":
        m = re.search(r"(\d+)\s*/\s*(\d+)\s+passed", out)
        if not m:
            return "FAIL", "no 'N/N passed' line"
        got, total = int(m.group(1)), int(m.group(2))
        if total == 0 or got != total:
            return "FAIL", f"{got}/{total} passed"
        return "PASS", f"{got}/{total} passed"
    if slug == "parity":
        m = re.search(r"bidirectional=([\d.]+)%", out)
        if not m:
            return "FAIL", "no 'bidirectional=N%' line"
        pct = float(m.group(1))
        cov = re.search(r"covered_both=(\d+)/(\d+)", out)
        cov_s = f", covered_both={cov.group(1)}/{cov.group(2)}" if cov else ""
        if pct < 100.0:
            return "FAIL", f"{pct}% bidirectional{cov_s}"
        return "PASS", f"{pct}% bidirectional{cov_s}"
    if slug == "compile":
        m = re.search(r"\[done\]\s+compiled\s+(\d+)\s+patterns", out)
        if not m:
            return "FAIL", "no '[done] compiled N patterns' line"
        return "PASS", f"compiled {m.group(1)} patterns"
    if slug == "lint":
        lint_md = DOCS / "DETECTOR_LINT_REPORT.md"
        if lint_md.exists():
            out = lint_md.read_text()
        # Sum HIGH-section counts; FAIL if any > 0.
        high_block = re.search(r"#\s+HIGH severity(.+?)(?:\n#\s+\w|\Z)", out, re.S)
        total_high = 0
        if high_block:
            for c in re.findall(r"\*\*Count:\*\*\s*(\d+)", high_block.group(1)):
                total_high += int(c)
        if total_high > 0:
            return "FAIL", f"{total_high} HIGH-severity issues"
        return "PASS", "0 HIGH-severity issues"
    if slug == "exploit-regression":
        m = re.search(r"PASS=(\d+)\s+FAIL=(\d+)\s+ADVISORY=(\d+)", out)
        if not m:
            return "FAIL", "no 'PASS=N FAIL=N ADVISORY=N' summary line"
        p, f, a = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if f > 0:
            return "FAIL", f"{f} anchor(s) below min_recall (pass={p})"
        return "PASS", f"{p} anchors pass (advisory={a})"
    if slug == "cross-link":
        m = re.search(r"(\d+)\s+broken", out)
        n = int(m.group(1)) if m else -1
        if n == 0:
            return "PASS", "0 broken links"
        if n > 0:
            return "ADVISORY", f"{n} broken links (non-blocking)"
        return "ADVISORY", "could not parse"
    if slug == "coverage-matrix":
        m = re.search(r"buckets=(\d+)\s+rust=(\d+)\s+sol=(\d+)", out)
        if m:
            return "ADVISORY", f"buckets={m.group(1)} rust={m.group(2)} sol={m.group(3)}"
        return "ADVISORY", "ran" if rc == 0 else f"rc={rc}"
    if slug == "freshness":
        m = re.search(r"scanned\s+(\d+)\s+patterns", out)
        return "ADVISORY", (f"scanned {m.group(1)} patterns" if m else ("ran" if rc == 0 else f"rc={rc}"))
    if slug == "detector-dedupe":
        m = re.search(r"scanned\s+(\d+)\s+detectors,\s+flagged\s+(\d+)\s+pair", out)
        if m:
            return "ADVISORY", f"scanned {m.group(1)} detectors, {m.group(2)} pairs flagged"
        return "ADVISORY", "ran" if rc == 0 else f"rc={rc}"
    if slug in ("submissions-lint", "verify-pocs", "flow-gate", "pre-submit"):
        # rc=2 → SKIPPED (graceful: no audits dir or no eligible workspaces)
        if rc == 2 and "SKIPPED" in out:
            first = out.splitlines()[0] if out else "skipped"
            return "SKIPPED", first.replace("SKIPPED: ", "")
        m = re.search(r"PASS=(\d+)\s+FAIL=(\d+)\s+TOTAL=(\d+)", out)
        if not m:
            return "FAIL", f"no PASS/FAIL summary (rc={rc})"
        p, f, t = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if f > 0:
            return "FAIL", f"{f}/{t} workspace(s) failed (pass={p})"
        return "PASS", f"{p}/{t} workspace(s) passed"
    return "ADVISORY", "ran" if rc == 0 else f"rc={rc}"


def icon(status):
    return {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": "SKIP", "ADVISORY": "ADV "}[status]


def main():
    results = []  # list of (slug, category, status, headline, elapsed)
    for slug, cat, cmd, cwd in GATES:
        if cmd is None:
            results.append((slug, cat, "SKIPPED", "requires CORPUS arg — advisory skip", 0.0))
            print(f"[{slug}] SKIPPED (needs CORPUS)")
            continue
        if isinstance(cmd, str) and cmd in _AGGREGATORS:
            print(f"[{slug}] running (aggregator)...", flush=True)
            rc, out, elapsed = _AGGREGATORS[cmd]()
            status, headline = classify(slug, rc, out)
            if cat == "advisory" and status == "FAIL":
                status = "ADVISORY"
            print(f"[{slug}] {icon(status)}  {headline}  ({elapsed:.1f}s, rc={rc})")
            results.append((slug, cat, status, headline, elapsed))
            continue
        if not Path(cmd[1] if cmd[0] != "bash" else cmd[1]).exists():
            results.append((slug, cat, "SKIPPED", f"missing script: {cmd[1]}", 0.0))
            print(f"[{slug}] SKIPPED (missing)")
            continue
        print(f"[{slug}] running...", flush=True)
        rc, out, elapsed = run(cmd, cwd)
        status, headline = classify(slug, rc, out)
        # advisory gates never block; downgrade FAIL to ADVISORY for them
        if cat == "advisory" and status == "FAIL":
            status = "ADVISORY"
        print(f"[{slug}] {icon(status)}  {headline}  ({elapsed:.1f}s, rc={rc})")
        results.append((slug, cat, status, headline, elapsed))

    blocking_fails = [r for r in results if r[1] == "blocking" and r[2] == "FAIL"]
    advisories = [r for r in results if r[1] == "advisory"]
    overall = "PASS" if not blocking_fails else "FAIL"

    lines = []
    lines.append("# CI Status")
    lines.append("")
    lines.append(f"**Overall: {overall}**  —  {len(blocking_fails)} blocking failure(s), "
                 f"{len([a for a in advisories if a[2] == 'ADVISORY'])} advisory note(s)")
    lines.append("")
    lines.append("| Gate | Category | Status | Headline | Time |")
    lines.append("|------|----------|--------|----------|------|")
    for slug, cat, status, headline, elapsed in results:
        lines.append(f"| `{slug}` | {cat} | **{status}** | {headline} | {elapsed:.1f}s |")
    lines.append("")
    lines.append("## Blocking gates")
    if blocking_fails:
        for slug, _, _, headline, _ in blocking_fails:
            lines.append(f"- `{slug}` FAIL — {headline}")
    else:
        lines.append("- All blocking gates passed (`test`, `parity`, `compile`, `lint`).")
    lines.append("")
    lines.append("## Advisory gates")
    for slug, _, status, headline, _ in advisories:
        lines.append(f"- `{slug}` {status} — {headline}")
    lines.append("")
    lines.append("## Summary")
    if overall == "PASS":
        lines.append("All blocking CI gates passed. This PR is ready for review.")
    else:
        names = ", ".join(f"`{r[0]}`" for r in blocking_fails)
        lines.append(f"This PR would FAIL CI. Blocking gate(s): {names}. See the table above for details.")
    lines.append("")
    lines.append("_Generated by `tools/ci-check-all.py` (`make ci-check`)._")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines) + "\n")
    print(f"\n[ci-check] wrote {REPORT.relative_to(ROOT)}  (overall: {overall})")
    sys.exit(0 if overall == "PASS" else 1)


if __name__ == "__main__":
    main()
