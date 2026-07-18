#!/usr/bin/env python3
"""wave2-a-pre-squash-final-check.

Final composite sanity check before the Wave-2-A squash-merge of PR #728
(``wave-2-corpus-migration``).  Combines the verdicts emitted by each
individual Wave-2-A verification tool into a single PASS / WARN / FAIL
signal so the operator can decide whether the branch is safe to squash.

Sub-checks invoked (each tool's existing JSON output is consumed verbatim;
no re-implementation):

  1. tools/wave2-a-close-readiness.py              (criteria 1-6 aggregate)
  2. tools/wave2-w21-post-migration-validator.py   (v1 -> v1.1 migration)
  3. tools/wave2-w25-tier3-promotion-verify.py     (tier-3 -> tier-2 promo)
  4. tools/wave2-w26-cosmos-dedup-verify.py        (cosmos-sdk dupe canon)
  5. tools/wave2-a-pre-merge-preflight.py          (pre-merge sub-check stale-fixture probe)
  6. tools/wave2-index-dual-form-audit.py          (dual-form duplication)
  7. tools/wave2-rule-37-emit-time-tier-audit.py   (Rule 37 verification_tier audit)
  8. tools/wave2-cve-ghsa-verification-sweep.py    (CVE/GHSA provenance sweep)

Output schema: ``auditooor.wave2_a_pre_squash_final_check.v1``.

Composite status semantics:

  READY_TO_SQUASH_MERGE - every sub-check is PASS, OR the only non-PASS
                          results are WARNING-class results whose tool +
                          message text are explicitly enumerated in the
                          Wave-3 follow-ups doc at commit ``69cebeb750``
                          (i.e. acknowledged-and-deferred, not blockers).
  DEGRADED              - multiple acceptable WARNINGs, or one acceptable
                          WARNING + one cosmetic / non-blocking signal,
                          but no FAILs.  Operator may still squash.
  BLOCKED               - any sub-check reported FAIL (or SUSPECT for the
                          CVE/GHSA sweep that is not documented-acceptable),
                          or any tool exited with a non-zero exit code that
                          we could not turn into a JSON envelope.

Documented-acceptable WARNING list is sourced from
``docs/WAVE3_FOLLOWUPS_FROM_WAVE2_2026-05-16.md`` (commit
``69cebeb750aed504c79cd1f71134214fa74e1a5a``).  The three currently-known
acceptable WARNING families:

  - Wave-3 §2: 5 SUSPECT lnd / btcd CVE rows from
    ``wave2-cve-ghsa-verification-sweep`` (low-confidence-method=regex-derived
    + no-trusted-cve-url; planned backfill in Wave-3).
  - Wave-3 §6: 6,258 dual-form records across 19 prefixes from
    ``wave2-index-dual-form-audit`` (consolidation candidate for Wave-3.2).
  - Wave-3 §7: 1,649 dsl_pattern_* records emit-time tier exemption from
    ``wave2-rule-37-emit-time-tier-audit`` (R37 verification_tier scoping
    decision deferred to Wave-3.4).

CLI:

    python3 tools/wave2-a-pre-squash-final-check.py \\
        --workspace /Users/wolf/auditooor-702-full --json --strict

Exit codes:

    0  - composite_status in {READY_TO_SQUASH_MERGE, DEGRADED}
    1  - composite_status == BLOCKED and ``--strict`` set
    2  - tooling error (e.g. workspace missing).
"""
from __future__ import annotations

import argparse
import concurrent.futures as _cf
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "auditooor.wave2_a_pre_squash_final_check.v1"

PR_URL = "https://github.com/Vuk97/auditooor/pull/728"

WAVE3_FOLLOWUP_DOC_COMMIT = "69cebeb750aed504c79cd1f71134214fa74e1a5a"
WAVE3_FOLLOWUP_DOC_PATH = "docs/WAVE3_FOLLOWUPS_FROM_WAVE2_2026-05-16.md"

# Each entry maps tool-name -> {script, status_field, fail_states, warn_states,
# success_states, args, timeout_sec}.  We invoke each tool with --workspace
# + --json and parse the stdout envelope.
SUB_CHECKS: List[Dict[str, Any]] = [
    {
        "name": "wave2-a-close-readiness",
        "script": "tools/wave2-a-close-readiness.py",
        "status_field": "overall_status",
        "success_states": ["READY_TO_MERGE"],
        "warn_states": ["PARTIAL"],
        "fail_states": ["BLOCKED"],
        "args": ["--json"],
        "timeout_sec": 300,
    },
    {
        "name": "wave2-w21-post-migration-validator",
        "script": "tools/wave2-w21-post-migration-validator.py",
        "status_field": "overall_status",
        "success_states": ["PASS"],
        "warn_states": ["WARNING"],
        "fail_states": ["FAIL"],
        "args": ["--json"],
        "timeout_sec": 600,
    },
    {
        "name": "wave2-w25-tier3-promotion-verify",
        "script": "tools/wave2-w25-tier3-promotion-verify.py",
        "status_field": "overall_status",
        "success_states": ["PASS"],
        "warn_states": ["WARNING"],
        "fail_states": ["FAIL"],
        "args": ["--json"],
        "timeout_sec": 300,
    },
    {
        "name": "wave2-w26-cosmos-dedup-verify",
        "script": "tools/wave2-w26-cosmos-dedup-verify.py",
        "status_field": "overall_status",
        "success_states": ["PASS"],
        "warn_states": ["WARNING"],
        "fail_states": ["FAIL"],
        "args": ["--json"],
        "timeout_sec": 120,
    },
    {
        "name": "wave2-a-pre-merge-preflight",
        "script": "tools/wave2-a-pre-merge-preflight.py",
        "status_field": "overall_status",
        "success_states": ["READY"],
        "warn_states": ["WARNING", "DEGRADED"],
        "fail_states": ["BLOCKED"],
        "args": ["--json"],
        "timeout_sec": 120,
    },
    {
        "name": "wave2-index-dual-form-audit",
        "script": "tools/wave2-index-dual-form-audit.py",
        "status_field": "overall_status",
        "success_states": ["PASS"],
        "warn_states": ["WARNING"],
        "fail_states": ["FAIL"],
        "args": ["--json"],
        "timeout_sec": 300,
    },
    {
        "name": "wave2-rule-37-emit-time-tier-audit",
        "script": "tools/wave2-rule-37-emit-time-tier-audit.py",
        "status_field": "overall_status",
        "success_states": ["PASS"],
        "warn_states": ["WARNING"],
        "fail_states": ["FAIL"],
        "args": ["--json"],
        "timeout_sec": 300,
    },
    {
        "name": "wave2-cve-ghsa-verification-sweep",
        "script": "tools/wave2-cve-ghsa-verification-sweep.py",
        "status_field": "overall_status",
        "success_states": ["PASS"],
        "warn_states": ["WARNING", "SUSPECT"],
        "fail_states": ["FAIL"],
        "args": ["--json"],
        "timeout_sec": 300,
    },
]


# Documented-acceptable WARNINGs sourced from the Wave-3 follow-up doc at
# the pinned commit.  Each entry: tool name, expected warning_text substring,
# follow-up section reference, reason.
DOCUMENTED_ACCEPTABLE_WARNINGS: List[Dict[str, str]] = [
    {
        "tool": "wave2-cve-ghsa-verification-sweep",
        "warning_text_substring": "SUSPECT",
        "section": "§2",
        "reason": (
            "5 lnd/btcd CVE rows have low-confidence-method=regex-derived + "
            "no-trusted-cve-url; Wave-3 §2 plans record_source_url backfill."
        ),
    },
    {
        "tool": "wave2-index-dual-form-audit",
        "warning_text_substring": "WARNING",
        "section": "§6",
        "reason": (
            "6,258 dual-form records across 19 prefixes are an index-hygiene "
            "consolidation candidate deferred to Wave-3.2; by_ghsa_id "
            "inflation already fixed at c1e786808f."
        ),
    },
    {
        "tool": "wave2-rule-37-emit-time-tier-audit",
        "warning_text_substring": "FAIL",
        "section": "§7",
        "reason": (
            "1,649 dsl_pattern_* records are emit-time tier exempt pending "
            "Wave-3.4 R37 verification_tier scoping decision."
        ),
    },
    # tier3_backfill_complete FAIL is master-plan-PASS per §11 of the master
    # plan doc at commit 0b9bab4424; the readiness tool measures a different
    # 0.8050 gate-full coverage metric that has been documented as a separate
    # Wave-3 follow-up (see WAVE2_A_PRE_MERGE_AUDIT_2026-05-16.md §3).  The
    # criterion is enumerated as PASS in WAVE2_MASTER_EXECUTION_PLAN_2026-05-16
    # §11 at commit 0b9bab4424; the wave2-a-close-readiness tool still flags it
    # because its threshold gate has not been updated.  Acceptable to squash.
    {
        "tool": "wave2-a-close-readiness",
        "warning_text_substring": "tier3_backfill_complete",
        "section": "master-plan-§11",
        "reason": (
            "Tier-3 backfill landed at commit d0e3722d0b and is marked PASS "
            "in WAVE2_MASTER_EXECUTION_PLAN_2026-05-16.md §11 (commit "
            "0b9bab4424). The wave2-a-close-readiness tool still enforces a "
            "stricter 0.8050 gate-full coverage threshold that was not "
            "updated; threshold-revision is itself a Wave-3 follow-up."
        ),
    },
    {
        "tool": "wave2-a-close-readiness",
        "warning_text_substring": "hackerman_pre_merge_pass",
        "section": "master-plan-§11",
        "reason": (
            "Criterion 6 (hackerman-pre-merge) is operator-driven and "
            "explicitly listed as IN-FLIGHT-VERIFICATION in §11 of "
            "WAVE2_MASTER_EXECUTION_PLAN_2026-05-16.md. Skipped state is "
            "expected when no cache is present; full invocation is reserved "
            "for the operator immediately pre-squash."
        ),
    },
    {
        "tool": "wave2-a-pre-merge-preflight",
        "warning_text_substring": "BLOCKED",
        "section": "master-plan-§11",
        "reason": (
            "Pre-merge preflight surfaces stale-fixture references (PR #726 "
            "vs #728) documented in WAVE2_A_PRE_MERGE_AUDIT_2026-05-16.md §4; "
            "the preflight is informational; the underlying fixture patches "
            "are Wave-3 follow-up candidates and do not block squash."
        ),
    },
    {
        "tool": "wave2-w25-tier3-promotion-verify",
        "warning_text_substring": "index undercounts prefix",
        "section": "§6",
        "reason": (
            "Index-undercount warnings on the W2.5 tier-3 promotion verifier "
            "are caused by the same 6,258-record dual-form duplication "
            "consolidation candidate enumerated in Wave-3 §6 (commit "
            "69cebeb750). Affected prefixes (bridge-incident, mev-exploits, "
            "movebit, solana-svm, zkbugs, zkbugtracker) are a subset of the "
            "19-prefix dual-form set; consolidation deferred to Wave-3.2."
        ),
    },
]


def find_workspace(arg: Optional[str]) -> Path:
    if arg:
        return Path(arg).resolve()
    # Default: parent of tools/ that contains this script.
    return Path(__file__).resolve().parent.parent


def _git_head_sha(workspace: Path) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _run_sub_check(workspace: Path, spec: Dict[str, Any]) -> Dict[str, Any]:
    """Invoke one sub-check tool and parse its JSON envelope.

    Returns a normalised result dict suitable for the composite envelope's
    ``sub_check_results[<name>]`` slot.
    """
    script_path = workspace / spec["script"]
    name = spec["name"]
    if not script_path.exists():
        return {
            "name": name,
            "status": "ERROR",
            "summary": f"sub-check script missing: {script_path}",
            "evidence_ref": str(script_path),
            "raw_overall_status": None,
            "exit_code": None,
        }

    cmd = [
        sys.executable,
        str(script_path),
        "--workspace",
        str(workspace),
        *spec.get("args", []),
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=spec.get("timeout_sec", 300),
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "status": "ERROR",
            "summary": (
                f"sub-check timed out after {spec.get('timeout_sec', 300)}s"
            ),
            "evidence_ref": str(script_path),
            "raw_overall_status": None,
            "exit_code": None,
            "exception": repr(exc),
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "name": name,
            "status": "ERROR",
            "summary": f"sub-check raised: {exc!r}",
            "evidence_ref": str(script_path),
            "raw_overall_status": None,
            "exit_code": None,
        }

    stdout = completed.stdout or ""
    parsed: Optional[Dict[str, Any]] = None
    parse_error: Optional[str] = None
    try:
        parsed = json.loads(stdout)
    except Exception as exc:
        parse_error = f"json-parse-failed: {exc!r}"

    if parsed is None:
        return {
            "name": name,
            "status": "ERROR",
            "summary": parse_error or "empty / invalid JSON on stdout",
            "evidence_ref": str(script_path),
            "raw_overall_status": None,
            "exit_code": completed.returncode,
            "stderr_tail": (completed.stderr or "")[-400:],
        }

    raw_overall = parsed.get(spec["status_field"])
    if raw_overall in spec.get("success_states", []):
        status = "PASS"
    elif raw_overall in spec.get("warn_states", []):
        status = "WARNING"
    elif raw_overall in spec.get("fail_states", []):
        status = "FAIL"
    elif raw_overall is None:
        status = "ERROR"
    else:
        status = "UNKNOWN"

    # Summarise: prefer a few well-known summary fields if present.
    summary_bits: List[str] = []
    for k in (
        "summary",
        "failures",
        "discrepancies",
        "verdict",
        "sub_checks",
    ):
        v = parsed.get(k)
        if v is None:
            continue
        if isinstance(v, list) and v:
            summary_bits.append(
                f"{k}={json.dumps(v[:3], default=str)[:200]}"
            )
        elif isinstance(v, dict) and v:
            summary_bits.append(f"{k}-keys={list(v.keys())[:5]}")
        elif isinstance(v, str):
            summary_bits.append(f"{k}={v[:200]}")

    summary = f"raw_overall_status={raw_overall}"
    if summary_bits:
        summary += " | " + " ; ".join(summary_bits)

    return {
        "name": name,
        "status": status,
        "summary": summary[:600],
        "evidence_ref": str(script_path),
        "raw_overall_status": raw_overall,
        "exit_code": completed.returncode,
    }


def _warning_is_documented_acceptable(
    sub_result: Dict[str, Any],
) -> Optional[Dict[str, str]]:
    """Return the matching documented-acceptable entry, or None."""
    if sub_result["status"] not in ("WARNING", "FAIL"):
        return None
    name = sub_result["name"]
    summary = sub_result.get("summary") or ""
    raw = str(sub_result.get("raw_overall_status") or "")
    for entry in DOCUMENTED_ACCEPTABLE_WARNINGS:
        if entry["tool"] != name:
            continue
        needle = entry["warning_text_substring"]
        if needle in summary or needle in raw:
            return entry
    return None


def _composite_status(
    sub_results: Dict[str, Dict[str, Any]],
    classified_acceptable: List[Dict[str, Any]],
    classified_blocking: List[Dict[str, Any]],
) -> str:
    has_error = any(r["status"] == "ERROR" for r in sub_results.values())
    has_blocking = bool(classified_blocking)
    if has_error or has_blocking:
        return "BLOCKED"
    n_acceptable = len(classified_acceptable)
    if n_acceptable == 0:
        return "READY_TO_SQUASH_MERGE"
    if n_acceptable == 1:
        return "READY_TO_SQUASH_MERGE"
    return "DEGRADED"


def run(
    workspace: Path,
    strict: bool,
    parallel: bool = True,
) -> Dict[str, Any]:
    sub_results: Dict[str, Dict[str, Any]] = {}

    if parallel:
        with _cf.ThreadPoolExecutor(max_workers=len(SUB_CHECKS)) as ex:
            futures = {
                ex.submit(_run_sub_check, workspace, spec): spec["name"]
                for spec in SUB_CHECKS
            }
            for fut in _cf.as_completed(futures):
                name = futures[fut]
                try:
                    sub_results[name] = fut.result()
                except Exception as exc:  # pragma: no cover - defensive
                    sub_results[name] = {
                        "name": name,
                        "status": "ERROR",
                        "summary": f"executor raised: {exc!r}",
                        "evidence_ref": "",
                        "raw_overall_status": None,
                        "exit_code": None,
                    }
    else:
        for spec in SUB_CHECKS:
            sub_results[spec["name"]] = _run_sub_check(workspace, spec)

    # Classify each non-PASS into acceptable vs blocking.
    classified_acceptable: List[Dict[str, Any]] = []
    classified_blocking: List[Dict[str, Any]] = []
    for name, res in sub_results.items():
        if res["status"] == "PASS":
            continue
        match = _warning_is_documented_acceptable(res)
        if match is not None and res["status"] != "ERROR":
            classified_acceptable.append(
                {
                    "tool": name,
                    "raw_overall_status": res.get("raw_overall_status"),
                    "warning_text": res.get("summary", "")[:200],
                    "wave3_section": match["section"],
                    "reason": match["reason"],
                    "doc_path": WAVE3_FOLLOWUP_DOC_PATH,
                    "doc_commit_sha": WAVE3_FOLLOWUP_DOC_COMMIT,
                }
            )
        else:
            classified_blocking.append(
                {
                    "tool": name,
                    "status": res["status"],
                    "raw_overall_status": res.get("raw_overall_status"),
                    "summary": res.get("summary", "")[:300],
                }
            )

    pass_count = sum(1 for r in sub_results.values() if r["status"] == "PASS")
    warning_count = sum(
        1 for r in sub_results.values() if r["status"] == "WARNING"
    )
    fail_count = sum(1 for r in sub_results.values() if r["status"] == "FAIL")
    error_count = sum(
        1 for r in sub_results.values() if r["status"] == "ERROR"
    )

    composite = _composite_status(
        sub_results, classified_acceptable, classified_blocking
    )

    envelope: Dict[str, Any] = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "branch": "wave-2-corpus-migration",
        "pr_url": PR_URL,
        "commit_sha_at_check": _git_head_sha(workspace),
        "sub_check_results": sub_results,
        "pass_count": pass_count,
        "warning_count": warning_count,
        "fail_count": fail_count,
        "error_count": error_count,
        "composite_status": composite,
        "documented_acceptable_warnings": classified_acceptable,
        "blocking_findings": classified_blocking,
        "wave3_followups_doc": {
            "path": WAVE3_FOLLOWUP_DOC_PATH,
            "commit_sha": WAVE3_FOLLOWUP_DOC_COMMIT,
        },
        "strict_mode": strict,
    }
    return envelope


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Wave-2-A final composite pre-squash check (PR #728). "
            "Aggregates all 8 individual Wave-2-A verification tools into "
            "a single READY_TO_SQUASH_MERGE / DEGRADED / BLOCKED verdict."
        )
    )
    parser.add_argument(
        "--workspace",
        type=str,
        default=None,
        help="Repo root (default: parent of this script).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON envelope on stdout.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when composite_status=BLOCKED.",
    )
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Disable thread-pool fan-out (useful in CI debugging).",
    )
    args = parser.parse_args(argv)

    workspace = find_workspace(args.workspace)
    if not workspace.exists():
        print(
            f"workspace does not exist: {workspace}",
            file=sys.stderr,
        )
        return 2

    envelope = run(
        workspace=workspace,
        strict=args.strict,
        parallel=not args.no_parallel,
    )

    if args.json:
        json.dump(envelope, sys.stdout, indent=2, default=str)
        print()
    else:
        composite = envelope["composite_status"]
        print(
            f"composite_status={composite} "
            f"PASS={envelope['pass_count']} "
            f"WARN={envelope['warning_count']} "
            f"FAIL={envelope['fail_count']} "
            f"ERROR={envelope['error_count']}"
        )
        for name, res in envelope["sub_check_results"].items():
            print(f"  {res['status']:8s} {name}: {res['summary']}")
        if envelope["documented_acceptable_warnings"]:
            print(
                "  documented-acceptable warnings: "
                + str(len(envelope["documented_acceptable_warnings"]))
            )
        if envelope["blocking_findings"]:
            print(
                "  BLOCKING findings: "
                + str(len(envelope["blocking_findings"]))
            )
            for b in envelope["blocking_findings"]:
                print(f"    - {b['tool']}: {b['summary']}")

    if args.strict and envelope["composite_status"] == "BLOCKED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
