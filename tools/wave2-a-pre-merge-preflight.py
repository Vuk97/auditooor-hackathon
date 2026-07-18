#!/usr/bin/env python3
"""wave2-a-pre-merge-preflight.

Lower-level diagnostic for ``tools/hackerman-pre-merge.py`` sub-checks.

Runs only the sub-checks that do NOT require Phase-3 corpus migration to be
complete, plus a stale-fixture inventory derived from
``docs/WAVE2_A_PRE_MERGE_AUDIT_2026-05-16.md``. Surfaces which currently-
failing pre-merge sub-checks are expected to flip to PASS after Phase-3
lands cleanly, and which contain stale-fixture references that will FAIL
regardless.

Output schema: ``auditooor.wave2_a_pre_merge_preflight.v1``::

    {
      "schema": "auditooor.wave2_a_pre_merge_preflight.v1",
      "generated_at": "2026-05-16T...Z",
      "workspace": "/Users/wolf/auditooor-702-full",
      "sub_checks": [
          {"name": "...", "status": "PASS|FAIL|SKIPPED", "detail": "..."},
          ...
      ],
      "overall_status": "READY|BLOCKED|PARTIAL",
      "expected_post_phase3": [<sub_check_name>, ...]
    }

CLI:

    python3 tools/wave2-a-pre-merge-preflight.py \\
        --workspace /Users/wolf/auditooor-702-full --json --strict

Exit codes:

    0  - overall_status=READY (or non-strict mode regardless)
    1  - overall_status in {BLOCKED, PARTIAL} and ``--strict`` set
    2  - tooling error (workspace missing, etc.)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "auditooor.wave2_a_pre_merge_preflight.v1"

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"

OVERALL_READY = "READY"
OVERALL_BLOCKED = "BLOCKED"
OVERALL_PARTIAL = "PARTIAL"


def _now_iso(pin: Optional[str]) -> str:
    if pin:
        return pin
    env_pin = os.environ.get("AUDITOOOR_WAVE2_A_PREFLIGHT_GENERATED_AT")
    if env_pin:
        return env_pin
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_pre_merge_script_present(workspace: Path) -> Dict[str, Any]:
    """Sub-check 1: ``tools/hackerman-pre-merge.py`` exists and parses."""
    path = workspace / "tools" / "hackerman-pre-merge.py"
    if not path.is_file():
        return {
            "name": "pre_merge_script_present",
            "status": FAIL,
            "detail": f"missing: {path}",
        }
    src = path.read_text(encoding="utf-8")
    if "STEPS:" not in src or "def compute_overall" not in src:
        return {
            "name": "pre_merge_script_present",
            "status": FAIL,
            "detail": "STEPS or compute_overall missing - script may be corrupt",
        }
    return {
        "name": "pre_merge_script_present",
        "status": PASS,
        "detail": "tools/hackerman-pre-merge.py present and structurally valid",
    }


def check_step_dependencies_resolvable(workspace: Path) -> Dict[str, Any]:
    """Sub-check 2: each STEP argv references a make target or tool that exists."""
    required_make_targets = [
        "hackerman-all",
        "docs-check",
        "hackerman-docs-cross-link-audit",
        "hackerman-pr726-merge-checklist",
        "hackerman-mcp-smoke-test",
    ]
    makefile = workspace / "Makefile"
    if not makefile.is_file():
        return {
            "name": "step_dependencies_resolvable",
            "status": FAIL,
            "detail": "Makefile missing",
        }
    src = makefile.read_text(encoding="utf-8")
    missing: List[str] = []
    for tgt in required_make_targets:
        # match `^TGT:` at start of line.
        if not re.search(rf"(?m)^{re.escape(tgt)}\s*:", src):
            missing.append(tgt)
    if missing:
        return {
            "name": "step_dependencies_resolvable",
            "status": FAIL,
            "detail": "missing make targets: " + ", ".join(missing),
        }
    return {
        "name": "step_dependencies_resolvable",
        "status": PASS,
        "detail": (
            "all 5 make-target dependencies resolved in Makefile "
            f"({', '.join(required_make_targets)})"
        ),
    }


# Stale-fixture inventory (audit doc section 4).
STALE_FIXTURE_PR_NUMBER_DEFAULT = 726
STALE_FIXTURE_BRANCH_DEFAULT = "wave-1-hackerman-capability-lift"
EXPECTED_PR_NUMBER = 728
EXPECTED_BRANCH = "wave-2-corpus-migration"


def check_pr726_checklist_stale_branch(workspace: Path) -> Dict[str, Any]:
    """Sub-check 3: hackerman-pr726-merge-checklist defaults to wave-1 branch.

    This is the HARD FAIL identified by the audit at
    ``tools/hackerman-pr726-merge-checklist.py:90-91``. Until the script is
    generalized or pre-merge invocation passes BRANCH/PR_NUMBER overrides,
    Step 4 of pre-merge will FAIL on PR #728.
    """
    path = workspace / "tools" / "hackerman-pr726-merge-checklist.py"
    if not path.is_file():
        return {
            "name": "pr726_checklist_stale_branch",
            "status": FAIL,
            "detail": f"missing: {path}",
        }
    src = path.read_text(encoding="utf-8")
    pr_default_match = re.search(r"DEFAULT_PR_NUMBER\s*=\s*(\d+)", src)
    branch_default_match = re.search(r'DEFAULT_BRANCH\s*=\s*"([^"]+)"', src)
    if not pr_default_match or not branch_default_match:
        return {
            "name": "pr726_checklist_stale_branch",
            "status": FAIL,
            "detail": "could not locate DEFAULT_PR_NUMBER / DEFAULT_BRANCH",
        }
    pr_default = int(pr_default_match.group(1))
    branch_default = branch_default_match.group(1)
    is_stale = (
        pr_default != EXPECTED_PR_NUMBER
        or branch_default != EXPECTED_BRANCH
    )
    # Also inspect pre-merge.py argv to see if it overrides these.
    pre_merge_path = workspace / "tools" / "hackerman-pre-merge.py"
    overrides_present = False
    if pre_merge_path.is_file():
        pm_src = pre_merge_path.read_text(encoding="utf-8")
        if (
            f"PR_NUMBER={EXPECTED_PR_NUMBER}" in pm_src
            or f"BRANCH={EXPECTED_BRANCH}" in pm_src
        ):
            overrides_present = True
    if is_stale and not overrides_present:
        return {
            "name": "pr726_checklist_stale_branch",
            "status": FAIL,
            "detail": (
                f"DEFAULT_PR_NUMBER={pr_default} (expected {EXPECTED_PR_NUMBER}); "
                f"DEFAULT_BRANCH={branch_default!r} "
                f"(expected {EXPECTED_BRANCH!r}); pre-merge.py does not "
                "override via PR_NUMBER= / BRANCH= make vars"
            ),
        }
    if is_stale and overrides_present:
        return {
            "name": "pr726_checklist_stale_branch",
            "status": PASS,
            "detail": (
                f"stale defaults present (pr={pr_default}, branch={branch_default!r}) "
                "but pre-merge.py supplies overrides"
            ),
        }
    return {
        "name": "pr726_checklist_stale_branch",
        "status": PASS,
        "detail": (
            f"defaults already match target (pr={pr_default}, branch={branch_default!r})"
        ),
    }


def check_schema_files_present(workspace: Path) -> Dict[str, Any]:
    """Sub-check 4: v1 and v1.1 hackerman-record schemas both present."""
    v1 = workspace / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.schema.json"
    v1_1 = workspace / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.1.schema.json"
    missing: List[str] = []
    if not v1.is_file():
        missing.append(str(v1))
    if not v1_1.is_file():
        missing.append(str(v1_1))
    if missing:
        return {
            "name": "schema_files_present",
            "status": FAIL,
            "detail": "missing schema files: " + ", ".join(missing),
        }
    return {
        "name": "schema_files_present",
        "status": PASS,
        "detail": "v1 + v1.1 schemas both present",
    }


def check_close_readiness_companion_present(workspace: Path) -> Dict[str, Any]:
    """Sub-check 5: companion higher-level gate present.

    Pre-merge does NOT cover criteria 3 and 4 of the SKILL Wave-2-A close
    criteria; ``tools/wave2-a-close-readiness.py`` is required for them.
    """
    path = workspace / "tools" / "wave2-a-close-readiness.py"
    if not path.is_file():
        return {
            "name": "close_readiness_companion_present",
            "status": FAIL,
            "detail": f"missing: {path} (required for criteria 3 + 4 coverage)",
        }
    return {
        "name": "close_readiness_companion_present",
        "status": PASS,
        "detail": (
            "tools/wave2-a-close-readiness.py present - operator must run it "
            "before squash-merge for criteria 3 (cosmos-sdk dedup) + 4 (R38/R39 wiring)"
        ),
    }


SUB_CHECKS = [
    check_pre_merge_script_present,
    check_step_dependencies_resolvable,
    check_pr726_checklist_stale_branch,
    check_schema_files_present,
    check_close_readiness_companion_present,
]

# Sub-check names that are EXPECTED to flip from FAIL to PASS after Phase-3
# corpus migration lands. The pre_merge_step references below are not run
# by this preflight (they need live corpus); they are documented so the
# operator knows the post-Phase-3 expectation.
EXPECTED_POST_PHASE3_FLIPS = [
    "hackerman-all/schema (Step 1 substage)",
    "hackerman-all/tier (Step 1 substage, only after tier-3 backfill also runs)",
]


def compute_overall(sub_checks: List[Dict[str, Any]]) -> str:
    fails = [c for c in sub_checks if c["status"] == FAIL]
    if not fails:
        return OVERALL_READY
    # The PR-726 stale-branch failure is structural and blocks the whole
    # pre-merge gate. Any other failure is PARTIAL.
    for c in fails:
        if c["name"] == "pr726_checklist_stale_branch":
            return OVERALL_BLOCKED
    return OVERALL_PARTIAL


def run_preflight(workspace: Path, generated_at: str) -> Dict[str, Any]:
    sub_checks = [fn(workspace) for fn in SUB_CHECKS]
    overall = compute_overall(sub_checks)
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "workspace": str(workspace),
        "sub_checks": sub_checks,
        "overall_status": overall,
        "expected_post_phase3": EXPECTED_POST_PHASE3_FLIPS,
    }


def _print_human(payload: Dict[str, Any]) -> None:
    print(f"wave2-a-pre-merge-preflight :: {payload['overall_status']}")
    print(f"  workspace: {payload['workspace']}")
    print(f"  generated_at: {payload['generated_at']}")
    print("")
    for c in payload["sub_checks"]:
        marker = {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": "SKIP"}[c["status"]]
        print(f"  [{marker}] {c['name']}")
        print(f"         {c['detail']}")
    print("")
    print("Expected to flip PASS post-Phase-3:")
    for name in payload["expected_post_phase3"]:
        print(f"  - {name}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Wave-2-A pre-merge preflight diagnostic"
    )
    parser.add_argument(
        "--workspace",
        type=str,
        default=str(Path(__file__).resolve().parents[1]),
        help="repo root (default: parent of this script)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON envelope")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when overall_status != READY",
    )
    parser.add_argument(
        "--generated-at",
        type=str,
        default=None,
        help="pin envelope timestamp (reproducible)",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).resolve()
    if not workspace.is_dir():
        sys.stderr.write(f"workspace not found: {workspace}\n")
        return 2

    payload = run_preflight(workspace, _now_iso(args.generated_at))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_human(payload)

    if args.strict and payload["overall_status"] != OVERALL_READY:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
