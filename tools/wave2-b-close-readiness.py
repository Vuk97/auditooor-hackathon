#!/usr/bin/env python3
"""wave2-b-close-readiness.

Automates the six "Wave-2-B close criteria" for PR #729 (branch
``wave-2-capability-expansion``).  Mirrors ``tools/wave2-a-close-readiness.py``
(commit ``53296c5d76``) but checks PR-B's distinct close criteria covering
W2.2 detector-autogen Phase-1, W2.4 7-firm PDF parsers, W2.8
``vault_corpus_freshness`` callable, and the cross-firm dedup detector.

The six criteria:

  1. W2.2 detector-autogen Phase-1 wired -
     ``tools/audit/wave2_w22_detector_loader.py`` exists AND references
     the ``AUDITOOOR_W22_PHASE1_ENABLED`` env flag (default OFF).

  2. W2.4 PDF parsers >= 7 firms shipped -
     glob ``tools/hackerman-etl-from-audit-firm-pdf-*.py`` and require
     >= 7 firm parsers; the discovered firms are listed in the detail.

  3. W2.8 ``vault_corpus_freshness`` callable wired into
     ``tools/vault-mcp-server.py``; the total callable count is reported
     and we soft-target >= 66 callables.

  4. Cross-firm dedup detector present -
     ``tools/wave2-cross-firm-dedup-detector.py`` exists and is non-empty.

  5. All W2.4 firm-parser regression tests PASS -
     ``--run-regression`` opts into the live unittest invocation across
     the eight firm-parser test modules; the default mode reads the
     latest cached verdict at ``/tmp/wave2-b-firm-regression*.json`` or
     reports ``SKIPPED`` if no cache exists.

  6. No PR-A criteria leakage -
     scan the PR-B branch's commit history (since divergence from
     ``origin/main``) for explicit dependencies on PR-A landing first
     ("Phase-3 migration", "v1.1 corpus", etc.).  Emit FAIL/WARN if
     leakage detected; PR-B is supposed to be independently mergeable.

Output schema: ``auditooor.wave2_b_close_readiness.v1``.

CLI:

    python3 tools/wave2-b-close-readiness.py \\
        --workspace /Users/wolf/auditooor-702-full --json --strict

Exit codes:

    0 - overall_status=READY_TO_MERGE (or non-strict mode regardless)
    1 - overall_status in {BLOCKED, PARTIAL} and ``--strict`` set
    2 - tooling error (workspace missing, etc.)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

SCHEMA = "auditooor.wave2_b_close_readiness.v1"

DEFAULT_WORKSPACE = Path("/Users/wolf/auditooor-702-full")
PR_URL = "https://github.com/Vuk97/auditooor/pull/729"
BRANCH_NAME = "wave-2-capability-expansion"

CRITERION_NAMES = [
    "w22_detector_loader_phase1_wired",
    "w24_firm_pdf_parsers_seven_plus",
    "w28_vault_corpus_freshness_callable_wired",
    "cross_firm_dedup_detector_present",
    "w24_firm_parser_regression_pass",
    "no_pr_a_dependency_leakage",
]

# Minimum number of firm parsers required (W2.4 Phase-1).
W24_FIRM_PARSER_MIN = 7

# Soft minimum number of vault callables (PR-B adds vault_corpus_freshness).
VAULT_CALLABLE_SOFT_MIN = 66

# W2.4 firm-parser unittest modules.
W24_FIRM_TEST_MODULES = [
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_tob",
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_sherlock",
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_pashov",
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_zellic",
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_cyfrin",
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_spearbit",
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_chainsecurity",
    "tools.tests.test_hackerman_etl_from_audit_firm_pdf_openzeppelin",
]

# Cache search paths for the optional pre-run regression verdict.
REGRESSION_CACHE_GLOBS = [
    "/tmp/wave2-b-firm-regression*.json",
    "/tmp/wave2-b-pdf-regression*.json",
]

# Phrases that indicate a PR-B commit depends on PR-A landing first.
# Allowlist phrases (substring) override generic matches when present in
# the same commit body (e.g. a commit that explicitly states "does NOT
# require Phase-3 migration to land first").
PR_A_LEAKAGE_PHRASES = [
    "depends on phase-3 migration",
    "requires phase-3 migration to land first",
    "blocked on schema v1.1 migration",
    "wait for v1.1 corpus",
    "depends on pr-a",
    "requires pr #728",
    "blocked on pr #728",
]
PR_A_LEAKAGE_ALLOWLIST = [
    "does not depend on",
    "does not require",
    "independent of pr-a",
    "independent of pr #728",
    "mergeable before pr-a",
    "mergeable independently",
]

W22_LOADER_ENV_FLAG = "AUDITOOOR_W22_PHASE1_ENABLED"


def _git_head_sha(workspace: Path) -> str:
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
    return ""


def _git_branch(workspace: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return ""


def check_criterion_1_w22_loader(workspace: Path) -> Dict[str, Any]:
    """W2.2 detector-autogen Phase-1 loader exists AND references the
    AUDITOOOR_W22_PHASE1_ENABLED env flag."""
    name = CRITERION_NAMES[0]
    loader = workspace / "tools" / "audit" / "wave2_w22_detector_loader.py"
    if not loader.is_file():
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"W2.2 loader missing at {loader}",
            "evidence_ref": str(loader),
        }
    try:
        text = loader.read_text(errors="replace")
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"could not read W2.2 loader: {exc!r}",
            "evidence_ref": str(loader),
        }
    if W22_LOADER_ENV_FLAG not in text:
        return {
            "name": name,
            "status": "FAIL",
            "detail": (
                f"W2.2 loader at {loader} does not reference env flag "
                f"{W22_LOADER_ENV_FLAG!r}"
            ),
            "evidence_ref": str(loader),
        }
    return {
        "name": name,
        "status": "PASS",
        "detail": (
            f"W2.2 loader present at {loader.name}; "
            f"references {W22_LOADER_ENV_FLAG} (default OFF)"
        ),
        "evidence_ref": str(loader),
    }


_FIRM_PARSER_RE = re.compile(
    r"^hackerman-etl-from-audit-firm-pdf-([a-z0-9_\-]+)\.py$"
)


def _discover_firms(workspace: Path) -> List[str]:
    tools_dir = workspace / "tools"
    if not tools_dir.is_dir():
        return []
    firms: List[str] = []
    for p in sorted(tools_dir.glob("hackerman-etl-from-audit-firm-pdf-*.py")):
        m = _FIRM_PARSER_RE.match(p.name)
        if m:
            firms.append(m.group(1))
    return firms


def check_criterion_2_firm_parsers(workspace: Path) -> Dict[str, Any]:
    """W2.4: glob hackerman-etl-from-audit-firm-pdf-*.py and require >= 7
    firms.  Detail lists every discovered firm."""
    name = CRITERION_NAMES[1]
    firms = _discover_firms(workspace)
    detail = (
        f"{len(firms)} firm parser(s) discovered "
        f"(target: >={W24_FIRM_PARSER_MIN}); firms={firms}"
    )
    if len(firms) >= W24_FIRM_PARSER_MIN:
        return {
            "name": name,
            "status": "PASS",
            "detail": detail,
            "evidence_ref": str(workspace / "tools"),
        }
    return {
        "name": name,
        "status": "FAIL",
        "detail": detail,
        "evidence_ref": str(workspace / "tools"),
    }


_CALLABLE_NAME_RE = re.compile(r'^\s*"name":\s*"(vault_[a-z0-9_]+)"', re.MULTILINE)
_CALLABLE_DEF_RE = re.compile(
    r"^\s*def (vault_[a-z0-9_]+)\(self", re.MULTILINE
)


def check_criterion_3_vault_callable(workspace: Path) -> Dict[str, Any]:
    """W2.8: vault_corpus_freshness callable definition present in
    tools/vault-mcp-server.py."""
    name = CRITERION_NAMES[2]
    server = workspace / "tools" / "vault-mcp-server.py"
    if not server.is_file():
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"vault-mcp-server.py missing at {server}",
            "evidence_ref": str(server),
        }
    try:
        text = server.read_text(errors="replace")
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"could not read vault-mcp-server.py: {exc!r}",
            "evidence_ref": str(server),
        }
    name_hits = set(_CALLABLE_NAME_RE.findall(text))
    def_hits = set(_CALLABLE_DEF_RE.findall(text))
    # A callable counts if it is exposed either via a `def vault_X(self...`
    # method OR via a `"name": "vault_X"` registry entry.  The production
    # server has both forms; synthetic fixtures may only have one.
    callables = name_hits | def_hits
    total = len(callables)
    has_freshness = "vault_corpus_freshness" in callables
    if not has_freshness:
        return {
            "name": name,
            "status": "FAIL",
            "detail": (
                f"vault_corpus_freshness callable not wired in "
                f"{server.name}; total callables={total}"
            ),
            "evidence_ref": str(server),
        }
    # Pass even if the soft-min isn't hit; note it in the detail.
    detail = (
        f"vault_corpus_freshness callable wired; "
        f"total callables={total} "
        f"(soft target: >={VAULT_CALLABLE_SOFT_MIN})"
    )
    return {
        "name": name,
        "status": "PASS",
        "detail": detail,
        "evidence_ref": str(server),
    }


def check_criterion_4_dedup_detector(workspace: Path) -> Dict[str, Any]:
    """Cross-firm dedup detector file exists and is non-empty."""
    name = CRITERION_NAMES[3]
    path = workspace / "tools" / "wave2-cross-firm-dedup-detector.py"
    if not path.is_file():
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"dedup detector missing at {path}",
            "evidence_ref": str(path),
        }
    try:
        size = path.stat().st_size
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"could not stat {path}: {exc!r}",
            "evidence_ref": str(path),
        }
    if size <= 0:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"dedup detector at {path} is empty",
            "evidence_ref": str(path),
        }
    return {
        "name": name,
        "status": "PASS",
        "detail": f"dedup detector present at {path.name}; size={size} bytes",
        "evidence_ref": str(path),
    }


def _find_latest_regression_cache() -> Optional[Path]:
    candidates: List[Path] = []
    for pattern in REGRESSION_CACHE_GLOBS:
        if pattern.startswith("/tmp/"):
            tmp = Path("/tmp")
            if tmp.is_dir():
                stem = pattern[len("/tmp/"):]
                for p in tmp.glob(stem):
                    if p.is_file():
                        candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def check_criterion_5_firm_regression(
    workspace: Path,
    run_regression: bool = False,
    test_modules_override: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """If --run-regression, invoke unittest live; else read cached verdict."""
    name = CRITERION_NAMES[4]
    use_modules = test_modules_override or W24_FIRM_TEST_MODULES
    if run_regression:
        proc = subprocess.run(
            ["python3", "-m", "unittest", *use_modules],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=900,
        )
        out = proc.stdout + proc.stderr
        last_lines = out.strip().splitlines()[-10:] if out.strip() else []
        tail = "\n".join(last_lines)
        if proc.returncode == 0 and ("\nOK" in out or out.strip().endswith("OK")):
            return {
                "name": name,
                "status": "PASS",
                "detail": (
                    f"unittest OK across {len(use_modules)} firm-parser "
                    f"modules (live)"
                ),
                "evidence_ref": (
                    "python3 -m unittest " + " ".join(use_modules)
                ),
            }
        return {
            "name": name,
            "status": "FAIL",
            "detail": (
                f"unittest rc={proc.returncode}; tail:\n{tail}"
            ),
            "evidence_ref": (
                "python3 -m unittest " + " ".join(use_modules)
            ),
        }
    cache = _find_latest_regression_cache()
    if cache is None:
        return {
            "name": name,
            "status": "SKIPPED",
            "detail": (
                "no firm-parser regression cache found under /tmp/; "
                "rerun with --run-regression to invoke unittest live "
                "or write the cache via the regression runner"
            ),
            "evidence_ref": "/tmp/wave2-b-firm-regression*.json",
        }
    try:
        payload = json.loads(cache.read_text())
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"regression cache at {cache} not parseable: {exc!r}",
            "evidence_ref": str(cache),
        }
    verdict = payload.get("overall_verdict") or payload.get("verdict") or ""
    if str(verdict).upper() in ("PASS", "OK"):
        return {
            "name": name,
            "status": "PASS",
            "detail": (
                f"cached firm-parser regression verdict={verdict} "
                f"(cache={cache})"
            ),
            "evidence_ref": str(cache),
        }
    return {
        "name": name,
        "status": "FAIL",
        "detail": (
            f"cached firm-parser regression verdict={verdict!r} "
            f"(cache={cache})"
        ),
        "evidence_ref": str(cache),
    }


def _branch_commit_messages(workspace: Path) -> List[Dict[str, str]]:
    """Walk PR-B's commits since divergence from origin/main.  Falls back
    to the last N commits on HEAD if origin/main is unreachable."""
    # Prefer the merge-base range against origin/main.
    cmds = [
        ["git", "log", "--format=%H%n%B%x1f", "origin/main..HEAD"],
        ["git", "log", "--format=%H%n%B%x1f", "-50"],
    ]
    for cmd in cmds:
        try:
            out = subprocess.run(
                cmd,
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=20,
            )
        except Exception:
            continue
        if out.returncode != 0 or not out.stdout.strip():
            continue
        commits: List[Dict[str, str]] = []
        for chunk in out.stdout.split("\x1f"):
            chunk = chunk.strip()
            if not chunk:
                continue
            head, _, body = chunk.partition("\n")
            commits.append({"sha": head.strip(), "body": body})
        return commits
    return []


def check_criterion_6_no_pr_a_leakage(workspace: Path) -> Dict[str, Any]:
    """Scan PR-B's commits for explicit PR-A-landing dependency phrases."""
    name = CRITERION_NAMES[5]
    commits = _branch_commit_messages(workspace)
    if not commits:
        return {
            "name": name,
            "status": "SKIPPED",
            "detail": (
                "could not enumerate PR-B commits "
                "(origin/main..HEAD empty; git log unavailable)"
            ),
            "evidence_ref": "git log origin/main..HEAD",
        }
    leakage_hits: List[Dict[str, str]] = []
    for c in commits:
        body_lower = c["body"].lower()
        # Skip the commit entirely if an allowlist phrase is present.
        if any(allow in body_lower for allow in PR_A_LEAKAGE_ALLOWLIST):
            continue
        for phrase in PR_A_LEAKAGE_PHRASES:
            if phrase in body_lower:
                leakage_hits.append(
                    {"sha": c["sha"][:12], "phrase": phrase}
                )
                break
    if leakage_hits:
        return {
            "name": name,
            "status": "FAIL",
            "detail": (
                f"detected {len(leakage_hits)} PR-B commit(s) referencing "
                f"PR-A landing as a dependency: {leakage_hits[:5]}"
            ),
            "evidence_ref": "git log origin/main..HEAD",
        }
    return {
        "name": name,
        "status": "PASS",
        "detail": (
            f"scanned {len(commits)} PR-B commit(s); no PR-A landing "
            f"dependency phrases detected (PR-B is independently mergeable)"
        ),
        "evidence_ref": "git log origin/main..HEAD",
    }


def evaluate(
    workspace: Path,
    run_regression: bool = False,
    skip_criteria: Optional[Set[str]] = None,
    test_modules_override: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run all six criteria; return the full status pack."""
    skip = skip_criteria or set()
    workspace = workspace.expanduser().resolve()

    criteria: List[Dict[str, Any]] = []

    def _run(idx: int, fn, *args, **kwargs) -> None:
        name = CRITERION_NAMES[idx]
        if name in skip:
            criteria.append(
                {
                    "name": name,
                    "status": "SKIPPED",
                    "detail": "skipped via --skip-criteria",
                    "evidence_ref": "--skip-criteria",
                }
            )
            return
        criteria.append(fn(*args, **kwargs))

    _run(0, check_criterion_1_w22_loader, workspace)
    _run(1, check_criterion_2_firm_parsers, workspace)
    _run(2, check_criterion_3_vault_callable, workspace)
    _run(3, check_criterion_4_dedup_detector, workspace)
    _run(
        4,
        check_criterion_5_firm_regression,
        workspace,
        run_regression,
        test_modules_override,
    )
    _run(5, check_criterion_6_no_pr_a_leakage, workspace)

    failures = [c["name"] for c in criteria if c["status"] == "FAIL"]
    passes = [c["name"] for c in criteria if c["status"] == "PASS"]
    skipped = [c["name"] for c in criteria if c["status"] == "SKIPPED"]

    if failures:
        overall = "BLOCKED"
    elif skipped:
        overall = "PARTIAL"
    else:
        overall = "READY_TO_MERGE"

    return {
        "schema": SCHEMA,
        "branch": _git_branch(workspace) or BRANCH_NAME,
        "head_sha": _git_head_sha(workspace),
        "pr_url": PR_URL,
        "overall_status": overall,
        "criteria": criteria,
        "failures": failures,
        "passes": passes,
        "skipped": skipped,
    }


def _print_human(payload: Dict[str, Any]) -> None:
    print(f"wave2-b-close-readiness :: {payload['overall_status']}")
    print(f"  branch:  {payload['branch']}")
    print(f"  head:    {payload['head_sha']}")
    print(f"  pr_url:  {payload['pr_url']}")
    print("")
    for c in payload["criteria"]:
        marker = {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": "SKIP"}[c["status"]]
        print(f"  [{marker}] {c['name']}")
        print(f"        detail:   {c['detail']}")
        print(f"        evidence: {c['evidence_ref']}")
    print("")
    if payload["failures"]:
        print(f"  failures: {payload['failures']}")
    if payload["skipped"]:
        print(f"  skipped:  {payload['skipped']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help="Repo root (default: %(default)s).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON pack.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero unless overall_status=READY_TO_MERGE.",
    )
    parser.add_argument(
        "--run-regression",
        action="store_true",
        help=(
            "Actually invoke unittest across the W2.4 firm-parser modules "
            "for criterion 5 (default: read cached verdict)."
        ),
    )
    parser.add_argument(
        "--skip-criteria",
        action="append",
        default=[],
        help="Criterion name to skip (repeatable; testing knob).",
    )
    args = parser.parse_args(argv)

    skip = set(args.skip_criteria or [])
    unknown = skip - set(CRITERION_NAMES)
    if unknown:
        sys.stderr.write(
            f"error: unknown --skip-criteria names: {sorted(unknown)}\n"
            f"valid names: {CRITERION_NAMES}\n"
        )
        return 2
    try:
        payload = evaluate(
            args.workspace,
            run_regression=args.run_regression,
            skip_criteria=skip,
        )
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    if args.json:
        json.dump(payload, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(payload)

    if not args.strict:
        return 0
    return 0 if payload["overall_status"] == "READY_TO_MERGE" else 1


if __name__ == "__main__":
    sys.exit(main())
