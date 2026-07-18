#!/usr/bin/env python3
"""Hackerman capability-lift PR final pre-merge checklist (generic).

Operator-runnable, single-command, GO/NO-GO verdict aggregator that runs
the canonical set of pre-merge verification steps for a hackerman
capability-lift PR (originally PR #726 on
``wave-1-hackerman-capability-lift``; generalized in Wave-2 to support
PR #728 on ``wave-2-corpus-migration`` and successors via auto-
discovery). Emits per-step verdict plus an overall
``GO`` / ``NO-GO`` / ``YELLOW``.

Target PR + branch are AUTO-DISCOVERED via
``discover_target_pr_and_branch`` when no explicit
``--pr-number`` / ``--branch`` flags or ``AUDITOOOR_TARGET_PR`` /
``AUDITOOOR_TARGET_BRANCH`` env vars are set (see the function
docstring for the priority order). Without that, the prior defaults
silently locked the gate to PR #726 / wave-1 and rejected every other
branch at the equality check, blocking Wave-2-A squash-merge.

Why this exists
~~~~~~~~~~~~~~~

PR #726 is the wave-1 hackerman capability lift PR carrying dozens of
tool / Makefile / test additions across multiple sub-waves. Before
merging the PR into ``main``, the operator wants ONE command that
mechanically verifies:

  1. ``make hackerman-all-json`` exits 0 (full hackerman suite green),
     OR exits non-zero but only because of stages explicitly exempted
     via ``--exempt-stage`` (downgrades overall verdict to ``YELLOW``).
  2. ``make docs-check`` exits 0 (cross-link validator + docs gates).
  3. Origin sync: ``git fetch`` succeeds and ``git status --branch``
     does NOT report ``ahead/behind`` divergence vs the upstream
     branch (or reports zero ``behind`` if ``ahead`` is OK).
  4. PR #726 is reported mergeable by GitHub via ``gh pr view 726
     --json mergeable`` (only when ``gh`` is on PATH; otherwise the
     step is SKIPPED with a documented reason rather than failed).
  5. A bounded set of MCP callable smoke-tests PASS:
     ``vault_resume_context``, ``vault_exploit_context``,
     ``vault_knowledge_gap_context``, ``vault_harness_context``.

Per-step exit handling
~~~~~~~~~~~~~~~~~~~~~~

Each step returns one of:

- ``PASS``  - step succeeded; counts toward GO.
- ``FAIL``  - step failed; overall verdict at least NO-GO.
- ``YELLOW``- step is documented-exempt (e.g. ``hackerman-all-json``
  failed but only on exempt stages); overall verdict at most YELLOW.
- ``SKIPPED``- preconditions missing (e.g. ``gh`` not on PATH); does
  not count for or against the verdict.
- ``ERROR`` - infrastructure broke (e.g. subprocess raised); treated as
  FAIL for verdict purposes.

Overall verdict is then computed as:

- ``GO``     - every step is PASS or SKIPPED, AND there are zero YELLOW.
- ``YELLOW`` - every step is PASS / SKIPPED / YELLOW, no FAIL/ERROR.
- ``NO-GO``  - at least one FAIL or ERROR.

CLI
~~~

  python3 tools/hackerman-pr-merge-checklist.py            # auto-discover PR
  python3 tools/hackerman-pr-merge-checklist.py --json     # JSON envelope
  python3 tools/hackerman-pr-merge-checklist.py --out-json out.json
  python3 tools/hackerman-pr-merge-checklist.py --skip-step hackerman-all
  python3 tools/hackerman-pr-merge-checklist.py --exempt-stage some-stage
  python3 tools/hackerman-pr-merge-checklist.py --pr-number 728 --branch wave-2-corpus-migration
  AUDITOOOR_TARGET_PR=728 AUDITOOOR_TARGET_BRANCH=wave-2-corpus-migration \
      python3 tools/hackerman-pr-merge-checklist.py
  python3 tools/hackerman-pr-merge-checklist.py --strict   # exit 1 unless GO

Exit codes
~~~~~~~~~~

- 0  - overall verdict ``GO`` (or ``YELLOW`` when ``--strict`` is NOT set).
- 1  - overall verdict ``NO-GO`` (or ``YELLOW`` when ``--strict`` is set).
- 2  - argparse / wiring error.

This script is the canonical pre-merge gate for hackerman capability-
lift PRs (#726 wave-1, #728 wave-2, and successors). The companion
doc is ``docs/HACKERMAN_PR726_MERGE_CHECKLIST_2026-05-16.md`` and the
Makefile target is ``make hackerman-pr-merge-checklist`` (the
``make hackerman-pr726-merge-checklist`` alias is preserved for
backward compatibility).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
# Schema name kept stable across the rename for envelope compatibility
# with downstream consumers (vault sync, deep-crawler, dashboards).
SCHEMA = "auditooor.hackerman_pr726_merge_checklist.v1"
# Wave-1 fallback values. Used ONLY when discovery fails AND no CLI / env
# override is provided; in Wave-2+ the operator should rely on the
# discover_target_pr_and_branch() helper (CLI > env > gh pr status >
# current-branch heuristic) instead of these constants.
WAVE1_FALLBACK_PR_NUMBER = 726
WAVE1_FALLBACK_BRANCH = "wave-1-hackerman-capability-lift"
# Back-compat aliases (anything importing these names keeps working).
DEFAULT_PR_NUMBER = WAVE1_FALLBACK_PR_NUMBER
DEFAULT_BRANCH = WAVE1_FALLBACK_BRANCH
DEFAULT_TIMEOUT_SECONDS = 1800  # 30 min global cap per step
ENV_PR_NUMBER = "AUDITOOOR_TARGET_PR"
ENV_BRANCH = "AUDITOOOR_TARGET_BRANCH"

# Bounded MCP smoke-test callables (Layer-1 set per CLAUDE.md L25).
SMOKE_TEST_CALLABLES: tuple[str, ...] = (
    "vault_resume_context",
    "vault_exploit_context",
    "vault_knowledge_gap_context",
    "vault_harness_context",
)

# Verdict tokens.
PASS = "PASS"
FAIL = "FAIL"
YELLOW = "YELLOW"
SKIPPED = "SKIPPED"
ERROR = "ERROR"

# Overall verdicts.
GO = "GO"
NO_GO = "NO-GO"
# (YELLOW also used as overall; same token.)


# ---------------------------------------------------------------------------
# Target PR + branch discovery (Wave-2 generalization)
# ---------------------------------------------------------------------------


class DiscoveryError(RuntimeError):
    """Raised when target PR + branch cannot be determined from any source.

    Carries a multi-line message naming all 3 fallback paths the operator
    can use (CLI flag, env var, gh pr status). The CLI ``main`` function
    catches this and exits 1 with the verbatim message.
    """


def _git_current_branch(*, cwd: Path) -> str | None:
    """Return the current branch name via ``git rev-parse``.

    Returns None if not in a git repo or HEAD is detached. Defensive:
    never raises.
    """
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    name = (proc.stdout or "").strip()
    if not name or name == "HEAD":  # detached
        return None
    return name


def _gh_pr_status_lookup(*, cwd: Path) -> tuple[int | None, str | None]:
    """Try ``gh pr status --json currentBranch`` to discover (pr, branch).

    Returns (pr_number, branch) where each may be None if gh is missing
    / unauthenticated / on a branch without a PR. Defensive: never raises.
    """
    gh = shutil.which("gh")
    if gh is None:
        return None, None
    try:
        proc = subprocess.run(
            [
                gh,
                "pr",
                "status",
                "--json",
                "currentBranch",
            ],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None, None
    if proc.returncode != 0 or not proc.stdout:
        return None, None
    try:
        env = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, None
    cur = env.get("currentBranch") if isinstance(env, dict) else None
    if not isinstance(cur, dict):
        return None, None
    pr_raw = cur.get("number")
    branch_raw = cur.get("headRefName")
    pr_num: int | None = None
    if isinstance(pr_raw, int) and pr_raw > 0:
        pr_num = pr_raw
    elif isinstance(pr_raw, str) and pr_raw.isdigit():
        pr_num = int(pr_raw)
    branch: str | None = None
    if isinstance(branch_raw, str) and branch_raw.strip():
        branch = branch_raw.strip()
    return pr_num, branch


def discover_target_pr_and_branch(
    *,
    cli_pr: int | None,
    cli_branch: str | None,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Resolve (pr_number, branch, source) for this checklist run.

    Priority (highest wins):
      1. CLI flags ``--pr-number`` / ``--branch`` (passed as
         ``cli_pr`` / ``cli_branch``).
      2. Env vars ``AUDITOOOR_TARGET_PR`` / ``AUDITOOOR_TARGET_BRANCH``.
      3. ``gh pr status --json currentBranch`` (Wave-2 default — picks
         up the PR for the branch currently checked out).
      4. ``git rev-parse --abbrev-ref HEAD`` heuristic (branch only;
         PR number must come from one of paths 1-3).

    Returns a 3-tuple ``(pr_number, branch, source)`` where ``source``
    is a human-readable summary of which paths contributed (e.g.
    ``"cli:pr+branch"``, ``"env:pr; gh:branch"``).

    Raises ``DiscoveryError`` with a multi-line message listing all 3
    fallback paths when discovery fails entirely (no CLI + no env + no
    gh + no detectable branch).
    """
    env = env if env is not None else dict(os.environ)
    pr: int | None = None
    branch: str | None = None
    sources: list[str] = []

    # 1. CLI flags
    if cli_pr is not None:
        pr = int(cli_pr)
        sources.append("cli:pr")
    if cli_branch:
        branch = cli_branch
        sources.append("cli:branch")

    # 2. Env vars
    if pr is None:
        env_pr = env.get(ENV_PR_NUMBER, "").strip()
        if env_pr.isdigit():
            pr = int(env_pr)
            sources.append(f"env:{ENV_PR_NUMBER}")
    if branch is None:
        env_branch = env.get(ENV_BRANCH, "").strip()
        if env_branch:
            branch = env_branch
            sources.append(f"env:{ENV_BRANCH}")

    # 3. gh pr status
    if pr is None or branch is None:
        gh_pr, gh_branch = _gh_pr_status_lookup(cwd=cwd)
        if pr is None and gh_pr is not None:
            pr = gh_pr
            sources.append("gh:pr_status")
        if branch is None and gh_branch is not None:
            branch = gh_branch
            if "gh:pr_status" not in sources:
                sources.append("gh:pr_status")

    # 4. git current branch (branch only)
    if branch is None:
        git_branch = _git_current_branch(cwd=cwd)
        if git_branch:
            branch = git_branch
            sources.append("git:rev-parse")

    if pr is None or branch is None:
        raise DiscoveryError(
            "Could not auto-discover target PR + branch for the pre-merge "
            "checklist. Fix via one of these 3 fallback paths:\n"
            "  1. CLI flags:   --pr-number <N> --branch <name>\n"
            f"  2. Env vars:    {ENV_PR_NUMBER}=<N> {ENV_BRANCH}=<name>\n"
            "  3. gh CLI:      ensure `gh auth status` is green and the\n"
            "                  current branch has an open PR (the tool\n"
            "                  invokes `gh pr status --json currentBranch`).\n"
            f"Partial state: pr={pr!r} branch={branch!r} "
            f"sources={sources!r}."
        )
    return pr, branch, "; ".join(sources) or "fallback"


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int,
    env_overlay: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a subprocess and return a structured result.

    Returns a dict with keys: ``cmd``, ``returncode``, ``stdout``,
    ``stderr``, ``elapsed_seconds``, ``timed_out``, ``raised``.
    """
    env = os.environ.copy()
    if env_overlay:
        env.update(env_overlay)
    start = time.monotonic()
    timed_out = False
    raised: str | None = None
    rc = -1
    stdout = ""
    stderr = ""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            timeout=timeout,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        rc = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - timing
        timed_out = True
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(
            exc.stdout, (bytes, bytearray)
        ) else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(
            exc.stderr, (bytes, bytearray)
        ) else (exc.stderr or "")
    except FileNotFoundError as exc:
        raised = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        raised = f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - start
    return {
        "cmd": cmd,
        "returncode": rc,
        "stdout": stdout,
        "stderr": stderr,
        "elapsed_seconds": round(elapsed, 3),
        "timed_out": timed_out,
        "raised": raised,
    }


def _truncate(text: str, *, limit: int = 1200) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    head = text[: limit - 60]
    return head + f"\n...[truncated, {len(text) - len(head)} chars]"


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------


def step_hackerman_all_json(
    *,
    repo_root: Path,
    timeout: int,
    exempt_stages: list[str],
) -> dict[str, Any]:
    """Run ``make hackerman-all-json``.

    Verdict logic:
      - rc == 0                                     -> PASS
      - rc != 0 and JSON envelope parseable and
        every failed stage is in ``exempt_stages``  -> YELLOW
      - otherwise                                   -> FAIL
    """
    step_id = "hackerman-all-json"
    res = _run(
        ["make", "hackerman-all-json"],
        cwd=repo_root,
        timeout=timeout,
    )
    if res["raised"] is not None:
        return {
            "step_id": step_id,
            "verdict": ERROR,
            "reason": f"subprocess raised: {res['raised']}",
            "exit_code": res["returncode"],
            "elapsed_seconds": res["elapsed_seconds"],
            "stdout_tail": _truncate(res["stdout"]),
            "stderr_tail": _truncate(res["stderr"]),
        }
    if res["timed_out"]:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": f"timed out after {timeout}s",
            "exit_code": res["returncode"],
            "elapsed_seconds": res["elapsed_seconds"],
            "stdout_tail": _truncate(res["stdout"]),
            "stderr_tail": _truncate(res["stderr"]),
        }
    failed_stages = _parse_failed_stages(res["stdout"])
    if res["returncode"] == 0:
        return {
            "step_id": step_id,
            "verdict": PASS,
            "reason": "make hackerman-all-json exited 0",
            "exit_code": 0,
            "failed_stages": [],
            "exempt_stages": list(exempt_stages),
            "elapsed_seconds": res["elapsed_seconds"],
        }
    # Non-zero exit. If every failed stage is exempted, downgrade to YELLOW.
    if failed_stages and exempt_stages and all(
        s in exempt_stages for s in failed_stages
    ):
        return {
            "step_id": step_id,
            "verdict": YELLOW,
            "reason": (
                "make hackerman-all-json failed, but every failed stage "
                "is in the operator exemption list"
            ),
            "exit_code": res["returncode"],
            "failed_stages": failed_stages,
            "exempt_stages": list(exempt_stages),
            "elapsed_seconds": res["elapsed_seconds"],
            "stdout_tail": _truncate(res["stdout"]),
            "stderr_tail": _truncate(res["stderr"]),
        }
    return {
        "step_id": step_id,
        "verdict": FAIL,
        "reason": (
            f"make hackerman-all-json exited {res['returncode']}; "
            f"failed_stages={failed_stages or '<unparseable>'}"
        ),
        "exit_code": res["returncode"],
        "failed_stages": failed_stages,
        "exempt_stages": list(exempt_stages),
        "elapsed_seconds": res["elapsed_seconds"],
        "stdout_tail": _truncate(res["stdout"]),
        "stderr_tail": _truncate(res["stderr"]),
    }


def _parse_failed_stages(stdout: str) -> list[str]:
    """Best-effort extraction of failed-stage ids from a
    ``hackerman-all`` JSON envelope on stdout.

    The envelope shape (auditooor.hackerman_all.v1) carries a
    ``stages`` list with each entry having ``stage_id`` and
    ``verdict``. Any stage whose verdict is not ``PASS`` (case-
    insensitive) is treated as failed. Parser is defensive: if the
    envelope cannot be parsed, returns an empty list (which means the
    caller falls through to the non-exempt FAIL branch).
    """
    if not stdout:
        return []
    # Find a JSON object boundary heuristically.
    try:
        first = stdout.index("{")
        last = stdout.rindex("}")
    except ValueError:
        return []
    blob = stdout[first : last + 1]
    try:
        env = json.loads(blob)
    except json.JSONDecodeError:
        return []
    stages = env.get("stages") if isinstance(env, dict) else None
    if not isinstance(stages, list):
        return []
    failed: list[str] = []
    for s in stages:
        if not isinstance(s, dict):
            continue
        sid = s.get("stage_id") or s.get("id") or s.get("name")
        verdict = (s.get("verdict") or "").upper()
        if isinstance(sid, str) and verdict and verdict != PASS:
            failed.append(sid)
    return failed


def step_docs_check(*, repo_root: Path, timeout: int) -> dict[str, Any]:
    step_id = "docs-check"
    res = _run(["make", "docs-check"], cwd=repo_root, timeout=timeout)
    if res["raised"] is not None:
        return {
            "step_id": step_id,
            "verdict": ERROR,
            "reason": f"subprocess raised: {res['raised']}",
            "exit_code": res["returncode"],
            "elapsed_seconds": res["elapsed_seconds"],
            "stderr_tail": _truncate(res["stderr"]),
        }
    if res["timed_out"]:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": f"timed out after {timeout}s",
            "exit_code": res["returncode"],
            "elapsed_seconds": res["elapsed_seconds"],
            "stderr_tail": _truncate(res["stderr"]),
        }
    if res["returncode"] == 0:
        return {
            "step_id": step_id,
            "verdict": PASS,
            "reason": "make docs-check exited 0",
            "exit_code": 0,
            "elapsed_seconds": res["elapsed_seconds"],
        }
    return {
        "step_id": step_id,
        "verdict": FAIL,
        "reason": f"make docs-check exited {res['returncode']}",
        "exit_code": res["returncode"],
        "elapsed_seconds": res["elapsed_seconds"],
        "stdout_tail": _truncate(res["stdout"]),
        "stderr_tail": _truncate(res["stderr"]),
    }


def step_origin_sync(
    *,
    repo_root: Path,
    branch: str,
    timeout: int,
    allow_ahead: bool,
) -> dict[str, Any]:
    """Run ``git fetch`` + ``git status --branch`` and assert the
    current branch is not BEHIND its upstream.

    ``allow_ahead`` controls whether being AHEAD of upstream (i.e. local
    commits not yet pushed) is treated as PASS or FAIL. Default True
    because PR #726 routinely has local commits ahead of upstream
    during late-stage merge prep.
    """
    step_id = "origin-sync"
    fetch = _run(
        ["git", "fetch", "--quiet", "--prune"],
        cwd=repo_root,
        timeout=timeout,
    )
    if fetch["raised"] is not None:
        return {
            "step_id": step_id,
            "verdict": ERROR,
            "reason": f"git fetch raised: {fetch['raised']}",
            "elapsed_seconds": fetch["elapsed_seconds"],
        }
    if fetch["returncode"] != 0:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": f"git fetch exited {fetch['returncode']}",
            "exit_code": fetch["returncode"],
            "elapsed_seconds": fetch["elapsed_seconds"],
            "stderr_tail": _truncate(fetch["stderr"]),
        }
    status = _run(
        ["git", "status", "--branch", "--porcelain=v2"],
        cwd=repo_root,
        timeout=timeout,
    )
    if status["raised"] is not None:
        return {
            "step_id": step_id,
            "verdict": ERROR,
            "reason": f"git status raised: {status['raised']}",
            "elapsed_seconds": status["elapsed_seconds"],
        }
    if status["returncode"] != 0:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": f"git status exited {status['returncode']}",
            "exit_code": status["returncode"],
            "elapsed_seconds": status["elapsed_seconds"],
            "stderr_tail": _truncate(status["stderr"]),
        }
    ahead, behind, current_branch = _parse_porcelain_v2(status["stdout"])
    detail = {
        "current_branch": current_branch,
        "expected_branch": branch,
        "ahead": ahead,
        "behind": behind,
        "elapsed_seconds": (
            fetch["elapsed_seconds"] + status["elapsed_seconds"]
        ),
    }
    if current_branch and branch and current_branch != branch:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": (
                f"on branch {current_branch!r} but expected "
                f"{branch!r}"
            ),
            **detail,
        }
    if behind > 0:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": f"branch is {behind} commits BEHIND upstream",
            **detail,
        }
    if ahead > 0 and not allow_ahead:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": (
                f"branch is {ahead} commits AHEAD of upstream "
                "and --no-allow-ahead was set"
            ),
            **detail,
        }
    reason = "in sync with upstream"
    if ahead > 0:
        reason = f"{ahead} commits ahead of upstream (allow_ahead=True)"
    return {
        "step_id": step_id,
        "verdict": PASS,
        "reason": reason,
        **detail,
    }


def _parse_porcelain_v2(stdout: str) -> tuple[int, int, str | None]:
    """Parse ``git status --porcelain=v2 --branch`` output.

    Returns (ahead, behind, branch_name). branch_name is None if the
    parser cannot find a ``# branch.head`` header (e.g. detached HEAD).
    Defensive: returns zeros when the relevant headers are missing.
    """
    ahead = 0
    behind = 0
    branch: str | None = None
    for line in (stdout or "").splitlines():
        if line.startswith("# branch.head "):
            branch = line.split(" ", 2)[2].strip()
        elif line.startswith("# branch.ab "):
            # Format: # branch.ab +N -M
            parts = line.split()
            if len(parts) >= 4:
                try:
                    ahead = int(parts[2].lstrip("+"))
                    behind = int(parts[3].lstrip("-"))
                except ValueError:
                    pass
    return ahead, behind, branch


def step_gh_pr_mergeable(
    *,
    repo_root: Path,
    pr_number: int,
    timeout: int,
) -> dict[str, Any]:
    """Run ``gh pr view <n> --json mergeable`` if ``gh`` is on PATH.

    Verdict logic:
      - gh missing                         -> SKIPPED
      - gh returns mergeable=MERGEABLE     -> PASS
      - gh returns CONFLICTING / UNKNOWN   -> FAIL (UNKNOWN means GH
        has not yet computed mergeability; we treat that as FAIL so the
        operator re-runs once GH catches up rather than merge blind)
      - any other failure                  -> FAIL (or ERROR if raised)
    """
    step_id = "gh-pr-mergeable"
    gh = shutil.which("gh")
    if gh is None:
        return {
            "step_id": step_id,
            "verdict": SKIPPED,
            "reason": "gh CLI not on PATH; mergeability check skipped",
            "pr_number": pr_number,
        }
    res = _run(
        [gh, "pr", "view", str(pr_number), "--json", "mergeable,state,title"],
        cwd=repo_root,
        timeout=timeout,
    )
    if res["raised"] is not None:
        return {
            "step_id": step_id,
            "verdict": ERROR,
            "reason": f"gh raised: {res['raised']}",
            "pr_number": pr_number,
            "elapsed_seconds": res["elapsed_seconds"],
        }
    if res["timed_out"]:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": f"gh timed out after {timeout}s",
            "pr_number": pr_number,
            "elapsed_seconds": res["elapsed_seconds"],
        }
    if res["returncode"] != 0:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": (
                f"gh pr view exited {res['returncode']}; "
                "is the PR number correct and gh authenticated?"
            ),
            "pr_number": pr_number,
            "exit_code": res["returncode"],
            "elapsed_seconds": res["elapsed_seconds"],
            "stderr_tail": _truncate(res["stderr"]),
        }
    try:
        env = json.loads(res["stdout"])
    except json.JSONDecodeError:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": "gh pr view returned unparseable JSON",
            "pr_number": pr_number,
            "stdout_tail": _truncate(res["stdout"]),
        }
    mergeable = (env.get("mergeable") or "").upper()
    state = (env.get("state") or "").upper()
    title = env.get("title") or ""
    if state in {"CLOSED", "MERGED"}:
        return {
            "step_id": step_id,
            "verdict": FAIL,
            "reason": f"PR state is {state!r}; cannot merge",
            "pr_number": pr_number,
            "pr_state": state,
            "pr_title": title,
        }
    if mergeable == "MERGEABLE":
        return {
            "step_id": step_id,
            "verdict": PASS,
            "reason": "gh reports MERGEABLE",
            "pr_number": pr_number,
            "pr_state": state,
            "pr_title": title,
            "mergeable": mergeable,
        }
    return {
        "step_id": step_id,
        "verdict": FAIL,
        "reason": f"gh mergeable={mergeable!r}; expected MERGEABLE",
        "pr_number": pr_number,
        "pr_state": state,
        "pr_title": title,
        "mergeable": mergeable,
    }


def step_mcp_smoke_tests(
    *,
    repo_root: Path,
    workspace: Path,
    timeout: int,
    callables: tuple[str, ...],
) -> dict[str, Any]:
    """Invoke each MCP callable through ``vault-mcp-server.py --call``.

    Per-callable verdict:
      - rc 0 and stdout looks like JSON       -> pass
      - otherwise                             -> fail

    Step verdict is PASS only if every callable passed; FAIL otherwise.
    """
    step_id = "mcp-smoke-tests"
    per_callable: list[dict[str, Any]] = []
    overall_pass = True
    server = repo_root / "tools" / "vault-mcp-server.py"
    if not server.is_file():
        return {
            "step_id": step_id,
            "verdict": ERROR,
            "reason": f"vault-mcp-server.py not found at {server}",
            "callables": list(callables),
        }
    for name in callables:
        args_obj = {"workspace_path": str(workspace), "limit": 2}
        res = _run(
            [
                sys.executable,
                str(server),
                "--call",
                name,
                "--args",
                json.dumps(args_obj),
            ],
            cwd=repo_root,
            timeout=timeout,
        )
        ok = (
            res["raised"] is None
            and not res["timed_out"]
            and res["returncode"] == 0
            and _looks_like_json(res["stdout"])
        )
        per_callable.append(
            {
                "callable": name,
                "verdict": PASS if ok else FAIL,
                "exit_code": res["returncode"],
                "raised": res["raised"],
                "timed_out": res["timed_out"],
                "elapsed_seconds": res["elapsed_seconds"],
                "stdout_tail": _truncate(res["stdout"], limit=400),
                "stderr_tail": _truncate(res["stderr"], limit=400),
            }
        )
        if not ok:
            overall_pass = False
    return {
        "step_id": step_id,
        "verdict": PASS if overall_pass else FAIL,
        "reason": (
            "all callables returned valid JSON"
            if overall_pass
            else "one or more callables failed; see per_callable[]"
        ),
        "callables": list(callables),
        "per_callable": per_callable,
    }


def _looks_like_json(stdout: str) -> bool:
    """Best-effort: does stdout contain at least one parseable JSON
    object after stripping a possible single-line preamble?"""
    if not stdout:
        return False
    # Strip server-default-vault preamble line ("[vault-mcp-server] ...").
    body = "\n".join(
        line for line in stdout.splitlines()
        if not line.startswith("[vault-mcp-server]")
    ).strip()
    if not body:
        return False
    try:
        first = body.index("{")
        last = body.rindex("}")
    except ValueError:
        return False
    blob = body[first : last + 1]
    try:
        json.loads(blob)
        return True
    except json.JSONDecodeError:
        return False


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


CANONICAL_STEPS: tuple[str, ...] = (
    "hackerman-all-json",
    "docs-check",
    "origin-sync",
    "gh-pr-mergeable",
    "mcp-smoke-tests",
)


def run_checklist(
    *,
    repo_root: Path,
    workspace: Path,
    pr_number: int,
    branch: str,
    timeout: int,
    exempt_stages: list[str],
    skip_steps: list[str],
    allow_ahead: bool,
    smoke_callables: tuple[str, ...] = SMOKE_TEST_CALLABLES,
) -> dict[str, Any]:
    """Run every (non-skipped) step and aggregate verdicts."""
    steps: list[dict[str, Any]] = []
    runners: dict[str, Callable[[], dict[str, Any]]] = {
        "hackerman-all-json": lambda: step_hackerman_all_json(
            repo_root=repo_root,
            timeout=timeout,
            exempt_stages=exempt_stages,
        ),
        "docs-check": lambda: step_docs_check(
            repo_root=repo_root,
            timeout=timeout,
        ),
        "origin-sync": lambda: step_origin_sync(
            repo_root=repo_root,
            branch=branch,
            timeout=timeout,
            allow_ahead=allow_ahead,
        ),
        "gh-pr-mergeable": lambda: step_gh_pr_mergeable(
            repo_root=repo_root,
            pr_number=pr_number,
            timeout=timeout,
        ),
        "mcp-smoke-tests": lambda: step_mcp_smoke_tests(
            repo_root=repo_root,
            workspace=workspace,
            timeout=timeout,
            callables=smoke_callables,
        ),
    }
    for step_id in CANONICAL_STEPS:
        if step_id in skip_steps:
            steps.append(
                {
                    "step_id": step_id,
                    "verdict": SKIPPED,
                    "reason": "skipped by operator via --skip-step",
                }
            )
            continue
        try:
            res = runners[step_id]()
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            res = {
                "step_id": step_id,
                "verdict": ERROR,
                "reason": f"runner raised: {type(exc).__name__}: {exc}",
            }
        steps.append(res)

    overall = compute_overall(steps)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(repo_root),
        "pr_number": pr_number,
        "branch": branch,
        "workspace": str(workspace),
        "exempt_stages": list(exempt_stages),
        "skip_steps": list(skip_steps),
        "smoke_callables": list(smoke_callables),
        "steps": steps,
        "overall_verdict": overall,
        "operator_action": _operator_action(overall, steps),
    }


def compute_overall(steps: list[dict[str, Any]]) -> str:
    """Aggregate per-step verdicts into overall GO / YELLOW / NO-GO."""
    has_fail = any(s.get("verdict") in (FAIL, ERROR) for s in steps)
    has_yellow = any(s.get("verdict") == YELLOW for s in steps)
    if has_fail:
        return NO_GO
    if has_yellow:
        return YELLOW
    return GO


def _operator_action(overall: str, steps: list[dict[str, Any]]) -> str:
    if overall == GO:
        return (
            "All steps PASS or SKIPPED. Safe to merge the target PR via "
            "`gh pr merge <N> --squash --delete-branch` (or the "
            "operator's preferred merge strategy)."
        )
    if overall == YELLOW:
        return (
            "Documented YELLOW: every failed stage is on the exempt "
            "list. Review the exempt stages with the operator before "
            "merging; default-deny without operator sign-off."
        )
    bad = [
        s for s in steps if s.get("verdict") in (FAIL, ERROR)
    ]
    summary = "; ".join(
        f"{s.get('step_id')}={s.get('verdict')} ({s.get('reason')})"
        for s in bad
    )
    return f"NO-GO. Fix the following before re-running: {summary}"


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def render_human(report: dict[str, Any]) -> str:
    out: list[str] = []
    out.append(
        f"# Hackerman PR #{report['pr_number']} pre-merge checklist"
    )
    out.append("")
    out.append(f"- generated_at: {report['generated_at']}")
    out.append(f"- branch: {report['branch']}")
    out.append(f"- repo_root: {report['repo_root']}")
    out.append(f"- workspace: {report['workspace']}")
    out.append(f"- exempt_stages: {report['exempt_stages'] or '<none>'}")
    out.append(f"- skip_steps: {report['skip_steps'] or '<none>'}")
    out.append("")
    out.append("## Per-step verdicts")
    out.append("")
    out.append("```")
    headers = ["step_id", "verdict", "reason"]
    rows: list[list[str]] = []
    for s in report["steps"]:
        rows.append(
            [
                str(s.get("step_id", "?")),
                str(s.get("verdict", "?")),
                str(s.get("reason", "")),
            ]
        )
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = lambda row: " | ".join(  # noqa: E731
        cell.ljust(widths[i]) for i, cell in enumerate(row)
    )
    sep = "-+-".join("-" * w for w in widths)
    out.append(fmt(headers))
    out.append(sep)
    for row in rows:
        out.append(fmt(row))
    out.append("```")
    out.append("")
    out.append(f"## Overall verdict: **{report['overall_verdict']}**")
    out.append("")
    out.append(f"Operator action: {report['operator_action']}")
    out.append("")
    return "\n".join(out)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Pre-merge checklist aggregator for hackerman capability-"
            "lift PRs (PR #726 wave-1, PR #728 wave-2-corpus-migration, "
            "and successors). Target PR + branch auto-discovered via "
            "CLI > env > `gh pr status` > git current-branch."
        )
    )
    p.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="repo root (default: this script's parent)",
    )
    p.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help=(
            "workspace path forwarded to MCP smoke-test callables; "
            "default: --repo-root"
        ),
    )
    p.add_argument(
        "--pr-number",
        type=int,
        default=None,
        help=(
            "PR number; if omitted, auto-discovered via "
            f"{ENV_PR_NUMBER} env then `gh pr status --json currentBranch`. "
            f"Wave-1 fallback: {WAVE1_FALLBACK_PR_NUMBER}."
        ),
    )
    p.add_argument(
        "--branch",
        default=None,
        help=(
            "expected branch; if omitted, auto-discovered via "
            f"{ENV_BRANCH} env then `gh pr status` then "
            "`git rev-parse --abbrev-ref HEAD`. "
            f"Wave-1 fallback: {WAVE1_FALLBACK_BRANCH}."
        ),
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            "per-step subprocess timeout in seconds "
            f"(default: {DEFAULT_TIMEOUT_SECONDS})"
        ),
    )
    p.add_argument(
        "--exempt-stage",
        action="append",
        default=[],
        dest="exempt_stages",
        help=(
            "hackerman-all stage id to treat as exempt "
            "(YELLOW instead of FAIL); repeatable"
        ),
    )
    p.add_argument(
        "--skip-step",
        action="append",
        default=[],
        dest="skip_steps",
        choices=CANONICAL_STEPS,
        help=(
            "step id to skip entirely (marked SKIPPED in the report); "
            "repeatable"
        ),
    )
    p.add_argument(
        "--no-allow-ahead",
        action="store_true",
        help=(
            "treat the local branch being ahead of upstream as FAIL "
            "instead of PASS"
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="emit JSON envelope to stdout",
    )
    p.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help="also write the JSON envelope to this path",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help=(
            "exit 1 unless overall verdict is GO (i.e. YELLOW also "
            "counts as failure for the exit code)"
        ),
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = args.repo_root.resolve()
    workspace = (args.workspace or args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"repo-root does not exist: {repo_root}", file=sys.stderr)
        return 2
    try:
        pr_number, branch, discovery_source = discover_target_pr_and_branch(
            cli_pr=args.pr_number,
            cli_branch=args.branch,
            cwd=repo_root,
        )
    except DiscoveryError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    report = run_checklist(
        repo_root=repo_root,
        workspace=workspace,
        pr_number=pr_number,
        branch=branch,
        timeout=args.timeout,
        exempt_stages=list(args.exempt_stages or []),
        skip_steps=list(args.skip_steps or []),
        allow_ahead=not args.no_allow_ahead,
    )
    report["discovery_source"] = discovery_source
    if args.json:
        sys.stdout.write(render_json(report))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(report))
        sys.stdout.write("\n")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            render_json(report) + "\n", encoding="utf-8"
        )
    overall = report["overall_verdict"]
    if overall == GO:
        return 0
    if overall == YELLOW:
        return 1 if args.strict else 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
