#!/usr/bin/env python3
"""lane-integrator.py - canonical integration-commit tool (WF-7 #3).

# Rule 36 + Rule 55: this tool emits no corpus record.

Eliminates the iter17-style overclaim catches + R36 sibling-stomp pattern by
making the integration commit fully mechanical:

  1. Auto-discover the lane's results report under
     `reports/v3_iter_*/lane_<id>/results.md` (or accept --report).
  2. Look up the lane's declared pathspec in `.auditooor/agent_pathspec.json`.
  3. Stage by explicit per-file pathspec only (no `git add -A`, no dir add).
  4. Refuse if any sibling-owned file would slip into the stage (R36 + R55).
  5. Run pre-commit gates (`make docs-check`, optional lane-declared tests).
  6. Claim-verify the commit message body against the lane report - catches
     iter17 TTTTT-style overclaim where the message describes work the report
     does not document.
  7. Compose the commit message from the lane report + claim_evidence header.
  8. Optionally push after a clean commit (default: off; `--push` to enable).

CLI:
  python3 tools/lane-integrator.py --lane-id <X> [--auto-discover]
                                   [--report path/to/results.md]
                                   [--pathspec-file .auditooor/agent_pathspec.json]
                                   [--message "Phase X: short title"]
                                   [--message-file <path>]
                                   [--dry-run] [--strict] [--push]
                                   [--allow-empty-stage]
                                   [--json]

Verdicts (schema `auditooor.lane_integrator.v1.2`):
  - pass-clean-commit
  - pass-clean-commit-and-push
  - pass-clean-commit-and-push-and-automerged
  - pass-clean-commit-and-push-with-unmerged-feature-branch
  - pass-dry-run
  - fail-sibling-file-staged
  - fail-claim-overclaim
  - fail-gate-broken
  - fail-no-pathspec-registered
  - fail-no-lane-report
  - fail-empty-stage
  - fail-feature-branch-diverged-from-main
  - error

v1.2 auto-merge (LANE-INTEGRATOR-AUTOMERGE-PATCH, 2026-05-23):
After a successful `--push` from a per-lane feature branch
(`lane/<id>-<short-sha>` per spawn-lane-worktree.sh), the integrator
fast-forward-merges HEAD into origin/main when possible. The merge is
strictly FF-only (R55: no destructive ops, no --force). When the feature
branch has diverged from origin/main, the integrator emits
`fail-feature-branch-diverged-from-main` and leaves the feature branch in
place for operator-driven 3-way merge. Closes the structural gap audited
in `reports/v3_iter_2026-05-23_iter18_phase_0/lane_BRANCH_RECONCILE_AUDIT/`.

Exit codes:
  0 - pass
  1 - fail (any verdict starting with `fail-`)
  2 - input / runtime error

Empirical anchor (iter17 TTTTT / Phase NEG R36 stomp): manual integration
commits absorbed sibling-lane work via sweeping `git add` and described work
the underlying lane report did not contain. This tool removes the human-in-
the-loop step that produced both failure modes.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from tools.lib.fuzz_target_corpus import (
    emit_fuzz_targets,
    extract_fuzz_target_rows_from_file,
    fuzz_target_output_path,
)

SCHEMA_VERSION = "auditooor.lane_integrator.v1.2"
INVARIANT_CANDIDATE_SCHEMA_VERSION = "auditooor.invariant_candidate.v1"
GATE = "LANE-INTEGRATOR"
# r36-rebuttal: lane-GAP-FIX-3-B registered via tools/agent-pathspec-register.py (this file declared in pathspec).

# Gap #52 (codified 2026-05-26): exhaustion-class verdicts whose emit
# path must first invoke Check #109 (Gap #37 exhaustion-verdict-tools-
# attempt-required-check) AND the salvage-negation-verdict-check. The
# trigger phrase list mirrors EXHAUSTION_TRIGGERS in
# tools/exhaustion-verdict-tools-attempt-required-check.py PLUS the
# explicit negation-framing tokens from salvage-negation-verdict-check.
# A lane's results.md whose body contains ANY of these tokens fires the
# handshake gate.
GAP52_EXHAUSTION_TRIGGERS: tuple[str, ...] = (
    "exhausted",
    "genuinely-exhausted",
    "genuinely exhausted",
    "negative-closed-exhausted",
    "negative closed exhausted",
    "negative-closed-with-observation",
    "negative closed with observation",
    "negative-closed",
    "hunt-done",
    "hunt done",
    "hunt-exhausted",
    "salvage-exhausted",
    "exhaustion verdict",
    "exhaustion-confirmed",
    "not-salvageable-confirmed",
    "drop-confirmed",
    "killed-confirmed",
)

# Gap #52 rebuttal marker forms (both HTML-comment and visible-line).
_GAP52_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*gap52-rebuttal\s*:\s*(?P<inner>[^\n>]{1,200}?)\s*-->|"
    r"^\s*gap52-rebuttal\s*:\s*(?P<line>[^\n]{1,200}))",
    re.IGNORECASE | re.MULTILINE,
)

# Per-lane feature-branch convention from tools/spawn-lane-worktree.sh
# (line 148): `BRANCH_NAME="lane/${LANE_ID}-${SHORT_SHA}"`. The regex tolerates
# any non-slash lane id token and a 7+-hex short sha tail.
LANE_FEATURE_BRANCH_RE = re.compile(r"^refs/heads/lane/[^/]+-[0-9a-f]{7,}$")

DEFAULT_PATHSPEC_REL = ".auditooor/agent_pathspec.json"
DEFAULT_REPORTS_GLOB = "reports/v3_iter_*/lane_*/results.md"
DEFAULT_GATE_CMD = ["make", "docs-check"]

# Tokens we look for in commit messages that often signal a claim
# the report must back. Surfaced for the overclaim check.
_CLAIM_KEYWORD_RE = re.compile(
    r"\b(?:wire[ds]?|land(?:s|ed|ing)?|ship(?:s|ped|ping)?|"
    r"add(?:s|ed)?|fix(?:es|ed)?|implement(?:s|ed)?|"
    r"refactor(?:s|ed)?|delete[ds]?|remove[ds]?|restore[ds]?)\b",
    re.IGNORECASE,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_root() -> Path | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return None
    if out.returncode != 0:
        return None
    root = out.stdout.strip()
    return Path(root) if root else None


def _is_per_lane_worktree(repo_root: Path) -> bool:
    """Return True when `repo_root` looks like a per-lane worktree provisioned
    by `tools/spawn-lane-worktree.sh`.

    The convention is `/tmp/auditooor-lane-<id>-<short-sha>` or
    `<root>/auditooor-lane-<id>-<short-sha>` plus a `.git` file (worktree
    pointer) rather than a `.git` directory (real repo). We sniff both.
    """
    try:
        name = repo_root.name
        if not name.startswith("auditooor-lane-"):
            return False
        git_marker = repo_root / ".git"
        # In a linked worktree, .git is a file pointing at the gitdir.
        if git_marker.is_file():
            return True
        # In some test setups it might still be a dir; the naming convention
        # is enough to identify intent.
        if git_marker.is_dir():
            return True
    except (OSError, ValueError):
        return False
    return False


def _worktree_lane_id(repo_root: Path) -> str | None:
    """Extract the lane id from a per-lane worktree directory name.

    `/tmp/auditooor-lane-MY-LANE-deadbeef00` -> `MY-LANE`.
    Returns None if the directory name does not match the convention.
    """
    name = repo_root.name
    if not name.startswith("auditooor-lane-"):
        return None
    rest = name[len("auditooor-lane-"):]
    # Last `-XXXXXXXXXX` (10-hex short sha) is the suffix; strip it if present.
    if len(rest) > 11 and rest[-11] == "-":
        tail = rest[-10:]
        if all(c in "0123456789abcdef" for c in tail.lower()):
            return rest[:-11]
    return rest or None


def _current_symbolic_ref(cwd: Path) -> str | None:
    """Return the HEAD symbolic ref (e.g. `refs/heads/lane/X-abc1234`)
    or None when HEAD is detached / git fails.
    """
    try:
        out = subprocess.run(
            ["git", "symbolic-ref", "HEAD"],
            cwd=str(cwd), capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return None
    if out.returncode != 0:
        return None
    ref = out.stdout.strip()
    return ref or None


def _is_on_lane_feature_branch(cwd: Path) -> bool:
    """Return True when HEAD points at a `lane/<id>-<short-sha>` branch.

    Matches the spawn-lane-worktree.sh branch convention. Independent of
    the per-lane-worktree directory naming (a feature branch checked out
    in any worktree triggers the auto-merge path).
    """
    ref = _current_symbolic_ref(cwd)
    if not ref:
        return False
    return bool(LANE_FEATURE_BRANCH_RE.match(ref))


def _attempt_ff_merge_to_main(
    cwd: Path, base_branch: str = "main",
) -> tuple[str, str]:
    """Attempt to fast-forward `origin/<base_branch>` to current HEAD.

    Returns (verdict_suffix, detail) where verdict_suffix is one of:
      - 'automerged'                    - FF push to main succeeded
      - 'unmerged-feature-branch'       - operator-action needed (info)
      - 'feature-branch-diverged'       - non-FF, must resolve
      - 'fetch-failed'                  - fetch origin failed
      - 'push-failed'                   - FF-able but push HEAD:main failed

    R55-safe: never uses --force / --force-with-lease. The push is FF-only;
    if origin/main has advanced since the FF check, the remote rejects the
    push and we surface that as `feature-branch-diverged`.
    """
    # Fetch origin/main first so the ancestor check is current.
    fetch = subprocess.run(
        ["git", "fetch", "origin", base_branch],
        cwd=str(cwd), capture_output=True, text=True, check=False,
    )
    if fetch.returncode != 0:
        return "fetch-failed", fetch.stderr.strip()
    # Verify origin/<base_branch> resolves.
    origin_ref = f"origin/{base_branch}"
    rev = subprocess.run(
        ["git", "rev-parse", "--verify", "-q", origin_ref],
        cwd=str(cwd), capture_output=True, text=True, check=False,
    )
    if rev.returncode != 0:
        return "fetch-failed", f"origin/{base_branch} not resolvable"
    # FF-check: is origin/<base_branch> an ancestor of HEAD?
    is_anc = subprocess.run(
        ["git", "merge-base", "--is-ancestor", origin_ref, "HEAD"],
        cwd=str(cwd), capture_output=True, text=True, check=False,
    )
    if is_anc.returncode != 0:
        # Non-ancestor -> the feature branch has diverged. Operator-driven
        # 3-way merge or rebase required. Do NOT --force.
        return "feature-branch-diverged", (
            f"origin/{base_branch} is not an ancestor of HEAD; "
            "FF-only merge unsafe (R55)"
        )
    # FF-able. Push HEAD:<base_branch>. The push itself is FF-only on the
    # remote side too (no --force, no --force-with-lease).
    push = subprocess.run(
        ["git", "push", "origin", f"HEAD:{base_branch}"],
        cwd=str(cwd), capture_output=True, text=True, check=False,
    )
    if push.returncode != 0:
        # Remote rejected the FF push (likely because origin/<base_branch>
        # advanced between fetch and push). Treat as divergence and let the
        # operator resolve.
        return "feature-branch-diverged", (
            f"FF push to origin/{base_branch} rejected: "
            f"{push.stderr.strip()[:200]}"
        )
    return "automerged", f"FF-merged HEAD into origin/{base_branch}"


def _emit(verdict: str, **extra: Any) -> dict:
    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "verdict": verdict,
        "timestamp": _now_iso(),
    }
    payload.update(extra)
    return payload


# ---------------------------------------------------------------------------
# Discovery + pathspec loading
# ---------------------------------------------------------------------------

def _normalize_id(value: str) -> str:
    """Lower-case + collapse separators so 'lane-X_Y' == 'lane_x-y'."""
    return value.lower().replace("-", "_")


def _lane_tokens(value: str) -> list[str]:
    """Tokenize a lane identifier on `-` / `_` separators, lowercase, drop
    empty tokens, and drop ALL leading `lane` prefix tokens.

    Stripping ALL leading `lane` tokens handles the case where a lane
    identifier accidentally repeats the word LANE (e.g. agent_id
    `lane-LANE-INTEGRATOR-AUTODISCOVER-FIX` whose directory is
    `lane_LANE_INTEGRATOR_AUTODISCOVER_FIX`). Both sides reduce to the
    same `[integrator, autodiscover, fix]` token list.

    Examples (LANE-INTEGRATOR-AUTODISCOVER-FIX, 2026-05-23):
      'STATUS-SNAPSHOT'                  -> ['status', 'snapshot']
      'lane_STATUS_SNAPSHOT'             -> ['status', 'snapshot']
      'lane-WIRE-1-hunt-tools-wiring'    -> ['wire', '1', 'hunt', 'tools',
                                              'wiring']
      'lane_FIX_A_pathspec_race'         -> ['fix', 'a', 'pathspec', 'race']
      'LANE-INTEGRATOR-AUTODISCOVER-FIX' -> ['integrator', 'autodiscover',
                                              'fix']
      'lane_LANE_INTEGRATOR_AUTODISCOVER_FIX' -> ['integrator',
                                                   'autodiscover', 'fix']
    """
    if not value:
        return []
    out: list[str] = []
    for tok in value.lower().replace("-", "_").split("_"):
        if tok:
            out.append(tok)
    # Drop ALL leading 'lane' prefix tokens (handles both `lane-X` and
    # `lane-LANE-X` cases where the operator accidentally doubled the
    # prefix when typing or naming the directory).
    while out and out[0] == "lane":
        out = out[1:]
    return out


def _lane_token_match(a: str, b: str) -> bool:
    """Return True if two lane identifiers refer to the same lane, tolerating
    case, hyphen-vs-underscore variants, and either side being a token-prefix
    of the other.

    The canonical match rule (LANE-INTEGRATOR-AUTODISCOVER-FIX, 2026-05-23):
    - Tokenize both sides (lowercase, split on `-`/`_`, drop leading `lane`).
    - Match when token lists are equal, OR the shorter list is a strict
      token-prefix of the longer list.

    Empirical anchors:
    - STATUS-SNAPSHOT (operator-typed) matches lane_STATUS_SNAPSHOT (dir).
    - lane-WIRE-1 matches lane_WIRE_1 (hyphen vs underscore).
    - lane-FIX-A-pathspec matches lane_FIX_A_pathspec_race (token-prefix).
    - lane-X registered vs lane_Y on disk -> still NO match (genuine miss).
    """
    ta = _lane_tokens(a)
    tb = _lane_tokens(b)
    if not ta or not tb:
        return False
    if ta == tb:
        return True
    # Token-prefix match: shorter list is a prefix of the longer list.
    short, long_ = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    return long_[: len(short)] == short


def discover_report(repo_root: Path, lane_id: str) -> Path | None:
    """Return the most recent results.md whose path mentions the lane id.

    Uses the canonical `_lane_token_match` rule so directory names with
    different casing / separator style / trailing tokens still match.
    Empirical anchor: STATUS-SNAPSHOT failed against lane_STATUS_SNAPSHOT/
    in the original regex matcher (iter18, 2026-05-23).
    """
    if not lane_id:
        return None
    candidates: list[tuple[float, Path]] = []
    for p in repo_root.glob(DEFAULT_REPORTS_GLOB):
        try:
            parent_name = p.parent.name
        except Exception:
            continue
        if _lane_token_match(lane_id, parent_name):
            try:
                mtime = p.stat().st_mtime
            except OSError:
                mtime = 0.0
            candidates.append((mtime, p))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def load_pathspec(
    pathspec_file: Path,
) -> tuple[list[dict], list[str]]:
    """Return (all_agents, warnings).  Empty list if file missing/broken."""
    warnings: list[str] = []
    if not pathspec_file.exists():
        warnings.append(f"pathspec file missing: {pathspec_file}")
        return [], warnings
    try:
        data = json.loads(pathspec_file.read_text(encoding="utf-8"))
    except Exception as exc:
        warnings.append(f"pathspec file unparseable: {exc}")
        return [], warnings
    agents: list[dict] = []
    if isinstance(data, dict):
        if isinstance(data.get("agents"), list):
            agents = [a for a in data["agents"] if isinstance(a, dict)]
        elif "files" in data:
            agents = [data]
    return agents, warnings


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def split_lane_vs_sibling(
    agents: list[dict],
    lane_id: str,
    now: datetime | None = None,
) -> tuple[set[str], set[str]]:
    """Return (lane_files, sibling_live_files).

    `lane_files` is the set declared by the agent whose id matches `lane_id`.
    `sibling_live_files` is the union of all OTHER non-expired agents' files.
    Expired agents are silently dropped from siblings (the R36 hook does the
    same).
    """
    now = now or datetime.now(timezone.utc)
    lane_files: set[str] = set()
    sibling: set[str] = set()
    for agent in agents:
        files = agent.get("files")
        if not isinstance(files, list):
            continue
        declared = {str(f).strip() for f in files if str(f).strip()}
        if not declared:
            continue
        agent_id = str(agent.get("agent_id", "")).strip()
        # Canonical token-prefix match (LANE-INTEGRATOR-AUTODISCOVER-FIX,
        # 2026-05-23): tolerates case + hyphen/underscore variants + either
        # side being a token-prefix of the other. Replaces the original
        # endswith-based matcher which failed on registered ids like
        # `lane-STATUS-SNAPSHOT-iter18` vs operator-typed `STATUS-SNAPSHOT`.
        is_lane = _lane_token_match(agent_id, lane_id)
        if is_lane:
            lane_files |= declared
            continue
        expires = _parse_ts(agent.get("expires_at"))
        if expires is not None and expires <= now:
            continue
        sibling |= declared
    return lane_files, sibling


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git_run(
    args: list[str], cwd: Path, check: bool = False,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git"] + args, cwd=str(cwd), capture_output=True, text=True,
        check=check,
    )


def git_status_porcelain(cwd: Path) -> list[tuple[str, str]]:
    """Return list of (status, path) tuples from `git status --porcelain -uall`.

    Renames produce paths like `OLD -> NEW`; we keep the new path.
    """
    out = git_run(["status", "--porcelain", "-uall"], cwd=cwd)
    rows: list[tuple[str, str]] = []
    for line in out.stdout.splitlines():
        if not line.strip():
            continue
        # porcelain v1 format: XY <path>  (or XY <old> -> <new> for renames)
        if len(line) < 4:
            continue
        status = line[:2]
        rest = line[3:]
        if " -> " in rest:
            rest = rest.split(" -> ", 1)[1]
        # Strip surrounding quotes git emits for paths with whitespace.
        if rest.startswith('"') and rest.endswith('"'):
            rest = rest[1:-1]
        rows.append((status, rest))
    return rows


def git_diff_staged_names(cwd: Path) -> list[str]:
    out = git_run(["diff", "--cached", "--name-only"], cwd=cwd)
    return [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Lane report parsing + claim verification
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^#+\s+(.*\S)\s*$")
_INVARIANT_ID_RE = re.compile(
    r"\b(?P<id>INV-(?P<target>[A-Z0-9][A-Z0-9_-]*?)-(?P<num>\d{3,}))\b"
    r"(?P<marker>\s+candidate\b|:|\s+-|\s+--)?"
    r"(?P<tail>[^\n]*)",
    re.IGNORECASE,
)
_CODE_PATH_RE = re.compile(
    r"\b(?P<file>[A-Za-z0-9_./-]+\.(?:sol|rs|go|ts|tsx|js|jsx|py|vy|move|c|h|cpp|hpp|java|kt|swift|md))"
    r":(?P<line>\d+(?:-\d+)?)\b"
)


def _check_prior_lane_acknowledgement_soft_gate(
    repo_root: Path,
    lane_id: str,
    report_text: str,
) -> dict[str, Any]:
    """CAPABILITY-GAP-2 soft gate (2026-05-25).

    Detect whether `lane_id` was spawned with `--inject-prior-lanes` (per
    `.auditooor/spawn_worker_log.jsonl`) and, if so, whether its
    `results.md` text contains `prior_negative_chains_acknowledged`.

    Returns a dict that lane-integrator surfaces in its plan output. The
    gate is WARN-only - never blocks the commit. Empty dict = nothing to
    warn about.
    """
    log_path = repo_root / ".auditooor" / "spawn_worker_log.jsonl"
    if not log_path.is_file():
        return {}
    inject_record = None
    try:
        with log_path.open("r", encoding="utf-8") as fh:
            # Walk from the END (most-recent spawn). Bounded scan.
            tail_lines = fh.readlines()[-500:]
        for raw in reversed(tail_lines):
            raw = raw.strip()
            if not raw or not raw.startswith("{"):
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if str(row.get("lane_id", "")) != lane_id:
                continue
            inject_record = row
            break
    except Exception:
        return {}
    if inject_record is None:
        return {}
    scan_status = str(inject_record.get("prior_lane_scan_status", ""))
    inject_flag = inject_record.get("inject_prior_lanes_flag")
    # Only fire warn if injection actually happened (status='injected')
    # and at least one match was returned.
    matches = int(inject_record.get("prior_lane_scan_matches", 0) or 0)
    if scan_status != "injected" or matches == 0:
        return {}
    # Look for the acknowledgement line / frontmatter key.
    ack_re = re.compile(
        r"prior_negative_chains_acknowledged\s*[:=]", re.IGNORECASE
    )
    if ack_re.search(report_text):
        return {
            "prior_lane_scan_acknowledged": True,
            "prior_lane_scan_matches": matches,
        }
    return {
        "warning_prior_lane_scan_unacknowledged": True,
        "prior_lane_scan_status": scan_status,
        "prior_lane_scan_matches": matches,
        "prior_lane_scan_remediation": (
            "lane was spawned with --inject-prior-lanes and "
            f"{matches} prior NEGATIVE/DROP/CLOSED chain(s) were "
            "surfaced; results.md should include "
            "`prior_negative_chains_acknowledged: [...]` frontmatter "
            "citing each."
        ),
    }


# r36-rebuttal: lane-GAP-FIX-3-B (tools/lane-integrator.py declared in agent_pathspec.json)
def _detect_gap52_exhaustion_trigger(text: str) -> tuple[bool, str]:
    """Gap #52: detect whether a results.md body claims an exhaustion-class
    verdict that should trip the hunt-lane emit handshake.

    Returns (triggered, excerpt_around_first_match).
    """
    low = text.lower()
    for trig in GAP52_EXHAUSTION_TRIGGERS:
        idx = low.find(trig)
        if idx >= 0:
            start = max(0, idx - 40)
            end = min(len(text), idx + len(trig) + 40)
            return True, text[start:end].strip()
    return False, ""


def _detect_gap52_rebuttal(text: str) -> str:
    """Gap #52 rebuttal marker (HTML-comment OR visible bounded line)."""
    m = _GAP52_REBUTTAL_RE.search(text)
    if not m:
        return ""
    val = (m.group("inner") or m.group("line") or "").strip()
    if 0 < len(val) <= 200:
        return val
    return ""


def run_lane_emit_handshake(
    results_md: Path,
    repo_root: Path,
    workspace: Path | None = None,
    strict: bool = False,
) -> dict[str, Any]:
    """Gap #52 hunt-lane emit handshake (codified 2026-05-26).

    Before declaring a lane verdict as exhaustion-class (EXHAUSTED /
    NEGATIVE-CLOSED / DROP-CONFIRMED / NOT-SALVAGEABLE-CONFIRMED /
    KILLED-CONFIRMED), the lane's results.md MUST be cross-checked
    against Check #109 (Gap #37 tools-attempt-required) AND the salvage-
    negation-verdict-check. Returns a dict with:

      - verdict:               pass-no-exhaustion-trigger
                              | pass-handshake-ok
                              | ok-rebuttal
                              | fail-lane-emit-gate-fail
                              | error
      - exhaustion_check:      sub-dict {verdict, reason}
      - salvage_check:         sub-dict {verdict, reason}
      - rebuttal:              str (empty if none)

    The handshake is FAIL-CLOSED: any non-pass / non-ok-rebuttal verdict
    from either sub-check causes fail-lane-emit-gate-fail unless the
    results.md carries a valid gap52-rebuttal marker.
    """
    payload: dict[str, Any] = {
        "verdict": "error",
        "reason": "",
        "results_md": str(results_md),
        "exhaustion_check": {},
        "salvage_check": {},
        "rebuttal": "",
    }
    if not results_md.exists():
        payload["verdict"] = "error"
        payload["reason"] = f"results.md not found: {results_md}"
        return payload
    text = results_md.read_text(encoding="utf-8", errors="replace")
    triggered, excerpt = _detect_gap52_exhaustion_trigger(text)
    payload["exhaustion_trigger_excerpt"] = excerpt
    if not triggered:
        payload["verdict"] = "pass-no-exhaustion-trigger"
        payload["reason"] = (
            "results.md does not claim an exhaustion-class verdict; "
            "Gap #52 handshake not required"
        )
        return payload

    ws = workspace or repo_root
    # Sub-check 1: exhaustion-verdict-tools-attempt-required (Check #109).
    tool_check = repo_root / "tools" / "exhaustion-verdict-tools-attempt-required-check.py"
    if not tool_check.exists():
        payload["verdict"] = "error"
        payload["reason"] = f"sub-check tool missing: {tool_check}"
        return payload
    cmd_exh = [
        sys.executable, str(tool_check), str(results_md),
        "--workspace", str(ws), "--json",
    ]
    if strict:
        cmd_exh.append("--strict")
    try:
        out_exh = subprocess.run(
            cmd_exh, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as exc:
        payload["verdict"] = "error"
        payload["reason"] = f"failed to run {tool_check}: {exc}"
        return payload
    try:
        exh_result = json.loads(out_exh.stdout or "{}")
    except json.JSONDecodeError:
        exh_result = {
            "verdict": "error",
            "reason": (out_exh.stderr or out_exh.stdout)[:500],
        }
    payload["exhaustion_check"] = {
        "verdict": exh_result.get("verdict", ""),
        "reason": exh_result.get("reason", "")[:500],
        "rc": out_exh.returncode,
    }

    # Sub-check 2: salvage-negation-verdict-check (Gap #37b).
    salvage_check = repo_root / "tools" / "salvage-negation-verdict-check.py"
    if not salvage_check.exists():
        payload["verdict"] = "error"
        payload["reason"] = f"sub-check tool missing: {salvage_check}"
        return payload
    cmd_sal = [
        sys.executable, str(salvage_check), str(results_md), "--json",
    ]
    if strict:
        cmd_sal.append("--strict")
    try:
        out_sal = subprocess.run(
            cmd_sal, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as exc:
        payload["verdict"] = "error"
        payload["reason"] = f"failed to run {salvage_check}: {exc}"
        return payload
    try:
        sal_result = json.loads(out_sal.stdout or "{}")
    except json.JSONDecodeError:
        sal_result = {
            "verdict": "error",
            "reason": (out_sal.stderr or out_sal.stdout)[:500],
        }
    payload["salvage_check"] = {
        "verdict": sal_result.get("verdict", ""),
        "reason": sal_result.get("reason", "")[:500],
        "rc": out_sal.returncode,
    }

    # Classify final verdict. A pass / ok-rebuttal verdict from each sub-
    # check means the handshake succeeds. Anything else fails closed
    # unless results.md carries a valid gap52-rebuttal marker.
    pass_prefixes = ("pass-", "ok-rebuttal")
    exh_pass = any(
        str(exh_result.get("verdict", "")).startswith(p) for p in pass_prefixes
    )
    sal_pass = any(
        str(sal_result.get("verdict", "")).startswith(p) for p in pass_prefixes
    )
    if exh_pass and sal_pass:
        payload["verdict"] = "pass-handshake-ok"
        payload["reason"] = (
            "Gap #52 handshake: both Check #109 (exhaustion-tools-attempt) "
            "and salvage-negation-verdict gates passed"
        )
        return payload
    rebuttal = _detect_gap52_rebuttal(text)
    if rebuttal:
        payload["rebuttal"] = rebuttal
        payload["verdict"] = "ok-rebuttal"
        payload["reason"] = f"gap52-rebuttal accepted: {rebuttal}"
        return payload
    failures: list[str] = []
    if not exh_pass:
        failures.append(
            f"exhaustion-tools-attempt={exh_result.get('verdict','?')}"
        )
    if not sal_pass:
        failures.append(
            f"salvage-negation={sal_result.get('verdict','?')}"
        )
    payload["verdict"] = "fail-lane-emit-gate-fail"
    payload["reason"] = (
        "Gap #52 handshake refused: " + "; ".join(failures)
        + ". Run depth-tools-orchestrator and/or add the required "
        "negation framing in results.md, OR add a "
        "<!-- gap52-rebuttal: <reason up to 200 chars> --> marker."
    )
    return payload


def parse_lane_report(text: str) -> dict[str, Any]:
    """Extract title, headings, claim corpus from a lane report.

    Best-effort: returns whatever it can.  Used for claim verification.
    """
    context_pack_id = ""
    pack_match = re.search(
        r"(?m)^\s*(?:(?:\*\*)?MCP(?:\*\*)?\s+)?context_pack_id:\s*(\S.*\S|\S)\s*$",
        text,
    )
    if pack_match:
        context_pack_id = pack_match.group(1).strip()
    title = ""
    headings: list[str] = []
    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if not m:
            continue
        if not title:
            title = m.group(1).strip()
        headings.append(m.group(1).strip().lower())
    return {
        "title": title,
        "headings": headings,
        "context_pack_id": context_pack_id,
        "body_lower": text.lower(),
    }


def _workspace_slug(repo_root: Path) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", repo_root.name.strip())
    return slug.strip("-") or "workspace"


def _source_lane_from_report(report_path: Path, text: str) -> str:
    lane_match = re.search(r"(?m)^\s*(?:-\s*)?Lane:\s*(\S.*\S|\S)\s*$", text)
    if lane_match:
        return lane_match.group(1).strip()
    parent = report_path.parent.name
    if parent.startswith("lane_"):
        return parent[len("lane_"):]
    return parent


def _statement_from_invariant_match(tail: str, block_lines: list[str]) -> str:
    tail = tail.strip()
    tail = re.sub(r"^(?:candidate\b\s*[:-]?\s*)", "", tail, flags=re.IGNORECASE)
    tail = tail.strip(" :-\t")
    if tail:
        return tail
    for raw in block_lines[1:]:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("```"):
            continue
        if line.lower().startswith("enforcing code path"):
            continue
        return line
    return ""


def _extract_code_paths(block_text: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for match in _CODE_PATH_RE.finditer(block_text):
        value = f"{match.group('file')}:{match.group('line')}"
        if value not in seen:
            seen.add(value)
            paths.append(value)
    return paths


def extract_invariant_candidates_from_report(
    report_path: Path,
    text: str,
) -> list[dict[str, Any]]:
    """Extract auditooor.invariant_candidate.v1 rows from a lane results.md.

    The canonical block starts with an ``INV-<TARGET>-NNN candidate`` marker,
    but existing lane reports sometimes use ``INV-<TARGET>-NNN:``. Treat both
    forms as candidates so older anchors can be ingested without report churn.
    A block ends at the next heading, next invariant id, or EOF.
    """
    report = parse_lane_report(text)
    audit_pin = str(report.get("context_pack_id") or "").strip()
    source_lane = _source_lane_from_report(report_path, text)
    lines = text.splitlines()
    rows: list[dict[str, Any]] = []

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = _INVARIANT_ID_RE.search(line)
        if not match or not match.group("marker"):
            idx += 1
            continue
        prefix = line[: match.start()].strip()
        if prefix and prefix.strip("#-* ") != "":
            idx += 1
            continue

        block_lines = [line]
        j = idx + 1
        while j < len(lines):
            candidate = lines[j]
            if _HEADING_RE.match(candidate) or _INVARIANT_ID_RE.search(candidate):
                break
            block_lines.append(candidate)
            j += 1

        statement = _statement_from_invariant_match(
            match.group("tail") or "",
            block_lines,
        )
        block_text = "\n".join(block_lines)
        enforcing_code_path = _extract_code_paths(block_text)
        if statement and enforcing_code_path:
            inv_id = match.group("id").upper()
            rows.append(
                {
                    "schema_version": INVARIANT_CANDIDATE_SCHEMA_VERSION,
                    "invariant_id": inv_id,
                    "target": match.group("target").upper(),
                    "statement": statement,
                    "enforcing_code_path": enforcing_code_path,
                    "verification_tier": "tier-2-verified-public-archive",
                    "source_lane": source_lane,
                    "audit_pin": audit_pin,
                }
            )
        idx = j
    return rows


def invariant_candidate_output_path(
    repo_root: Path,
    workspace_slug: str | None = None,
) -> Path:
    slug = workspace_slug or _workspace_slug(repo_root)
    return repo_root / "audit" / "corpus_tags" / slug / "invariants_extracted.jsonl"


def emit_invariant_candidates(
    output_path: Path,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Append novel invariant candidate rows to ``output_path`` idempotently."""
    if not rows:
        return {
            "path": str(output_path),
            "candidates_found": 0,
            "rows_appended": 0,
            "rows_existing": 0,
        }
    existing_keys: set[tuple[str, str, str]] = set()
    existing_count = 0
    if output_path.exists():
        try:
            with output_path.open("r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        row = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(row, dict):
                        continue
                    existing_count += 1
                    existing_keys.add(
                        (
                            str(row.get("invariant_id") or ""),
                            str(row.get("source_lane") or ""),
                            str(row.get("audit_pin") or ""),
                        )
                    )
        except OSError:
            existing_keys = set()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    appended = 0
    with output_path.open("a", encoding="utf-8") as fh:
        for row in rows:
            key = (
                str(row.get("invariant_id") or ""),
                str(row.get("source_lane") or ""),
                str(row.get("audit_pin") or ""),
            )
            if key in existing_keys:
                continue
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            existing_keys.add(key)
            appended += 1
    return {
        "path": str(output_path),
        "candidates_found": len(rows),
        "rows_appended": appended,
        "rows_existing": existing_count,
    }


def claim_overclaim_check(
    commit_message: str, report: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Return (overclaims, missing_claim_tokens).

    Heuristic: every claim-keyword-bearing line in the commit message body
    must have at least one substantive content noun that appears in the
    report body OR in a report heading.  A line that says "wires foo + bar"
    where neither 'foo' nor 'bar' appears anywhere in the report is an
    overclaim - the report does not document the claim.
    """
    body_lower = report.get("body_lower", "")
    if not body_lower:
        return False, []
    overclaims: list[str] = []
    for line in commit_message.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if not _CLAIM_KEYWORD_RE.search(s):
            continue
        # Extract content tokens: alnum+_/.- tokens of length >= 4 that are
        # not pure claim keywords.
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_\-/.]{3,}", s)
        if not tokens:
            continue
        # A line passes if at least one substantive token (length >= 4) is
        # present in the report body.
        passed = False
        for tok in tokens:
            tok_lower = tok.lower()
            if _CLAIM_KEYWORD_RE.fullmatch(tok_lower):
                continue
            # Skip very generic words that wouldn't be load-bearing claims.
            if tok_lower in {
                "this", "that", "with", "from", "into", "onto",
                "phase", "lane", "iter", "rule", "tool", "tools",
                "test", "tests", "code", "file", "files", "the",
                "per", "wf", "via", "and", "for",
            }:
                continue
            if tok_lower in body_lower:
                passed = True
                break
        if not passed:
            overclaims.append(s)
    return bool(overclaims), overclaims


# ---------------------------------------------------------------------------
# Gate runner
# ---------------------------------------------------------------------------

def run_gate(
    cmd: list[str], cwd: Path, env: dict[str, str] | None = None,
) -> tuple[int, str]:
    try:
        out = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True,
            env=env, check=False,
        )
    except FileNotFoundError as exc:
        return 127, str(exc)
    combined = (out.stdout or "") + (out.stderr or "")
    return out.returncode, combined.strip()


def _record_roadmap_result(
    *,
    repo_root: Path,
    item_id: str,
    claim_token: str,
    result_status: str,
    result_summary: str,
    remember_signed_token: str,
    roadmap_path: Path | None = None,
    state_path: Path | None = None,
) -> dict[str, Any]:
    """Best-effort bridge from a clean lane integration into roadmap result-time.

    This intentionally calls the in-process MCP implementation so completion
    records take the same `vault_active_roadmap -> vault_remember` path as
    operator-driven result calls, without requiring network or a running server.
    """
    if not item_id or not claim_token:
        return {
            "attempted": False,
            "accepted": False,
            "reason": "missing_item_id_or_claim_token",
        }
    try:
        module_path = repo_root / "tools" / "vault-mcp-server.py"
        if not module_path.exists():
            module_path = Path(__file__).resolve().with_name("vault-mcp-server.py")
        spec = importlib.util.spec_from_file_location("vault_mcp_server", module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load {module_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        vault = module.VaultQuery(repo_root / "obsidian-vault", repo_root)
        call_args: dict[str, Any] = {
            "side": "codex",
            "item_id": item_id,
            "claim_token": claim_token,
            "result_status": result_status,
            "result_summary": result_summary,
        }
        if remember_signed_token:
            call_args["remember_signed_token"] = remember_signed_token
        if roadmap_path is not None:
            call_args["roadmap_path"] = str(roadmap_path)
        if state_path is not None:
            call_args["state_path"] = str(state_path)
        result = vault.vault_active_roadmap(**call_args)
        mutation = result.get("mutation") if isinstance(result, dict) else {}
        return {
            "attempted": True,
            "accepted": bool(isinstance(mutation, dict) and mutation.get("accepted")),
            "reason": mutation.get("reason") if isinstance(mutation, dict) else "unknown",
            "result_remember": result.get("result_remember") if isinstance(result, dict) else None,
            "context_pack_id": result.get("context_pack_id") if isinstance(result, dict) else "",
        }
    except Exception as exc:  # noqa: BLE001 - integration commit must survive.
        return {
            "attempted": True,
            "accepted": False,
            "reason": f"exception:{exc}",
        }


# ---------------------------------------------------------------------------
# Commit message composition
# ---------------------------------------------------------------------------

def compose_commit_message(
    headline: str,
    report_path: Path,
    lane_id: str,
    declared_files: Iterable[str],
    claim_evidence: str | None = None,
) -> str:
    parts: list[str] = [headline.strip()]
    parts.append("")
    parts.append(f"Lane: {lane_id}")
    parts.append(f"Lane report: {report_path}")
    if claim_evidence:
        parts.append(f"Claim evidence: {claim_evidence}")
    files_list = sorted(declared_files)
    if files_list:
        parts.append("")
        parts.append("Declared pathspec (R36):")
        for f in files_list:
            parts.append(f"  - {f}")
    parts.append("")
    parts.append("Integrated by tools/lane-integrator.py per WF-7 #3.")
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    verdict = payload.get("verdict", "?")
    reason = payload.get("reason", "")
    print(f"[{GATE}] verdict={verdict}")
    if reason:
        print(f"  reason: {reason}")
    for key in ("lane_id", "lane_report", "staged_files", "sibling_overflow",
                "overclaim_lines", "gate_command", "gate_rc",
                "commit_sha", "pushed"):
        if key in payload:
            print(f"  {key}: {payload[key]}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="lane-integrator",
        description=(
            "Canonical integration-commit tool per WF-7 #3. Stages by "
            "declared pathspec, runs pre-commit gates, claim-verifies "
            "commit message vs lane report, refuses sibling overflow."
        ),
    )
    # r36-rebuttal: lane-GAP-FIX-3-B argparse extension
    p.add_argument("--lane-id", required=False, default="",
                   help="Lane id as it appears in agent_pathspec.json (e.g. "
                        "'P-minus-1-D-lane-integrator' or short 'X'). "
                        "Not required in --lane-emit-handshake mode.")
    p.add_argument("--auto-discover", action="store_true",
                   help="Discover the lane's results.md by globbing.")
    p.add_argument("--lane-emit-handshake", type=Path, default=None,
                   help=(
                       "Gap #52 hunt-lane emit handshake mode (codified "
                       "2026-05-26). Argument is a path to the lane's "
                       "results.md. The handshake runs Check #109 "
                       "(exhaustion-verdict-tools-attempt-required-check) "
                       "AND salvage-negation-verdict-check against the "
                       "results.md and refuses emit with "
                       "fail-lane-emit-gate-fail when either sub-check "
                       "fails and no <!-- gap52-rebuttal: <reason> --> "
                       "marker is present. The handshake exits without "
                       "performing any staging/commit; use it from the "
                       "hunt-lane reply step BEFORE declaring an "
                       "exhaustion-class verdict, or from `make "
                       "lane-emit`."))
    p.add_argument("--lane-emit-handshake-workspace", type=Path,
                   default=None,
                   help=(
                       "Optional workspace override for "
                       "--lane-emit-handshake. Default: repo root."))
    p.add_argument("--report", type=Path,
                   help="Explicit path to the lane's results.md.")
    p.add_argument("--pathspec-file", type=Path,
                   help="Path to agent_pathspec.json. Default: "
                        ".auditooor/agent_pathspec.json under repo root.")
    p.add_argument("--message",
                   help="Single-line commit headline.")
    p.add_argument("--message-file", type=Path,
                   help="File containing the commit message (overrides "
                        "--message).")
    p.add_argument("--gate", action="append", default=None,
                   help=("Pre-commit gate command (repeatable). "
                         "Default: 'make docs-check'. Pass '--gate skip' to "
                         "disable all gates."))
    p.add_argument("--claim-evidence",
                   help="Optional claim_evidence line to include in commit "
                        "message body (e.g. test transcript line, hash).")
    p.add_argument("--dry-run", action="store_true",
                   help="Plan and validate, but do not stage or commit.")
    p.add_argument("--strict", action="store_true",
                   help="Treat warnings as fails (e.g. empty stage).")
    p.add_argument("--push", action="store_true",
                   help="Push after a successful commit.")
    p.add_argument("--allow-empty-stage", action="store_true",
                   help="Permit a commit even if nothing is staged.")
    p.add_argument("--json", action="store_true",
                   help="Emit verdict as JSON on stdout.")
    p.add_argument("--repo-root", type=Path,
                   help="Override repo root (default: git rev-parse).")
    p.add_argument("--invariant-workspace",
                   help=("Workspace slug for auditooor.invariant_candidate.v1 "
                         "JSONL emission. Default: repo root directory name."))
    p.add_argument("--no-invariant-candidate-emit", action="store_true",
                   help=("Disable scanning results.md for INV-<TARGET>-NNN "
                         "candidate blocks and emitting "
                         "audit/corpus_tags/<ws>/invariants_extracted.jsonl."))
    p.add_argument("--fuzz-workspace",
                   help=("Workspace slug for auditooor.fuzz_target.v1 JSONL "
                         "emission. Default: --invariant-workspace or repo root "
                         "directory name."))
    p.add_argument("--no-fuzz-target-emit", action="store_true",
                   help=("Disable scanning sibling fuzz_results.json and emitting "
                         "audit/corpus_tags/<ws>/fuzz_targets.jsonl."))
    p.add_argument("--auto-cleanup-worktree", action="store_true",
                   help=("When running inside a per-lane worktree provisioned "
                         "by tools/spawn-lane-worktree.sh, invoke "
                         "tools/cleanup-lane-worktree.sh after a successful "
                         "--push. The cleanup respects the same dirty/ahead "
                         "guard the cleanup tool enforces (PER-LANE-WORKTREE, "
                         "2026-05-23)."))
    p.add_argument("--no-auto-cleanup-worktree", dest="auto_cleanup_worktree",
                   action="store_false",
                   help="Disable the auto-cleanup behaviour (default OFF).")
    p.add_argument("--roadmap-item-id",
                   help=("Optional vault_active_roadmap item_id to mark "
                         "complete after a clean commit."))
    p.add_argument("--roadmap-claim-token",
                   help=("Claim token returned by vault_active_roadmap "
                         "claim:true for --roadmap-item-id."))
    p.add_argument("--roadmap-result-status", default="LANDED",
                   choices=["LANDED", "BLOCKED", "PARTIAL"],
                   help="Result status to record for --roadmap-item-id.")
    p.add_argument("--roadmap-result-summary",
                   help=("Concise result output persisted through "
                         "vault_remember; defaults to commit summary."))
    p.add_argument("--roadmap-remember-signed-token",
                   help=("Optional remember-scoped HMAC token for the "
                         "result-time vault_remember call."))
    p.add_argument("--roadmap-path", type=Path,
                   help="Optional roadmap markdown path for result recording.")
    p.add_argument("--roadmap-state-path", type=Path,
                   help="Optional roadmap state JSON path for result recording.")
    args = p.parse_args(argv)

    # Resolve repo root.
    repo_root = args.repo_root or _repo_root()
    if repo_root is None or not Path(repo_root).is_dir():
        payload = _emit("error", reason="not inside a git repo",
                        lane_id=args.lane_id)
        _print(payload, args.json)
        return 2
    repo_root = Path(repo_root)

    # r36-rebuttal: lane-GAP-FIX-3-B
    # Gap #52 hunt-lane emit handshake mode. When --lane-emit-handshake is
    # passed, run the cross-check pair and exit WITHOUT performing any
    # staging/commit/push. This is the canonical "before-declaring-verdict"
    # gate that hunt-lane reply scripts and `make lane-emit` invoke.
    if args.lane_emit_handshake is not None:
        results_md = args.lane_emit_handshake
        if not results_md.is_absolute():
            results_md = repo_root / results_md
        ws = args.lane_emit_handshake_workspace or repo_root
        if not ws.is_absolute():
            ws = repo_root / ws
        handshake = run_lane_emit_handshake(
            results_md=results_md,
            repo_root=repo_root,
            workspace=ws,
            strict=args.strict,
        )
        verdict = handshake.get("verdict", "error")
        payload = _emit(
            verdict,
            reason=handshake.get("reason", ""),
            lane_id=args.lane_id or "",
            lane_emit_handshake=handshake,
        )
        _print(payload, args.json)
        if verdict.startswith("pass-") or verdict == "ok-rebuttal":
            return 0
        if verdict == "fail-lane-emit-gate-fail":
            return 1
        return 2

    if not args.lane_id:
        payload = _emit(
            "error",
            reason=(
                "--lane-id is required unless --lane-emit-handshake is used"
            ),
        )
        _print(payload, args.json)
        return 2

    # Resolve pathspec file.
    pathspec_file = args.pathspec_file or (repo_root / DEFAULT_PATHSPEC_REL)
    agents, warnings = load_pathspec(pathspec_file)
    if not agents:
        payload = _emit("fail-no-pathspec-registered",
                        reason=("; ".join(warnings)
                                or f"no agents in {pathspec_file}"),
                        lane_id=args.lane_id,
                        pathspec_file=str(pathspec_file))
        _print(payload, args.json)
        return 1

    lane_files, sibling_files = split_lane_vs_sibling(agents, args.lane_id)
    if not lane_files:
        payload = _emit(
            "fail-no-pathspec-registered",
            reason=(f"no pathspec entry for lane_id={args.lane_id} in "
                    f"{pathspec_file}"),
            lane_id=args.lane_id,
            pathspec_file=str(pathspec_file),
        )
        _print(payload, args.json)
        return 1

    # Resolve report path.
    report_path: Path | None = None
    if args.report:
        report_path = args.report if args.report.is_absolute() else (
            repo_root / args.report
        )
        if not report_path.exists():
            payload = _emit("fail-no-lane-report",
                            reason=f"--report path does not exist: "
                                   f"{report_path}",
                            lane_id=args.lane_id)
            _print(payload, args.json)
            return 1
    elif args.auto_discover:
        report_path = discover_report(repo_root, args.lane_id)
        if report_path is None:
            payload = _emit(
                "fail-no-lane-report",
                reason=(f"no results.md matched lane_id={args.lane_id} "
                        f"under {DEFAULT_REPORTS_GLOB}"),
                lane_id=args.lane_id,
            )
            _print(payload, args.json)
            return 1
    else:
        # Best-effort: try discovery silently as a convenience.
        report_path = discover_report(repo_root, args.lane_id)
        if report_path is None:
            payload = _emit(
                "fail-no-lane-report",
                reason=("no --report or --auto-discover, and no results.md "
                        f"matched lane_id={args.lane_id}"),
                lane_id=args.lane_id,
            )
            _print(payload, args.json)
            return 1

    report_text = report_path.read_text(encoding="utf-8", errors="replace")
    report = parse_lane_report(report_text)
    if not str(report.get("context_pack_id", "")).strip():
        payload = _emit(
            "fail-no-pack-id-in-lane-results",
            reason=(f"results.md lacks context_pack_id: {report_path}"),
            lane_id=args.lane_id,
            lane_report=str(report_path),
        )
        _print(payload, args.json)
        return 1

    # CAPABILITY-GAP-2 soft gate (2026-05-25): if this lane was spawned
    # with `--inject-prior-lanes` (per spawn-worker.sh's
    # `.auditooor/spawn_worker_log.jsonl`), the lane's results.md should
    # carry a `prior_negative_chains_acknowledged` frontmatter line that
    # explicitly acknowledges each surfaced prior chain. WARN-only -
    # never blocks the commit.
    _prior_lane_warn = _check_prior_lane_acknowledgement_soft_gate(
        repo_root=repo_root,
        lane_id=args.lane_id,
        report_text=report_text,
    )

    invariant_emit: dict[str, Any] = {}
    if not args.no_invariant_candidate_emit:
        invariant_rows = extract_invariant_candidates_from_report(
            report_path=report_path,
            text=report_text,
        )
        invariant_output = invariant_candidate_output_path(
            repo_root,
            args.invariant_workspace,
        )
        if args.dry_run:
            invariant_emit = {
                "path": str(invariant_output),
                "candidates_found": len(invariant_rows),
                "rows_appended": 0,
                "dry_run": True,
            }
        else:
            invariant_emit = emit_invariant_candidates(
                invariant_output,
                invariant_rows,
            )

    fuzz_emit: dict[str, Any] = {}
    if not args.no_fuzz_target_emit:
        fuzz_results_path = report_path.with_name("fuzz_results.json")
        if fuzz_results_path.is_file():
            fuzz_workspace = args.fuzz_workspace or args.invariant_workspace
            fuzz_rows = extract_fuzz_target_rows_from_file(
                fuzz_results_path,
                ws=fuzz_workspace,
            )
            fuzz_output = fuzz_target_output_path(repo_root, fuzz_workspace)
            if args.dry_run:
                fuzz_emit = {
                    "path": str(fuzz_output),
                    "targets_found": len(fuzz_rows),
                    "rows_appended": 0,
                    "dry_run": True,
                }
            else:
                fuzz_emit = emit_fuzz_targets(
                    fuzz_output,
                    fuzz_rows,
                )

    # Inventory the working tree.
    status_rows = git_status_porcelain(repo_root)
    all_changed = [path for _, path in status_rows]

    # Files we can stage = changed files that are declared in lane pathspec.
    declared_files = sorted(lane_files)
    to_stage = [f for f in all_changed if f in lane_files]

    # Sibling overflow detection: any non-declared changed file that lies in
    # a sibling pathspec.  We do NOT auto-fail on undeclared-but-no-sibling
    # files (the R36 hook is the final authority); we just refuse to absorb
    # them.
    sibling_in_tree = [
        f for f in all_changed if f in sibling_files and f not in lane_files
    ]

    # Dry-run reporting before any mutation.
    plan = {
        "lane_id": args.lane_id,
        "lane_report": str(report_path),
        "declared_files": declared_files,
        "would_stage": to_stage,
        "sibling_in_tree": sibling_in_tree,
        "all_changed_count": len(all_changed),
    }
    if invariant_emit:
        plan["invariant_candidate_emit"] = invariant_emit
    if fuzz_emit:
        plan["fuzz_target_emit"] = fuzz_emit

    if not to_stage and not args.allow_empty_stage:
        verdict = "fail-empty-stage"
        payload = _emit(
            verdict,
            reason=(f"no changed file in working tree is declared in lane "
                    f"pathspec ({len(declared_files)} files declared, "
                    f"{len(all_changed)} files changed). "
                    "Use --allow-empty-stage to override."),
            **plan,
        )
        _print(payload, args.json)
        return 1

    # Sibling-overflow detection is informational pre-stage; it becomes a
    # hard fail if any sibling file would actually be staged.  Since we
    # stage by explicit pathspec, sibling files cannot land in `to_stage`
    # by construction.  We still surface the warning.
    if sibling_in_tree:
        plan["warning_sibling_in_tree"] = sibling_in_tree

    # CAPABILITY-GAP-2 soft warn: surface prior-lane-scan acknowledgement
    # status in the plan output. Never blocks the commit.
    if _prior_lane_warn:
        plan.update(_prior_lane_warn)

    # Compose commit message early so claim-verification runs before any
    # mutation.
    if args.message_file:
        msg_path = (args.message_file
                    if args.message_file.is_absolute()
                    else repo_root / args.message_file)
        if not msg_path.exists():
            payload = _emit(
                "error",
                reason=f"--message-file does not exist: {msg_path}",
                lane_id=args.lane_id,
            )
            _print(payload, args.json)
            return 2
        commit_message = msg_path.read_text(encoding="utf-8")
    else:
        headline = args.message or report.get("title") or (
            f"Lane {args.lane_id}: integrated by lane-integrator"
        )
        commit_message = compose_commit_message(
            headline=headline,
            report_path=report_path.relative_to(repo_root)
                if report_path.is_relative_to(repo_root) else report_path,
            lane_id=args.lane_id,
            declared_files=declared_files,
            claim_evidence=args.claim_evidence,
        )

    # Claim overclaim check (catches iter17 TTTTT pattern).
    overclaims, overclaim_lines = claim_overclaim_check(commit_message, report)
    if overclaims:
        payload = _emit(
            "fail-claim-overclaim",
            reason=("commit message claims work not documented in the "
                    f"lane report ({len(overclaim_lines)} line(s) failed "
                    "claim-vs-report match)"),
            overclaim_lines=overclaim_lines,
            **plan,
        )
        _print(payload, args.json)
        return 1

    # Gate runs (skip in dry-run; user may disable explicitly).
    gates = args.gate or [" ".join(DEFAULT_GATE_CMD)]
    if any(g.strip().lower() == "skip" for g in gates):
        gates = []
    if args.dry_run:
        # Always include the planned gate(s) in the dry-run output but do
        # not execute them; this preserves the iter17 fail-fast property
        # without surprising the operator.
        payload = _emit(
            "pass-dry-run",
            reason="dry-run: planned stage + gate set returned",
            planned_gates=gates,
            **plan,
        )
        _print(payload, args.json)
        return 0

    for raw_cmd in gates:
        cmd = raw_cmd.split()
        rc, output = run_gate(cmd, cwd=repo_root)
        if rc != 0:
            payload = _emit(
                "fail-gate-broken",
                reason=f"pre-commit gate failed: {raw_cmd}",
                gate_command=raw_cmd,
                gate_rc=rc,
                gate_output_tail=output[-2000:],
                **plan,
            )
            _print(payload, args.json)
            return 1

    # Stage by explicit pathspec only.
    for f in to_stage:
        add = git_run(["add", "--", f], cwd=repo_root)
        if add.returncode != 0:
            payload = _emit(
                "error",
                reason=f"git add failed for {f}: {add.stderr.strip()}",
                **plan,
            )
            _print(payload, args.json)
            return 2

    # Verify staging matches.  Anything in the staged set that is NOT in
    # the lane's declared files is overflow - either a sibling-lane file
    # or an undeclared pre-staged file from another process.  Unstage it
    # and refuse the commit (mirrors the R36 hook's authority but catches
    # the violation BEFORE git commit so the operator sees a clean
    # workspace).
    staged_now = git_diff_staged_names(repo_root)
    overflow = [f for f in staged_now if f not in lane_files]
    if overflow:
        # Unstage the offending files so the working tree is left clean.
        # We use reset HEAD -- so they go back to their pre-stage state.
        git_run(["reset", "HEAD", "--"] + overflow, cwd=repo_root)
        # Distinguish: a declared sibling vs an undeclared pre-staged file.
        sibling_in_stage = [f for f in overflow if f in sibling_files]
        undeclared = [f for f in overflow if f not in sibling_files]
        payload = _emit(
            "fail-sibling-file-staged",
            reason=("staged set contains files outside the lane's declared "
                    "pathspec; refused (overflow unstaged)"),
            sibling_overflow=overflow,
            sibling_owned=sibling_in_stage,
            undeclared_overflow=undeclared,
            staged_files=staged_now,
            **plan,
        )
        _print(payload, args.json)
        return 1

    if not staged_now and not args.allow_empty_stage:
        payload = _emit(
            "fail-empty-stage",
            reason="post-stage diff is empty; nothing to commit",
            **plan,
        )
        _print(payload, args.json)
        return 1

    # Commit.
    if not staged_now and args.allow_empty_stage:
        commit_args = ["commit", "--allow-empty", "-m", commit_message]
    else:
        commit_args = ["commit", "-m", commit_message]
    commit = git_run(commit_args, cwd=repo_root)
    if commit.returncode != 0:
        payload = _emit(
            "error",
            reason=f"git commit failed: {commit.stderr.strip()}",
            staged_files=staged_now,
            **plan,
        )
        _print(payload, args.json)
        return 2

    sha_out = git_run(["rev-parse", "HEAD"], cwd=repo_root)
    commit_sha = sha_out.stdout.strip()

    verdict = "pass-clean-commit"
    pushed = False
    automerge_detail: dict[str, Any] = {}
    if args.push:
        # For per-lane worktree push: we need to push the local worktree
        # branch to its own ref. Use HEAD:<branch> form if upstream isn't set.
        push_cmd = ["push"]
        # Use `-u origin HEAD` whenever HEAD is a lane feature branch
        # (per-lane-worktree OR canonical worktree currently on a
        # lane/<id>-<sha> branch). This makes the feature-branch push
        # idempotent regardless of which worktree the integrator runs in.
        if (_is_per_lane_worktree(repo_root) or
                _is_on_lane_feature_branch(repo_root)):
            push_cmd = ["push", "-u", "origin", "HEAD"]
        push = git_run(push_cmd, cwd=repo_root)
        if push.returncode != 0:
            payload = _emit(
                "error",
                reason=f"git push failed after commit: "
                       f"{push.stderr.strip()}",
                commit_sha=commit_sha,
                staged_files=staged_now,
                **plan,
            )
            _print(payload, args.json)
            return 2
        pushed = True
        verdict = "pass-clean-commit-and-push"

        # v1.2 auto-merge (LANE-INTEGRATOR-AUTOMERGE-PATCH, 2026-05-23):
        # When HEAD points at a `lane/<id>-<short-sha>` feature branch,
        # attempt a FF-only merge to origin/main so the work is visible on
        # main without operator intervention. Closes the structural merge
        # gap from `lane_BRANCH_RECONCILE_AUDIT`. R55-safe: FF-only, no
        # --force / --force-with-lease.
        if _is_on_lane_feature_branch(repo_root):
            am_suffix, am_detail = _attempt_ff_merge_to_main(
                repo_root, base_branch="main",
            )
            automerge_detail = {
                "automerge_attempted": True,
                "automerge_suffix": am_suffix,
                "automerge_detail": am_detail,
                "feature_branch": _current_symbolic_ref(repo_root),
            }
            if am_suffix == "automerged":
                verdict = "pass-clean-commit-and-push-and-automerged"
            elif am_suffix == "feature-branch-diverged":
                # Hard failure on the auto-merge axis. The push to the
                # feature branch already succeeded, so the commit is not
                # lost; the operator must resolve the divergence.
                payload = _emit(
                    "fail-feature-branch-diverged-from-main",
                    reason=(
                        f"feature branch diverged from origin/main; "
                        "FF-only auto-merge refused (R55). Operator must "
                        f"3-way merge or rebase: {am_detail}"
                    ),
                    commit_sha=commit_sha,
                    staged_files=staged_now,
                    pushed=pushed,
                    **automerge_detail,
                    **plan,
                )
                _print(payload, args.json)
                return 1
            else:
                # fetch-failed / push-failed -> informational pass, keep
                # the push but flag the unmerged state so the operator can
                # follow up.
                verdict = "pass-clean-commit-and-push-with-unmerged-feature-branch"
        else:
            automerge_detail = {"automerge_attempted": False}

    # Per-lane worktree auto-cleanup hook (PER-LANE-WORKTREE, 2026-05-23).
    # Only fires when: (a) --auto-cleanup-worktree is set, (b) we successfully
    # pushed, and (c) we're running inside a per-lane worktree directory.
    # The cleanup tool itself enforces dirty/ahead safety guards.
    worktree_cleanup_verdict = None
    auto_cleanup = bool(getattr(args, "auto_cleanup_worktree", False))
    if auto_cleanup and pushed and _is_per_lane_worktree(repo_root):
        lane_id_from_dir = _worktree_lane_id(repo_root)
        # Try the underlying canonical repo first; fall back to looking up
        # tools/ relative to repo_root.
        cleanup_tool = None
        # Walk up to find canonical tools/cleanup-lane-worktree.sh - the
        # per-lane worktree shares the same .git so other worktrees in the
        # repository can be discovered via `git worktree list`.
        try:
            wt_list = subprocess.run(
                ["git", "worktree", "list", "--porcelain"],
                cwd=str(repo_root), capture_output=True, text=True, check=False,
            )
            if wt_list.returncode == 0:
                for line in wt_list.stdout.splitlines():
                    if line.startswith("worktree "):
                        candidate = Path(line[len("worktree "):].strip())
                        tool_path = candidate / "tools" / "cleanup-lane-worktree.sh"
                        if tool_path.exists():
                            cleanup_tool = tool_path
                            break
        except FileNotFoundError:
            pass

        if cleanup_tool is None:
            # Last-resort fallback: in-worktree copy.
            local_copy = repo_root / "tools" / "cleanup-lane-worktree.sh"
            if local_copy.exists():
                cleanup_tool = local_copy

        if cleanup_tool is None or lane_id_from_dir is None:
            worktree_cleanup_verdict = "skipped-no-cleanup-tool"
        else:
            try:
                cl = subprocess.run(
                    [str(cleanup_tool),
                     "--lane-id", lane_id_from_dir,
                     "--worktree-path", str(repo_root),
                     "--unregister-pathspec",
                     "--json"],
                    capture_output=True, text=True, check=False,
                )
                if cl.returncode == 0 and cl.stdout.strip():
                    try:
                        cl_payload = json.loads(cl.stdout.strip().splitlines()[-1])
                        worktree_cleanup_verdict = cl_payload.get("verdict",
                                                                  "unknown")
                    except (ValueError, IndexError):
                        worktree_cleanup_verdict = "ran-no-parse"
                else:
                    worktree_cleanup_verdict = "cleanup-tool-error"
            except FileNotFoundError:
                worktree_cleanup_verdict = "cleanup-tool-missing"

    extra: dict[str, Any] = dict(plan)
    if worktree_cleanup_verdict is not None:
        extra["worktree_cleanup_verdict"] = worktree_cleanup_verdict
        extra["worktree_lane_id"] = _worktree_lane_id(repo_root)
    if automerge_detail:
        extra.update(automerge_detail)
    roadmap_result: dict[str, Any] | None = None
    if args.roadmap_item_id or args.roadmap_claim_token:
        summary = args.roadmap_result_summary or (
            f"{args.lane_id} integrated commit {commit_sha[:12]} with "
            f"{len(staged_now)} staged file(s): {', '.join(staged_now[:8])}"
        )
        roadmap_path = (
            args.roadmap_path
            if args.roadmap_path is None or args.roadmap_path.is_absolute()
            else repo_root / args.roadmap_path
        )
        roadmap_state_path = (
            args.roadmap_state_path
            if (
                args.roadmap_state_path is None
                or args.roadmap_state_path.is_absolute()
            )
            else repo_root / args.roadmap_state_path
        )
        roadmap_result = _record_roadmap_result(
            repo_root=repo_root,
            item_id=str(args.roadmap_item_id or ""),
            claim_token=str(args.roadmap_claim_token or ""),
            result_status=str(args.roadmap_result_status or "LANDED"),
            result_summary=summary,
            remember_signed_token=str(args.roadmap_remember_signed_token or ""),
            roadmap_path=roadmap_path,
            state_path=roadmap_state_path,
        )
        extra["roadmap_result"] = roadmap_result

    payload = _emit(
        verdict,
        reason=f"committed {len(staged_now)} file(s) under lane pathspec",
        commit_sha=commit_sha,
        staged_files=staged_now,
        pushed=pushed,
        **extra,
    )
    _print(payload, args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
