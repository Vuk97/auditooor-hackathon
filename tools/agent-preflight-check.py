#!/usr/bin/env python3
"""agent-preflight-check.py — mechanical foot-gun guardrails before PR push.

Background: a session-feedback memory file (referenced as
``feedback_recurring_agent_mistakes.md`` in the user's MEMORY) accumulated 14
recurring agent foot-guns. Many were advisory-only — pasted into agent
prompts. This tool converts the most-frequent MECHANICALLY-CHECKABLE ones
into a script that an agent harness can run *before* opening a PR.

Checks (each exits with structured ``{check, status, evidence}`` JSON):

  fixture_path           foot-gun #1 — fixtures must live under canonical
                         ``detectors/test_fixtures/``; reject any added .sol
                         under ``patterns/fixtures/``.  FAIL-CLOSED.
  fixture_comment_leak   foot-gun #2 — added fixtures must not contain
                         comment trigger words like ``// VULN``, ``// CLEAN``,
                         ``// BUG``, ``// missing`` that the predicate engine
                         ingests via source-mapping content.  FAIL-CLOSED.
  standalone_md          foot-gun #6 — agents must not create new top-level
                         ``.md`` docs (Codex-owns-docs).  Edits to existing
                         ``.md`` files are fine.  FAIL-CLOSED on new files
                         outside an allowlist; the allowlist matches the
                         "okay" cases (release notes alongside detectors,
                         scoped engagement notes, etc.).
  tier_a_promotion       foot-gun #7 — newly-added Tier A entries in
                         ``detectors/_tier_registry.yaml`` must declare a
                         ``corpus_noise_count`` field.  FAIL-CLOSED.
  gh_api_placeholder     foot-gun #9 — added shell scripts must not use the
                         old ``gh api repos/:owner/:repo/`` colon placeholder  # preflight-allow: gh_api_placeholder
                         syntax (``gh api`` does not expand it).  FAIL-CLOSED.
  verified_push          foot-gun #10 — LOCAL HEAD must match REMOTE HEAD for
                         the current branch.  Cross-checks via
                         ``gh api repos/<o>/<r>/git/refs/heads/<branch>``.
                         FAIL-CLOSED if mismatch; SKIP if network/gh
                         unavailable or ``--no-network`` is passed.

Out of scope (stay advisory):
  #3 regex-anchor pitfalls       — requires DSL-engine semantic check
  #4 stale-base parallel batch   — already covered by check-pr-base-freshness
  #5 redundant pattern-compile   — caught at cherry-pick conflict time
  #8 aggregate vs named blocker  — trust-gauge specific
  #11 LLM false-positive         — needs LLM eval
  #12 n=1 overgeneralization     — needs sample-size context
  #13/13a-e fan-out parser       — concurrent-agent harness concerns

Exit codes:
  0  all checks PASS or SKIP
  1  at least one check FAIL

Usage:
  python3 tools/agent-preflight-check.py [--repo PATH] [--base BRANCH]
                                         [--branch BRANCH] [--no-network]
                                         [--check NAME] [--json]

Speed budget: <5s on a clean workspace.  Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ---- check-result plumbing -------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclass
class CheckResult:
    check: str
    status: str  # PASS | FAIL | SKIP
    evidence: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "status": self.status,
            "evidence": self.evidence,
            "elapsed_ms": self.elapsed_ms,
        }


# ---- helpers ---------------------------------------------------------------


def _git(repo: Path, *args: str, check: bool = True) -> str:
    """Run ``git`` in ``repo`` and return stripped stdout. Raises on non-zero
    when ``check=True``; returns "" on non-zero when ``check=False``."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=check,
        )
        return proc.stdout.strip()
    except subprocess.CalledProcessError:
        if check:
            raise
        return ""


def _added_or_modified_files(repo: Path, base: str) -> list[str]:
    """Return paths added or modified vs ``base`` (e.g. ``origin/main``).

    Falls back to all tracked files if the base ref is missing — this lets
    the tool still produce useful output on a fresh checkout that has no
    diff context (it will be more aggressive but never silently wrong).
    """
    out = _git(repo, "diff", "--name-only", "--diff-filter=AM", f"{base}...HEAD",
               check=False)
    if not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _added_files(repo: Path, base: str) -> list[str]:
    """Return only added (status=A) files vs ``base``."""
    out = _git(repo, "diff", "--name-only", "--diff-filter=A", f"{base}...HEAD",
               check=False)
    if not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _file_text(repo: Path, rel: str) -> str:
    p = repo / rel
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---- check #1: fixture_path ------------------------------------------------


_PATTERNS_FIXTURES_RE = re.compile(r"(^|/)patterns/fixtures/")


def check_fixture_path(repo: Path, base: str) -> CheckResult:
    t0 = time.monotonic()
    files = _added_or_modified_files(repo, base)
    sol = [f for f in files if f.endswith(".sol")]
    bad = [f for f in sol if _PATTERNS_FIXTURES_RE.search(f)]
    elapsed = int((time.monotonic() - t0) * 1000)
    if bad:
        return CheckResult(
            check="fixture_path",
            status=FAIL,
            evidence=[
                "Solidity fixtures must live under `detectors/test_fixtures/` "
                "(canonical). `patterns/fixtures/` is matched by the loader's "
                "_VENDORED_OR_TEST_SUBSTRINGS skip-list and silently dropped.",
                *[f"  bad: {p}" for p in bad],
            ],
            elapsed_ms=elapsed,
        )
    return CheckResult(
        check="fixture_path",
        status=PASS,
        evidence=[f"scanned {len(sol)} added/modified .sol files; 0 under patterns/fixtures/"],
        elapsed_ms=elapsed,
    )


# ---- check #2: fixture_comment_leak ----------------------------------------

# These trigger words appear in fixture *comments* and leak into
# source-mapping content that the predicate engine searches.  Foot-gun #2 in
# the memory file enumerates: VULN, CLEAN, BUG, missing, plus generic
# predicate-keywords like revert, require, external.  The first set is
# fixture-only convention chatter; the second set is risky because real
# fixtures legitimately contain those tokens in code.  We only flag the
# first set, scoped to comment lines, to keep false positives near zero.

_FIXTURE_COMMENT_TRIGGERS = (
    re.compile(r"//\s*VULN\b", re.IGNORECASE),
    re.compile(r"//\s*CLEAN\b", re.IGNORECASE),
    re.compile(r"//\s*BUG\b", re.IGNORECASE),
    re.compile(r"//\s*FIXME\b", re.IGNORECASE),
    re.compile(r"//\s*missing\b", re.IGNORECASE),
)

_FIXTURE_PATH_RE = re.compile(r"(^|/)test_fixtures/")


def check_fixture_comment_leak(repo: Path, base: str) -> CheckResult:
    t0 = time.monotonic()
    files = _added_or_modified_files(repo, base)
    targets = [f for f in files if f.endswith(".sol") and _FIXTURE_PATH_RE.search(f)]
    bad: list[str] = []
    for rel in targets:
        text = _file_text(repo, rel)
        for ln_no, line in enumerate(text.splitlines(), 1):
            for rx in _FIXTURE_COMMENT_TRIGGERS:
                m = rx.search(line)
                if m:
                    bad.append(f"  {rel}:{ln_no}: {m.group(0).strip()!r}")
                    break  # one report per line is enough
    elapsed = int((time.monotonic() - t0) * 1000)
    if bad:
        return CheckResult(
            check="fixture_comment_leak",
            status=FAIL,
            evidence=[
                "Fixture comments leak into the predicate engine's "
                "source-mapping content. Avoid trigger words in comments "
                "(// VULN, // CLEAN, // BUG, // FIXME, // missing).",
                *bad,
            ],
            elapsed_ms=elapsed,
        )
    return CheckResult(
        check="fixture_comment_leak",
        status=PASS,
        evidence=[f"scanned {len(targets)} fixture .sol files; 0 trigger-word comments"],
        elapsed_ms=elapsed,
    )


# ---- check #6: standalone_md -----------------------------------------------

# Allowlist of dirs where new .md files are still acceptable. Matched as
# path *prefixes* on the repo-relative path. Anything outside this set is
# flagged on add — Codex owns standalone docs.
_MD_ALLOWLIST_PREFIXES = (
    "case_study/",         # case_study/* are user-blessed engagement notes
    "engagements/",        # engagement workspaces own their own docs
    "audits/",
    "submissions/",
    "agent_briefs/",       # per-task briefs, not standalone docs
    "agent_outputs/",
    "patches/",            # PR review patch markdown
    ".github/",            # PR templates etc
    "checklists/",         # pre-existing checklist set
    "templates/",          # pre-existing template set
    "tools/tests/fixtures/", # test-input fixtures, including markdown cases
)

# Exact canonical-doc exceptions. Keep this tiny: do not add "docs/" as a
# prefix, or the standalone-doc guard stops catching accidental doc sprawl.
_MD_ALLOWLIST_EXACT = (
    "docs/ROADMAP_10_OF_10_V4.md",
    "docs/DOCS_INDEX.md",
    # Polymarket V4-tooling validation campaign deliverables (2026-04-26).
    # User-blessed: V5 / 30-of-10 input for Codex roadmap. See PR
    # "fix(dispatch): kimi OAuth fallback + polymarket V4 campaign report".
    "docs/CAMPAIGN_POLYMARKET_2026-04-26.md",
    "docs/CAMPAIGN_POLYMARKET_2026-04-26_findings.md",
    # V5 capability-gaps inventory from 2026-04-26 session (45 gaps, 7 classes).
    # User-blessed for Codex review. See PR
    # "docs(v5): comprehensive capability gaps from 2026-04-26 session".
    "docs/V5_CAPABILITY_GAPS_2026-04-26.md",
    # Pattern-hits mining round R105 (2026-04-26). Cross-workspace mining
    # over 7 audit workspaces (centrifuge-v3, thegraph, kiln-v1, monetrix,
    # polymarket, morpho, base-azul, snowbridge — k2 missing). Negative
    # result: 0 truly novel patterns shipped after Kimi+Minimax filter and
    # M14-trap library cross-check. User-blessed: input for Codex review of
    # library-coverage thesis (the 1364-entry library appears mature).
    "docs/MINING_PATTERN_HITS_2026-04-26.md",
    # Session retrospective (post-completion, dated, no forward-looking claims).
    "docs/SESSION_STATUS_2026-04-26.md",
    # Bug-hunt PR #263 deep verification — both NEW-CANDIDATEs rejected
    # via PoC + duplicate-check. Reproducible PoC artifact at
    # ~/audits/kiln-v1/poc-tests/test/ELFD_ReentrancyPoC.t.sol.
    "docs/BUG_HUNT_263_VERIFICATION_2026-04-26.md",
    # Pattern-DSL authoring gotchas referenced by SOURCE_MINING_RUNBOOK.md.
    # Foot-gun #16 mirror: real predicate-engine fixes from 2026-04-26 mining.
    "docs/PATTERN_DSL_GOTCHAS.md",
    # Strategic-LLM policy gate (V5-P0-22 / Gap 42). Operator-policy doc
    # cited by tools/llm-dispatch.py refusal output and by
    # docs/LLM_DELEGATION_MATRIX.md. User-blessed in V5 P0 wave-1 plan.
    "docs/STRATEGIC_LLM_POLICY.md",
    # V5 P0 Codex execution plan + tracker — authored by Codex on the
    # codex/v5-p0-claude-execution-plan branch, inherited by the wave-1
    # implementation PRs. User-blessed.
    "docs/V5_P0_CLAUDE_EXECUTION_PLAN_2026-04-27.md",
    "docs/V5_P0_FOLLOWUPS.md",
    "docs/FOREVER_LOOPS_DOCTRINE.md",
    # Library hygiene triage — fixture-less patterns + 3-orphan resolution
    # surfaced by PR #283's 9th check + PR #286 report. User-blessed.
    "docs/LIBRARY_FIXTURE_TRIAGE_2026-04-27.md",
    # GitHub surface cleanup and operator handoff docs (2026-05-02).
    # User-blessed highest-priority cleanup loop: fresh clones should expose a
    # compact front door, archived provenance, and a Claude-readable full
    # known-limitations burndown without keeping volatile root artifacts live.
    "docs/CLAUDE_TAKEOVER_BURNDOWN.md",
    "docs/archive/capability-loop-evidence-2026-05-02/README.md",
    "docs/cleanup/DOC_FRONT_DOOR_SIMPLIFICATION_2026-05-02.md",
    "docs/cleanup/ROOT_ARTIFACT_RETENTION_2026-05-02.md",
    "docs/cleanup/ROOT_CLEANUP_IMPLEMENTATION_2026-05-02.md",
)


def check_standalone_md(repo: Path, base: str) -> CheckResult:
    t0 = time.monotonic()
    added = _added_files(repo, base)
    md_added = [f for f in added if f.endswith(".md")]
    bad: list[str] = []
    for rel in md_added:
        if rel in _MD_ALLOWLIST_EXACT:
            continue
        if any(rel.startswith(prefix) for prefix in _MD_ALLOWLIST_PREFIXES):
            continue
        bad.append(rel)
    elapsed = int((time.monotonic() - t0) * 1000)
    if bad:
        return CheckResult(
            check="standalone_md",
            status=FAIL,
            evidence=[
                "Codex owns standalone .md docs (foot-gun #6). New top-level "
                ".md files are forbidden; put rationale in the PR body and "
                "the .py docstring instead. Editing existing .md files is "
                "fine. Allowlist prefixes: " + ", ".join(_MD_ALLOWLIST_PREFIXES),
                *[f"  new: {p}" for p in bad],
            ],
            elapsed_ms=elapsed,
        )
    return CheckResult(
        check="standalone_md",
        status=PASS,
        evidence=[f"scanned {len(md_added)} added .md files; 0 outside allowlist"],
        elapsed_ms=elapsed,
    )


# ---- check #7: tier_a_promotion --------------------------------------------

_TIER_A_RE = re.compile(r"^\+\s*tier:\s*A\s*$", re.MULTILINE)


def check_tier_a_promotion(repo: Path, base: str) -> CheckResult:
    """Look at the diff for ``detectors/_tier_registry.yaml``.

    For each added line ``+ tier: A``, we inspect the surrounding hunk and
    require that the same hunk contains ``corpus_noise_count``.  The check
    is intentionally simple: it doesn't parse YAML semantics; it just makes
    sure the noise-probe field shows up alongside the promotion.  This
    catches the "Tier A without baseline noise probe" foot-gun without
    needing a full YAML diff parser.
    """
    t0 = time.monotonic()
    target = "detectors/_tier_registry.yaml"
    diff = _git(repo, "diff", f"{base}...HEAD", "--", target, check=False)
    elapsed_init = int((time.monotonic() - t0) * 1000)
    if not diff:
        return CheckResult(
            check="tier_a_promotion",
            status=SKIP,
            evidence=[f"no diff in {target} vs {base}"],
            elapsed_ms=elapsed_init,
        )
    # Split into hunks (each "@@" introduces a new hunk).
    hunks = re.split(r"^@@.*?@@", diff, flags=re.MULTILINE)
    bad: list[str] = []
    for idx, hunk in enumerate(hunks):
        a_matches = list(_TIER_A_RE.finditer(hunk))
        if not a_matches:
            continue
        # Require corpus_noise_count to appear *added* (+ prefix) in the
        # same hunk as the tier: A line.  We don't try to scope to the
        # specific entry — if a hunk promotes one detector to A, the noise
        # count for that detector should be visible too.
        if not re.search(r"^\+\s*corpus_noise_count:", hunk, re.MULTILINE):
            for m in a_matches:
                bad.append(f"  hunk #{idx}: '{m.group(0).strip()}' without "
                           f"'+ corpus_noise_count:' in same hunk")
    elapsed = int((time.monotonic() - t0) * 1000)
    if bad:
        return CheckResult(
            check="tier_a_promotion",
            status=FAIL,
            evidence=[
                "Tier-A promotion without baseline noise probe (foot-gun #7). "
                "Tier A means default-on, <=1 noise on baseline corpus. "
                "Either add a corpus_noise_count: <int> field in the same "
                "hunk, or hold the detector at Tier B/E pending the noise "
                "probe.",
                *bad,
            ],
            elapsed_ms=elapsed,
        )
    return CheckResult(
        check="tier_a_promotion",
        status=PASS,
        evidence=[f"checked {len(hunks)} hunks in {target}; all Tier-A promotions "
                  f"carry corpus_noise_count"],
        elapsed_ms=elapsed,
    )


# ---- check #9: gh_api_placeholder ------------------------------------------

# Old colon-style placeholders that gh api does NOT expand.  We look for
# `gh api ... :owner` or `:repo` patterns; the conservative regex requires
# the literal token `gh api` somewhere on the line before the placeholder
# so that doc-only mentions of `:owner` (e.g. in commit-message text)
# don't false-positive.
_GH_API_BAD_RE = re.compile(r"\bgh\s+api\b[^\n]*?repos/:(?:owner|org)\b")


_PREFLIGHT_ALLOW_RE = re.compile(r"preflight-allow:\s*gh_api_placeholder")


def check_gh_api_placeholder(repo: Path, base: str) -> CheckResult:
    t0 = time.monotonic()
    files = _added_or_modified_files(repo, base)
    targets = [f for f in files if f.endswith((".sh", ".bash", ".zsh", ".py"))]
    bad: list[str] = []
    for rel in targets:
        text = _file_text(repo, rel)
        for ln_no, line in enumerate(text.splitlines(), 1):
            if _GH_API_BAD_RE.search(line) and not _PREFLIGHT_ALLOW_RE.search(line):
                bad.append(f"  {rel}:{ln_no}: {line.strip()[:120]}")
    elapsed = int((time.monotonic() - t0) * 1000)
    if bad:
        return CheckResult(
            check="gh_api_placeholder",
            status=FAIL,
            evidence=[
                "`gh api` does NOT expand `:owner/:repo` (old-style colon "
                "placeholders). Use `{owner}/{repo}` (curly braces) or "
                "derive owner/repo from `git remote get-url origin` and "
                "interpolate explicitly. (foot-gun #9)",
                *bad,
            ],
            elapsed_ms=elapsed,
        )
    return CheckResult(
        check="gh_api_placeholder",
        status=PASS,
        evidence=[f"scanned {len(targets)} added/modified shell+py files; 0 colon placeholders"],
        elapsed_ms=elapsed,
    )


# ---- check #10: verified_push ----------------------------------------------

_REMOTE_URL_RES = (
    # https://github.com/<owner>/<repo>(.git)?
    re.compile(r"https?://github\.com/(?P<o>[^/]+)/(?P<r>[^/]+?)(?:\.git)?/?$"),
    # git@github.com:<owner>/<repo>(.git)?
    re.compile(r"git@github\.com:(?P<o>[^/]+)/(?P<r>[^/]+?)(?:\.git)?$"),
    # ssh://git@github.com[:/]<owner>/<repo>(.git)?
    re.compile(r"ssh://git@github\.com[:/](?P<o>[^/]+)/(?P<r>[^/]+?)(?:\.git)?$"),
)


def _resolve_owner_repo(repo: Path) -> tuple[str, str] | None:
    url = _git(repo, "remote", "get-url", "origin", check=False)
    if not url:
        return None
    for rx in _REMOTE_URL_RES:
        m = rx.match(url.strip())
        if m:
            return m.group("o"), m.group("r")
    return None


def check_verified_push(
    repo: Path,
    branch: str | None,
    no_network: bool,
) -> CheckResult:
    """Compare LOCAL HEAD vs REMOTE HEAD for the current branch."""
    t0 = time.monotonic()
    if no_network:
        return CheckResult(
            check="verified_push",
            status=SKIP,
            evidence=["--no-network passed; skipping remote SHA fetch"],
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    if shutil.which("gh") is None:
        return CheckResult(
            check="verified_push",
            status=SKIP,
            evidence=["`gh` not on PATH; cannot fetch remote SHA"],
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    if not branch:
        # Detect HEAD's branch.
        branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD", check=False)
        if not branch or branch == "HEAD":
            return CheckResult(
                check="verified_push",
                status=SKIP,
                evidence=["detached HEAD; pass --branch to verify"],
                elapsed_ms=int((time.monotonic() - t0) * 1000),
            )
    or_ = _resolve_owner_repo(repo)
    if not or_:
        return CheckResult(
            check="verified_push",
            status=SKIP,
            evidence=["could not parse owner/repo from `git remote get-url origin`"],
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    owner, name = or_
    local_sha = _git(repo, "rev-parse", "HEAD", check=False)
    if not local_sha:
        return CheckResult(
            check="verified_push",
            status=FAIL,
            evidence=["could not resolve local HEAD"],
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    api_path = f"repos/{owner}/{name}/git/refs/heads/{branch}"
    try:
        proc = subprocess.run(
            ["gh", "api", api_path, "--jq", ".object.sha"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            check="verified_push",
            status=SKIP,
            evidence=["`gh api` timed out after 10s"],
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )
    elapsed = int((time.monotonic() - t0) * 1000)
    if proc.returncode != 0:
        # Branch may not exist on remote yet — that's a FAIL for "verified".
        # V5-P0-19 explanation paragraph: make the consequences impossible
        # to glance past in agent output.
        return CheckResult(
            check="verified_push",
            status=FAIL,
            evidence=[
                "BLOCKER (foot-gun #10 / V5-P0-19): the branch is not "
                "present on the remote — gh api could not resolve it. "
                "Opening a PR now is the canonical 'I pushed but didn't' "
                "silent failure: the create either errors, or — worse — "
                "races a later push and pins a stale commit so reviewers "
                "see an SHA the agent never intended.",
                f"`gh api {api_path}` returned rc={proc.returncode}",
                f"stderr: {proc.stderr.strip()[:200]}",
                f"local HEAD: {local_sha}",
                f"suggested fix: git push -u origin {branch}",
            ],
            elapsed_ms=elapsed,
        )
    remote_sha = proc.stdout.strip()
    if remote_sha != local_sha:
        return CheckResult(
            check="verified_push",
            status=FAIL,
            evidence=[
                "BLOCKER (foot-gun #10 / V5-P0-19): LOCAL HEAD does not "
                "match REMOTE HEAD on this branch. Reviewers will see a "
                "different SHA than the agent is reasoning about; "
                "force-pushes after PR open can invalidate prior "
                "approvals. Push the latest commit before opening the "
                "PR; if a force-push is needed, prefer "
                "--force-with-lease so a remote update you missed is "
                "detected instead of silently overwritten.",
                f"LOCAL  = {local_sha}",
                f"REMOTE = {remote_sha}",
                f"branch = {branch} on {owner}/{name}",
                f"suggested fix: git push origin {branch}",
            ],
            elapsed_ms=elapsed,
        )
    return CheckResult(
        check="verified_push",
        status=PASS,
        evidence=[
            f"LOCAL = REMOTE = {local_sha}",
            f"branch = {branch} on {owner}/{name}",
        ],
        elapsed_ms=elapsed,
    )


# ---- driver ----------------------------------------------------------------


_ALL_CHECKS = {
    "fixture_path": lambda repo, args: check_fixture_path(repo, args.base),
    "fixture_comment_leak": lambda repo, args: check_fixture_comment_leak(repo, args.base),
    "standalone_md": lambda repo, args: check_standalone_md(repo, args.base),
    "tier_a_promotion": lambda repo, args: check_tier_a_promotion(repo, args.base),
    "gh_api_placeholder": lambda repo, args: check_gh_api_placeholder(repo, args.base),
    "verified_push": lambda repo, args: check_verified_push(repo, args.branch, args.no_network),
}


def _format_human(results: Iterable[CheckResult]) -> str:
    lines = []
    width = max((len(r.check) for r in results), default=20)
    for r in results:
        marker = {PASS: "[PASS]", FAIL: "[FAIL]", SKIP: "[SKIP]"}[r.status]
        lines.append(f"{marker} {r.check:<{width}}  ({r.elapsed_ms}ms)")
        if r.status != PASS or r.evidence:
            for ev in r.evidence:
                lines.append(f"        {ev}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Mechanical foot-gun guardrails before agent-PR push.",
    )
    p.add_argument("--repo", type=Path, default=Path.cwd(),
                   help="Repository root (default: cwd)")
    p.add_argument("--base", default="origin/main",
                   help="Base ref for diff comparisons (default: origin/main)")
    p.add_argument("--branch", default=None,
                   help="Branch name for verified_push (default: detect HEAD)")
    p.add_argument("--no-network", action="store_true",
                   help="Skip network-touching checks (verified_push)")
    p.add_argument("--check", action="append", default=None,
                   help="Run only the named check; repeatable. "
                        f"Available: {', '.join(_ALL_CHECKS)}")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON aggregate instead of human-readable output")
    args = p.parse_args(argv)

    if not (args.repo / ".git").exists():
        # Worktrees have a .git file (not dir); accept either.
        if not (args.repo / ".git").is_file():
            print(f"[agent-preflight] error: {args.repo} is not a git repo",
                  file=sys.stderr)
            return 2

    selected = list(_ALL_CHECKS) if not args.check else args.check
    unknown = [c for c in selected if c not in _ALL_CHECKS]
    if unknown:
        print(f"[agent-preflight] unknown check(s): {unknown}", file=sys.stderr)
        return 2

    results: list[CheckResult] = []
    for name in selected:
        fn = _ALL_CHECKS[name]
        try:
            r = fn(args.repo, args)
        except Exception as exc:  # don't let a single check crash the run
            r = CheckResult(
                check=name,
                status=FAIL,
                evidence=[f"unhandled exception: {type(exc).__name__}: {exc}"],
            )
        results.append(r)

    if args.json:
        print(json.dumps({
            "results": [r.to_dict() for r in results],
            "fail_count": sum(1 for r in results if r.status == FAIL),
            "skip_count": sum(1 for r in results if r.status == SKIP),
            "pass_count": sum(1 for r in results if r.status == PASS),
        }, indent=2))
    else:
        print(_format_human(results))
        n_fail = sum(1 for r in results if r.status == FAIL)
        n_skip = sum(1 for r in results if r.status == SKIP)
        n_pass = sum(1 for r in results if r.status == PASS)
        print(f"\n{n_pass} pass, {n_fail} fail, {n_skip} skip")

    return 1 if any(r.status == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
