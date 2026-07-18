#!/usr/bin/env python3
"""obsidian-vault-sync.py — Incremental refresh of the Obsidian vault.

Compares source mtimes against the last sync stamp (.last_sync.json) and only
regenerates sections whose canonical sources have changed.

Usage:
    python3 tools/obsidian-vault-sync.py [--vault-dir <path>] [--force]
    python3 tools/obsidian-vault-sync.py --status    # show staleness only

Section → canonical sources mapping:
  patterns     → reference/patterns.dsl* (any .yaml newer than stamp)
  detectors    → detectors/_tier_registry.yaml
  findings     → ~/audits/*/submissions/**/*.md
  workspaces   → ~/audits/* (directory mtime)
  mining       → reference/patterns.dsl* + reference/contest_cache/
  limitations  → docs/KNOWN_LIMITATIONS.md + KNOWN_LIMITATIONS_BURNDOWN_MAP.json
  tasks        → docs/CONTINUATION_PLAN.md
  agent-memory → ~/.claude/.../memory/MEMORY.md + linked subfiles
  claude-memory → ~/.claude/.../memory/*.md
  codex-memory → ~/.codex/rules/default.rules + ~/.codex/session_index.jsonl
  tools-api    → tools/*.py (docstrings drive per-tool notes)
  harness-phases → docs/CAPABILITY_V3_ITER_*_RESULTS.md
  routines     → ~/.claude/scheduled-tasks/ (deep-crawler)
  make-targets → Makefile (deep-crawler)
  errors       → /private/tmp/auditooor-inventory/*.log (deep-crawler)
  commits      → git log (deep-crawler, git-backed; throttled - see below)
  prs          → gh pr list (deep-crawler, git-backed; throttled - see below)

W6-3 / Gap G1: the 5 deep-crawler sections above are registered so
`make docs-check` / `make vault-sync` proactively refresh them, but
`commits` and `prs` shell out to git/gh (network + latency cost). To keep
the default sync fast, those two are GIT-BACKED sections and are only
treated as stale once their last refresh exceeds GIT_SECTION_STALE_HOURS
(default 24h) OR the operator passes --include-git-sections. The cheap
filesystem-backed sections (routines / make-targets / errors) refresh on
every run like any other section.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
AUDITS_ROOT = Path.home() / "audits"
MEMORY_PATH = (
    Path.home()
    / ".claude"
    / "projects"
    / "-Users-wolf-Downloads-GTO-WEBSITE-proper-installation-polymarket-clob2"
    / "memory"
    / "MEMORY.md"
)
CLAUDE_MEMORY_DIR = MEMORY_PATH.parent
MEMORY_PATH_ENV_VARS = (
    "AUDITOOOR_CLAUDE_MEMORY_PATHS",
    "CLAUDE_MEMORY_PATHS",
    "MEMORY_PATHS",
)
_CONFIGURED_MEMORY_PATHS: list[Path] | None = None
CODEX_RULES_PATH = Path.home() / ".codex" / "rules" / "default.rules"
CODEX_SESSION_INDEX_PATH = Path.home() / ".codex" / "session_index.jsonl"
TOOLS_DIR = REPO_ROOT / "tools"
# W6-3 / Gap G1: source dir for the `routines` deep-crawler section. Mirrors
# memory-deep-crawler.py SCHEDULED_TASKS_DIR. Resolved dynamically (home dir)
# the same way claude-memory / codex-memory are.
SCHEDULED_TASKS_DIR = Path.home() / ".claude" / "scheduled-tasks"

# Map section name → list of glob patterns (relative to REPO_ROOT unless absolute)
SECTION_SOURCES: dict[str, list[str]] = {
    "patterns": [
        "reference/patterns.dsl/**/*.yaml",
        "reference/patterns.dsl.r*/**/*.yaml",
    ],
    "detectors": [
        "detectors/_tier_registry.yaml",
    ],
    "findings": [
        str(AUDITS_ROOT / "*/submissions/**/*.md"),
        str(AUDITS_ROOT / "*/submissions/*.md"),
    ],
    "workspaces": [
        str(AUDITS_ROOT / "*/.auditooor-state.yaml"),
        str(AUDITS_ROOT / "*/.auditooor/SUBMISSIONS.md"),
    ],
    "mining": [
        "reference/patterns.dsl.r*/**/*.yaml",
        "reference/contest_cache/**/*.json",
        "reference/corpus_mined/*.md",
        # r36-rebuttal: lane mimo-corpus-mining-wave-2026-05-28
        # MIMO learning-loop derived corpora (read via vault_mimo_corpus_intelligence)
        "audit/corpus_tags/derived/mimo_observed_yield.json",
        "audit/corpus_tags/derived/hacker_q_signal_scores.jsonl",
        "audit/corpus_tags/derived/chain_candidates_from_mimo.jsonl",
        "audit/corpus_tags/derived/exploit_predicates_from_mimo_maybes.jsonl",
        "audit/corpus_tags/derived/mimo_hallucination_classification.jsonl",
        "audit/corpus_tags/derived/workspace_oos_extension_*.json",
        "audit/corpus_tags/derived/exploit_queue_from_triage_survivors.jsonl",
        "audit/corpus_tags/derived/exploit_predicates_defense_found_from_triage.jsonl",
        "reports/yield_per_question_per_workspace.json",
        # question_target_fit.jsonl (per-question vs target-surface fit / language exclusions)
        "audit/corpus_tags/derived/question_target_fit.jsonl",
        # r36-rebuttal: lane mega-learn-2026-05-28
        # brain_prime_priors_<ws>.json (consumed by brain-prime.py Phase E.1)
        "audit/corpus_tags/derived/brain_prime_priors_*.json",
        # canonical chain_candidates.jsonl (mimo-mined records appended here)
        "audit/corpus_tags/derived/chain_candidates.jsonl",
        # r36-rebuttal: lane learning-closeout-wiring
        # Cross-workspace agent-learning-ledger roll-up (tools/learning-ledger-aggregate.py).
        # Previously the per-workspace <ws>/.auditooor/agent_artifacts/learning_ledger.jsonl
        # files were written locally and never lifted; vault_agent_learning_context only
        # reads ONE workspace. This aggregated corpus makes the ~18k learning rows usable
        # in cross-workspace recall (vault_corpus_search / brain-prime / reweighter).
        "audit/corpus_tags/derived/agent_learning_ledger_aggregated.jsonl",
    ],
    "limitations": [
        "docs/KNOWN_LIMITATIONS.md",
        "docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
    ],
    "tasks": [
        "docs/CONTINUATION_PLAN.md",
    ],
    "agent-memory": [],
    "claude-memory": [],
    "codex-memory": [],
    "tools-api": [],
    "harness-phases": [
        "docs/CAPABILITY_V3_ITER_*_RESULTS.md",
    ],
    # PR #658 P0-3: vault-indexed prior_audits/ for cheap originality recall.
    # Sources are dynamic (one glob per workspace prior_audits/ tree).
    "external-audits-extracts": [],
    # W4.12: cross-session memory carry. tools/audit/session-memory-carry.py
    # writes <ws>/.auditooor/session_memory_carry.json at session end; the
    # next vault_resume_context reads session-memory/<slug>.md. Staleness is
    # detected against the workspace artifact; the carry tool itself writes
    # the vault note directly (no obsidian-vault-emit.py section needed).
    "session-memory": [
        str(AUDITS_ROOT / "*/.auditooor/session_memory_carry.json"),
        # per-ws hunt_failure_breakdown.json (why prior hunts produced no finding)
        str(AUDITS_ROOT / "*/.auditooor/hunt_failure_breakdown.json"),
    ],
    # W6-3 / Gap G1: the remaining 5 memory-deep-crawler.py ALL_SECTIONS
    # were previously absent from SECTION_SOURCES, so the sync orchestrator
    # never proactively refreshed them. Registered below.
    #
    # routines / make-targets / errors are filesystem-backed (cheap stat()),
    # so they get ordinary globs and are detected via _max_mtime_for_globs.
    "routines": [],
    "make-targets": [
        "Makefile",
    ],
    "errors": [
        "/private/tmp/auditooor-inventory/*.log",
    ],
    # commits / prs are git-backed: refreshing them shells out to git / gh
    # (network + latency). Their globs are intentionally empty so the cheap
    # mtime scan never marks them stale; staleness is decided instead by
    # _git_section_is_stale() against the GIT_SECTION_STALE_HOURS window or
    # the explicit --include-git-sections flag. This keeps the default
    # `make docs-check` / `make vault-sync` fast.
    "commits": [],
    "prs": [],
}

DEEP_CRAWLER_SECTIONS = {
    "workspaces", "claude-memory", "codex-memory", "tools-api",
    # W6-3 / Gap G1: the 5 newly-registered deep-crawler sections.
    "routines", "make-targets", "errors", "commits", "prs",
}
# W6-3 / Gap G1: sections whose refresh shells out to git / gh. These are
# throttled - only marked stale once the last refresh is older than
# GIT_SECTION_STALE_HOURS, or when --include-git-sections is passed. This is
# what keeps the default sync (and therefore `make docs-check`) fast.
GIT_BACKED_SECTIONS = {"commits", "prs"}
# Hours a git-backed section may go un-refreshed before the sync treats it
# as stale on a default (non-flagged) run.
GIT_SECTION_STALE_HOURS = 24.0
# Sections handled by tools/external-audits-extract-emitter.py instead of
# memory-deep-crawler.py / obsidian-vault-emit.py.
EXTERNAL_AUDITS_SECTIONS = {"external-audits-extracts"}
# W4.12: section handled by tools/audit/session-memory-carry.py — re-runs the
# carry tool per workspace so the vault session-memory/<slug>.md note is fresh.
SESSION_MEMORY_SECTIONS = {"session-memory"}


def _now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def _iso_to_ts(iso: str) -> float:
    """Parse an ISO-8601 Z timestamp to a Unix timestamp float."""
    try:
        return _dt.datetime.strptime(iso, "%Y-%m-%dT%H:%MZ").replace(
            tzinfo=_dt.timezone.utc
        ).timestamp()
    except ValueError:
        return 0.0


def _max_mtime_for_globs(globs: list[str]) -> float:
    max_mtime = 0.0
    import glob as _glob
    for pattern in globs:
        if pattern.startswith("/"):
            matches = _glob.glob(pattern, recursive=True)
        else:
            matches = _glob.glob(str(REPO_ROOT / pattern), recursive=True)
        for m in matches:
            try:
                mtime = Path(m).stat().st_mtime
                if mtime > max_mtime:
                    max_mtime = mtime
            except OSError:
                pass
    return max_mtime


def _split_memory_path_value(value: str) -> list[str]:
    """Split an env/CLI path-list value into non-empty path strings."""
    parts = []
    for line in value.splitlines():
        parts.extend(line.split(os.pathsep))
    return [part.strip() for part in parts if part.strip()]


def _dedupe_paths(paths: Sequence[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        try:
            key = str(path.expanduser().resolve(strict=False))
        except OSError:
            key = str(path.expanduser().absolute())
        if key in seen:
            continue
        seen.add(key)
        result.append(Path(key))
    return result


def _normalize_memory_path(path: Path) -> Path:
    path = path.expanduser()
    if path.name != "MEMORY.md":
        path = path / "MEMORY.md"
    try:
        return path.resolve(strict=False)
    except OSError:
        return path.absolute()


def _parse_memory_paths(values: Sequence[str | Path]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        if isinstance(value, Path):
            paths.append(_normalize_memory_path(value))
            continue
        for part in _split_memory_path_value(value):
            paths.append(_normalize_memory_path(Path(part)))
    return _dedupe_paths(paths)


def _memory_paths_from_env(environ: dict[str, str] | None = None) -> list[Path]:
    if environ is None:
        environ = os.environ
    for name in MEMORY_PATH_ENV_VARS:
        raw = environ.get(name)
        if raw:
            return _parse_memory_paths([raw])
    return []


def _configured_memory_paths(
    cli_memory_paths: Sequence[str | Path] | None = None,
    environ: dict[str, str] | None = None,
) -> list[Path]:
    paths: list[Path] = []
    paths.extend(_memory_paths_from_env(environ))
    if cli_memory_paths:
        paths.extend(_parse_memory_paths(cli_memory_paths))
    if not paths:
        paths = [_normalize_memory_path(MEMORY_PATH)]
    return _dedupe_paths(paths)


def _active_memory_paths() -> list[Path]:
    if _CONFIGURED_MEMORY_PATHS is not None:
        return _CONFIGURED_MEMORY_PATHS
    return _configured_memory_paths()


def _claude_memory_dirs(memory_paths: Sequence[Path] | None = None) -> list[Path]:
    if memory_paths is None and _CONFIGURED_MEMORY_PATHS is None:
        # Preserve legacy test/operator overrides of CLAUDE_MEMORY_DIR when no
        # multi-path config has been supplied.
        if CLAUDE_MEMORY_DIR != MEMORY_PATH.parent:
            return _dedupe_paths([CLAUDE_MEMORY_DIR])
    if memory_paths is None:
        memory_paths = _active_memory_paths()
    return _dedupe_paths([path.parent for path in memory_paths])


def _agent_memory_source_paths(
    memory_paths: Path | Sequence[Path] | None = None,
) -> list[Path]:
    """Return MEMORY.md plus linked subfiles mirrored by the emitter."""
    if memory_paths is None:
        memory_paths = _active_memory_paths()
    elif isinstance(memory_paths, Path):
        memory_paths = [_normalize_memory_path(memory_paths)]
    else:
        memory_paths = _parse_memory_paths(memory_paths)

    paths: list[Path] = []
    for memory_path in memory_paths:
        paths.extend(_agent_memory_source_paths_for_one(memory_path))
    return _dedupe_paths(paths)


def _agent_memory_source_paths_for_one(memory_path: Path) -> list[Path]:
    if not memory_path.exists():
        return []

    paths = [memory_path]
    try:
        memory_text = memory_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return paths

    entry_pattern = re.compile(r"- \[([^\]]+)\]\(([^)]+)\)\s*[—-]\s*(.+)")
    for _title, fname, _desc in entry_pattern.findall(memory_text):
        paths.append(memory_path.parent / fname)
    return paths


def _section_sources(section: str) -> list[str]:
    if section == "agent-memory":
        return [str(path) for path in _agent_memory_source_paths()]
    if section == "claude-memory":
        sources: list[Path] = []
        for memory_dir in _claude_memory_dirs():
            sources.extend([memory_dir, memory_dir / "*.md"])
        return [str(path) for path in _dedupe_paths(sources)]
    if section == "codex-memory":
        return [
            str(CODEX_RULES_PATH),
            str(CODEX_SESSION_INDEX_PATH),
        ]
    if section == "tools-api":
        return [
            str(TOOLS_DIR / "*.py"),
        ]
    if section == "routines":
        # W6-3 / Gap G1: scheduled-task SKILL.md files under ~/.claude/.
        return [
            str(SCHEDULED_TASKS_DIR),
            str(SCHEDULED_TASKS_DIR / "**" / "*.md"),
        ]
    if section == "external-audits-extracts":
        # Walk ~/audits/<ws>/prior_audits/* for staleness detection.
        return [
            str(AUDITS_ROOT / "*/prior_audits/*.md"),
            str(AUDITS_ROOT / "*/prior_audits/*.txt"),
        ]
    return SECTION_SOURCES[section]


def _load_stamp(vault: Path) -> dict:
    stamp_path = vault / ".last_sync.json"
    if stamp_path.exists():
        try:
            return json.loads(stamp_path.read_text())
        except Exception:
            pass
    return {}


def _git_section_is_stale(
    section: str, stamp: dict, now_ts: float | None = None
) -> bool:
    """W6-3 / Gap G1: decide whether a git-backed section needs a refresh.

    Git-backed sections (`commits`, `prs`) shell out to git / gh, so they are
    NOT refreshed on every default sync. They are marked stale only once the
    time since their last refresh exceeds GIT_SECTION_STALE_HOURS. The last
    refresh time is read from the stamp's `git_section_refreshed` map (written
    by main() whenever a git-backed section is actually emitted).

    Returns True if the section is stale (overdue for a refresh).
    """
    if now_ts is None:
        now_ts = _dt.datetime.now(tz=_dt.timezone.utc).timestamp()
    refreshed = stamp.get("git_section_refreshed", {})
    last_iso = refreshed.get(section)
    if not last_iso:
        # Never refreshed through the sync path - treat as stale so the first
        # opt-in / overdue run picks it up.
        return True
    last_ts = _iso_to_ts(last_iso)
    age_hours = (now_ts - last_ts) / 3600.0
    return age_hours >= GIT_SECTION_STALE_HOURS


def _stale_sections(
    vault: Path, force: bool, include_git_sections: bool = False
) -> list[str]:
    """Return the list of sections that need a refresh.

    W6-3 / Gap G1: git-backed sections (GIT_BACKED_SECTIONS) are only included
    on a default run when they are overdue past GIT_SECTION_STALE_HOURS, or
    unconditionally when `include_git_sections` is set (the --include-git-sections
    flag) or `force` is set. This keeps the default `make docs-check` /
    `make vault-sync` fast - no git/gh shell-out unless genuinely stale.
    """
    stamp = _load_stamp(vault)
    last_sync_ts = _iso_to_ts(stamp.get("generated", "1970-01-01T00:00Z"))

    if force:
        return list(SECTION_SOURCES.keys())

    stale = []
    for section in SECTION_SOURCES:
        if section in GIT_BACKED_SECTIONS:
            # Throttled: not part of the cheap mtime scan. Decide via the
            # staleness window unless the operator opted in explicitly.
            if include_git_sections or _git_section_is_stale(section, stamp):
                stale.append(section)
            continue
        globs = _section_sources(section)
        max_mtime = _max_mtime_for_globs(globs)
        if max_mtime > last_sync_ts:
            stale.append(section)
    return stale


def _section_command(section: str, vault: Path) -> list[str]:
    if section in DEEP_CRAWLER_SECTIONS:
        return [
            sys.executable,
            str(REPO_ROOT / "tools" / "memory-deep-crawler.py"),
            "--vault-dir",
            str(vault),
            "--section",
            section,
        ]
    if section in EXTERNAL_AUDITS_SECTIONS:
        return [
            sys.executable,
            str(REPO_ROOT / "tools" / "external-audits-extract-emitter.py"),
            "--vault-dir",
            str(vault),
            # default --workspaces-root ~/audits walks every workspace
        ]
    if section in SESSION_MEMORY_SECTIONS:
        # Refresh every workspace's session-memory note in one batch.
        return [
            sys.executable,
            str(REPO_ROOT / "tools" / "audit" / "session-memory-carry.py"),
            "--vault-dir",
            str(vault),
            "--sync-all-workspaces",
        ]
    return [
        sys.executable,
        str(REPO_ROOT / "tools" / "obsidian-vault-emit.py"),
        "--vault-dir",
        str(vault),
        "--section",
        section,
    ]


def _run_emit(sections: list[str], vault: Path) -> int:
    """Refresh each stale section through its owning writer."""
    total_new = 0
    for section in sections:
        cmd = _section_command(section, vault)
        print(f"  [sync] refreshing section: {section}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"    ERROR: {result.stderr.strip()[:200]}")
        else:
            # Parse note count from output
            import re
            m = re.search(
                r"(?:TOTAL notes|New/updated notes|Planned notes):\s+(\d+)"
                r"|(\d+)\s+new/updated\s+notes",
                result.stdout,
            )
            if m and not m.group(1) and m.group(2):
                # rewrap match to expose the count via group(1) for the
                # downstream `int(m.group(1))` call below.
                class _M:
                    def __init__(self, n: str) -> None:
                        self._n = n
                    def group(self, _i: int) -> str:
                        return self._n
                m = _M(m.group(2))  # type: ignore[assignment]
            if m:
                total_new += int(m.group(1))
            print(result.stdout.rstrip())
    return total_new


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Incremental vault sync — only refresh stale sections."
    )
    parser.add_argument(
        "--vault-dir",
        type=Path,
        default=VAULT_DEFAULT,
        help="Vault directory (default: obsidian-vault/ in repo root)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force full rebuild even if no sources changed",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show staleness status only — do not write",
    )
    parser.add_argument(
        "--include-git-sections",
        action="store_true",
        help=(
            "W6-3: also refresh the git-backed sections (commits, prs) even "
            "if they are not yet past the staleness window. Off by default so "
            "`make docs-check` / `make vault-sync` stay fast (no git/gh shell-out)."
        ),
    )
    parser.add_argument(
        "--memory-path",
        action="append",
        default=[],
        help=(
            "Claude memory MEMORY.md path or memory directory to track; repeatable. "
            f"Path lists separated by {os.pathsep!r} are also accepted here "
            f"and via {MEMORY_PATH_ENV_VARS[0]}."
        ),
    )
    args = parser.parse_args()

    global _CONFIGURED_MEMORY_PATHS
    _CONFIGURED_MEMORY_PATHS = _configured_memory_paths(args.memory_path)

    vault = args.vault_dir.resolve()
    stamp = _load_stamp(vault)
    last_sync = stamp.get("generated", "never")
    total_notes = stamp.get("total_notes", 0)

    print(f"[obsidian-vault-sync]")
    print(f"  vault:       {vault}")
    print(f"  last sync:   {last_sync}")
    print(f"  notes (last): {total_notes}")

    stale = _stale_sections(
        vault, args.force, include_git_sections=args.include_git_sections
    )

    if not stale:
        print("  All sections up to date. Nothing to sync.")
        return

    print(f"  Stale sections: {', '.join(stale)}")

    if args.status:
        print("  (--status mode: no writes)")
        return

    vault.mkdir(parents=True, exist_ok=True)
    total_new = _run_emit(stale, vault)

    # Refresh master INDEX only if full run or stale
    if set(stale) == set(SECTION_SOURCES.keys()) or args.force:
        cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "obsidian-vault-emit.py"),
            "--vault-dir", str(vault),
            "--section", "all",
        ]
        print("  [sync] final INDEX + sub-index refresh")
        subprocess.run(cmd, capture_output=False)

    # Update stamp
    new_stamp = dict(stamp)
    new_stamp["generated"] = _now()
    new_stamp["sync_stale_sections"] = stale
    # W6-3 / Gap G1: record the refresh time of each git-backed section that
    # was actually emitted this run so _git_section_is_stale() can throttle
    # the next default run.
    git_refreshed = dict(new_stamp.get("git_section_refreshed", {}))
    for section in stale:
        if section in GIT_BACKED_SECTIONS:
            git_refreshed[section] = new_stamp["generated"]
    if git_refreshed:
        new_stamp["git_section_refreshed"] = git_refreshed
    (vault / ".last_sync.json").write_text(json.dumps(new_stamp, indent=2))
    print(f"\n  Sync complete. Stamp updated.")


if __name__ == "__main__":
    main()
