#!/usr/bin/env python3
"""Rule 70 File-Tracked-In-Git verifier (Check #118).

# Rule 70: this tool emits no corpus record.
# R36: declared in .auditooor/agent_pathspec.json as LANE-218-R70-FILE-TRACKED-VERIFIER.

GENERAL RULE - applies to any lane/draft that claims a file was SHIPPED /
LANDED / CREATED / ADDED. The claim is hollow if the file is not on disk,
is on disk but untracked in git, or is staged-but-never-committed.

R70 is the sibling of R69 (callable-wiring verifier, Check #117 family).
R69 checks the MCP callable-surface side of LANDED claims; R70 checks the
file-existence + git-tracking side.

Trigger: ANY lane result, draft, or operator-facing summary that names file
paths under the auditooor tree (tools/, docs/, audit/, reports/, reference/,
obsidian-vault/, agent_outputs/, submissions/) and asserts they were shipped.

For each claimed path the tool runs four checks:
  1. file exists on disk
  2. file is git-tracked (`git ls-files <path>` returns non-empty)
  3. file is in HEAD (with --require-committed) OR staged in index
  4. file is non-empty (not a zero-byte placeholder)

Verdict vocabulary (per-path):
  tracked-and-committed             - all 4 checks PASS
  tracked-staged-not-committed      - staged in index, not in HEAD (WARN)
  tracked-modified-uncommitted      - in HEAD but working tree differs (WARN)
  untracked-on-disk                 - file exists, ls-files empty (FAIL; the
                                       LIFT-9 #194 corpus-refresh hook anchor)
  missing-from-disk                 - file does not exist (FAIL; the Codex
                                       Phase 3 false-LANDED anchor)
  tracked-but-empty                 - file exists, tracked, 0 bytes (WARN)
  error                             - input error

Overall verdict (across all paths):
  pass-all-tracked-and-committed    - every claimed path tracked-and-committed
  pass-no-paths-claimed             - --claimed-paths empty / not provided
  ok-rebuttal                       - draft carries `r70-rebuttal: <reason>`
  warn-some-uncommitted             - all on disk + tracked but at least one
                                       not yet committed (advisory)
  fail-untracked-or-missing         - at least one untracked-on-disk or
                                       missing-from-disk
  fail-strict                       - --strict promoted any non-tracked-and-
                                       committed to FAIL
  error                             - input error

Exit codes:
  0 - pass / warn-only / accepted rebuttal
  1 - Rule 70 violation
  2 - input error

Schema: auditooor.r70_file_tracked_verifier.v1

Empirical anchors (3 cases this session):
  1. LIFT-9 #194 corpus-refresh hook: tools/hooks/auditooor-corpus-change-
     refresh.sh on disk but `git ls-files` empty - hook script LANDED but
     never `git add`-ed.
  2. Codex Phase 3 takeover: vault_global_chain_template_match callable
     LANDED claim with the underlying seed module
     (tools/lib/global_chain_templates_seed.py) and JSONL
     (audit/corpus_tags/derived/global_chain_templates.jsonl) both untracked.
  3. Chain templates JSONL: claimed shipped but
     audit/corpus_tags/derived/global_chain_templates.jsonl untracked-on-disk.

Override marker: a visible bounded line `r70-rebuttal: <reason>` (<=200
chars) OR HTML-comment form `<!-- r70-rebuttal: <reason> -->`. Empty or
oversized reason is ignored; original fail verdict stands. Valid anchors:
intentional untracked working-tree artifact (build output, calibration log
excluded from VCS), file is staged for the operator's commit but lane lacks
commit permission, file lives under a `.gitignore`-d path by design.

Usage:
  python3 tools/r70-file-tracked-verifier.py --claimed-paths PATH1,PATH2
  python3 tools/r70-file-tracked-verifier.py --claimed-paths-file paths.txt
  python3 tools/r70-file-tracked-verifier.py --draft <draft.md>
  python3 tools/r70-file-tracked-verifier.py --strict --require-committed ...
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = "auditooor.r70_file_tracked_verifier.v1"
GATE = "R70-FILE-TRACKED-IN-GIT"

# Per-path verdict constants
V_TRACKED_AND_COMMITTED = "tracked-and-committed"
V_TRACKED_STAGED_NOT_COMMITTED = "tracked-staged-not-committed"
V_TRACKED_MODIFIED_UNCOMMITTED = "tracked-modified-uncommitted"
V_UNTRACKED_ON_DISK = "untracked-on-disk"
V_MISSING_FROM_DISK = "missing-from-disk"
V_TRACKED_BUT_EMPTY = "tracked-but-empty"
V_ERROR = "error"

# Overall verdict constants
OV_PASS_ALL = "pass-all-tracked-and-committed"
OV_PASS_NO_PATHS = "pass-no-paths-claimed"
OV_OK_REBUTTAL = "ok-rebuttal"
OV_WARN_UNCOMMITTED = "warn-some-uncommitted"
OV_FAIL_UNTRACKED_OR_MISSING = "fail-untracked-or-missing"
OV_FAIL_STRICT = "fail-strict"
OV_ERROR = "error"
# No-op pass: agent claimed only /tmp/ paths (or nothing persistent) - treat
# as a pass-state, not a failure. Introduced in Lane 231 (2026-05-26) to
# handle the Lane #220 anti-pattern where an agent fixed /tmp/-only artifacts.
OV_NO_OP = "no-op-no-persistent-changes"

_TMP_PREFIX = ("/tmp/", "/var/folders/", "/private/tmp/")

# Path-extraction regex for lane briefs / drafts: matches file paths under the
# canonical auditooor sub-trees. Extension whitelist keeps it bounded and
# avoids matching random sentence fragments.
# R36: extension whitelist updated under LANE-218 declared in
# .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py.
# Longer alternatives must come first because regex alternation tries
# matches in declaration order; jsonl must precede json, tsx must precede
# ts, yaml must precede yml, otherwise `foo.jsonl` extracts as `foo.json`.
PATH_LINE_RE = re.compile(
    r"\b((?:tools|docs|audit|reports|reference|obsidian-vault|agent_outputs|"
    r"submissions|patterns|detectors|skills|\.auditooor)/[^\s,;\"'`)]+"
    r"\.(?:jsonl|json|yaml|yml|tsx|ts|toml|md|py|sh|txt|sol|rs|go|cfg|ini))",
    re.IGNORECASE,
)

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r70-rebuttal\s*:\s*(?P<reason>[^>]{1,200}?)\s*-->",
    re.IGNORECASE,
)
REBUTTAL_LINE_RE = re.compile(
    r"^\s*r70-rebuttal\s*:\s*(?P<reason>.{1,200})\s*$",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _run_git(args: list[str], cwd: Path) -> tuple[int, str, str]:
    """Run a git command and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "git executable not found"
    except subprocess.TimeoutExpired:
        return 124, "", "git command timed out"


def _resolve_repo_root(start: Path) -> Path:
    """Find the git repo root containing `start` (falling back to start)."""
    rc, out, _ = _run_git(["rev-parse", "--show-toplevel"], cwd=start)
    if rc == 0 and out.strip():
        return Path(out.strip())
    return start


# ---------------------------------------------------------------------------
# Per-path classifier
# ---------------------------------------------------------------------------

def _classify_path(
    raw_path: str,
    repo_root: Path,
) -> dict:
    """Classify a single claimed path against the four R70 checks."""
    raw = raw_path.strip()
    if not raw:
        return {
            "path": raw_path,
            "abs_path": None,
            "verdict": V_ERROR,
            "notes": "empty path",
        }

    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            rel = candidate.resolve().relative_to(repo_root.resolve())
        except ValueError:
            exists = candidate.exists()
            size = candidate.stat().st_size if exists and candidate.is_file() else 0
            return {
                "path": raw,
                "abs_path": str(candidate),
                "verdict": V_UNTRACKED_ON_DISK if exists else V_MISSING_FROM_DISK,
                "exists": exists,
                "tracked": False,
                "in_head": False,
                "staged": False,
                "modified": False,
                "size_bytes": size,
                "notes": "path outside repo root",
            }
    else:
        rel = candidate

    abs_path = (repo_root / rel).resolve()
    exists = abs_path.exists()
    size = abs_path.stat().st_size if exists and abs_path.is_file() else 0
    rel_str = str(rel)

    rc, ls_out, _ = _run_git(["ls-files", "--error-unmatch", "--", rel_str], cwd=repo_root)
    tracked = (rc == 0 and ls_out.strip() != "")

    in_head = False
    if tracked:
        rc_h, _, _ = _run_git(
            ["cat-file", "-e", f"HEAD:{rel_str}"], cwd=repo_root
        )
        in_head = (rc_h == 0)

    staged = False
    modified = False
    if tracked:
        rc_s, staged_out, _ = _run_git(
            ["diff", "--cached", "--name-only", "--", rel_str], cwd=repo_root
        )
        if rc_s == 0 and staged_out.strip():
            staged = True
        rc_m, mod_out, _ = _run_git(
            ["diff", "--name-only", "--", rel_str], cwd=repo_root
        )
        if rc_m == 0 and mod_out.strip():
            modified = True

    if not exists:
        verdict = V_MISSING_FROM_DISK
    elif not tracked:
        verdict = V_UNTRACKED_ON_DISK
    elif tracked and size == 0:
        verdict = V_TRACKED_BUT_EMPTY
    elif in_head and not modified and not staged:
        verdict = V_TRACKED_AND_COMMITTED
    elif in_head and (modified or staged):
        verdict = V_TRACKED_MODIFIED_UNCOMMITTED
    elif tracked and not in_head:
        verdict = V_TRACKED_STAGED_NOT_COMMITTED
    else:
        verdict = V_ERROR

    return {
        "path": raw,
        "abs_path": str(abs_path),
        "verdict": verdict,
        "exists": exists,
        "tracked": tracked,
        "in_head": in_head,
        "staged": staged,
        "modified": modified,
        "size_bytes": size,
    }


# ---------------------------------------------------------------------------
# Overall verdict composition
# ---------------------------------------------------------------------------

FAIL_PER_PATH = {V_UNTRACKED_ON_DISK, V_MISSING_FROM_DISK}
WARN_PER_PATH = {
    V_TRACKED_STAGED_NOT_COMMITTED,
    V_TRACKED_MODIFIED_UNCOMMITTED,
    V_TRACKED_BUT_EMPTY,
}


def _is_no_op_path_list(paths: list[dict]) -> bool:
    """Return True when all claimed paths are under /tmp/ or similar transient dirs.

    A lane that only touched /tmp/ artifacts has no persistent repo changes;
    the correct verdict is no-op-no-persistent-changes (a pass-state).
    Introduced: Lane 231 (2026-05-26) - handles the Lane-220 anti-pattern.
    """
    if not paths:
        return False
    return all(
        any(
            (p.get("abs_path") or p.get("path") or "").startswith(prefix)
            for prefix in _TMP_PREFIX
        )
        for p in paths
    )


def _compose_overall(
    per_path: list[dict],
    strict: bool,
    require_committed: bool,
    rebuttal_reason: str | None,
) -> tuple[str, str]:
    """Return (overall_verdict, human_message)."""
    if not per_path:
        return OV_PASS_NO_PATHS, "no paths claimed"

    if _is_no_op_path_list(per_path):
        return OV_NO_OP, "all claimed paths are under transient /tmp/ dirs - no persistent repo changes (pass)"

    if rebuttal_reason:
        return OV_OK_REBUTTAL, f"rebuttal accepted: {rebuttal_reason[:120]}"

    any_fail = any(p["verdict"] in FAIL_PER_PATH for p in per_path)
    any_warn = any(p["verdict"] in WARN_PER_PATH for p in per_path)
    all_committed = all(p["verdict"] == V_TRACKED_AND_COMMITTED for p in per_path)

    if any_fail:
        return OV_FAIL_UNTRACKED_OR_MISSING, "at least one path untracked-on-disk or missing-from-disk"
    if strict and any_warn:
        return OV_FAIL_STRICT, "strict mode: warn verdicts promoted to FAIL"
    if require_committed and any_warn:
        return OV_FAIL_STRICT, "require-committed: staged/modified verdicts treated as FAIL"
    if all_committed:
        return OV_PASS_ALL, "every claimed path is tracked-and-committed"
    return OV_WARN_UNCOMMITTED, "all paths exist + tracked, some not yet committed"


# ---------------------------------------------------------------------------
# Path-extraction (for --draft mode)
# ---------------------------------------------------------------------------

def _extract_paths_from_text(text: str) -> list[str]:
    """Find canonical-tree paths referenced in the draft body."""
    seen: set[str] = set()
    out: list[str] = []
    for m in PATH_LINE_RE.finditer(text):
        p = m.group(1).rstrip(".,;:)\"'`")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _extract_rebuttal(text: str) -> str | None:
    """Return the rebuttal reason if a valid r70-rebuttal marker is present."""
    m = REBUTTAL_HTML_RE.search(text)
    if m and m.group("reason").strip():
        reason = m.group("reason").strip()
        if 1 <= len(reason) <= 200:
            return reason
    m = REBUTTAL_LINE_RE.search(text)
    if m and m.group("reason").strip():
        reason = m.group("reason").strip()
        if 1 <= len(reason) <= 200:
            return reason
    return None


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def check(
    claimed_paths: Iterable[str],
    repo_root: Path,
    strict: bool = False,
    require_committed: bool = False,
    rebuttal_reason: str | None = None,
) -> dict:
    """Run the R70 verifier against `claimed_paths`.

    Fast-path no-op detection: if all claimed paths are under /tmp/ (or
    equivalent transient directories), returns OV_NO_OP immediately without
    classifying each path. This avoids git-ls-files calls against /tmp/ paths
    that are guaranteed untracked.
    """
    paths = [p.strip() for p in claimed_paths if p and p.strip()]

    # Fast-path: empty paths or all /tmp/ -> no-op pass
    if not paths:
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": OV_PASS_NO_PATHS,
            "message": "no paths claimed",
            "claimed_path_count": 0,
            "per_path": [],
            "strict": strict,
            "require_committed": require_committed,
            "rebuttal_accepted": bool(rebuttal_reason),
        }
    if all(
        any(p.startswith(prefix) for prefix in _TMP_PREFIX)
        for p in paths
    ):
        return {
            "schema": SCHEMA_VERSION,
            "gate": GATE,
            "verdict": OV_NO_OP,
            "message": "all claimed paths are under transient /tmp/ dirs - no persistent repo changes (pass)",
            "claimed_path_count": len(paths),
            "per_path": [{"path": p, "verdict": OV_NO_OP} for p in paths],
            "strict": strict,
            "require_committed": require_committed,
            "rebuttal_accepted": bool(rebuttal_reason),
            "no_op": True,
        }

    per_path = [
        _classify_path(p, repo_root=repo_root)
        for p in paths
    ]
    overall, message = _compose_overall(
        per_path, strict=strict, require_committed=require_committed,
        rebuttal_reason=rebuttal_reason,
    )
    return {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "verdict": overall,
        "message": message,
        "claimed_path_count": len(paths),
        "per_path": per_path,
        "strict": strict,
        "require_committed": require_committed,
        "rebuttal_accepted": bool(rebuttal_reason),
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--claimed-paths", type=str, default=None,
                   help="Comma-separated list of file paths to verify.")
    p.add_argument("--claimed-paths-file", type=str, default=None,
                   help="File with one path per line.")
    p.add_argument("--draft", type=str, default=None,
                   help="Path to a draft/lane-result markdown; extract paths automatically.")
    p.add_argument("--repo-root", type=str, default=None,
                   help="Override the git repo root (default: auto-detect).")
    p.add_argument("--strict", action="store_true",
                   help="Promote warn verdicts (staged/modified/empty) to FAIL.")
    p.add_argument("--require-committed", action="store_true",
                   help="Require every path to be in HEAD (no staged-only).")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON envelope instead of human-readable summary.")
    return p.parse_args(argv)


def _load_paths(args: argparse.Namespace) -> tuple[list[str], str | None]:
    """Gather paths from CLI args. Returns (paths, rebuttal_reason)."""
    paths: list[str] = []
    rebuttal_reason: str | None = None
    if args.claimed_paths:
        paths.extend(s.strip() for s in args.claimed_paths.split(",") if s.strip())
    if args.claimed_paths_file:
        fp = Path(args.claimed_paths_file)
        if fp.exists():
            for line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    paths.append(s)
    if args.draft:
        fp = Path(args.draft)
        if not fp.exists():
            print(f"error: draft not found: {fp}", file=sys.stderr)
            return paths, None
        body = fp.read_text(encoding="utf-8", errors="replace")
        paths.extend(_extract_paths_from_text(body))
        rebuttal_reason = _extract_rebuttal(body)
    # De-duplicate while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out, rebuttal_reason


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    paths, rebuttal_reason = _load_paths(args)

    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        cwd_root = _resolve_repo_root(Path.cwd())
        if cwd_root.exists() and (cwd_root / ".git").exists():
            repo_root = cwd_root
        else:
            script = Path(__file__).resolve()
            repo_root = script.parent.parent

    result = check(
        claimed_paths=paths,
        repo_root=repo_root,
        strict=args.strict,
        require_committed=args.require_committed,
        rebuttal_reason=rebuttal_reason,
    )

    if args.json:
        # R36: dump in insertion order so the top-level "verdict" key is the
        # first one shell parsers (pre-submit-check.sh) see. agent_pathspec
        # registered via tools/agent-pathspec-register.py for LANE-218.
        # Sort_keys=True would push per_path's nested "verdict" entries above
        # the top-level "verdict", causing the shell's `head -1` regex to
        # pick the wrong field.
        print(json.dumps(result, indent=2))
    else:
        print(f"[{GATE}] verdict={result['verdict']}  paths={result['claimed_path_count']}")
        print(f"  message: {result['message']}")
        if result["per_path"]:
            print("  per-path:")
            for p in result["per_path"]:
                marker = "  " if p["verdict"] == V_TRACKED_AND_COMMITTED else "!!"
                print(f"    {marker} {p['verdict']:<35s} {p['path']}")

    overall = result["verdict"]
    if overall in {OV_PASS_ALL, OV_PASS_NO_PATHS, OV_OK_REBUTTAL, OV_WARN_UNCOMMITTED, OV_NO_OP}:
        return 0
    if overall == OV_ERROR:
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
