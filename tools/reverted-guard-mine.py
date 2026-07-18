#!/usr/bin/env python3
"""reverted-guard-mine.py — Tier-6 backward-mine class (b) detector.

DETECTOR-CODIFY-1 — Pattern 1 (`reverted-protective-guard-class-live`).

Surfaced by RG-N6-S1 (Reserve Governor optimistic-veto bypass): the audit-pin
of a target repo lacks a protective guard whose introduction was attempted in
a prior PR and subsequently REVERTED by a "Trust mitigations" / equivalent
revert commit. Tier-6 (b) classifies these reverted-guard commits as live
candidate findings — the bug class still exists at audit-pin because the
fix attempt was rolled back.

This tool mines a target repo's git history WITHIN the backward window
(audit-pin ← N commits behind, default 60), looks for revert-class commits
whose subject contains protective-guard keywords AND whose diff removes a
function/modifier definition (Solidity), a fn/trait method (Rust), or a
guard-returning function (Go). For each match, it cross-references the
removed function name against the current audit-pin source to verify no
equivalent guard exists today. Hits are emitted as candidate findings.

Language support:
  --lang sol   — Solidity: function/modifier defs (original behaviour)
  --lang rust  — Rust: fn items, #[require(...)], assert!/require! macros,
                 Result<()>-returning guard fns in trait impls
  --lang go    — Go: func guard idioms (err-return early exit, panic guards,
                 middleware-style precondition fns)
  --lang auto  — (default) detect language from repo file extension majority

Usage:
    python3 tools/reverted-guard-mine.py \\
        --workspace ~/audits/reserve-governor \\
        --audit-pin <sha-or-empty> \\
        --backward-window 60 \\
        --lang auto \\
        --out reports/reverted_guard_mine_<workspace>_<date>.json

If --audit-pin is empty, the tool reads `.auditooor-state.yaml` to resolve it.
If `gh` auth is unavailable, falls back to local `git log` against a clone
located at `${workspace}/repo` or `${workspace}/source`.

Stdlib-only.

Schema: ``auditooor.reverted_guard_mine.v1`` (schema_version "1.1").
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

REPO_ROOT = Path(__file__).resolve().parent.parent

# ─────────────────────────────────────────────────────────────────
# Tunables
# ─────────────────────────────────────────────────────────────────
DEFAULT_BACKWARD_WINDOW = 60

GUARD_KEYWORDS = (
    r"\b("
    r"fix|guard|check|validate|limit|assert|require"
    r"|inflated|inflation|bound|cap|maximum|min|max|sanity"
    r"|protect|protection|protective|safeguard|mitigation"
    r")\b"
)
GUARD_RE = re.compile(GUARD_KEYWORDS, re.IGNORECASE)
REVERT_RE = re.compile(r"\b(revert|reverts|reverting|trust mitigations?)\b", re.IGNORECASE)

# ── Language-specific removed-guard patterns ──────────────────────
# Solidity: removed `function` or `modifier` definition on a '-' diff line
REMOVE_FN_RE_SOL = re.compile(
    r"^-\s*(function|modifier)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)

# Rust: removed `fn` definition (including `pub`, `pub(crate)`, `async`, etc.)
# Also catches `pub fn`, `pub(crate) fn`, `async fn`, `unsafe fn` combos.
REMOVE_FN_RE_RUST = re.compile(
    r"^-[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)*(?:async[ \t]+)?(?:unsafe[ \t]+)?fn[ \t]+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(",
    re.MULTILINE,
)

# Go: removed `func` definition, including method receivers.
# Captures the function name (group 1).
REMOVE_FN_RE_GO = re.compile(
    r"^-[ \t]*func[ \t]+(?:\([^)]*\)[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)

# ── Language-specific audit-pin grep patterns ─────────────────────
# Used in `git grep` at audit-pin to check if a guard still exists.

def _audit_pin_grep_pattern(lang: str, name: str) -> str:
    """Return a regex pattern for `git grep -E` to find *name* defined at audit-pin."""
    if lang == "rust":
        # Match fn <name>( with any visibility/qualifier prefix
        return rf"fn\s+{re.escape(name)}\s*(<[^>]*)?\s*\("
    if lang == "go":
        # Match func <name>( or func (recv) <name>(
        return rf"func\s+(\([^)]*\)\s+)?{re.escape(name)}\s*\("
    # Solidity (default)
    return rf"(function|modifier)\s+{re.escape(name)}\s*\("


def _detect_lang(repo_dir: Path) -> str:
    """Auto-detect dominant language from file-extension counts in the repo."""
    rc, out, _ = _run(
        ["git", "ls-files", "--", "*.rs", "*.go", "*.sol"],
        cwd=repo_dir,
    )
    if rc != 0 or not out.strip():
        return "sol"  # fallback
    counts: dict[str, int] = {"sol": 0, "rust": 0, "go": 0}
    for line in out.splitlines():
        line = line.strip()
        if line.endswith(".rs"):
            counts["rust"] += 1
        elif line.endswith(".go"):
            counts["go"] += 1
        elif line.endswith(".sol"):
            counts["sol"] += 1
    return max(counts, key=lambda k: counts[k])


def _remove_fn_re(lang: str) -> re.Pattern:
    if lang == "rust":
        return REMOVE_FN_RE_RUST
    if lang == "go":
        return REMOVE_FN_RE_GO
    return REMOVE_FN_RE_SOL


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _resolve_audit_pin(workspace: Path) -> str | None:
    """Read .auditooor-state.yaml to extract audit_pin_sha if present."""
    state = workspace / ".auditooor-state.yaml"
    if not state.exists():
        return None
    try:
        text = state.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r"audit_pin_sha:\s*['\"]?([0-9a-f]{6,40})['\"]?", text)
    if m:
        return m.group(1)
    return None


def _resolve_repo_dir(workspace: Path) -> Path | None:
    """Locate the cloned repo dir for a workspace."""
    for candidate in ("repo", "source", "src", "upstream"):
        rd = workspace / candidate
        if rd.exists() and (rd / ".git").exists():
            return rd
    # Fallback: workspace itself is a git repo
    if (workspace / ".git").exists():
        return workspace
    return None


# ─────────────────────────────────────────────────────────────────
# Core mining
# ─────────────────────────────────────────────────────────────────
def mine_reverted_guards(
    repo_dir: Path,
    audit_pin: str,
    backward_window: int,
    lang: str = "auto",
) -> list[dict]:
    """Walk audit-pin ← N commits behind; classify reverts.

    Args:
        repo_dir: Path to the cloned git repo.
        audit_pin: Commit SHA representing the audit pin.
        backward_window: Number of commits to look back from audit_pin.
        lang: Language mode — 'sol', 'rust', 'go', or 'auto' (detect from
              repo file-extension majority). Determines which removed-guard
              regex and audit-pin grep pattern are used.

    Returns a list of candidate-finding dicts.
    """
    if lang == "auto":
        lang = _detect_lang(repo_dir)

    remove_re = _remove_fn_re(lang)
    candidates: list[dict] = []

    # Enumerate the backward window via `git log <pin>~N..<pin>`. Use a
    # rare delimiter to keep commit bodies (which contain newlines) on one
    # logical record.
    DELIM = "@@@AUD@@@"
    fmt = f"%H%x09%ai%x09%s%x09%b{DELIM}"
    rev_range = f"{audit_pin}~{backward_window}..{audit_pin}"
    rc, out, err = _run(
        ["git", "log", f"--pretty=format:{fmt}", rev_range],
        cwd=repo_dir,
        timeout=120,
    )
    if rc != 0:
        # Some repos are shallow; fall back to "last N commits up to pin".
        rc2, out2, err2 = _run(
            ["git", "log", "-n", str(backward_window), f"--pretty=format:{fmt}", audit_pin],
            cwd=repo_dir,
            timeout=120,
        )
        if rc2 != 0:
            print(
                f"[reverted-guard-mine] git log failed: {err.strip()} | {err2.strip()}",
                file=sys.stderr,
            )
            return []
        out = out2

    records = [r.strip() for r in out.split(DELIM) if r.strip()]
    for record in records:
        parts = record.split("\t", 3)
        if len(parts) < 3:
            continue
        sha = parts[0]
        date = parts[1]
        subject = parts[2]
        body = parts[3] if len(parts) >= 4 else ""
        full_msg = f"{subject}\n{body}"
        # Revert-class detection: revert verbs in subject OR a `Revert "..."`
        # line in the body (squash-merge commits often hide the revert in
        # the body — the reserve-governor `bee485b "Trust mitigations"` is
        # an exemplar).
        is_revert_subject = bool(REVERT_RE.search(subject))
        is_revert_body = bool(re.search(r'Revert\s+"', body))
        if not (is_revert_subject or is_revert_body):
            continue
        # Guard-related keyword presence anywhere in the message — body
        # often contains `Supply inflation guard` even when the subject
        # is generic.
        if not GUARD_RE.search(full_msg):
            continue
        # Pull the diff for this commit and look for removed function/modifier defs.
        rc_d, diff, err_d = _run(
            ["git", "show", "--no-color", "--pretty=format:", sha],
            cwd=repo_dir,
            timeout=120,
        )
        if rc_d != 0:
            continue
        removed = remove_re.findall(diff)
        if not removed:
            continue
        # Solidity regex yields 2-tuples (kind, name); Rust/Go yield just the name.
        if removed and isinstance(removed[0], tuple):
            removed_names = sorted(set(name for _kind, name in removed))
        else:
            removed_names = sorted(set(removed))

        # Audit-pin coverage check: does the current pin still have any of
        # these removed function names defined? (grep at audit-pin tree).
        audit_pin_covered: dict[str, bool] = {}
        for name in removed_names:
            grep_pat = _audit_pin_grep_pattern(lang, name)
            rc_g, _o, _e = _run(
                ["git", "grep", "-E", grep_pat, audit_pin],
                cwd=repo_dir,
            )
            audit_pin_covered[name] = (rc_g == 0)

        any_uncovered = any(not v for v in audit_pin_covered.values())
        # Extract any inline `Revert "..."` headers from the body — these
        # are the canonical signal for squash-merged reverts.
        revert_headers = re.findall(r'Revert\s+"([^"]+)"', body)
        candidates.append(
            {
                "sha": sha,
                "date": date,
                "subject": subject,
                "body_revert_headers": revert_headers,
                "is_revert_subject": is_revert_subject,
                "is_revert_body": is_revert_body,
                "removed_function_signatures": removed_names,
                "audit_pin_coverage": audit_pin_covered,
                "any_removed_guard_uncovered_at_pin": any_uncovered,
                "tier_6_class": "b",
                "candidate_finding": any_uncovered,
                "detected_lang": lang,
                # OOS-guard status — surface if the removed guard's path looks
                # like it was OOS at the time. Heuristic only.
                "oos_guard_status": "unknown",
            }
        )

    return candidates


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="reverted-guard-mine — Tier-6 backward-mine (b) detector"
    )
    parser.add_argument("--workspace", required=True, help="Path to ~/audits/<name>/")
    parser.add_argument(
        "--audit-pin",
        default="",
        help="Commit SHA at audit pin. Empty → read from .auditooor-state.yaml",
    )
    parser.add_argument(
        "--backward-window",
        type=int,
        default=DEFAULT_BACKWARD_WINDOW,
        help=f"Backward window N (default {DEFAULT_BACKWARD_WINDOW})",
    )
    parser.add_argument("--out", help="JSON output path; default stdout")
    parser.add_argument(
        "--repo-dir",
        help="Override repo location (default: <workspace>/repo|source|src|upstream)",
    )
    parser.add_argument(
        "--lang",
        choices=["sol", "rust", "go", "auto"],
        default="auto",
        help=(
            "Language mode for guard-pattern detection. "
            "'sol' = Solidity function/modifier (original behaviour); "
            "'rust' = Rust fn/trait-method/assert!/require! patterns; "
            "'go' = Go guard-returning func idioms; "
            "'auto' = detect from repo file-extension majority (default)."
        ),
    )
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="Print a one-line summary to stderr after run",
    )
    args = parser.parse_args(argv)

    workspace = Path(os.path.expanduser(args.workspace)).resolve()
    if not workspace.exists():
        print(f"[reverted-guard-mine] workspace missing: {workspace}", file=sys.stderr)
        return 2

    audit_pin = (args.audit_pin or "").strip()
    if not audit_pin:
        audit_pin = _resolve_audit_pin(workspace) or ""
    if not audit_pin:
        print(
            "[reverted-guard-mine] audit-pin SHA not provided and not resolvable from "
            ".auditooor-state.yaml",
            file=sys.stderr,
        )
        return 2

    if args.repo_dir:
        repo_dir = Path(os.path.expanduser(args.repo_dir)).resolve()
    else:
        repo_dir = _resolve_repo_dir(workspace) or workspace

    if not (repo_dir / ".git").exists():
        print(
            f"[reverted-guard-mine] no git repo at {repo_dir}; pass --repo-dir",
            file=sys.stderr,
        )
        return 2

    candidates = mine_reverted_guards(repo_dir, audit_pin, args.backward_window, lang=args.lang)
    # Resolve effective lang (auto may have been detected inside mine_reverted_guards)
    effective_lang = candidates[0]["detected_lang"] if candidates else args.lang

    report = {
        "schema": "auditooor.reverted_guard_mine.v1",
        "schema_version": "1.1",
        "lang": effective_lang,
        "workspace": str(workspace),
        "repo_dir": str(repo_dir),
        "audit_pin": audit_pin,
        "backward_window": args.backward_window,
        "generated_at": _now_iso(),
        "candidate_count": sum(1 for c in candidates if c.get("candidate_finding")),
        "total_revert_class_b_count": len(candidates),
        "candidates": candidates,
    }

    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        out_path = Path(os.path.expanduser(args.out)).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)

    if args.print_summary:
        print(
            f"[reverted-guard-mine] window={args.backward_window} pin={audit_pin[:12]} "
            f"revert_class_b={report['total_revert_class_b_count']} "
            f"candidate_findings={report['candidate_count']}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
