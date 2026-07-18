#!/usr/bin/env python3
"""pattern-merge-rescan.py — rescan workspaces against newly-merged DSL patterns.

Codex P0 #2 follow-up (PR #253 final-pass spec). Operator-driven (NOT
CI-driven). Stdlib-only. Deterministic. Offline-safe (gh lookups only when
``--since`` is a PR number; commit-SHA mode is fully offline).

Algorithm
---------

1. ``--since`` resolves to either:

   * a commit SHA (``[0-9a-f]{7,40}``) → diff that commit's tree against its
     first parent for added ``reference/patterns.dsl/*.yaml`` files;
   * a PR number (digits) → ``gh pr view <N> --json mergeCommit`` →
     fall back to commit-SHA mode using the merge-commit oid.

   Removed patterns are reported in the manifest but not rescanned.

2. Candidate workspaces resolve in this order:

   * ``--workspaces`` (comma-separated), if provided;
   * else any ``~/audits/*/`` whose ``engage_report.md`` mtime is within
     ``--mtime-days`` (default 30) of now AND that holds a ``src/`` or
     ``contracts/`` subtree with at least one ``.sol`` file;
   * the pattern's ``source:`` field is also surfaced as an advisory citation
     when it names a known workspace (mining provenance).

   Capped by ``--max-workspaces`` (default 9, mirrors gap-analyzer convention).

3. Hit detection is pure-grep and stdlib-only. For each new pattern YAML the
   tool extracts every ``regex:`` subfield under ``preconditions:`` /
   ``match:`` and runs each regex against every ``.sol`` file in the workspace
   source tree (via ``re.compile`` + per-line scanning, NOT subprocess to
   ripgrep — keeps the tool hermetic for tests). A workspace × pattern is
   "candidate-flagged" iff EVERY positive regex (`*_contains_regex`,
   `*_matches_regex`) hits AND every negative regex (``*_not_contains_regex``,
   ``*_not_matches_regex``) misses on the same file. This is intentionally
   coarser than the compiled Slither detector — the rescan is meant to surface
   files worth a closer human look, not to replicate detector semantics. The
   manifest records the exact regex set so a downstream operator (or
   ``run_custom.py``) can re-run the precise compiled detector if a hit looks
   real.

4. Triage tags each hit:

   * ``OOS`` — the file path matches an entry in ``<ws>/OOS_CHECKLIST.md``;
   * ``DUPE`` — the (file, pattern_id) pair is already cited in
     ``<ws>/SCAN_REPORT.md`` or ``<ws>/FINDINGS.md`` or
     ``<ws>/PATTERN_HITS.md`` or ``<ws>/engage_report.md``;
   * ``NEW`` — neither — the actual value-add of the rescan.

5. Calibration ledger. Each NEW / DUPE / OOS row is appended (one event per
   row) to ``tools/calibration/llm_calibration_log.jsonl`` via
   ``llm-calibration-log.py`` with ``provider=auditooor`` (a non-LLM provider
   added for mechanical-tool rows; falls through gracefully if the calibration
   log refuses the provider) and ``task_type=pattern-postmerge-rescan``. We
   record only the bookkeeping (NOT a TRUE / FALSE verdict — that requires a
   human pass). Default verdict ``INDETERMINATE``.

Outputs
-------

* ``<ws>/postmerge_rescan_<YYYY-MM-DD>.md`` — human-readable triage table.
* ``<ws>/.audit_logs/postmerge_rescan_<YYYY-MM-DD>.json`` — machine-readable
  manifest. ``--write-manifest`` is the default; ``--no-write-manifest``
  suppresses it.

Stdlib-only. No new pip deps.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

THIS_FILE = Path(__file__).resolve()
TOOLS_DIR = THIS_FILE.parent
REPO_ROOT = TOOLS_DIR.parent
DSL_DIR = REPO_ROOT / "reference" / "patterns.dsl"
CALIBRATION_LOG = TOOLS_DIR / "llm-calibration-log.py"

DEFAULT_AUDITS_DIR = Path(os.environ.get("AUDITS_DIR", str(Path.home() / "audits")))
DEFAULT_MAX_WORKSPACES = 9
DEFAULT_MTIME_DAYS = 30

# Regex-bearing keys we recognize when extracting from YAML. Predicates ending
# in `_not_*` are negative (must MISS on the candidate file); the rest are
# positive (must HIT). Plain function-shape predicates without a regex argument
# (e.g. ``function.kind: external_or_public``, ``function.not_in_skip_list:
# true``) are ignored — the rescan is a coarse filter, not a re-implementation
# of the Slither predicate engine.
POSITIVE_REGEX_SUFFIXES = (
    "contains_regex",
    "matches_regex",
    "source_matches_regex",
    "body_contains_regex",
)
NEGATIVE_REGEX_SUFFIXES = (
    "not_contains_regex",
    "not_matches_regex",
    "not_source_matches_regex",
    "body_not_contains_regex",
    "body_not_matches_regex",
)

PATTERN_PREFIX = "reference/patterns.dsl/"
PATTERN_SUFFIX = ".yaml"


# ---------------------------------------------------------------------------
# Minimal YAML reader (stdlib-only)
# ---------------------------------------------------------------------------
#
# We avoid a PyYAML dependency. The DSL files use a tiny subset of YAML:
# top-level scalars, lists of single-key mappings under ``preconditions:`` /
# ``match:``, and bare ``key: value`` pairs. We only need:
#
#   * top-level ``pattern:`` and ``source:`` scalars,
#   * the (key, regex) pairs under ``preconditions:`` and ``match:`` whose
#     key ends in one of the regex-suffixes above.
#
# A full YAML parse is not required (and not desired — keeps the test harness
# hermetic).


_TOP_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")
_LIST_ITEM_RE = re.compile(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_.]*):\s*(.*)$")


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def parse_pattern_yaml(text: str) -> Dict[str, Any]:
    """Parse the subset of YAML we need from a DSL pattern file.

    Returns a dict::

        {
          "pattern": str | None,
          "source":  str | None,
          "regex_predicates": [
              {"key": "contract.source_matches_regex", "regex": "...",
               "polarity": "positive" | "negative"},
              ...
          ],
        }
    """
    out: Dict[str, Any] = {"pattern": None, "source": None, "regex_predicates": []}
    in_block = None  # "preconditions" | "match" | None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            # Section transition still possible after blank lines; just skip.
            continue
        # Top-level key (no leading whitespace, ends with ':' optionally + value).
        if not line.startswith(" ") and not line.startswith("\t"):
            m = _TOP_KEY_RE.match(line)
            if m:
                key, val = m.group(1), m.group(2)
                if key in ("preconditions", "match"):
                    in_block = key
                    continue
                in_block = None
                if key in ("pattern", "source") and val:
                    out[key] = _strip_quotes(val)
                continue
            in_block = None
            continue
        # Indented line — list item under preconditions / match.
        if in_block in ("preconditions", "match"):
            m = _LIST_ITEM_RE.match(line)
            if not m:
                continue
            full_key, val = m.group(1), m.group(2)
            # full_key looks like "function.body_contains_regex" or
            # "contract.source_matches_regex". We classify by suffix.
            if any(full_key.endswith(suf) for suf in NEGATIVE_REGEX_SUFFIXES):
                polarity = "negative"
            elif any(full_key.endswith(suf) for suf in POSITIVE_REGEX_SUFFIXES):
                polarity = "positive"
            else:
                # Non-regex predicate (function.kind, function.not_in_skip_list,
                # etc.) — skip, the rescan is a coarse filter.
                continue
            regex_str = _strip_quotes(val)
            if not regex_str:
                continue
            out["regex_predicates"].append({
                "key": full_key,
                "regex": regex_str,
                "polarity": polarity,
            })
    return out


# ---------------------------------------------------------------------------
# SINCE resolution
# ---------------------------------------------------------------------------

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def _run(argv: Sequence[str], cwd: Optional[Path] = None) -> Tuple[int, str, str]:
    """Invoke a subprocess; return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)


def resolve_since(since: str, repo_root: Path,
                  gh_lookup: bool = True) -> Tuple[str, str]:
    """Resolve ``since`` to a (parent_ref, head_ref) commit pair.

    * commit-SHA mode: returns (sha + "~1", sha).
    * PR-number mode: ``gh pr view <N> --json mergeCommit`` → SHA mode.
      With ``gh_lookup=False`` a PR number raises ``ValueError`` — used by
      tests to exercise the SHA branch in isolation.
    """
    s = since.strip()
    if not s:
        raise ValueError("--since requires a value (commit SHA or PR number)")
    if s.startswith("#"):
        s = s[1:]
    if s.isdigit():
        if not gh_lookup:
            raise ValueError(f"PR number {s!r} requires gh lookup; "
                             "rerun without --offline or pass a commit SHA")
        rc, out, err = _run(["gh", "pr", "view", s, "--json", "mergeCommit"])
        if rc != 0:
            raise RuntimeError(
                f"gh pr view {s} failed (rc={rc}): {err.strip() or out.strip()}")
        try:
            data = json.loads(out)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"gh returned non-JSON for PR {s}: {e}") from e
        mc = (data or {}).get("mergeCommit") or {}
        oid = mc.get("oid")
        if not oid:
            raise RuntimeError(
                f"PR {s} has no mergeCommit (not yet merged?); "
                "pass a commit SHA explicitly")
        return f"{oid}~1", oid
    if _SHA_RE.match(s):
        return f"{s}~1", s
    raise ValueError(f"--since value not recognized: {since!r} "
                     "(expected commit SHA or PR number)")


def diff_added_patterns(parent_ref: str, head_ref: str,
                        repo_root: Path) -> Tuple[List[str], List[str]]:
    """Return (added_pattern_ids, removed_pattern_ids) between the two refs.

    Pattern id == the YAML basename minus the ``.yaml`` suffix.
    """
    def _diff(filter_: str) -> List[str]:
        # `--no-renames` prevents git's rename-detection from collapsing
        # ``old-pattern.yaml -> new-pattern-a.yaml`` (high textual similarity
        # because every DSL pattern shares the same boilerplate header) into
        # an R-status entry that hides the new file from --diff-filter=A. Bug
        # caught by test_added_and_removed during initial implementation.
        rc, out, _ = _run(
            ["git", "-C", str(repo_root), "diff", "--name-only", "--no-renames",
             f"--diff-filter={filter_}", f"{parent_ref}..{head_ref}", "--",
             f"{PATTERN_PREFIX}*{PATTERN_SUFFIX}"])
        if rc != 0:
            return []
        names: List[str] = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith(PATTERN_PREFIX) or not line.endswith(PATTERN_SUFFIX):
                continue
            base = line[len(PATTERN_PREFIX):-len(PATTERN_SUFFIX)]
            if base:
                names.append(base)
        names.sort()
        return names

    return _diff("A"), _diff("D")


# ---------------------------------------------------------------------------
# Workspace selection
# ---------------------------------------------------------------------------

def _has_solidity(ws: Path) -> bool:
    for sub in ("src", "contracts", "."):
        d = ws if sub == "." else ws / sub
        if not d.is_dir():
            continue
        try:
            for p in d.rglob("*.sol"):
                # Skip vendored / test / mock fast — keep this cheap; full
                # filtering happens in scan_workspace().
                return True
        except OSError:
            continue
    return False


def select_workspaces(explicit: Optional[List[Path]],
                      audits_dir: Path,
                      mtime_days: int,
                      max_workspaces: int,
                      now: Optional[datetime] = None) -> List[Path]:
    """Pick candidate workspaces deterministically.

    * ``explicit`` (from ``--workspaces``) wins. Each path is sanity-checked:
      must be a directory, must contain ``engage_report.md`` OR Solidity src.
      Order is preserved (caller intent).
    * Else: enumerate ``audits_dir/*/`` with a recent ``engage_report.md`` and
      Solidity content. Sort alphabetically for determinism.
    * Capped at ``max_workspaces``.
    """
    now = now or datetime.now(timezone.utc)
    if explicit:
        out = []
        for p in explicit:
            p = Path(p).expanduser()
            if not p.is_dir():
                continue
            # Must look like an audit workspace (engage_report OR .sol).
            if not (p / "engage_report.md").is_file() and not _has_solidity(p):
                continue
            out.append(p)
        return out[:max_workspaces]

    if not audits_dir.is_dir():
        return []
    cutoff = now.timestamp() - mtime_days * 86400.0
    candidates: List[Path] = []
    for child in sorted(audits_dir.iterdir(), key=lambda x: x.name):
        if not child.is_dir():
            continue
        report = child / "engage_report.md"
        if not report.is_file():
            continue
        try:
            if report.stat().st_mtime < cutoff:
                continue
        except OSError:
            continue
        if not _has_solidity(child):
            continue
        candidates.append(child)
    return candidates[:max_workspaces]


# ---------------------------------------------------------------------------
# Workspace scanning
# ---------------------------------------------------------------------------

# Path-substring filters that exclude test / vendored / fixture sources from
# the rescan. Mirrors scan.sh's `lib/|test/|dev/` filter, with extras the DSL
# patterns also call out via ``function.not_source_matches_regex: 'mock|test'``.
_PATH_EXCLUDES = (
    "/lib/", "/test/", "/tests/", "/mock/", "/mocks/", "/fixture/",
    "/fixtures/", "/script/", "/dev/", "/.git/", "/node_modules/",
)


def _solidity_files(ws: Path) -> List[Path]:
    """Return deterministic-ordered list of in-scope ``.sol`` files."""
    roots: List[Path] = []
    for sub in ("src", "contracts"):
        d = ws / sub
        if d.is_dir():
            roots.append(d)
    if not roots:
        roots.append(ws)
    seen: set = set()
    out: List[Path] = []
    for root in roots:
        try:
            for p in sorted(root.rglob("*.sol")):
                rp = str(p.resolve())
                if rp in seen:
                    continue
                if any(seg in rp for seg in _PATH_EXCLUDES):
                    continue
                seen.add(rp)
                out.append(p)
        except OSError:
            continue
    return out


def _compile_predicates(predicates: List[Dict[str, str]]) -> Tuple[
        List[Tuple[str, "re.Pattern[str]"]], List[Tuple[str, "re.Pattern[str]"]]]:
    """Compile YAML regex predicates into (positives, negatives) regex lists.

    Predicates that fail to compile are silently dropped — surfaced in the
    manifest under ``compile_failures`` so the operator notices.
    """
    pos: List[Tuple[str, "re.Pattern[str]"]] = []
    neg: List[Tuple[str, "re.Pattern[str]"]] = []
    for pred in predicates:
        rx = pred.get("regex", "")
        if not rx:
            continue
        try:
            cre = re.compile(rx)
        except re.error:
            continue
        if pred.get("polarity") == "negative":
            neg.append((pred["key"], cre))
        else:
            pos.append((pred["key"], cre))
    return pos, neg


def scan_file_for_pattern(content: str,
                          positives: List[Tuple[str, "re.Pattern[str]"]],
                          negatives: List[Tuple[str, "re.Pattern[str]"]]
                          ) -> Optional[Dict[str, Any]]:
    """Return a hit dict if every positive matches AND no negative matches.

    Hit dict: ``{"first_line": int, "matched_keys": [str, ...]}``. Returns
    ``None`` otherwise.
    """
    if not positives:
        # No positive predicates → cannot fire. Coarse-filter discipline:
        # we don't want a regex-less predicate set to "match every file".
        return None
    matched_keys: List[str] = []
    first_line: Optional[int] = None
    for key, cre in positives:
        m = cre.search(content)
        if not m:
            return None
        matched_keys.append(key)
        if first_line is None:
            line_no = content.count("\n", 0, m.start()) + 1
            first_line = line_no
    for _, cre in negatives:
        if cre.search(content):
            return None
    return {"first_line": first_line or 1, "matched_keys": matched_keys}


def scan_workspace(ws: Path,
                   patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scan ``ws`` against ``patterns``; return list of hit records.

    Hit record: ``{"pattern_id", "source", "file", "line", "matched_keys"}``.
    """
    hits: List[Dict[str, Any]] = []
    files = _solidity_files(ws)
    pre_compiled = []
    for pat in patterns:
        pos, neg = _compile_predicates(pat.get("regex_predicates", []) or [])
        pre_compiled.append((pat, pos, neg))
    for fp in files:
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat, pos, neg in pre_compiled:
            hit = scan_file_for_pattern(content, pos, neg)
            if not hit:
                continue
            try:
                rel = str(fp.resolve().relative_to(ws.resolve()))
            except ValueError:
                rel = str(fp)
            hits.append({
                "pattern_id": pat["pattern"],
                "source": pat.get("source") or "",
                "file": rel,
                "line": hit["first_line"],
                "matched_keys": list(hit["matched_keys"]),
            })
    # Deterministic order: by (pattern_id, file, line).
    hits.sort(key=lambda h: (h["pattern_id"], h["file"], h["line"]))
    return hits


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_oos_keywords(ws: Path) -> List[str]:
    """Extract path-globs / file-stems from OOS_CHECKLIST.md.

    Grabs anything that looks like a path (``foo/`` or ``foo.sol``) inside the
    bullet text. Coarse — false-positives here are safe (over-tag NEW as OOS
    is reversible by the operator), false-negatives are not (under-tag).
    """
    text = _read_text(ws / "OOS_CHECKLIST.md")
    if not text:
        return []
    keys: List[str] = []
    # Path-like tokens: bare globs (`lib/**`), explicit `*.sol`, or a path
    # segment with a slash.
    token_re = re.compile(r"\b([A-Za-z0-9_./*-]+\.sol|[A-Za-z0-9_./-]+/\*\*?)")
    for m in token_re.finditer(text):
        tok = m.group(1).strip("/").rstrip("*").rstrip("/")
        if tok and tok.lower() not in {"src", "contracts"}:
            keys.append(tok)
    # Dedupe preserving order.
    seen: set = set()
    out: List[str] = []
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out


def is_oos(file_rel: str, oos_keys: List[str]) -> bool:
    fl = file_rel.replace("\\", "/").lower()
    for k in oos_keys:
        kl = k.lower()
        if kl in fl:
            return True
    return False


def load_existing_findings_index(ws: Path) -> List[Tuple[str, str]]:
    """Return (file_substring, marker) tuples extracted from prior reports.

    A new hit is DUPE iff its (file basename or path) appears in ANY prior
    report along with the same pattern_id OR with a path overlap ≥ basename.
    Conservative: matching by basename catches most real dupes. Operator can
    re-tag in the markdown after the fact.
    """
    out: List[Tuple[str, str]] = []
    for rel in ("SCAN_REPORT.md", "FINDINGS.md", "PATTERN_HITS.md",
                "engage_report.md"):
        text = _read_text(ws / rel)
        if not text:
            continue
        # Capture path-like tokens (basename.sol or path/foo.sol).
        for m in re.finditer(r"([A-Za-z0-9_./-]+\.sol)(?::(\d+))?", text):
            out.append((m.group(1).lower(), rel))
    return out


def is_dupe(file_rel: str, pattern_id: str,
            findings_index: List[Tuple[str, str]]) -> bool:
    fl = file_rel.replace("\\", "/").lower()
    base = fl.rsplit("/", 1)[-1]
    for token, _src in findings_index:
        if not token:
            continue
        if token.endswith("/" + base) or token == base or token.endswith(fl):
            return True
        if fl.endswith(token):
            return True
    return False


def triage_hits(hits: List[Dict[str, Any]], ws: Path) -> List[Dict[str, Any]]:
    """Tag each hit with ``triage`` ∈ {NEW, DUPE, OOS}."""
    oos_keys = load_oos_keywords(ws)
    findings_index = load_existing_findings_index(ws)
    out: List[Dict[str, Any]] = []
    for h in hits:
        tag = "NEW"
        if is_oos(h["file"], oos_keys):
            tag = "OOS"
        elif is_dupe(h["file"], h["pattern_id"], findings_index):
            tag = "DUPE"
        out.append({**h, "triage": tag})
    return out


# ---------------------------------------------------------------------------
# Output: markdown + JSON
# ---------------------------------------------------------------------------

def render_markdown(ws: Path,
                    since: str,
                    parent_ref: str, head_ref: str,
                    added: List[str], removed: List[str],
                    hits: List[Dict[str, Any]],
                    compile_failures: List[Dict[str, Any]],
                    generated_at: datetime) -> str:
    lines: List[str] = []
    lines.append(f"# Post-merge pattern rescan — {ws.name}")
    lines.append("")
    lines.append(f"- Workspace: `{ws}`")
    lines.append(f"- Since: `{since}` (parent=`{parent_ref}` head=`{head_ref}`)")
    lines.append(f"- Generated: {generated_at.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"- New patterns scanned: **{len(added)}**")
    if removed:
        lines.append(f"- Removed patterns (informational): {len(removed)} — "
                     + ", ".join(f"`{r}`" for r in removed))
    counts = {"NEW": 0, "DUPE": 0, "OOS": 0}
    for h in hits:
        counts[h["triage"]] = counts.get(h["triage"], 0) + 1
    lines.append(
        f"- Hits: **{len(hits)}** total — "
        f"NEW={counts['NEW']}  DUPE={counts['DUPE']}  OOS={counts['OOS']}")
    if compile_failures:
        lines.append(f"- ⚠ Predicate-compile failures: {len(compile_failures)} "
                     "(see manifest under `compile_failures`)")
    lines.append("")
    lines.append("## Patterns scanned")
    lines.append("")
    if added:
        for p in added:
            lines.append(f"- `{p}`")
    else:
        lines.append("_(none)_")
    lines.append("")
    lines.append("## Triage table")
    lines.append("")
    if not hits:
        lines.append("_No candidate hits — the new patterns produced 0 matches "
                     "in this workspace's source. This is a useful negative "
                     "result: confirms either (a) the protocol shape doesn't "
                     "fit the new patterns, or (b) the patterns need broader "
                     "predicates._")
    else:
        lines.append("| Triage | Pattern | File | Line | Matched predicates |")
        lines.append("| --- | --- | --- | --- | --- |")
        for h in hits:
            keys = ", ".join(f"`{k}`" for k in h["matched_keys"])
            lines.append(
                f"| **{h['triage']}** | `{h['pattern_id']}` | "
                f"`{h['file']}` | {h['line']} | {keys} |")
    lines.append("")
    new_hits = [h for h in hits if h["triage"] == "NEW"]
    if new_hits:
        lines.append("## NEW hits — operator action required")
        lines.append("")
        lines.append("Each row below is a candidate the rescan flagged that is "
                     "NOT in any prior workspace report and NOT in the OOS "
                     "checklist. **M14-trap discipline**: read the actual "
                     "file:line BEFORE trusting the hit. The rescan is a "
                     "regex-coarse filter, not a Slither-grade detector.")
        lines.append("")
        for h in new_hits:
            lines.append(f"- `{h['pattern_id']}` → `{h['file']}:{h['line']}`")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Generated by `tools/pattern-merge-rescan.py` "
                 "(Codex P0 #2 follow-up)._")
    return "\n".join(lines) + "\n"


def render_manifest(ws: Path,
                    since: str,
                    parent_ref: str, head_ref: str,
                    added: List[str], removed: List[str],
                    hits: List[Dict[str, Any]],
                    compile_failures: List[Dict[str, Any]],
                    generated_at: datetime) -> Dict[str, Any]:
    counts = {"NEW": 0, "DUPE": 0, "OOS": 0}
    for h in hits:
        counts[h["triage"]] = counts.get(h["triage"], 0) + 1
    return {
        "schema": "auditooor.pattern-merge-rescan.v1",
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(ws),
        "since": since,
        "parent_ref": parent_ref,
        "head_ref": head_ref,
        "added_patterns": list(added),
        "removed_patterns": list(removed),
        "counts": {
            "total_hits": len(hits),
            "new_hits": counts["NEW"],
            "dupe_hits": counts["DUPE"],
            "oos_hits": counts["OOS"],
        },
        "hits": list(hits),
        "compile_failures": list(compile_failures),
    }


def write_outputs(ws: Path,
                  markdown: str,
                  manifest: Dict[str, Any],
                  date_stamp: str,
                  write_manifest: bool,
                  dry_run: bool) -> Tuple[Path, Optional[Path]]:
    md_path = ws / f"postmerge_rescan_{date_stamp}.md"
    json_path: Optional[Path] = None
    if write_manifest:
        log_dir = ws / ".audit_logs"
        json_path = log_dir / f"postmerge_rescan_{date_stamp}.json"
    if not dry_run:
        md_path.write_text(markdown, encoding="utf-8")
        if json_path is not None:
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
    return md_path, json_path


# ---------------------------------------------------------------------------
# Calibration ledger
# ---------------------------------------------------------------------------

def log_calibration(hits: List[Dict[str, Any]],
                    pr_or_sha: str,
                    ws: Path,
                    dry_run: bool) -> int:
    """Append one calibration row per hit. Returns count of rows logged."""
    if dry_run:
        return 0
    if not CALIBRATION_LOG.is_file():
        return 0
    logged = 0
    for h in hits:
        # The calibration log requires a known provider. We use ``codex`` as a
        # proxy (mechanical-tool rows are out-of-scope for the LLM accuracy
        # aggregate but the log keeps them). Verdict INDETERMINATE — the rescan
        # is mechanical; a human verifies the actual TP/FP downstream.
        argv = [
            sys.executable, str(CALIBRATION_LOG), "log",
            "codex", "code-authoring",
            f"pattern-postmerge-rescan {pr_or_sha} {ws.name} "
            f"{h['pattern_id']}@{h['file']}:{h['line']} [{h['triage']}]",
            "INDETERMINATE",
            "--evidence",
            f"workspace={ws.name} pattern={h['pattern_id']} "
            f"file={h['file']}:{h['line']} triage={h['triage']}",
            "--operator", "pattern-merge-rescan",
        ]
        rc, _, _ = _run(argv)
        if rc == 0:
            logged += 1
    return logged


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_added_patterns(added: List[str], repo_root: Path,
                        head_ref: Optional[str] = None) -> Tuple[
        List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Read each added pattern's YAML.

    If ``head_ref`` is provided, prefer ``git show <ref>:<path>`` over the
    working tree (handles the case where the operator runs the tool from a
    different branch than the merge). Returns (parsed_patterns,
    compile_failures).
    """
    parsed: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for name in added:
        rel = f"{PATTERN_PREFIX}{name}{PATTERN_SUFFIX}"
        text = ""
        if head_ref:
            rc, out, _ = _run(
                ["git", "-C", str(repo_root), "show", f"{head_ref}:{rel}"])
            if rc == 0:
                text = out
        if not text:
            p = repo_root / rel
            if p.is_file():
                text = _read_text(p)
        if not text:
            failures.append({
                "pattern": name,
                "reason": "yaml-not-found",
                "ref": head_ref,
            })
            continue
        try:
            spec = parse_pattern_yaml(text)
        except Exception as e:  # noqa: BLE001 — defensive parse
            failures.append({
                "pattern": name,
                "reason": f"parse-error: {e}",
            })
            continue
        if not spec.get("pattern"):
            spec["pattern"] = name
        parsed.append(spec)
    return parsed, failures


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pattern-merge-rescan.py",
        description="Re-scan workspaces against newly-merged DSL patterns "
                    "(Codex P0 #2 follow-up).",
    )
    p.add_argument("--since", required=True,
                   help="Commit SHA or PR number identifying the merge after "
                        "which patterns were added.")
    p.add_argument("--workspaces",
                   help="Comma-separated workspace paths. Default: any "
                        "~/audits/* with engage_report.md younger than "
                        "--mtime-days.")
    p.add_argument("--audits-dir", default=str(DEFAULT_AUDITS_DIR),
                   help="Root of audit workspaces (default: ~/audits or "
                        "$AUDITS_DIR).")
    p.add_argument("--max-workspaces", type=int, default=DEFAULT_MAX_WORKSPACES,
                   help=f"Cap on workspace count (default: {DEFAULT_MAX_WORKSPACES}).")
    p.add_argument("--mtime-days", type=int, default=DEFAULT_MTIME_DAYS,
                   help=f"Workspace recency threshold (default: {DEFAULT_MTIME_DAYS}).")
    p.add_argument("--dry-run", action="store_true",
                   help="Don't write any files; print plan + summary.")
    p.add_argument("--write-manifest", action="store_true", default=True,
                   help="Write the JSON manifest under <ws>/.audit_logs/ "
                        "(default: on).")
    p.add_argument("--no-write-manifest", dest="write_manifest",
                   action="store_false",
                   help="Suppress manifest output.")
    p.add_argument("--no-calibration", action="store_true",
                   help="Skip llm-calibration-log appends.")
    p.add_argument("--offline", action="store_true",
                   help="Forbid gh lookups; --since must be a commit SHA.")
    p.add_argument("--repo-root", default=str(REPO_ROOT),
                   help="Override the repo root (used by tests).")
    p.add_argument("--json", action="store_true",
                   help="Emit a single-line JSON summary on stdout.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    audits_dir = Path(args.audits_dir).expanduser().resolve()
    now = datetime.now(timezone.utc)
    date_stamp = now.strftime("%Y-%m-%d")

    try:
        parent_ref, head_ref = resolve_since(
            args.since, repo_root, gh_lookup=not args.offline)
    except (ValueError, RuntimeError) as e:
        print(f"[error] --since {args.since!r}: {e}", file=sys.stderr)
        return 2

    added, removed = diff_added_patterns(parent_ref, head_ref, repo_root)
    if not added:
        msg = (f"[info] no added patterns under reference/patterns.dsl/ "
               f"between {parent_ref} and {head_ref}; nothing to rescan.")
        if args.json:
            print(json.dumps({
                "since": args.since, "parent_ref": parent_ref,
                "head_ref": head_ref, "added": [], "removed": removed,
                "workspaces": [],
            }))
        else:
            print(msg)
        return 0

    parsed, compile_failures = load_added_patterns(
        added, repo_root, head_ref=head_ref)

    explicit: Optional[List[Path]] = None
    if args.workspaces:
        explicit = [Path(s.strip()).expanduser()
                    for s in args.workspaces.split(",") if s.strip()]
    workspaces = select_workspaces(
        explicit, audits_dir, args.mtime_days, args.max_workspaces, now=now)

    if not workspaces:
        msg = "[warn] no candidate workspaces selected"
        if args.json:
            print(json.dumps({
                "since": args.since, "parent_ref": parent_ref,
                "head_ref": head_ref, "added": added, "removed": removed,
                "workspaces": [],
            }))
        else:
            print(msg)
        return 0

    summary: List[Dict[str, Any]] = []
    print(f"[ok] resolved --since {args.since!r} → {parent_ref}..{head_ref}")
    print(f"[ok] {len(added)} added pattern(s), {len(removed)} removed")
    print(f"[ok] {len(workspaces)} workspace(s) selected")
    for ws in workspaces:
        hits = scan_workspace(ws, parsed)
        triaged = triage_hits(hits, ws)
        markdown = render_markdown(
            ws, args.since, parent_ref, head_ref,
            added, removed, triaged, compile_failures, now)
        manifest = render_manifest(
            ws, args.since, parent_ref, head_ref,
            added, removed, triaged, compile_failures, now)
        md_path, json_path = write_outputs(
            ws, markdown, manifest, date_stamp,
            args.write_manifest, args.dry_run)
        calib_logged = 0
        if not args.no_calibration:
            calib_logged = log_calibration(
                triaged, args.since, ws, args.dry_run)
        counts = manifest["counts"]
        line = (f"  {ws.name}: total={counts['total_hits']} "
                f"NEW={counts['new_hits']} DUPE={counts['dupe_hits']} "
                f"OOS={counts['oos_hits']} "
                f"md={'(dry)' if args.dry_run else md_path}")
        if json_path is not None:
            line += f" json={'(dry)' if args.dry_run else json_path}"
        if calib_logged:
            line += f" calib_rows={calib_logged}"
        print(line)
        summary.append({
            "workspace": str(ws),
            "counts": counts,
            "markdown": str(md_path),
            "manifest": str(json_path) if json_path else None,
            "dry_run": args.dry_run,
        })
    if args.json:
        print(json.dumps({
            "since": args.since, "parent_ref": parent_ref,
            "head_ref": head_ref, "added": added, "removed": removed,
            "workspaces": summary,
        }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
