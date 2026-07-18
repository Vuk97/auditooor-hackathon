#!/usr/bin/env python3
"""cross-engagement-fanout — Wave-7 BIG_PLAN A6 deliverable.

For each filed CRITICAL/HIGH in source engagement A, extract its bug-class
shape (file pattern + function signature shape + key invariants), then scan
destination engagement B's source tree for matching shapes. Surface matches
as "fanout candidates" with confidence + provenance.

Pipeline:

1. Walk ``audit/corpus_tags/tags/*.yaml`` for verdicts with
   ``target_repo`` matching ``--source-engagement``'s repo family (e.g.
   dydx → dydxprotocol/*).
2. Keep only ``verdict_class in {FILED, CONFIRMED}`` and
   ``severity_claimed in {CRITICAL, HIGH}`` (override via ``--bug-class``).
3. For each surviving verdict, extract a pattern shape:
     * ``file_path_pattern``  — regex over each ``sites[].file_path``
     * ``shape_hashes``       — set of ``shape_hash`` over all sites
     * ``bug_class``          — copied verbatim
     * ``key_invariants``     — list of regex patterns derived from the
                                 verdict's ``attack_classes_to_try`` slug
     * ``function_names``     — set of ``sites[].function_name``
4. Persist each pattern to
   ``audit/fanout_patterns/<source>_<verdict-id-slug>.yaml``.
5. Scan destination engagement's source tree
   (``~/audits/<engagement>/external/``) for files matching the pattern.
   Match scoring is the sum of:
     * 0.40 — file_path_pattern matches the file
     * 0.30 — at least one shape_hash matches (via best-effort sig-extract
              lookup OR by-fn-name match against the dest tree)
     * 0.30 — at least one function name from source appears in the dest
6. Emit ``<dest-ws>/fanout_candidates_from_<source>_<ts>.md`` with the
   top-10 matches.

Designed to be incremental: re-running emits a new timestamped report and
overwrites the pattern files in ``audit/fanout_patterns/``.
"""
from __future__ import annotations

# r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json
import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore


REPO_ROOT = Path(__file__).resolve().parents[1]
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
PATTERNS_DIR = REPO_ROOT / "audit" / "fanout_patterns"


# Engagement → upstream repo prefix mapping. Used to filter verdicts by
# ``target_repo`` field. New engagements append here.
ENGAGEMENT_REPO_PREFIXES: Dict[str, List[str]] = {
    "dydx": ["dydxprotocol/", "cosmos/cosmos-sdk", "cosmos/iavl",
             "cometbft/cometbft", "skip-mev/slinky"],
    "spark": ["buildonspark/spark", "lightsparkdev/"],
    "base-azul": ["base-org/azul", "base-org/op-rs"],
    "morpho": ["morpho-org/"],
    "centrifuge-v3": ["centrifuge/"],
    "polymarket": ["polymarket/"],
    "reserve-governor": ["reserve-protocol/"],
    "kiln-v1": ["kiln/"],
    "monetrix": ["monetrix-protocol/"],
    "k2": ["k2-finance/"],
    "thegraph": ["graphprotocol/"],
    "revert-stableswap-hooks": ["revert-finance/"],
    "snowbridge": ["Snowfork/"],
}


# Severity threshold for inclusion. Override with ``--include-medium``.
DEFAULT_SEVERITIES = {"CRITICAL", "HIGH"}
INCLUDED_VERDICT_CLASSES = {"FILED", "CONFIRMED"}


# ---------------------------------------------------------------------------
# Datatypes
# ---------------------------------------------------------------------------


@dataclass
class FanoutPattern:
    """Derived bug-class shape ready for fan-out scanning."""

    source_engagement: str
    source_verdict_id: str
    bug_class: str
    severity: str
    target_repo: str
    file_path_pattern: str
    shape_hashes: List[str]
    function_names: List[str]
    key_invariants: List[str]
    audit_pin_sha: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_engagement": self.source_engagement,
            "source_verdict_id": self.source_verdict_id,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "target_repo": self.target_repo,
            "file_path_pattern": self.file_path_pattern,
            "shape_hashes": self.shape_hashes,
            "function_names": self.function_names,
            "key_invariants": self.key_invariants,
            "audit_pin_sha": self.audit_pin_sha,
        }

    def slug(self) -> str:
        # Last path segment of verdict_id, sans extension
        last = self.source_verdict_id.rsplit("/", 1)[-1]
        last = re.sub(r"\.md(\.yaml)?$", "", last)
        last = re.sub(r"[^A-Za-z0-9_-]+", "-", last).strip("-")
        return last[:120] or "pattern"


@dataclass
class FanoutMatch:
    """One destination-tree match for a pattern."""

    pattern_slug: str
    bug_class: str
    severity: str
    dest_file: str
    matched_function: str = ""
    file_pattern_hit: bool = False
    shape_hash_hit: bool = False
    function_name_hit: bool = False
    invariant_hits: List[str] = field(default_factory=list)
    score: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pattern_slug": self.pattern_slug,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "dest_file": self.dest_file,
            "matched_function": self.matched_function,
            "file_pattern_hit": self.file_pattern_hit,
            "shape_hash_hit": self.shape_hash_hit,
            "function_name_hit": self.function_name_hit,
            "invariant_hits": self.invariant_hits,
            "score": round(self.score, 3),
        }


# ---------------------------------------------------------------------------
# Pattern shape extraction
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    if yaml is None:
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None


def _verdict_belongs_to(engagement: str, target_repo: str) -> bool:
    prefixes = ENGAGEMENT_REPO_PREFIXES.get(engagement, [])
    if not prefixes:
        return False
    tr = (target_repo or "").lower()
    return any(tr.startswith(p.lower()) or p.lower() in tr for p in prefixes)


def _derive_file_path_pattern(file_paths: List[str]) -> str:
    """Build a regex matching all source file_paths (or a common suffix)."""
    if not file_paths:
        return r".*"
    # If a single file, anchor on suffix (basename) for portability across forks.
    if len(file_paths) == 1:
        bn = Path(file_paths[0]).name
        return rf".*/{re.escape(bn)}$"
    # Multi-site: union the basenames.
    basenames = sorted({Path(p).name for p in file_paths if p})
    if not basenames:
        return r".*"
    return r".*/(?:" + "|".join(re.escape(b) for b in basenames) + r")$"


def _derive_key_invariants(bug_class: str, attack_classes: List[str]) -> List[str]:
    """Derive grep regexes that should be PRESENT in suspicious dest code."""
    tokens: List[str] = []
    if bug_class:
        tokens.extend(re.split(r"[-_/]+", bug_class))
    for ac in attack_classes or []:
        tokens.extend(re.split(r"[-_/]+", ac))
    # filter trivials
    stop = {"the", "and", "via", "vs", "from", "to", "in", "on", "a",
            "of", "for", "with", "by", ""}
    out: List[str] = []
    for t in tokens:
        t = t.strip().lower()
        if not t or t in stop or len(t) < 4:
            continue
        out.append(rf"(?i){re.escape(t)}")
    # de-dup while preserving order
    seen = set()
    dedup: List[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            dedup.append(x)
    return dedup[:8]


def extract_pattern(
    tag_yaml: Dict[str, Any],
    source_engagement: str,
) -> Optional[FanoutPattern]:
    sites = tag_yaml.get("sites") or []
    file_paths = [s.get("file_path", "") for s in sites if s.get("file_path")]
    shape_hashes = sorted({
        s.get("shape_hash") for s in sites if s.get("shape_hash")
    } | {
        s.get("shape_hash_fine") for s in sites if s.get("shape_hash_fine")
    })
    shape_hashes = [h for h in shape_hashes if h]
    fn_names = sorted({
        s.get("function_name", "") for s in sites if s.get("function_name")
    })
    bug_class = tag_yaml.get("bug_class", "") or ""
    attack_classes = tag_yaml.get("attack_classes_to_try", []) or []
    sev = (tag_yaml.get("severity_final")
           or tag_yaml.get("severity_claimed")
           or "UNKNOWN")
    return FanoutPattern(
        source_engagement=source_engagement,
        source_verdict_id=tag_yaml.get("verdict_id", ""),
        bug_class=bug_class,
        severity=sev,
        target_repo=tag_yaml.get("target_repo", ""),
        file_path_pattern=_derive_file_path_pattern(file_paths),
        shape_hashes=shape_hashes,
        function_names=fn_names,
        key_invariants=_derive_key_invariants(bug_class, attack_classes),
        audit_pin_sha=tag_yaml.get("audit_pin_sha", "") or "",
    )


# Module-level cache of the parsed tags corpus. Globbing + YAML-parsing the
# entire TAGS_DIR (often tens of thousands of files) once per source
# engagement is the second hot path behind the unbounded fanout walk. We
# parse the corpus ONCE per process and filter in-memory per engagement.
# r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json
_TAGS_CORPUS_CACHE: Optional[List[Dict[str, Any]]] = None


def _load_tags_corpus() -> List[Dict[str, Any]]:
    """Parse every tag YAML in TAGS_DIR once and memoize the result."""
    global _TAGS_CORPUS_CACHE
    if _TAGS_CORPUS_CACHE is not None:
        return _TAGS_CORPUS_CACHE
    corpus: List[Dict[str, Any]] = []
    if TAGS_DIR.exists():
        for tag_file in sorted(TAGS_DIR.glob("*.yaml")):
            data = _load_yaml(tag_file)
            if data:
                corpus.append(data)
    _TAGS_CORPUS_CACHE = corpus
    return corpus


def load_source_patterns(
    source_engagement: str,
    bug_class_filter: Optional[str] = None,
    severities: Optional[set] = None,
) -> List[FanoutPattern]:
    severities = severities or DEFAULT_SEVERITIES
    out: List[FanoutPattern] = []
    for data in _load_tags_corpus():
        if not _verdict_belongs_to(source_engagement, data.get("target_repo", "")):
            continue
        if data.get("verdict_class") not in INCLUDED_VERDICT_CLASSES:
            continue
        sev = (data.get("severity_final") or data.get("severity_claimed") or "").upper()
        if sev and sev not in severities:
            continue
        if bug_class_filter and bug_class_filter.lower() not in (
                data.get("bug_class", "") or "").lower():
            continue
        patt = extract_pattern(data, source_engagement)
        if patt is None:
            continue
        out.append(patt)
    return out


def persist_patterns(patterns: List[FanoutPattern]) -> List[Path]:
    if yaml is None:
        return []
    PATTERNS_DIR.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for p in patterns:
        out_path = PATTERNS_DIR / f"{p.source_engagement}_{p.slug()}.yaml"
        out_path.write_text(
            yaml.safe_dump(p.as_dict(), sort_keys=False),
            encoding="utf-8",
        )
        written.append(out_path)
    return written


# ---------------------------------------------------------------------------
# Destination tree scan
# ---------------------------------------------------------------------------


# Filename extensions to scan in the destination tree
DEST_SUFFIXES = (".go", ".rs", ".sol", ".ts", ".py")

# Default destination-file cap and wall-clock budget for the fanout walk.
# On large monorepo external/ trees (e.g. aztec-packages = 38,739 files /
# 4.2 GB) an unbounded walk pins a core at 100% CPU for tens of minutes and
# never completes. These bounds make the walk degrade gracefully instead of
# spinning. Both are overridable per-call and via env.
DEFAULT_MAX_DEST_FILES = int(os.environ.get("FANOUT_MAX_DEST_FILES", "4000"))
DEFAULT_SCAN_BUDGET_SECONDS = float(
    os.environ.get("FANOUT_SCAN_BUDGET_SECONDS", "60")
)


def iter_dest_files(
    dest_root: Path,
    max_dest_files: Optional[int] = None,
    deadline: Optional[float] = None,
) -> Iterable[Path]:
    """Walk the destination external/ tree. Skip vendor/node_modules/etc.

    r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json

    ``max_dest_files`` caps the number of files yielded (<=0 / None means the
    default cap; pass a very large number to effectively disable). ``deadline``
    is a ``time.monotonic()`` timestamp after which the walk stops yielding.
    """
    if max_dest_files is None or max_dest_files <= 0:
        max_dest_files = DEFAULT_MAX_DEST_FILES
    skip = {".git", "node_modules", "vendor", "third_party", "target",
            "dist", "build", ".cache"}
    yielded = 0
    for path in dest_root.rglob("*"):
        if deadline is not None and time.monotonic() >= deadline:
            break
        if path.is_dir():
            continue
        if any(part in skip for part in path.parts):
            continue
        if path.suffix not in DEST_SUFFIXES:
            continue
        yield path
        yielded += 1
        if yielded >= max_dest_files:
            break


def match_pattern_against_file(
    pattern: FanoutPattern,
    dest_file: Path,
    rel_path: str,
    file_text_cache: Dict[Path, str],
) -> Optional[FanoutMatch]:
    """Score a single destination file against a pattern. Returns None if score=0."""
    file_pattern_hit = bool(re.match(pattern.file_path_pattern, rel_path)
                            or re.match(pattern.file_path_pattern,
                                        str(dest_file.name)))
    # Load text only if needed (file is candidate by name or in fn-name path)
    needs_text = file_pattern_hit or bool(pattern.function_names) or bool(
        pattern.key_invariants)
    text = ""
    if needs_text:
        if dest_file in file_text_cache:
            text = file_text_cache[dest_file]
        else:
            try:
                text = dest_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            file_text_cache[dest_file] = text

    matched_fn = ""
    fn_hit = False
    for fn in pattern.function_names:
        if not fn:
            continue
        # Look for `func ... <fn>(` (Go) / `fn <fn>(` (Rust) / `function <fn>(`
        if re.search(rf"\b{re.escape(fn)}\s*\(", text) or re.search(
                rf"\bfn\s+{re.escape(fn)}\b", text) or re.search(
                rf"\bfunction\s+{re.escape(fn)}\b", text):
            fn_hit = True
            matched_fn = fn
            break

    invariant_hits: List[str] = []
    for inv in pattern.key_invariants:
        try:
            if re.search(inv, text):
                invariant_hits.append(inv)
        except re.error:
            continue

    # Shape-hash hit: best-effort by inspecting the dest file for shape-hash
    # sidecar (rare). We treat the presence of a function-name match together
    # with a high-density invariant match as a proxy.
    shape_hit = fn_hit and len(invariant_hits) >= 2

    score = 0.0
    if file_pattern_hit:
        score += 0.40
    if shape_hit:
        score += 0.30
    if fn_hit:
        score += 0.30
    if not file_pattern_hit and not fn_hit and not invariant_hits:
        return None
    # invariant-only weak match
    if not file_pattern_hit and not fn_hit:
        score = 0.10 * min(len(invariant_hits), 3)

    return FanoutMatch(
        pattern_slug=pattern.slug(),
        bug_class=pattern.bug_class,
        severity=pattern.severity,
        dest_file=rel_path,
        matched_function=matched_fn,
        file_pattern_hit=file_pattern_hit,
        shape_hash_hit=shape_hit,
        function_name_hit=fn_hit,
        invariant_hits=invariant_hits,
        score=score,
    )


def scan_destination(
    patterns: List[FanoutPattern],
    dest_root: Path,
    top_n: int = 10,
    max_dest_files: Optional[int] = None,
    budget_seconds: Optional[float] = None,
) -> List[FanoutMatch]:
    # r36-rebuttal: lane aztec-brainprime-fix registered in agent_pathspec.json
    if not dest_root.exists():
        return []
    if budget_seconds is None:
        budget_seconds = DEFAULT_SCAN_BUDGET_SECONDS
    deadline = (time.monotonic() + budget_seconds) if budget_seconds and budget_seconds > 0 else None
    matches: List[FanoutMatch] = []
    file_text_cache: Dict[Path, str] = {}
    for dest_file in iter_dest_files(dest_root, max_dest_files=max_dest_files,
                                     deadline=deadline):
        if deadline is not None and time.monotonic() >= deadline:
            break
        rel_path = str(dest_file.relative_to(dest_root)) if dest_file.is_relative_to(dest_root) else str(dest_file)
        for p in patterns:
            m = match_pattern_against_file(p, dest_file, rel_path, file_text_cache)
            if m and m.score > 0:
                matches.append(m)
    matches.sort(key=lambda x: x.score, reverse=True)
    return matches[: top_n if top_n > 0 else len(matches)]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def emit_report(
    dest_ws: Path,
    source: str,
    dest: str,
    patterns: List[FanoutPattern],
    matches: List[FanoutMatch],
    bug_class_filter: Optional[str],
) -> Path:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = dest_ws / f"fanout_candidates_from_{source}_{ts}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    lines.append(f"# Cross-engagement fanout: {source} → {dest}")
    lines.append("")
    lines.append(f"- generated_at_utc: `{_dt.datetime.now(_dt.timezone.utc).isoformat()}`")
    lines.append(f"- source_engagement: `{source}`")
    lines.append(f"- dest_engagement: `{dest}`")
    if bug_class_filter:
        lines.append(f"- bug_class_filter: `{bug_class_filter}`")
    lines.append(f"- source_patterns_loaded: {len(patterns)}")
    lines.append(f"- destination_matches: {len(matches)}")
    lines.append("")
    lines.append("## Source patterns")
    lines.append("")
    if not patterns:
        lines.append("_No patterns loaded for source engagement (check ENGAGEMENT_REPO_PREFIXES)._")
    else:
        for p in patterns:
            lines.append(f"- `{p.slug()}` — bug_class=`{p.bug_class}` "
                         f"severity=`{p.severity}` "
                         f"target_repo=`{p.target_repo}` "
                         f"shape_hashes={len(p.shape_hashes)} "
                         f"functions={len(p.function_names)}")
    lines.append("")
    lines.append("## Top fanout matches")
    lines.append("")
    if not matches:
        lines.append("_No destination matches scored above the threshold._")
    else:
        lines.append("| Score | Bug class | Pattern | Dest file | Matched fn | Reasons |")
        lines.append("|------:|-----------|---------|-----------|------------|---------|")
        for m in matches:
            reasons = []
            if m.file_pattern_hit:
                reasons.append("file-pattern")
            if m.function_name_hit:
                reasons.append("fn-name")
            if m.shape_hash_hit:
                reasons.append("shape-hash")
            if m.invariant_hits:
                reasons.append(f"inv={len(m.invariant_hits)}")
            lines.append(
                f"| {m.score:.2f} | {m.bug_class} | `{m.pattern_slug}` | "
                f"`{m.dest_file}` | `{m.matched_function}` | "
                f"{', '.join(reasons)} |"
            )
    lines.append("")
    lines.append("## Operator action")
    lines.append("")
    lines.append("Top-scored matches with score ≥ 0.40 are worth a manual check.")
    lines.append("Spawn a worker brief per surviving candidate; do NOT auto-file.")
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-engagement", required=True,
                    help="Engagement slug whose FILED CRIT/HIGH verdicts feed patterns.")
    ap.add_argument("--dest-engagement", required=True,
                    help="Engagement slug whose source tree gets scanned.")
    ap.add_argument("--bug-class", default=None,
                    help="Restrict patterns to those whose bug_class contains "
                         "this substring (case-insensitive).")
    ap.add_argument("--audits-root", type=Path,
                    default=Path(os.path.expanduser("~/audits")),
                    help="Root of the engagement workspaces.")
    ap.add_argument("--include-medium", action="store_true",
                    help="Also pull MEDIUM-severity verdicts.")
    ap.add_argument("--top-n", type=int, default=10,
                    help="Top N matches to emit (default 10).")
    ap.add_argument("--persist-patterns", action="store_true",
                    help="Also write each pattern to audit/fanout_patterns/.")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON summary to stdout.")
    args = ap.parse_args(argv)

    severities = set(DEFAULT_SEVERITIES)
    if args.include_medium:
        severities.add("MEDIUM")

    patterns = load_source_patterns(
        args.source_engagement,
        bug_class_filter=args.bug_class,
        severities=severities,
    )

    if args.persist_patterns:
        persist_patterns(patterns)

    dest_ws = (args.audits_root / args.dest_engagement).expanduser()
    dest_external = dest_ws / "external"
    matches = scan_destination(patterns, dest_external, top_n=args.top_n)

    if dest_ws.exists():
        report = emit_report(
            dest_ws, args.source_engagement, args.dest_engagement,
            patterns, matches, args.bug_class,
        )
    else:
        report = None

    summary = {
        "source_engagement": args.source_engagement,
        "dest_engagement": args.dest_engagement,
        "patterns_loaded": len(patterns),
        "matches": [m.as_dict() for m in matches],
        "report_path": str(report) if report else None,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"cross-engagement-fanout: {args.source_engagement} → {args.dest_engagement}")
        print(f"  patterns={len(patterns)} matches={len(matches)} report={report}")
        for m in matches[:10]:
            print(f"  [{m.score:.2f}] {m.bug_class} :: {m.dest_file} fn={m.matched_function}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
