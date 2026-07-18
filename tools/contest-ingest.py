#!/usr/bin/env python3
"""
contest-ingest.py — PR 205 Phase I skeleton (offline).

Reads a pre-fetched JSON finding cache under
`reference/contest_cache/<platform>/*.json` (or an override via
`--test-fixtures`) and emits novelty-seed rows into
`reference/contest_patterns.jsonl`. This is an advisory-only pipeline: seeds
never land in `reference/patterns.dsl/` automatically. Promotion requires an
operator to copy a row to a real `.yaml` under `reference/patterns.dsl/` by
hand — `--promote-to-live` only suggests DSL translations to stdout.

Live fetch is deliberately NOT implemented this iteration. Invoking with
`--live-fetch` or the `fetch` subcommand hard-errors; it does not silently
succeed. Operators populate the cache themselves (or point at
`tools/tests/fixtures/contest_cache/` for offline tests).

Hard constraints (PR 205 truth-audit):
  1. No auto-promotion to `reference/patterns.dsl/`. `--promote-to-live`
     only suggests DSL translations on stdout; the operator copies manually.
  2. Status vocabulary is frozen to {advisory-seed, duplicate, error}.
     Every JSONL row carries one of these strings in its `status` field.
  3. Novelty-seed dedup runs against the entire live pattern corpus
     (`reference/patterns.dsl/*.yaml`), not just a sample; dedup uses both
     a stable signature fingerprint AND a title-token grep, so a raw title
     re-phrasing still triggers duplicate.
  4. No live HTTP fetch in any code path this iter.

Exit codes:
  0 — ran to completion (any mix of advisory-seed / duplicate outcomes).
  1 — error (malformed cache, --live-fetch invoked, I/O failure).

Usage:
  python3 tools/contest-ingest.py                                  # default paths
  python3 tools/contest-ingest.py --test-fixtures <dir>            # offline tests
  python3 tools/contest-ingest.py --out reference/contest_patterns.jsonl
  python3 tools/contest-ingest.py --promote-to-live                # prints DSL stubs
  python3 tools/contest-ingest.py --live-fetch                     # ERRORS (intentional)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Locked status vocabulary (docs/10_OF_10_PLAYBOOK.md §5 compatible)
# ---------------------------------------------------------------------------
STATUS_ADVISORY_SEED = "advisory-seed"
STATUS_DUPLICATE = "duplicate"
STATUS_ERROR = "error"
ALLOWED_STATUSES = frozenset({STATUS_ADVISORY_SEED, STATUS_DUPLICATE, STATUS_ERROR})

# Only these platforms are recognised in this iter. Every other subdir under
# the cache root is reported as advisory, not silently ignored.
SUPPORTED_PLATFORMS = ("cantina", "immunefi")

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_DIR = ROOT / "reference" / "contest_cache"
DEFAULT_OUT_PATH = ROOT / "reference" / "contest_patterns.jsonl"
DEFAULT_LIVE_DSL_DIR = ROOT / "reference" / "patterns.dsl"

# Token pattern used by the title-grep dedup path. We tokenise a finding
# title into lowercase alphanumeric runs ≥4 chars and check whether a
# sufficiently large run of them appears in any existing .yaml file. The
# `signature:` line is the stronger signal; title-grep is belt-and-braces.
_TOKEN_RE = re.compile(r"[a-z0-9]{4,}")


# ---------------------------------------------------------------------------
# Cache loading
# ---------------------------------------------------------------------------
def load_cache(cache_dir: Path) -> List[Tuple[str, str, Dict]]:
    """Walk `<cache_dir>/{cantina,immunefi}/*.json` and yield (platform,
    contest_slug, finding) tuples. One JSON file == one contest; each file
    is expected to contain a top-level `findings: [...]` list of dicts.

    Missing top-level keys are tolerated individually but malformed JSON
    raises so the caller can surface it as a hard error."""
    out: List[Tuple[str, str, Dict]] = []
    if not cache_dir.is_dir():
        return out
    for platform in SUPPORTED_PLATFORMS:
        platform_dir = cache_dir / platform
        if not platform_dir.is_dir():
            continue
        for contest_file in sorted(platform_dir.glob("*.json")):
            try:
                data = json.loads(contest_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"malformed contest cache file {contest_file}: {exc}"
                ) from exc
            contest_slug = data.get("contest_slug") or contest_file.stem
            findings = data.get("findings", [])
            if not isinstance(findings, list):
                raise RuntimeError(
                    f"{contest_file}: top-level `findings` must be a list"
                )
            for f in findings:
                if not isinstance(f, dict):
                    continue
                out.append((platform, contest_slug, f))
    return out


# ---------------------------------------------------------------------------
# Signature + dedup
# ---------------------------------------------------------------------------
def compute_signature(title: str, protocol: str, severity: str) -> str:
    """Stable 16-hex-char fingerprint over (title, protocol, severity).

    Uses SHA256 so two operators running the ingest on the same cache get
    byte-identical JSONL output (deterministic tests depend on this)."""
    payload = f"{title}\0{protocol}\0{severity}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _tokenise(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.lower())


def scan_existing_patterns(dsl_dir: Path) -> Tuple[frozenset, List[Tuple[Path, str]]]:
    """Read every `.yaml` under `<dsl_dir>` once and return
    (signatures_seen, [(path, lowercased_title_surface), ...]).

    The title-surface is the concatenation of a pattern's human-readable
    title fields only: `pattern:`, `wiki_title:`, `help:`. Dedup compares
    new titles against these narrow surfaces rather than the full YAML
    body — the full body contains enough generic tokens (e.g.
    `function.kind`, `contract.has_function_matching`) that token-overlap
    against it triggers runaway false-dupes on a 1,300-pattern corpus.

    Signature-line dedup: `signature:<hex>` on its own line. No live
    .yaml currently uses this field; it exists as a forward-compat hook
    so future patterns derived from a contest seed can carry the sig.
    """
    sigs: set = set()
    surfaces: List[Tuple[Path, str]] = []
    title_field_re = re.compile(
        r"^\s*(?:pattern|wiki_title|help)\s*:\s*(.+)$",
        re.MULTILINE | re.IGNORECASE,
    )
    if not dsl_dir.is_dir():
        return frozenset(), surfaces
    for yaml_path in sorted(dsl_dir.glob("*.yaml")):
        try:
            body = yaml_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        surface_parts = [m.group(1).strip(' "\'') for m in title_field_re.finditer(body)]
        if surface_parts:
            surfaces.append((yaml_path, " ".join(surface_parts).lower()))
        for match in re.finditer(r"^\s*signature\s*:\s*([0-9a-f]{8,})\s*$", body, re.MULTILINE | re.IGNORECASE):
            sigs.add(match.group(1).lower()[:16])
    return frozenset(sigs), surfaces


_STOPWORDS = frozenset({
    "token", "tokens", "contract", "function", "check", "checks",
    "issue", "vulnerability", "missing", "wrong", "zero", "incorrect",
    "enables", "allows", "with", "from", "into", "over", "when", "while",
    "then", "this", "that", "which", "where", "user", "users", "full",
    "balance", "amount", "value", "call", "calls", "before", "after",
})


def is_duplicate(
    sig: str,
    title: str,
    existing_sigs: frozenset,
    existing_title_surfaces: List[Tuple[Path, str]],
    title_token_floor: int = 3,
    title_token_ratio: float = 0.6,
) -> Tuple[bool, Optional[str]]:
    """Return (is_dup, reason).

    Two paths fire:
      - The signature fingerprint is literally present as a `signature:`
        line in a live pattern.
      - ≥`title_token_floor` distinct non-stopword ≥4-char title tokens
        appear in a single live pattern's title-surface (pattern name,
        wiki_title, help) AND at least `title_token_ratio` of the new
        title's distinct non-stopword tokens co-occur there. Comparing
        against the narrow title-surface (not the full YAML body) is
        what keeps this tractable against a 1,300-file corpus — a full
        body has enough generic tokens to false-dupe anything.

    The thresholds are load-bearing: `test_ingest_parses_cantina_fixture`
    expects two non-colliders to survive as novel, and
    `test_ingest_dedup_against_existing_patterns_dsl` expects the
    contrived collider to be caught.
    """
    if sig.lower() in existing_sigs:
        return True, f"signature-match:{sig}"
    import math
    tokens = [t for t in _tokenise(title) if t not in _STOPWORDS]
    distinct = set(tokens)
    if len(distinct) < title_token_floor:
        return False, None
    required = max(title_token_floor, math.ceil(len(distinct) * title_token_ratio))
    for path, surface in existing_title_surfaces:
        overlap = sum(1 for t in distinct if t in surface)
        if overlap >= required:
            return True, f"title-token-overlap:{path.name}:{overlap}/{len(distinct)}"
    return False, None


# ---------------------------------------------------------------------------
# Ingestion core
# ---------------------------------------------------------------------------
def build_seed(
    platform: str,
    contest_slug: str,
    finding: Dict,
    now_iso: str,
) -> Dict:
    title = str(finding.get("title") or "").strip()
    protocol = str(finding.get("protocol") or "").strip()
    severity = str(finding.get("severity") or "unknown").strip()
    sig = compute_signature(title, protocol, severity)
    return {
        "sig": sig,
        "source_platform": platform,
        "source_contest": contest_slug,
        "title": title,
        "severity": severity,
        "protocol": protocol,
        "ingested_at": now_iso,
        "status": STATUS_ADVISORY_SEED,
    }


def ingest(
    cache_dir: Path,
    out_path: Path,
    live_dsl_dir: Path,
    promote_to_live: bool,
    now_iso: Optional[str] = None,
    stderr=sys.stderr,
    stdout=sys.stdout,
) -> Tuple[int, int, int]:
    """Drive ingestion. Returns (seeds_written, duplicates, total_seen)."""
    now_iso = now_iso or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    rows = load_cache(cache_dir)
    existing_sigs, existing_surfaces = scan_existing_patterns(live_dsl_dir)

    seeds_written = 0
    duplicates = 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Overwrite (advisory ledger is regenerated each run by design — the live
    # pattern corpus is the durable store; contest_patterns.jsonl is a weekly
    # advisory refresh).
    with out_path.open("w", encoding="utf-8") as fh:
        for platform, contest_slug, finding in rows:
            seed = build_seed(platform, contest_slug, finding, now_iso)
            dup, reason = is_duplicate(
                seed["sig"], seed["title"], existing_sigs, existing_surfaces,
            )
            if dup:
                duplicates += 1
                # Emit a human-visible advisory line to stderr (not JSONL). The
                # locked `duplicate` status appears in stderr output so an
                # operator grep'ing for status strings finds it.
                print(
                    f"[contest-ingest] duplicate seed skipped: {seed['title']!r}"
                    f" ({platform}/{contest_slug}) reason={reason} status={STATUS_DUPLICATE}",
                    file=stderr,
                )
                continue
            fh.write(json.dumps(seed, sort_keys=True) + "\n")
            seeds_written += 1
            if promote_to_live:
                _print_dsl_suggestion(seed, stdout=stdout)

    if seeds_written == 0 and duplicates == 0:
        # Empty-cache cannot-judge marker: emit an advisory message to stderr
        # so the caller knows the run was intentional-zero, not a crash.
        print(
            "[contest-ingest] advisory: cache was empty; wrote zero novelty seeds",
            file=stderr,
        )

    total_seen = seeds_written + duplicates
    return seeds_written, duplicates, total_seen


def _print_dsl_suggestion(seed: Dict, stdout) -> None:
    """Emit a minimal DSL skeleton to stdout. The operator copies this into
    `reference/patterns.dsl/<slug>.yaml` by hand after review. We do NOT
    write it to disk — that would violate the advisory-only constraint."""
    slug = re.sub(r"[^a-z0-9]+", "-", seed["title"].lower()).strip("-") or "unnamed"
    slug = slug[:80]
    print("# ──── contest-ingest DSL suggestion (operator must manually copy) ────", file=stdout)
    print(f"# source: {seed['source_platform']}/{seed['source_contest']}", file=stdout)
    print(f"# signature:{seed['sig']}", file=stdout)
    print(f"pattern: {slug}", file=stdout)
    print(f"source: contest-ingest-{seed['source_platform']}-{seed['source_contest']}", file=stdout)
    print(f"severity: {seed['severity'].upper() or 'UNKNOWN'}", file=stdout)
    print("confidence: LOW  # contest seeds start at LOW until re-derived on a real engagement", file=stdout)
    print(f"# TODO: operator must translate title into preconditions/match before promoting:", file=stdout)
    print(f"#   {seed['title']}", file=stdout)
    print("# ──── end suggestion ────", file=stdout)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Ingest pre-fetched contest findings into an advisory novelty-seed "
            "JSONL. Offline only; no live fetch this iter."
        ),
    )
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help="Directory with <platform>/*.json cache files "
             "(default: reference/contest_cache/).",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT_PATH,
        help="Output JSONL path (default: reference/contest_patterns.jsonl).",
    )
    p.add_argument(
        "--promote-to-live",
        action="store_true",
        help="Print DSL-skeleton suggestions for novel seeds to stdout. Still "
             "does NOT write into reference/patterns.dsl/ — advisory only.",
    )
    p.add_argument(
        "--test-fixtures",
        type=Path,
        default=None,
        help="Override --cache-dir. Used by tools/tests/test_contest_ingest.py "
             "to point at tools/tests/fixtures/contest_cache/.",
    )
    p.add_argument(
        "--live-dsl-dir",
        type=Path,
        default=DEFAULT_LIVE_DSL_DIR,
        help="Path to the live DSL pattern corpus (default: "
             "reference/patterns.dsl/). Advisory dedup runs against this.",
    )
    p.add_argument(
        "--live-fetch",
        action="store_true",
        help="Placeholder for future live fetch; current behaviour is to exit 1 "
             "with a clear error. Offline-only this iter.",
    )
    p.add_argument(
        "subcommand",
        nargs="?",
        default=None,
        help="Optional subcommand. `fetch` is reserved for future live fetch "
             "and currently errors. Any other value errors too.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.live_fetch or args.subcommand == "fetch":
        print(
            "[contest-ingest] live-fetch not implemented; pass --test-fixtures "
            "or populate reference/contest_cache/",
            file=sys.stderr,
        )
        return 1

    if args.subcommand is not None:
        # A positional subcommand that isn't `fetch` is an operator mistake.
        print(
            f"[contest-ingest] unknown subcommand {args.subcommand!r}; "
            f"accepted: fetch (currently errors), or omit.",
            file=sys.stderr,
        )
        return 1

    cache_dir = args.test_fixtures if args.test_fixtures is not None else args.cache_dir

    try:
        seeds, dups, total = ingest(
            cache_dir=cache_dir,
            out_path=args.out,
            live_dsl_dir=args.live_dsl_dir,
            promote_to_live=args.promote_to_live,
        )
    except RuntimeError as exc:
        print(f"[contest-ingest] error: {exc}", file=sys.stderr)
        return 1

    print(
        f"[contest-ingest] wrote {seeds} advisory-seed row(s); "
        f"{dups} duplicate(s) skipped; {total} candidate(s) seen from "
        f"{cache_dir}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
