#!/usr/bin/env python3
"""Advisory-corpus-completeness gate (WHAT_WE_KEEP_MISSING #8, MechanizeGate #4).

r36-rebuttal: lane advisory-corpus-completeness registered; orchestrator commits
r37-rebuttal: read-only audit of tier-1 corpus; emits no records, fabricates nothing

WHY THIS EXISTS
---------------
The originality defense is only as strong as the advisory corpus it greps
against. The Zebra anchor (``docs/WHAT_WE_KEEP_MISSING.md`` section 8) is the
calibration fixture: the zebra miner baked only 4 of 10+ published GHSAs under
M14 / R37 anti-fabrication discipline, so the per-peer GHSAs that the filed
HIGHs cited were ABSENT from the corpus. An originality "clean" verdict against
that sparse corpus was a FALSE-clean. Nothing on disk verified the corpus was
COMPLETE for the target before the originality check was trusted.

This tool closes that gap. It compares the target's PUBLISHED advisory set
(the GHSA ids the live GitHub Security Advisories endpoint returns, via the
``tools/hackerman-etl-from-advisories.py`` loader) against the GHSA ids
actually INGESTED into that target's corpus tag dir, and fails CLOSED when any
published GHSA is missing from the corpus - listing the exact missing ids so
the operator can re-run the miner (or accept the gap via rebuttal).

This is the gate the master gate (MechanizeGate #4) calls.

VERDICTS
--------
  pass-advisory-corpus-complete    every published GHSA is present in the corpus
  fail-advisory-corpus-incomplete  >=1 published GHSA absent (missing ids listed)
  fail-no-published-advisories     could not enumerate the published set
                                   (live fetch returned 0 AND no cache) -> the
                                   completeness claim is unverifiable, so the
                                   gate fails CLOSED rather than passing blindly
  fail-corpus-dir-missing          the corpus tag dir does not exist / has no
                                   record.json files -> 0 ingested, cannot be
                                   complete unless 0 were published (handled by
                                   the published==0 branch above)
  ok-rebuttal                      a bounded ``advisory-corpus-rebuttal:`` marker
                                   explicitly accepts the gap
  error                            an unexpected failure (fails CLOSED)

A published-set of 0 with a cache present (an honest empty advisory repo) is a
PASS: 0 published <= 0 ingested is trivially complete. The
``fail-no-published-advisories`` verdict only fires when the published set is
UNKNOWN (no cache and the live fetch returned nothing), because then the
completeness claim cannot be evaluated and passing would re-arm the false-clean.

CLI
---
    # offline / deterministic (CI + master gate):
    python3 tools/advisory-corpus-completeness-check.py ZcashFoundation/zebra \\
        --cache-file /path/zebra-ghsa.json \\
        --records-dir audit/corpus_tags/tags/zebra_advisories --json

    # live fetch (calls gh api via the miner loader):
    python3 tools/advisory-corpus-completeness-check.py paradigmxyz/reth --json

The first positional argument is the target: either ``owner/repo`` (preferred)
or a workspace path whose ``.auditooor/advisory_target`` file names the repo.

EXIT CODES
----------
  0  pass-advisory-corpus-complete OR ok-rebuttal
  1  any fail-* verdict (fail-CLOSE)
  2  usage error

OVERRIDE
--------
Bounded marker (in the target's ``.auditooor/advisory_corpus_rebuttal.txt`` or
passed via ``--rebuttal``): ``advisory-corpus-rebuttal: <reason up to 200 chars>``.
An empty or oversized reason is ignored; the original fail verdict stands.

RELATED TOOLS (tool-duplication preflight, per CLAUDE.md operational anchor)
---------------------------------------------------------------------------
  * ``tools/hackerman-etl-from-advisories.py`` - the MINER this gate audits.
    It INGESTS published advisories into the corpus; this tool VERIFIES the
    ingestion is complete. Different direction (write vs read-only check),
    different output (corpus records vs pass/fail verdict + missing-id list).
  * ``tools/audit-completeness-check.py`` / ``tools/hunt-completeness-check.py``
    - completeness gates for the AUDIT / HUNT surfaces (engage stages, hunt
    lanes). This tool is the completeness gate for the ADVISORY-CORPUS surface
    specifically; orthogonal subject.
  * ``tools/detector-registry-completeness-check.py`` - completeness of the
    DETECTOR registry (documented patterns vs runnable detectors). Different
    corpus (detectors vs advisories).
  * ``tools/ghsa-requirements-check.py`` / ``tools/ghsa-advisory-export.py`` -
    GHSA submission-format / export helpers; not a corpus-completeness probe.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SUMMARY_SCHEMA = "auditooor.advisory_corpus_completeness.v1"

# GHSA ids are GHSA-xxxx-xxxx-xxxx (4-4-4 base32-ish). Case-insensitive match,
# normalized to upper for set comparison.
_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
_REBUTTAL_RE = re.compile(
    r"advisory-corpus-rebuttal:\s*(?P<reason>.+?)\s*$", re.IGNORECASE | re.MULTILINE
)


# ---------------------------------------------------------------------------
# load the miner module (the published-side loader)
# ---------------------------------------------------------------------------


def _load_miner() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_advisory_corpus_completeness_miner",
        str(REPO_ROOT / "tools" / "hackerman-etl-from-advisories.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def normalize_ghsa(value: object) -> Optional[str]:
    """Return the uppercase GHSA id found in *value*, or None."""
    if not isinstance(value, str):
        return None
    m = _GHSA_RE.search(value)
    return m.group(0).upper() if m else None


def published_ghsa_ids(advisories: List[Dict[str, Any]]) -> Set[str]:
    """Extract the set of published GHSA ids from a fetched advisory list."""
    ids: Set[str] = set()
    for adv in advisories or []:
        if not isinstance(adv, dict):
            continue
        # prefer the first-class ghsa_id field, fall back to any GHSA in url
        gid = normalize_ghsa(adv.get("ghsa_id")) or normalize_ghsa(
            adv.get("html_url") or adv.get("url")
        )
        if gid:
            ids.add(gid)
    return ids


def _ghsa_from_record(doc: Dict[str, Any]) -> Optional[str]:
    """Robustly extract the GHSA id from a corpus record.json document.

    Fallback chain: source_audit_ref (the GHSA html_url) -> record_id ->
    function_shape.shape_tags. Each carries the GHSA id verbatim per the
    miner's emit shape.
    """
    for key in ("source_audit_ref", "record_id"):
        gid = normalize_ghsa(doc.get(key))
        if gid:
            return gid
    shape = doc.get("function_shape")
    if isinstance(shape, dict):
        for tag in shape.get("shape_tags", []) or []:
            gid = normalize_ghsa(tag)
            if gid:
                return gid
    return None


def ingested_ghsa_ids(records_dir: Path) -> Tuple[Set[str], int]:
    """Walk *records_dir* for record.json files; return (ghsa id set, file count)."""
    ids: Set[str] = set()
    count = 0
    if not records_dir.exists():
        return ids, 0
    for rec in sorted(records_dir.rglob("record.json")):
        try:
            doc = json.loads(rec.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(doc, dict):
            continue
        count += 1
        gid = _ghsa_from_record(doc)
        if gid:
            ids.add(gid)
    return ids, count


def default_records_dir(repo: str) -> Path:
    """The miner's default tag dir for *repo* (owner/repo -> owner_repo_advisories)."""
    tok = repo.replace("/", "_")
    slug = re.sub(r"[^a-z0-9._:/-]+", "-", tok.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)[:80].strip("-._") or "record"
    return REPO_ROOT / "audit" / "corpus_tags" / "tags" / f"{slug}_advisories"


def resolve_target_repo(target: str) -> Optional[str]:
    """Resolve *target* to an ``owner/repo`` string.

    If *target* already looks like ``owner/repo`` and is not an existing
    directory, return it. Otherwise treat it as a workspace path and read
    ``<target>/.auditooor/advisory_target`` (first non-comment line).
    """
    p = Path(target).expanduser()
    looks_like_repo = bool(re.fullmatch(r"[^/\s]+/[^/\s]+", target))
    if looks_like_repo and not p.exists():
        return target
    if p.is_dir():
        marker = p / ".auditooor" / "advisory_target"
        if marker.is_file():
            for line in marker.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    return s
        # no marker; cannot resolve repo from a bare workspace
        return None
    if looks_like_repo:
        return target
    return None


def find_rebuttal(*, rebuttal_arg: Optional[str], workspace: Optional[Path]) -> Optional[str]:
    """Return a bounded (<=200 char, non-empty) rebuttal reason or None."""
    texts: List[str] = []
    if rebuttal_arg:
        texts.append(rebuttal_arg)
    if workspace is not None:
        marker = workspace / ".auditooor" / "advisory_corpus_rebuttal.txt"
        if marker.is_file():
            texts.append(marker.read_text(encoding="utf-8"))
    for blob in texts:
        m = _REBUTTAL_RE.search(blob)
        candidate = m.group("reason").strip() if m else blob.strip()
        if candidate and 0 < len(candidate) <= 200:
            return candidate
    return None


# ---------------------------------------------------------------------------
# core check
# ---------------------------------------------------------------------------


def check_completeness(
    *,
    repo: str,
    records_dir: Path,
    cache_file: Optional[Path] = None,
    rebuttal: Optional[str] = None,
    workspace: Optional[Path] = None,
    advisories: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Compare published vs ingested GHSA sets. *advisories* short-circuits the
    fetch for tests/determinism."""
    miner = _load_miner()

    if advisories is None:
        try:
            advisories = miner.load_advisories(repo, cache_file=cache_file)
        except Exception as exc:  # fail CLOSED on any loader failure
            return {
                "schema_version": SUMMARY_SCHEMA,
                "repo": repo,
                "verdict": "error",
                "reason": f"advisory load failed: {exc}",
                "published_count": 0,
                "ingested_count": 0,
                "missing_ghsa_ids": [],
                "extra_ingested_ghsa_ids": [],
                "records_dir": str(records_dir),
                "exit_code": 1,
            }

    published = published_ghsa_ids(advisories)
    ingested, ingested_files = ingested_ghsa_ids(records_dir)

    # Published set unknown: live fetch returned nothing AND no cache supplied.
    # The completeness claim is unverifiable -> fail CLOSED (do not false-clean).
    published_unknown = (not published) and cache_file is None and not advisories

    missing = sorted(published - ingested)
    extra = sorted(ingested - published)

    rebuttal_reason = find_rebuttal(rebuttal_arg=rebuttal, workspace=workspace)

    if published_unknown:
        verdict = "fail-no-published-advisories"
        reason = (
            "could not enumerate published advisories (live fetch returned 0 and "
            "no --cache-file); completeness is unverifiable, failing closed"
        )
    elif not published:
        # honest empty advisory repo (cache present, 0 advisories) -> complete
        verdict = "pass-advisory-corpus-complete"
        reason = "0 published advisories; corpus trivially complete"
    elif not records_dir.exists() or ingested_files == 0:
        verdict = "fail-corpus-dir-missing"
        reason = (
            f"corpus tag dir has no ingested records ({records_dir}); "
            f"{len(published)} published advisories absent"
        )
    elif missing:
        verdict = "fail-advisory-corpus-incomplete"
        reason = (
            f"{len(missing)} of {len(published)} published advisories are absent "
            f"from the corpus: {', '.join(missing)}"
        )
    else:
        verdict = "pass-advisory-corpus-complete"
        reason = (
            f"all {len(published)} published advisories present in the corpus "
            f"({ingested_files} record.json files ingested)"
        )

    # rebuttal can flip a fail to ok-rebuttal (never flips a pass)
    if verdict.startswith("fail") and rebuttal_reason:
        out_verdict = "ok-rebuttal"
        exit_code = 0
    else:
        out_verdict = verdict
        exit_code = 0 if verdict.startswith("pass") else 1

    return {
        "schema_version": SUMMARY_SCHEMA,
        "repo": repo,
        "verdict": out_verdict,
        "underlying_verdict": verdict,
        "reason": reason,
        "rebuttal_reason": rebuttal_reason,
        "published_count": len(published),
        "ingested_count": len(ingested),
        "ingested_record_files": ingested_files,
        "missing_ghsa_ids": missing,
        "extra_ingested_ghsa_ids": extra,
        "published_ghsa_ids": sorted(published),
        "records_dir": str(records_dir),
        "exit_code": exit_code,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        help="owner/repo (preferred) OR a workspace path whose "
        ".auditooor/advisory_target names the repo.",
    )
    parser.add_argument(
        "--records-dir",
        default=None,
        help="Corpus tag dir to audit (default "
        "audit/corpus_tags/tags/<owner>_<repo>_advisories).",
    )
    parser.add_argument(
        "--cache-file",
        default=None,
        help="Read published advisories from a saved JSON payload instead of "
        "calling gh api (offline / deterministic). Shape: [advisory,...] or "
        "{repo:[advisory,...]}.",
    )
    parser.add_argument(
        "--rebuttal",
        default=None,
        help="Inline 'advisory-corpus-rebuttal: <reason>' marker (<=200 chars).",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON summary")
    return parser


def _resolve(p: Optional[str]) -> Optional[Path]:
    if p is None:
        return None
    pp = Path(p).expanduser()
    return pp if pp.is_absolute() else (REPO_ROOT / pp)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    repo = resolve_target_repo(args.target)
    if not repo:
        print(
            f"error: cannot resolve target '{args.target}' to owner/repo "
            "(not owner/repo shape and no .auditooor/advisory_target marker)",
            file=sys.stderr,
        )
        return 2

    records_dir = _resolve(args.records_dir) or default_records_dir(repo)

    # workspace is the target path when it is a directory (for rebuttal marker)
    target_path = Path(args.target).expanduser()
    workspace = target_path if target_path.is_dir() else None

    summary = check_completeness(
        repo=repo,
        records_dir=records_dir,
        cache_file=_resolve(args.cache_file),
        rebuttal=args.rebuttal,
        workspace=workspace,
    )

    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "advisory-corpus-completeness: "
            f"repo={summary['repo']} "
            f"verdict={summary['verdict']} "
            f"published={summary['published_count']} "
            f"ingested={summary['ingested_count']} "
            f"missing={len(summary['missing_ghsa_ids'])} "
            f"-- {summary['reason']}"
        )
        if summary["missing_ghsa_ids"]:
            print("  missing GHSA ids: " + ", ".join(summary["missing_ghsa_ids"]))

    return summary["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
