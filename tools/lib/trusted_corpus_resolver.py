#!/usr/bin/env python3
"""Shared trusted-corpus resolver (Phase 1 enforcement wiring; PR2b).

PURPOSE
-------
Phase 1 of docs/FIND_ALL_BUGS_CAPABILITY_UPLIFT_PLAN_2026-05-29.md introduces a
TRUSTED corpus index that distinguishes scorable, source-backed records
(`active`) from advisory / prose-only / quarantined rows. Active hunt, originality,
and backtest scoring must read the TRUSTED index by default - never the raw,
unfiltered corpus tree - so fabricated / hallucinated / prose-only rows can never
silently drive a hypothesis or a score.

This module is the single resolution point those consumers call. It is
intentionally side-effect-free and import-light so it can be vendored into any
consumer (originality / backtest / hunt-guidance) without a heavy dependency.

CONTRACT
--------
resolve_active_corpus(repo_root=None, include_advisory=False) -> CorpusResolution

  - When the trusted index (reference/corpus_trust/TRUSTED_CORPUS_INDEX.jsonl)
    exists, returns trust_scope='active' and points consumers at it. With
    include_advisory=True (operator opt-in, mirrors INCLUDE_ADVISORY=1) the
    advisory ledger is added.
  - When the trusted index is ABSENT (e.g. before PR1 builds it), returns
    trust_scope='raw-fallback' pointing at the raw corpus root, and sets
    `is_fallback=True` so the consumer can warn / annotate its output. This is a
    graceful degrade, NOT a silent equivalence: the resolution object always
    states which scope it returned.

Env overrides (highest precedence first):
  AUDITOOOR_TRUSTED_CORPUS_INDEX  - explicit path to the trusted index jsonl
  AUDITOOOR_CORPUS_TRUST_DIR      - dir holding the corpus_trust ledgers
  INCLUDE_ADVISORY=1              - include advisory ledger (same as kwarg)

RELATED TOOLS:
  - tools/corpus-quality-routing.py  (PR2a): routes raw rows -> active/advisory/
    quarantine buckets. This resolver READS the routing output; it does not route.
  - tools/r76-hallucination-guard.py (PR2b): flags fabricated CONFIRMED records.
    The trusted index excludes R76-failed rows; this resolver is the read path.
  - tools/trusted-corpus-index-build.py (PR1, future): builds the index this
    resolver prefers.
Gap filled: no existing helper resolved "which corpus path should a hunt/score
consumer read, and with what trust_scope" - consumers each hard-coded raw paths.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Canonical layout (relative to repo root).
_TRUST_DIR_REL = "reference/corpus_trust"
_TRUSTED_INDEX_REL = f"{_TRUST_DIR_REL}/TRUSTED_CORPUS_INDEX.jsonl"
_ADVISORY_LEDGER_REL = f"{_TRUST_DIR_REL}/CORPUS_TRUST_LEDGER.jsonl"
_QUARANTINE_LEDGER_REL = f"{_TRUST_DIR_REL}/CORPUS_QUARANTINE_LEDGER.jsonl"
_PROSE_INDEX_REL = f"{_TRUST_DIR_REL}/PROSE_MEMORY_INDEX.jsonl"
_RAW_CORPUS_REL = "audit/corpus_tags"

# Valid trust scopes a consumer may request / receive.
TRUST_SCOPES = ("active", "advisory", "raw-fallback")

# ACTIVE invariant-corpus fuel (corpus-driven-hunt + brain share ONE source of
# truth here). Ordered so the incident-audited, brain-parity library wins the
# load_invariants first-wins dedup over any same-id-different-content row in the
# raw extracted snapshot (the lane-invariant-audit-ext.py:355 collision):
#   1. invariants_pilot_audited.jsonl       - incident-audited, brain-parity (994)
#   2. invariants_full_library_llm_v1.jsonl - full LLM library (502)
#   3. invariants_cross_lang_lifted.jsonl   - A->B cross-language transfer (324)
#   4. invariants_extracted.jsonl           - raw extracted, kept last (404)
# A relpath that is absent on disk is skipped (the caller warns); ordering of the
# survivors is preserved so the first-wins dedup contract still holds. The next
# corpus ingest repoints the hunt + the brain atomically by editing this one list.
_ACTIVE_INVARIANT_CORPORA_REL = (
    "audit/corpus_tags/derived/invariants_pilot_audited.jsonl",
    "audit/corpus_tags/derived/invariants_full_library_llm_v1.jsonl",
    "audit/corpus_tags/derived/invariants_cross_lang_lifted.jsonl",
    "audit/corpus_tags/derived/invariants_extracted.jsonl",
)
# The audited corpus whose mtime defines "fresh": a loaded set whose newest file
# predates this one is stale (the consumer warns).
_FRESHNESS_ANCHOR_REL = "audit/corpus_tags/derived/invariants_pilot_audited.jsonl"


def repo_root() -> Path:
    """Resolve the auditooor repo root (parent of tools/)."""
    return Path(__file__).resolve().parent.parent.parent


@dataclass(frozen=True)
class CorpusResolution:
    """The resolved corpus a consumer should read, plus its trust provenance."""

    trust_scope: str                 # 'active' | 'advisory' | 'raw-fallback'
    is_fallback: bool                # True when trusted index was absent
    primary_path: str                # path the consumer should read first
    extra_paths: tuple = field(default_factory=tuple)  # advisory ledger etc.
    raw_corpus_root: str = ""        # always populated (the raw tree)
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "trust_scope": self.trust_scope,
            "is_fallback": self.is_fallback,
            "primary_path": self.primary_path,
            "extra_paths": list(self.extra_paths),
            "raw_corpus_root": self.raw_corpus_root,
            "reason": self.reason,
        }


def _trusted_index_path(root: Path) -> Path:
    env = os.environ.get("AUDITOOOR_TRUSTED_CORPUS_INDEX")
    if env:
        return Path(env)
    trust_dir = os.environ.get("AUDITOOOR_CORPUS_TRUST_DIR")
    if trust_dir:
        return Path(trust_dir) / "TRUSTED_CORPUS_INDEX.jsonl"
    return root / _TRUSTED_INDEX_REL


def _advisory_ledger_path(root: Path) -> Path:
    trust_dir = os.environ.get("AUDITOOOR_CORPUS_TRUST_DIR")
    if trust_dir:
        return Path(trust_dir) / "CORPUS_TRUST_LEDGER.jsonl"
    return root / _ADVISORY_LEDGER_REL


def _raw_corpus_root(root: Path) -> Path:
    return root / _RAW_CORPUS_REL


def _want_advisory(include_advisory: bool) -> bool:
    if include_advisory:
        return True
    return os.environ.get("INCLUDE_ADVISORY") == "1"


def trusted_index_available(repo_root_path: Optional[Path] = None) -> bool:
    """True when the trusted corpus index exists and is non-empty."""
    root = Path(repo_root_path) if repo_root_path else repo_root()
    idx = _trusted_index_path(root)
    try:
        return idx.is_file() and idx.stat().st_size > 0
    except OSError:
        return False


def resolve_active_corpus(
    repo_root_path: Optional[Path] = None,
    include_advisory: bool = False,
) -> CorpusResolution:
    """Resolve which corpus a hunt/originality/backtest consumer should read.

    Prefers the trusted index. Falls back to the raw corpus root (with an
    explicit raw-fallback trust_scope) when the index is absent.
    """
    root = Path(repo_root_path) if repo_root_path else repo_root()
    raw_root = _raw_corpus_root(root)
    idx = _trusted_index_path(root)

    if trusted_index_available(root):
        extras: list[str] = []
        scope = "active"
        if _want_advisory(include_advisory):
            adv = _advisory_ledger_path(root)
            if adv.is_file():
                extras.append(str(adv))
                scope = "advisory"
        return CorpusResolution(
            trust_scope=scope,
            is_fallback=False,
            primary_path=str(idx),
            extra_paths=tuple(extras),
            raw_corpus_root=str(raw_root),
            reason=(
                "trusted index present; serving "
                + scope
                + (" (advisory ledger included)" if extras else "")
            ),
        )

    return CorpusResolution(
        trust_scope="raw-fallback",
        is_fallback=True,
        primary_path=str(raw_root),
        extra_paths=(),
        raw_corpus_root=str(raw_root),
        reason=(
            "trusted corpus index absent at "
            + str(idx)
            + "; degrading to raw corpus (build it via make trusted-corpus-index)"
        ),
    )


def freshness_anchor_path(repo_root_path: Optional[Path] = None) -> Path:
    """Absolute path of the corpus whose mtime defines hunt-fuel freshness."""
    root = Path(repo_root_path) if repo_root_path else repo_root()
    return root / _FRESHNESS_ANCHOR_REL


def resolve_active_invariant_corpora(
    repo_root_path: Optional[Path] = None,
    relative: bool = True,
) -> list:
    """Return the ACTIVE invariant-corpus relpaths the hunt + brain both read.

    Single source of truth for corpus-driven-hunt.py's DEFAULT_INVARIANT_CORPORA
    and the brain-prime fuel. Only relpaths that EXIST on disk are returned (an
    absent file is skipped); survivor ordering is preserved so the consumer's
    first-wins dedup keeps the incident-audited library winning over the raw
    extracted snapshot. Returns repo-relative paths by default (the hunt joins
    them to REPO_ROOT itself); pass relative=False for absolute paths.
    """
    root = Path(repo_root_path) if repo_root_path else repo_root()
    out = []
    for rel in _ACTIVE_INVARIANT_CORPORA_REL:
        if (root / rel).is_file():
            out.append(rel if relative else str(root / rel))
    return out


def annotate(payload: dict, resolution: CorpusResolution) -> dict:
    """Stamp a consumer's output payload with its corpus trust provenance.

    Consumers call this so every hunt/score record states the trust_scope it
    was produced under. Mutates and returns `payload`.
    """
    payload["corpus_trust"] = resolution.as_dict()
    return payload


if __name__ == "__main__":
    import json
    import sys

    inc = "--include-advisory" in sys.argv[1:] or os.environ.get("INCLUDE_ADVISORY") == "1"
    res = resolve_active_corpus(include_advisory=inc)
    print(json.dumps(res.as_dict(), indent=2))
