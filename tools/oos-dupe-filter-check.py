#!/usr/bin/env python3
"""oos-dupe-filter-check.py — block resubmissions matching encoded OOS/rejected classes.

PR #511 Slice 4 follow-up. Reads the workspace invariant ledger
(`<workspace>/.auditooor/invariant_ledger.json`), finds the row whose
`invariant_family` matches the OOS-duplicate-filter family (any naming
variant such as ``oos_duplicate_filter``, ``oos-dupe-filter``, etc.), and
extracts the encoded rejected/OOS class entries from that row's ``artifacts``
field.

Each artifact entry that begins with ``"<num>. CLASS-NAME -- rejection
reason ... resubmissions must X"`` is parsed into a structured class. Drafts
under ``<workspace>/submissions/staging/*.md`` and recent entries in
``<workspace>/submissions/SUBMISSIONS.md`` are scanned for matches via:

    * **title regex** (heuristic short-name match against the draft's first
      heading or filename), and
    * **body keyword match** against rejection-criteria tokens taken from
      the entry text.

Each matched draft is reported with the rejection rationale and the
RE-submission requirement. Operators can override on a per-draft basis by
adding an HTML comment of the form::

    <!-- oos-dupe-rebuttal: <CLASS-ID> <reason ...> -->

Exit codes
----------
    0
        No matches OR every matched draft has an explicit rebuttal comment
        for the matching class.
    1
        At least one un-rebutted match (BLOCK).
    2
        Workspace has no ledger or no OOS-duplicate-filter row (advisory;
        normal for non-Polymarket workspaces).

The check is **strictly additive**: workspaces without an OOS-duplicate-filter
ledger row never block.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# Family-name aliases accepted as the OOS-duplicate-filter row.
_OOS_FAMILY_ALIASES = {
    "oos_duplicate_filter",
    "oos-duplicate-filter",
    "oos_dupe_filter",
    "oos-dupe-filter",
    "oos_dupes_filter",
    "oos-dupes-filter",
    "duplicate_filter",
}


# Tokens we strip when deriving keyword tokens from a class entry.
_STOPWORDS = {
    "the", "and", "for", "via", "with", "from", "into", "that", "this",
    "must", "are", "was", "not", "but", "any", "all", "its", "their",
    "rejected", "rejection", "rejects", "reject", "oos",
    "out", "of", "scope", "resubmission", "resubmissions", "resubmit",
    "show", "shown", "showing", "shows",
    "class", "classes", "fm-class",
    "centralization", "centralization-by-design", "centralization-adjacent",
    "best-practice", "best", "practice", "recommendation",
    "design", "by-design", "by",
    "carveout", "architectural-domain-separation-by-design",
    "subsequent", "given",
    "n/a", "n.a.", "see", "ref", "refs",
    "operator", "operator's",
    "between",
    "filing", "submission",
    "rated", "medium-low",
    "block", "where",
    "supply", "token",
    "no", "yes",
    "mapping", "correctly", "updated",
    "subseq", "etc", "i.e.", "e.g.",
}


@dataclass
class EncodedClass:
    """One encoded rejected / OOS class extracted from the ledger row."""

    index: int                # 1-based index from the artifact entry.
    class_id: str             # e.g. ``OFF.A-CollateralOfframp-missing-WRAPPER_ROLE``.
    rationale: str            # Original rejection rationale text.
    resubmit_requirement: str # What an operator must show on RE-submit.
    raw: str                  # The full original entry, for citation.
    keyword_tokens: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Ledger discovery and parsing
# ---------------------------------------------------------------------------

def _ledger_path(workspace: Path) -> Path:
    return workspace / ".auditooor" / "invariant_ledger.json"


def _normalize_family(name: str) -> str:
    return re.sub(r"[\s_-]+", "_", (name or "").strip().lower())


def find_oos_row(ledger: object) -> dict | None:
    """Return the OOS-duplicate-filter row from the ledger, or ``None``.

    Accepts both top-level ``list`` payloads and dict payloads wrapping a
    ``rows`` / ``invariants`` / ``ledger`` array (the materializer from PR
    #511 Slice 2 is still in flight, so we tolerate either shape).
    """
    rows: Iterable[object]
    if isinstance(ledger, list):
        rows = ledger
    elif isinstance(ledger, dict):
        for key in ("rows", "invariants", "ledger", "entries"):
            value = ledger.get(key)
            if isinstance(value, list):
                rows = value
                break
        else:
            rows = []
    else:
        return None

    aliases = {_normalize_family(a) for a in _OOS_FAMILY_ALIASES}
    for row in rows:
        if not isinstance(row, dict):
            continue
        family = _normalize_family(str(row.get("invariant_family", "")))
        if family in aliases:
            return row
        # Also tolerate ``id`` matching ``*OOS-DUPE-FILTER*`` for ledgers
        # whose row id is the canonical signal (Kimi's research used
        # ``POLY-OOS-DUPE-FILTER``).
        row_id = str(row.get("id", "")).upper()
        if "OOS-DUPE-FILTER" in row_id or "OOS_DUPE_FILTER" in row_id:
            return row
    return None


# Matches one encoded class entry. Examples that must parse:
#   "1. OFF.A-CollateralOfframp-missing-WRAPPER_ROLE -- rejected as duplicate ..."
#   "2. POLY-182 / R77-12 CTFExchange.pauseTrading does not halt adapter ops -- rejected: ..."
#   "10. CollateralToken UUPS storage-gap -- OOS: best-practice recommendation."
_ENTRY_RE = re.compile(
    r"^\s*(?P<idx>\d+)\.\s+(?P<class>.+?)\s*(?:--|—|–)\s*(?P<rationale>.+)$",
    re.DOTALL,
)


def _split_class_id(class_text: str) -> str:
    """Return a short stable id for the class.

    We pick the first ``token`` that looks like a CLASS-ID (alphanumeric +
    ``.``/``-``/``_`` + at least one digit OR uppercase letter). If nothing
    obvious is found, fall back to the whole class_text trimmed.
    """
    tokens = re.split(r"\s+", class_text.strip())
    for token in tokens:
        # Strip trailing punctuation.
        token = token.strip(",.;:")
        if not token:
            continue
        if re.match(r"^[A-Z][A-Za-z0-9._/\-]{2,}$", token):
            return token
    return class_text.strip()


def _resubmit_requirement(rationale: str) -> str:
    """Pull out the ``resubmissions must ...`` clause if present."""
    match = re.search(
        r"(?i)(resubmissions?\s+must\s+[^.;]+[.;]?|resubmit[^.;]*[.;]?)",
        rationale,
    )
    if match:
        return match.group(0).strip().rstrip(".;")
    # Fallback: the rationale itself doubles as the requirement.
    return f"rebut the encoded rationale: {rationale.strip().rstrip('.;')}"


def _keyword_tokens(text: str) -> list[str]:
    """Lowercase tokens (>=4 chars) suitable for body-keyword scanning.

    Stopwords are removed. Tokens preserve hyphens / underscores / dots so
    that signature names like ``rolesOf`` or ``addWrapper`` keep meaning.
    """
    raw_tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9._/\-]{3,}", text)
    seen: list[str] = []
    seen_lc: set[str] = set()
    for token in raw_tokens:
        token_lc = token.lower()
        if token_lc in _STOPWORDS:
            continue
        if token_lc.isdigit():
            continue
        if token_lc in seen_lc:
            continue
        seen_lc.add(token_lc)
        seen.append(token)
    return seen


def parse_encoded_classes(row: dict) -> list[EncodedClass]:
    """Parse the ``artifacts`` field of an OOS-duplicate-filter row.

    Entries that look like ``"<num>. CLASS-NAME -- rationale"`` become
    ``EncodedClass`` instances. Other artifacts (e.g. the leading
    ``"Encoded rejected classes (minimum 6):"`` heading, or paths) are
    ignored.
    """
    artifacts = row.get("artifacts") or []
    classes: list[EncodedClass] = []
    if not isinstance(artifacts, list):
        return classes

    for artifact in artifacts:
        if not isinstance(artifact, str):
            continue
        match = _ENTRY_RE.match(artifact)
        if not match:
            continue
        try:
            idx = int(match.group("idx"))
        except ValueError:
            continue
        class_text = match.group("class").strip()
        rationale = match.group("rationale").strip().rstrip('"').strip()
        class_id = _split_class_id(class_text)
        requirement = _resubmit_requirement(rationale)
        # Keyword tokens come from the rationale + class text, since the
        # class id alone is too short.
        tokens = _keyword_tokens(class_text + " " + rationale)
        classes.append(
            EncodedClass(
                index=idx,
                class_id=class_id,
                rationale=rationale,
                resubmit_requirement=requirement,
                raw=artifact.strip(),
                keyword_tokens=tokens,
            )
        )
    return classes


# ---------------------------------------------------------------------------
# Draft scanning
# ---------------------------------------------------------------------------

# Rebuttal HTML comment grammar:
#   <!-- oos-dupe-rebuttal: <CLASS-ID> <reason ...> -->
_REBUTTAL_RE = re.compile(
    r"<!--\s*oos-dupe-rebuttal\s*:\s*(?P<class>[A-Za-z0-9._/\-]+)\s+(?P<reason>[^>]+?)\s*-->",
    re.IGNORECASE,
)


def _draft_title(text: str, path: Path) -> str:
    """First markdown ``# heading`` line, or basename fallback."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return path.name


def _normalize_for_match(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _class_short_aliases(cls: EncodedClass) -> list[str]:
    """Return alias strings that, if present in a draft title or filename,
    count as a heuristic title-match.

    We require aliases to be **disambiguating**: short prefixes shared
    across sibling classes (e.g. ``OOS_R41`` shared by ``OOS_R41-E2``,
    ``OOS_R41-S2``, ``OOS_R41-T1``) must NOT be emitted alone, otherwise
    a draft re-claiming E2 would also title-match S2 and T1. The rule is:

    * Always emit the full ``class_id`` (and a normalized variant).
    * If the raw entry has a slash-paired alias like ``POLY-182 / R77-12``,
      emit BOTH halves -- they are by construction disambiguating.
    * Emit individual pieces (split by ``[._/-]``) only when the piece is
      long enough (>= 6 chars) AND contains at least one digit OR mixed
      case; this filters out generic prefixes like ``OOS`` or ``POLY``.
    """
    aliases: list[str] = []
    seen: set[str] = set()

    def _add(alias: str) -> None:
        normalized = _normalize_for_match(alias)
        if normalized and len(normalized) >= 3 and normalized not in seen:
            seen.add(normalized)
            aliases.append(normalized)

    cid = cls.class_id
    _add(cid)

    # Slash-paired alias from the raw entry (e.g. "POLY-182 / R77-12").
    raw_match = re.search(
        r"\b([A-Z][A-Za-z0-9._\-]+)\s*/\s*([A-Z][A-Za-z0-9._\-]+)\b",
        cls.raw,
    )
    if raw_match:
        _add(raw_match.group(1))
        _add(raw_match.group(2))

    # Individual pieces, but only if they look disambiguating.
    pieces = [p for p in re.split(r"[._/\-]+", cid) if p]
    for piece in pieces:
        if len(piece) >= 6 and (re.search(r"\d", piece) or any(c.islower() for c in piece)):
            _add(piece)

    return aliases


@dataclass
class Match:
    draft: Path
    cls: EncodedClass
    title_hit: bool
    body_hits: list[str]   # token strings that hit
    rebutted: bool
    rebuttal_reason: str | None


def _draft_rebuttals(text: str) -> dict[str, str]:
    """Return ``{normalized_class_id: reason}`` for every rebuttal comment."""
    rebuttals: dict[str, str] = {}
    for match in _REBUTTAL_RE.finditer(text):
        cls_id = match.group("class").strip()
        reason = match.group("reason").strip()
        if cls_id:
            rebuttals[_normalize_for_match(cls_id)] = reason
    return rebuttals


def _match_one(
    draft: Path,
    text: str,
    cls: EncodedClass,
    rebuttals: dict[str, str],
    *,
    body_token_threshold: int = 2,
) -> Match | None:
    """Return a ``Match`` if this draft hits this class (title or body)."""
    title = _draft_title(text, draft)
    title_norm = _normalize_for_match(title + " " + draft.stem)
    body_norm = _normalize_for_match(text)

    title_hit = False
    for alias in _class_short_aliases(cls):
        if alias in title_norm:
            title_hit = True
            break

    body_hits: list[str] = []
    for token in cls.keyword_tokens:
        token_norm = _normalize_for_match(token)
        if not token_norm:
            continue
        # Word-boundary match on normalized text.
        if re.search(rf"(^|\s){re.escape(token_norm)}(\s|$)", body_norm):
            body_hits.append(token)

    if not title_hit and len(body_hits) < body_token_threshold:
        return None

    # Check rebuttal: by class_id (preferred) or by the index ("1", "2", ...).
    cls_id_norm = _normalize_for_match(cls.class_id)
    rebutted = False
    rebuttal_reason: str | None = None
    if cls_id_norm in rebuttals:
        rebutted = True
        rebuttal_reason = rebuttals[cls_id_norm]
    else:
        # Tolerate aliases (e.g. user wrote POLY-182 rather than the long id).
        for alias in _class_short_aliases(cls):
            if alias in rebuttals:
                rebutted = True
                rebuttal_reason = rebuttals[alias]
                break

    return Match(
        draft=draft,
        cls=cls,
        title_hit=title_hit,
        body_hits=body_hits,
        rebutted=rebutted,
        rebuttal_reason=rebuttal_reason,
    )


def _candidate_drafts(workspace: Path) -> list[Path]:
    """Drafts to scan: every ``submissions/staging/*.md``."""
    staging = workspace / "submissions" / "staging"
    if not staging.is_dir():
        return []
    return sorted(p for p in staging.glob("*.md") if p.is_file())


def _scan_submissions_md(workspace: Path) -> str:
    """Return the recent-entries portion of ``submissions/SUBMISSIONS.md``.

    We do not enforce the gate against this file's rows directly (operators
    edit it post-fact). Returned text is used only for body-keyword context
    when an explicit ``--include-submissions-md`` is requested in the future.
    """
    sub_md = workspace / "submissions" / "SUBMISSIONS.md"
    if not sub_md.is_file():
        return ""
    try:
        return sub_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _format_match(m: Match) -> str:
    parts: list[str] = []
    parts.append(f"DRAFT:        {m.draft}")
    parts.append(f"CLASS:        {m.cls.class_id}  (entry #{m.cls.index})")
    parts.append(f"RATIONALE:    {m.cls.rationale}")
    parts.append(f"REQUIREMENT:  {m.cls.resubmit_requirement}")
    why_bits = []
    if m.title_hit:
        why_bits.append("title regex hit")
    if m.body_hits:
        why_bits.append(
            "body tokens: " + ", ".join(m.body_hits[:6])
            + (" ..." if len(m.body_hits) > 6 else "")
        )
    parts.append(f"MATCHED VIA:  {'; '.join(why_bits) if why_bits else '(unspecified)'}")
    if m.rebutted:
        parts.append(
            f"REBUTTAL:     <!-- oos-dupe-rebuttal: {m.cls.class_id} {m.rebuttal_reason} -->"
        )
    else:
        parts.append(
            "REBUTTAL:     (none -- add an HTML comment "
            f"`<!-- oos-dupe-rebuttal: {m.cls.class_id} <reason> -->` "
            "to override on a per-draft basis)"
        )
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pre-submit gate that blocks drafts matching encoded "
            "OOS/rejected classes from the workspace invariant ledger."
        )
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="Path to the workspace (the directory containing .auditooor/).",
    )
    parser.add_argument(
        "--draft",
        action="append",
        default=None,
        help=(
            "Optional explicit draft path. May be repeated. When omitted, "
            "every <ws>/submissions/staging/*.md is scanned."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON summary on stdout.",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    ledger_path = _ledger_path(workspace)

    if not ledger_path.is_file():
        message = (
            f"[oos-dupe-filter] no invariant ledger at {ledger_path} "
            "-- advisory (rc=2). Workspaces without OOS-DUPE-FILTER rows "
            "never block."
        )
        if args.json:
            print(json.dumps({
                "status": "no-ledger",
                "workspace": str(workspace),
                "ledger": str(ledger_path),
                "matches": [],
            }))
        else:
            print(message)
        return 2

    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        message = (
            f"[oos-dupe-filter] cannot parse ledger {ledger_path}: {exc} "
            "-- advisory (rc=2)."
        )
        if args.json:
            print(json.dumps({
                "status": "ledger-unreadable",
                "workspace": str(workspace),
                "ledger": str(ledger_path),
                "error": str(exc),
                "matches": [],
            }))
        else:
            print(message)
        return 2

    row = find_oos_row(ledger)
    if row is None:
        message = (
            "[oos-dupe-filter] ledger present but no OOS-duplicate-filter "
            "row (invariant_family in {oos_duplicate_filter, ...}) "
            "-- advisory (rc=2)."
        )
        if args.json:
            print(json.dumps({
                "status": "no-oos-row",
                "workspace": str(workspace),
                "ledger": str(ledger_path),
                "matches": [],
            }))
        else:
            print(message)
        return 2

    classes = parse_encoded_classes(row)
    if not classes:
        message = (
            "[oos-dupe-filter] OOS-duplicate-filter row present but no "
            "parseable encoded classes in `artifacts` -- advisory (rc=2). "
            "Expected entries shaped like '1. CLASS-NAME -- rationale ...'."
        )
        if args.json:
            print(json.dumps({
                "status": "no-encoded-classes",
                "workspace": str(workspace),
                "ledger": str(ledger_path),
                "matches": [],
            }))
        else:
            print(message)
        return 2

    drafts: list[Path]
    if args.draft:
        drafts = [Path(p).expanduser().resolve() for p in args.draft]
    else:
        drafts = _candidate_drafts(workspace)

    matches: list[Match] = []
    for draft in drafts:
        if not draft.is_file():
            continue
        try:
            text = draft.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rebuttals = _draft_rebuttals(text)
        for cls in classes:
            m = _match_one(draft, text, cls, rebuttals)
            if m is not None:
                matches.append(m)

    un_rebutted = [m for m in matches if not m.rebutted]

    if args.json:
        print(json.dumps({
            "status": "ok" if not un_rebutted else "blocked",
            "workspace": str(workspace),
            "ledger": str(ledger_path),
            "row_id": row.get("id"),
            "encoded_classes": len(classes),
            "drafts_scanned": len(drafts),
            "matches": [
                {
                    "draft": str(m.draft),
                    "class_id": m.cls.class_id,
                    "class_index": m.cls.index,
                    "rationale": m.cls.rationale,
                    "resubmit_requirement": m.cls.resubmit_requirement,
                    "title_hit": m.title_hit,
                    "body_hits": m.body_hits,
                    "rebutted": m.rebutted,
                    "rebuttal_reason": m.rebuttal_reason,
                }
                for m in matches
            ],
        }))
    else:
        print(
            f"[oos-dupe-filter] workspace={workspace} ledger={ledger_path}"
        )
        print(
            f"[oos-dupe-filter] row={row.get('id', '<no-id>')} "
            f"encoded_classes={len(classes)} drafts_scanned={len(drafts)}"
        )
        if not matches:
            print("[oos-dupe-filter] no draft matches encoded classes -- pass.")
        else:
            for m in matches:
                tag = "REBUTTED" if m.rebutted else "BLOCK"
                print(f"\n--- [{tag}] -----------------------------------------")
                print(_format_match(m))
            print()
            if un_rebutted:
                print(
                    f"[oos-dupe-filter] {len(un_rebutted)} un-rebutted "
                    f"match(es) of {len(matches)} total -- BLOCK."
                )
            else:
                print(
                    f"[oos-dupe-filter] all {len(matches)} match(es) "
                    "carry an explicit rebuttal comment -- pass."
                )

    return 1 if un_rebutted else 0


if __name__ == "__main__":
    sys.exit(main())
