#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - cross-corpus duplicate-finding
preview detector.

Surfaces hackerman corpus records that point at the SAME underlying advisory
across DIFFERENT corpus subtrees. Example: a single GHSA-XXXX-YYYY-ZZZZ may
appear in both ``cosmos_sdk_ibc/`` and ``evm_client_advisories/``; a CVE may
appear in both ``vyper_cve_2023_39363/`` and ``audit_firm_public_reports/``;
a commit SHA may appear in both ``dex_fix_history/`` and ``bridge_incidents/``.

This is a PREVIEW / SURVEILLANCE tool only - it does NOT auto-delete, merge,
or rewrite any record. It emits two artifacts:

1. ``.auditooor/cross_corpus_dupes.jsonl`` (gitignored, machine-readable) - one
   JSON object per duplicate group, with the shared identifier, identifier
   type, contributing subtrees, and the list of record paths in the group.
2. ``docs/HACKERMAN_CROSS_CORPUS_DUPES_PREVIEW_2026-05-16.md`` (committed,
   operator-readable) - top-30 groups by subtree-count, plus the long-tail
   summary stats and the high-signal (3+ subtree) advisory list.

Walking strategy
----------------
- ``audit/corpus_tags/tags/<subtree>/<record-slug>/record.json`` (preferred)
- ``audit/corpus_tags/tags/<subtree>/<record-slug>/record.yaml`` (fallback if
  no JSON sibling)
- ``audit/corpus_tags/tags/<flat>.yaml`` (subtree label = ``__flat__``)

The same record-slug directory's JSON + YAML pair counts as a SINGLE record;
the JSON file wins when both are present (per hackerman corpus convention).

Identifier extraction (in priority order, first-hit-wins per record)
-------------------------------------------------------------------
- ``CVE-YYYY-NNNN`` (4-7 digit suffix, case-insensitive, normalised upper)
- ``GHSA-XXXX-YYYY-ZZZZ`` (4-char alnum groups, normalised upper)
- ``ASA-NNNN-NNNN`` (cosmos-sdk style audit shoutout id, normalised upper)
- ``ISA-NNNN-NNNN`` (Informal Systems audit id, normalised upper)
- commit-SHA-with-repo, encoded as ``<owner>/<repo>@<sha40>`` - 40-hex SHA
  must be paired with a ``github.com/<owner>/<repo>`` reference in the same
  record; bare 40-hex strings without a paired repo are intentionally NOT
  collected (would explode into thousands of weak-signal hits).
- raw-PDF-URL: any ``https://...\\.pdf`` URL, normalised to lowercased host +
  path. This catches the audit_firm_public_reports cross-references.

A record contributes AT MOST ONE identifier per category (de-duplicates within
a record). A group is only emitted when records from >=2 DIFFERENT subtrees
share the same (identifier_type, identifier_value) pair.

Determinism
-----------
- Subtree names, record paths, and identifier values are sorted asc.
- Group emission order: (subtree_count desc, identifier_type asc by priority
  order, identifier_value asc).
- ``--generated-at`` override (env ``AUDITOOOR_CROSS_CORPUS_DUPES_GENERATED_AT``)
  pins the timestamp so the docs file stays byte-stable across runs.

Wired into Makefile as ``make hackerman-cross-corpus-dupes`` (no args required).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - optional pyyaml.
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_JSONL_OUT = REPO_ROOT / ".auditooor" / "cross_corpus_dupes.jsonl"
DEFAULT_DOCS_OUT = REPO_ROOT / "docs" / "HACKERMAN_CROSS_CORPUS_DUPES_PREVIEW_2026-05-16.md"

SCHEMA = "auditooor.hackerman_cross_corpus_dupes.v1"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"
FLAT_SUBTREE_SENTINEL = "__flat__"
TOP_N_DOCS = 30
# W2.6 (2026-05-16): records carrying top-level ``verdict_artefact: true``
# (strict boolean True; non-boolean truthy values do NOT match) are
# workspace verdict outputs that re-cite advisory identifiers in their
# slug / body but are NOT advisory records. The dupe-finder skips them
# BEFORE identifier extraction so they never form a cross-corpus group.
# See ``docs/WAVE2_W26_DUPE_CANONICALIZATION_EXECUTION_PLAN_2026-05-16.md``.
VERDICT_ARTEFACT_MARKER_KEY = "verdict_artefact"


def _is_verdict_artefact(data: dict[str, Any]) -> bool:
    """Strict top-level ``verdict_artefact: true`` filter.

    Only returns ``True`` when the top-level key carries the boolean
    ``True``. Truthy non-boolean values (e.g. the string ``"true"``) do
    NOT match - this avoids accidental filter widening when YAML parsing
    coerces unexpected scalar shapes.
    """
    return data.get(VERDICT_ARTEFACT_MARKER_KEY) is True

# Identifier-type priority order; first-hit-wins inside one record but a
# single record can contribute ONE id per category (so a record citing both
# a CVE and a GHSA contributes to both buckets).
ID_TYPE_PRIORITY = ("CVE", "GHSA", "ASA", "ISA", "COMMIT_REPO", "PDF_URL")

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA(?:-[a-z0-9]{4}){3}\b", re.IGNORECASE)
# ASA-YYYY-NNNN (cosmos-sdk audit shoutout) and ISA-YYYY-NNNN (Informal
# Systems audit) - both use 4-digit year + 4-digit sequence.
ASA_RE = re.compile(r"\bASA-(\d{4})-(\d{3,5})\b", re.IGNORECASE)
ISA_RE = re.compile(r"\bISA-(\d{4})-(\d{3,5})\b", re.IGNORECASE)
SHA40_RE = re.compile(r"\b([0-9a-f]{40})\b", re.IGNORECASE)
REPO_RE = re.compile(r"github\.com[/:]([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*?)(?:\.git|/|\b)")
PDF_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+\.pdf", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Loader helpers - shared shape with hackerman-corpus-stats.py.
# ---------------------------------------------------------------------------


def _yaml_load(text: str) -> dict[str, Any]:
    """Best-effort YAML load; we only need scalar text fields anyway."""
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#") or line.startswith(" "):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip().strip("\"'")
    return out


def _json_load(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def _record_text_for_scan(data: dict[str, Any]) -> str:
    """Flatten the record's scalar values into a single text blob the
    identifier regex set is run against. Lists are joined with newlines."""
    chunks: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)
        elif node is None:
            return
        else:
            chunks.append(str(node))

    _walk(data)
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Walker.
# ---------------------------------------------------------------------------


def iter_records(tags_dir: Path) -> Iterable[tuple[str, Path, dict[str, Any]]]:
    """Yield ``(subtree, record_path, record_data)`` tuples.

    JSON wins over YAML when both exist in a record-slug directory. Flat
    ``tags/<name>.yaml`` files are yielded with subtree=``__flat__``.
    """
    if not tags_dir.exists():
        return
    # Flat files at the tags root.
    for entry in sorted(tags_dir.iterdir()):
        if entry.is_file() and entry.suffix == ".yaml":
            data = _yaml_load(entry.read_text(encoding="utf-8", errors="replace"))
            if data and not _is_verdict_artefact(data):
                yield FLAT_SUBTREE_SENTINEL, entry, data
    # Subtree directories.
    for subtree_dir in sorted(p for p in tags_dir.iterdir() if p.is_dir()):
        subtree_name = subtree_dir.name
        # Walk record-slug subdirs.
        for record_dir in sorted(p for p in subtree_dir.iterdir() if p.is_dir()):
            json_path = record_dir / "record.json"
            yaml_path = record_dir / "record.yaml"
            if json_path.exists():
                data = _json_load(json_path.read_text(encoding="utf-8", errors="replace"))
                if data and not _is_verdict_artefact(data):
                    yield subtree_name, json_path, data
                    continue
            if yaml_path.exists():
                data = _yaml_load(yaml_path.read_text(encoding="utf-8", errors="replace"))
                if data and not _is_verdict_artefact(data):
                    yield subtree_name, yaml_path, data
        # Flat files inside the subtree dir (not record-slug directories) - these
        # exist in subtrees like cve_db/ and vyper_cve_2023_39363/.
        for entry in sorted(subtree_dir.iterdir()):
            if entry.is_file() and entry.suffix == ".yaml":
                data = _yaml_load(entry.read_text(encoding="utf-8", errors="replace"))
                if data and not _is_verdict_artefact(data):
                    yield subtree_name, entry, data


# ---------------------------------------------------------------------------
# Identifier extraction.
# ---------------------------------------------------------------------------


def extract_identifiers(text: str) -> dict[str, list[str]]:
    """Return per-category identifier lists (de-duplicated, sorted asc).

    A single record may yield identifiers in MULTIPLE categories. Within
    a category the values are de-duplicated.
    """
    ids: dict[str, set[str]] = {k: set() for k in ID_TYPE_PRIORITY}

    for m in CVE_RE.finditer(text):
        ids["CVE"].add(f"CVE-{m.group(1)}-{m.group(2)}".upper())
    for m in GHSA_RE.finditer(text):
        ids["GHSA"].add(m.group(0).upper())
    for m in ASA_RE.finditer(text):
        ids["ASA"].add(f"ASA-{m.group(1)}-{m.group(2)}".upper())
    for m in ISA_RE.finditer(text):
        ids["ISA"].add(f"ISA-{m.group(1)}-{m.group(2)}".upper())

    # commit-SHA-with-repo: only collect a SHA when a github repo coord is
    # also present in the record (avoids 40-hex address false positives).
    repos = {(m.group(1), m.group(2)) for m in REPO_RE.finditer(text)}
    if repos:
        shas = {m.group(1).lower() for m in SHA40_RE.finditer(text)}
        if shas:
            # We cannot mechanically tell which SHA belongs to which repo when
            # multiple are cited; cross-pair every repo with every SHA. This
            # is conservative - groups still only emit when >=2 subtrees share
            # the same (repo, sha) pair, so spurious pairings get dropped.
            for owner, repo in repos:
                for sha in shas:
                    ids["COMMIT_REPO"].add(f"{owner.lower()}/{repo.lower()}@{sha}")

    # PDF URLs: normalise to lowercased URL, strip trailing punctuation that
    # the regex may grab from prose contexts.
    for m in PDF_URL_RE.finditer(text):
        url = m.group(0)
        # Strip trailing punctuation that's commonly stuck to a URL in prose.
        url = url.rstrip(".,;:)")
        ids["PDF_URL"].add(url.lower())

    return {k: sorted(v) for k, v in ids.items() if v}


# ---------------------------------------------------------------------------
# Group builder.
# ---------------------------------------------------------------------------


def build_groups(records: Iterable[tuple[str, Path, dict[str, Any]]],
                 tags_dir: Path) -> list[dict[str, Any]]:
    """Build the list of cross-corpus duplicate groups.

    Output schema (per group):

        {
          "identifier_type": "CVE" | "GHSA" | "ASA" | "ISA" | "COMMIT_REPO" | "PDF_URL",
          "identifier_value": "<normalised id>",
          "subtree_count": <int, >=2>,
          "record_count": <int, >=2>,
          "subtrees": ["<subtree>", ...],   # sorted asc
          "records": [
            {"subtree": "...", "path": "<repo-relative path>"},
            ...
          ]
        }
    """
    # (id_type, id_value) -> list[(subtree, repo_rel_path)]
    bucket: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    for subtree, path, data in records:
        text = _record_text_for_scan(data)
        ids = extract_identifiers(text)
        if not ids:
            continue
        try:
            rel = path.resolve().relative_to(REPO_ROOT.resolve())
            rel_str = str(rel)
        except ValueError:
            rel_str = str(path)
        for id_type, values in ids.items():
            for v in values:
                bucket[(id_type, v)].append((subtree, rel_str))

    groups: list[dict[str, Any]] = []
    type_rank = {t: i for i, t in enumerate(ID_TYPE_PRIORITY)}
    for (id_type, id_value), members in bucket.items():
        subtrees = sorted({s for s, _ in members})
        if len(subtrees) < 2:
            continue  # cross-corpus requires >=2 distinct subtrees
        # De-duplicate record entries (same path may appear twice if both
        # JSON and YAML are loaded - we only emit JSON when present, but be
        # defensive).
        seen_pairs: set[tuple[str, str]] = set()
        records_out: list[dict[str, str]] = []
        for subtree, rel_path in sorted(members):
            key = (subtree, rel_path)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            records_out.append({"subtree": subtree, "path": rel_path})
        groups.append({
            "identifier_type": id_type,
            "identifier_value": id_value,
            "subtree_count": len(subtrees),
            "record_count": len(records_out),
            "subtrees": subtrees,
            "records": records_out,
        })

    groups.sort(key=lambda g: (
        -g["subtree_count"],
        type_rank.get(g["identifier_type"], len(ID_TYPE_PRIORITY)),
        g["identifier_value"],
    ))
    return groups


# ---------------------------------------------------------------------------
# Output renderers.
# ---------------------------------------------------------------------------


def render_jsonl(groups: list[dict[str, Any]], generated_at: str) -> str:
    lines: list[str] = []
    header = {
        "schema_version": SCHEMA,
        "generated_at_iso": generated_at,
        "group_count": len(groups),
    }
    lines.append(json.dumps(header, sort_keys=True))
    for g in groups:
        lines.append(json.dumps(g, sort_keys=True))
    return "\n".join(lines) + "\n"


def _summary_stats(groups: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = defaultdict(int)
    by_subtree_count: dict[int, int] = defaultdict(int)
    high_signal: list[dict[str, Any]] = []
    for g in groups:
        by_type[g["identifier_type"]] += 1
        by_subtree_count[g["subtree_count"]] += 1
        if g["subtree_count"] >= 3:
            high_signal.append(g)
    return {
        "total_groups": len(groups),
        "by_identifier_type": dict(sorted(by_type.items())),
        "by_subtree_count": dict(sorted(by_subtree_count.items())),
        "high_signal_count": len(high_signal),
        "high_signal_groups": high_signal,
    }


def render_docs(groups: list[dict[str, Any]], generated_at: str,
                tags_dir: Path, total_records: int) -> str:
    stats = _summary_stats(groups)
    lines: list[str] = []
    lines.append("# Hackerman Cross-Corpus Duplicates - Preview")
    lines.append("")
    lines.append(f"- Schema: `{SCHEMA}`")
    lines.append(f"- Generated at: `{generated_at}`")
    lines.append(f"- Tags dir: `{tags_dir}`")
    lines.append(f"- Records scanned: `{total_records}`")
    lines.append(f"- Duplicate groups (>=2 subtrees): `{stats['total_groups']}`")
    lines.append(f"- High-signal groups (>=3 subtrees): `{stats['high_signal_count']}`")
    lines.append("")
    lines.append("This is a PREVIEW / SURVEILLANCE artifact. No record is auto-merged or")
    lines.append("auto-deleted. The full machine-readable group list is at")
    lines.append("`.auditooor/cross_corpus_dupes.jsonl` (gitignored).")
    lines.append("")
    lines.append("## Summary stats")
    lines.append("")
    lines.append("### Groups by identifier type")
    lines.append("")
    lines.append("| identifier_type | group_count |")
    lines.append("|-----------------|------------:|")
    for k, v in stats["by_identifier_type"].items():
        lines.append(f"| `{k}` | {v} |")
    lines.append("")
    lines.append("### Groups by subtree-count bucket")
    lines.append("")
    lines.append("| subtree_count | group_count |")
    lines.append("|--------------:|------------:|")
    for k, v in stats["by_subtree_count"].items():
        lines.append(f"| {k} | {v} |")
    lines.append("")
    lines.append(f"## Top-{TOP_N_DOCS} duplicate groups by subtree-count")
    lines.append("")
    if not groups:
        lines.append("_No cross-corpus duplicates detected._")
    else:
        lines.append("| # | identifier_type | identifier_value | subtree_count | record_count | subtrees |")
        lines.append("|--:|-----------------|------------------|--------------:|-------------:|----------|")
        for i, g in enumerate(groups[:TOP_N_DOCS], start=1):
            subtrees_str = ", ".join(f"`{s}`" for s in g["subtrees"])
            lines.append(
                f"| {i} | `{g['identifier_type']}` | `{g['identifier_value']}` | "
                f"{g['subtree_count']} | {g['record_count']} | {subtrees_str} |"
            )
    lines.append("")
    lines.append("## High-signal advisories (>=3 subtrees)")
    lines.append("")
    if not stats["high_signal_groups"]:
        lines.append("_No advisory appears in 3 or more corpus subtrees._")
    else:
        lines.append(
            "These advisories appear in 3 or more corpus subtrees and are the strongest"
        )
        lines.append("cross-referencing signals in the current corpus state.")
        lines.append("")
        for g in stats["high_signal_groups"]:
            lines.append(
                f"### `{g['identifier_type']}` / `{g['identifier_value']}` "
                f"({g['subtree_count']} subtrees, {g['record_count']} records)"
            )
            lines.append("")
            for r in g["records"]:
                lines.append(f"- `{r['subtree']}` -> `{r['path']}`")
            lines.append("")
    lines.append("## Provenance")
    lines.append("")
    lines.append(
        "Generated by `tools/hackerman-cross-corpus-dupe-finder.py`. The tool walks"
    )
    lines.append("`audit/corpus_tags/tags/**/record.{json,yaml}` + flat `tags/*.yaml`,")
    lines.append("extracts CVE/GHSA/ASA/ISA/commit-SHA-with-repo/raw-PDF-URL identifiers,")
    lines.append("groups records sharing the same identifier, and reports groups whose")
    lines.append("records span >=2 distinct subtrees. Read-only against the corpus tree.")
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _resolve_generated_at(arg: str | None) -> str:
    if arg:
        return arg
    env = os.environ.get("AUDITOOOR_CROSS_CORPUS_DUPES_GENERATED_AT")
    if env:
        return env
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR),
                        help="Hackerman corpus tags directory (default: %(default)s).")
    parser.add_argument("--jsonl-out", default=str(DEFAULT_JSONL_OUT),
                        help="JSONL preview artifact path (gitignored).")
    parser.add_argument("--docs-out", default=str(DEFAULT_DOCS_OUT),
                        help="Operator-readable Markdown preview path.")
    parser.add_argument("--generated-at", default=None,
                        help="Override the generated_at_iso timestamp.")
    parser.add_argument("--json", action="store_true",
                        help="Also dump the full group list to stdout as JSON.")
    args = parser.parse_args(argv)

    tags_dir = Path(args.tags_dir)
    generated_at = _resolve_generated_at(args.generated_at)

    records = list(iter_records(tags_dir))
    total_records = len(records)
    groups = build_groups(records, tags_dir)

    jsonl_out = Path(args.jsonl_out)
    docs_out = Path(args.docs_out)
    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    docs_out.parent.mkdir(parents=True, exist_ok=True)

    jsonl_text = render_jsonl(groups, generated_at)
    docs_text = render_docs(groups, generated_at, tags_dir, total_records)
    jsonl_out.write_text(jsonl_text, encoding="utf-8")
    docs_out.write_text(docs_text, encoding="utf-8")

    summary = {
        "schema_version": SCHEMA,
        "generated_at_iso": generated_at,
        "tags_dir": str(tags_dir),
        "records_scanned": total_records,
        "group_count": len(groups),
        "jsonl_out": str(jsonl_out),
        "docs_out": str(docs_out),
    }
    if args.json:
        print(json.dumps({"summary": summary, "groups": groups}, sort_keys=True))
    else:
        print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
