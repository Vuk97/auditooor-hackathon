#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - per-subtree README scaffolder.

Some hackerman corpus subtrees (``mev_exploits``, ``bridge_incidents``,
``oracle_advisories``) have a ``_MINER_README.md`` written at miner-author
time documenting provenance + verification tier + sample URLs.  Others
(``amm_yield_lst_protocols``, ``contest_platform_findings``, ``cve_db``,
``lending_protocols``, ``solana_svm``, ``zk_circuit_bugs``, ...) do not.

This tool scaffolds a ``README.md`` for every tier-1/tier-2 subtree under
``audit/corpus_tags/tags/<dir>/`` that lacks both ``_MINER_README.md`` and
``README.md`` at the dir root.  The scaffold is derived from the records
inside (source-channel + verification_tier + record count + sample URLs)
so it documents provenance even when the original miner author did not
leave a hand-written note.

Why
~~~

Wave-1 hackerman discoverability: a worker dispatched to a subtree should
be able to read its README and learn (a) what real-world source channel
the records were mined from, (b) the verification tier of the emission
run, (c) the record count + bug-class spread, (d) sample resolvable
source URLs so the M14-trap real-source-only discipline (`~/.claude/
CLAUDE.md`) is auditable without re-walking the YAML files.

Discovery model
~~~~~~~~~~~~~~~

Inputs (mirrors `tools/hackerman-domain-stats.py`):

- ``audit/corpus_tags/tags/<subtree>/**/record.{yaml,json}`` (preferred
  YAML over JSON when both are present)
- ``audit/corpus_tags/tags/<subtree>/<slug>.yaml`` (flat-record subtrees
  like ``cve_db`` use one YAML per record at subtree root, NOT a per-
  record directory)

Excluded subtrees (skipped silently):

- ``_QUARANTINE_*`` - already has a hand-written README documenting why
  the records are quarantined
- ``_deprecated`` - retired subtree; no point scaffolding a README

Existing-README skip rule:

- If ``<subtree>/_MINER_README.md`` exists -> skip (already documented)
- If ``<subtree>/README.md`` exists -> skip (already documented)
- Otherwise -> emit ``<subtree>/README.md`` with the scaffold

Scaffold sections:

1. Title (derived from subtree dir name)
2. Provenance block (source channel, verification tier, lane attribution)
3. Record-count + bug-class spread
4. Sample source URLs (up to 5 distinct resolvable https:// URLs)
5. Real-source-only discipline note (M14-trap citation)
6. MCP context pack block (caller fills in)

CLI examples
~~~~~~~~~~~~

  # default: scaffold any missing README under audit/corpus_tags/tags/
  python3 tools/hackerman-subtree-readme-scaffolder.py

  # dry-run: report what would be created but don't write files
  python3 tools/hackerman-subtree-readme-scaffolder.py --dry-run

  # alternate tags dir (used by the unit tests)
  python3 tools/hackerman-subtree-readme-scaffolder.py --tags-dir /tmp/tags

  # machine envelope to stdout
  python3 tools/hackerman-subtree-readme-scaffolder.py --json
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - optional
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
SCHEMA = "auditooor.hackerman_subtree_readme_scaffold.v1"

EXCLUDED_PREFIXES = ("_QUARANTINE_", "_deprecated")
EXISTING_README_NAMES = ("_MINER_README.md", "README.md")

DEFAULT_CONTEXT_PACK_ID = "auditooor.vault_context_pack.v1:resume:13e5d8c521f9c606"
DEFAULT_CONTEXT_PACK_HASH = (
    "13e5d8c521f9c606d94ac513f0d7412f3f85de85f6c66ddb8f8812f6c987f4bd"
)

URL_RE = re.compile(r"https?://[\w\-./%#?=&+:@,~()]+", re.IGNORECASE)


def _yaml_load(text: str) -> dict[str, Any]:
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith(" "):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if v == "":
                continue
            out[k] = v.strip("\"'")
    return out


def _load_record(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return _yaml_load(text)


def _list_subtrees(tags_dir: Path) -> list[Path]:
    if not tags_dir.is_dir():
        return []
    out: list[Path] = []
    for child in sorted(tags_dir.iterdir()):
        if not child.is_dir():
            continue
        if any(child.name.startswith(p) for p in EXCLUDED_PREFIXES):
            continue
        out.append(child)
    return out


def _has_existing_readme(subtree: Path) -> str | None:
    for name in EXISTING_README_NAMES:
        if (subtree / name).is_file():
            return name
    return None


def _iter_subtree_records(subtree: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    """Yield (path, record) for every loadable record in this subtree.

    Three layouts are supported (mirrors the corpus shapes observed in
    audit/corpus_tags/tags/):

    1. ``<subtree>/<slug>/record.yaml`` (preferred over record.json when
       both are present)
    2. ``<subtree>/<slug>/record.json`` (fallback when YAML absent)
    3. ``<subtree>/<slug>.yaml`` (flat-record layout, e.g. cve_db)
    """
    seen_dirs: set[Path] = set()
    for path in sorted(subtree.rglob("record.yaml")):
        seen_dirs.add(path.parent)
        rec = _load_record(path)
        if rec:
            yield path, rec
    for path in sorted(subtree.rglob("record.json")):
        if path.parent in seen_dirs:
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec
    # Flat YAML files at subtree root only (don't recurse into per-record dirs)
    for path in sorted(subtree.glob("*.yaml")):
        if path.name in ("README.yaml",):
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec


def _extract_urls(record: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    src = record.get("source_audit_ref")
    if isinstance(src, str):
        urls.extend(URL_RE.findall(src))
    preconds = record.get("required_preconditions")
    if isinstance(preconds, list):
        for p in preconds:
            if isinstance(p, str):
                urls.extend(URL_RE.findall(p))
    seq = record.get("attacker_action_sequence")
    if isinstance(seq, str):
        urls.extend(URL_RE.findall(seq))
    return urls


def _title_from_subtree(name: str) -> str:
    """Convert ``amm_yield_lst_protocols`` -> ``Amm Yield Lst Protocols``."""
    parts = [p for p in name.replace("-", "_").split("_") if p]
    return " ".join(p[:1].upper() + p[1:] for p in parts) if parts else name


def _summarise_subtree(subtree: Path) -> dict[str, Any]:
    """Walk a subtree and aggregate the fields the scaffold renders."""
    record_count = 0
    tiers: Counter[str] = Counter()
    bug_classes: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    sample_urls: list[str] = []
    seen_urls: set[str] = set()
    for _path, rec in _iter_subtree_records(subtree):
        record_count += 1
        tier = rec.get("record_tier")
        if isinstance(tier, str) and tier.strip():
            tiers[tier.strip()] += 1
        # Verification tier is encoded in shape_tags as
        # ``verification_tier:<value>``; surface that too if present.
        shape = rec.get("function_shape")
        if isinstance(shape, dict):
            tags = shape.get("shape_tags")
            if isinstance(tags, list):
                for t in tags:
                    if isinstance(t, str) and t.startswith("verification_tier:"):
                        tiers[t[len("verification_tier:"):].strip()] += 1
        bc = rec.get("bug_class")
        if isinstance(bc, str) and bc.strip():
            bug_classes[bc.strip()] += 1
        dom = rec.get("target_domain")
        if isinstance(dom, str) and dom.strip():
            domains[dom.strip()] += 1
        lang = rec.get("target_language")
        if isinstance(lang, str) and lang.strip():
            languages[lang.strip()] += 1
        sev = rec.get("severity_at_finding")
        if isinstance(sev, str) and sev.strip():
            severities[sev.strip()] += 1
        for url in _extract_urls(rec):
            url = url.rstrip(".,);]")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if len(sample_urls) < 5:
                sample_urls.append(url)
    return {
        "record_count": record_count,
        "tiers": dict(tiers),
        "bug_classes": dict(bug_classes),
        "domains": dict(domains),
        "languages": dict(languages),
        "severities": dict(severities),
        "sample_urls": sample_urls,
    }


def _render_counter(c: dict[str, int], max_rows: int = 5) -> str:
    if not c:
        return "(none)"
    rows = sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:max_rows]
    return ", ".join(f"`{k}`={v}" for k, v in rows)


def render_readme(
    subtree_name: str,
    summary: dict[str, Any],
    context_pack_id: str = DEFAULT_CONTEXT_PACK_ID,
    context_pack_hash: str = DEFAULT_CONTEXT_PACK_HASH,
    today: str | None = None,
) -> str:
    """Return the markdown body for a scaffolded subtree README."""
    today = today or datetime.date.today().isoformat()
    title = _title_from_subtree(subtree_name)
    rc = summary["record_count"]
    tiers = _render_counter(summary["tiers"])
    bug_classes = _render_counter(summary["bug_classes"])
    domains = _render_counter(summary["domains"])
    languages = _render_counter(summary["languages"])
    severities = _render_counter(summary["severities"])
    if summary["sample_urls"]:
        url_block = "\n".join(f"- {u}" for u in summary["sample_urls"])
    else:
        url_block = (
            "(no resolvable https:// URLs surfaced from `source_audit_ref` /"
            " `required_preconditions` / `attacker_action_sequence` fields;"
            " records in this subtree carry non-URL provenance anchors -"
            " e.g. CVE IDs, GHSA IDs, contest slugs, or fixed-list ETL"
            " curated taxonomies)"
        )
    body = f"""# {title} corpus (Wave-1)

This subtree holds auditooor Hackerman corpus rows for the
``{subtree_name}`` real-source channel.  Scaffolded by
``tools/hackerman-subtree-readme-scaffolder.py`` on {today} from the
records present at scaffold time.  Replace this scaffold with a hand-
written ``_MINER_README.md`` (preferred name) when the original miner
author returns to attribute the lane.

## Provenance summary

- Subtree: ``audit/corpus_tags/tags/{subtree_name}/``
- Record count at scaffold time: {rc}
- Verification tier mix: {tiers}
- Target domain mix: {domains}
- Target language mix: {languages}
- Bug-class top-5: {bug_classes}
- Severity mix: {severities}

## Sample source URLs (extracted from record fields)

{url_block}

## Real-source-only discipline (M14-trap, per `~/.claude/CLAUDE.md`)

- Every record's provenance is anchored by ``source_audit_ref`` plus the
  resolvable URLs (where present) re-cited in
  ``required_preconditions`` / ``attacker_action_sequence``.
- This README is a *scaffold* derived from the records themselves; it
  does not replace the original miner's hand-written attribution.  If
  the miner returns, rename to ``_MINER_README.md`` and rewrite by hand
  per the patterns in ``audit/corpus_tags/tags/mev_exploits/_MINER_README.md``
  and ``audit/corpus_tags/tags/bridge_incidents/_MINER_README.md``.
- Quarantined fabricated records (Vyper-CVE precedent) live under
  ``audit/corpus_tags/tags/_QUARANTINE_FABRICATED_CVE/`` and are
  excluded from this scaffolder by name.

## Re-walk the subtree

```
python3 tools/hackerman-domain-stats.py \\
    --tags-dir audit/corpus_tags/tags
python3 tools/hackerman-attack-class-distribution.py \\
    --tags-dir audit/corpus_tags/tags
```

## MCP context pack used at scaffold time

```
context_pack_id:   {context_pack_id}
context_pack_hash: {context_pack_hash}
```
"""
    return body


def scaffold(
    tags_dir: Path,
    dry_run: bool = False,
    context_pack_id: str = DEFAULT_CONTEXT_PACK_ID,
    context_pack_hash: str = DEFAULT_CONTEXT_PACK_HASH,
    today: str | None = None,
) -> dict[str, Any]:
    """Scan ``tags_dir`` and emit a README for every missing-README subtree.

    Returns a JSON-able envelope with ``created`` / ``skipped`` /
    ``excluded`` lists.
    """
    created: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    if not tags_dir.is_dir():
        return {
            "schema": SCHEMA,
            "tags_dir": str(tags_dir),
            "created": [],
            "skipped": [],
            "excluded": [],
            "totals": {"created": 0, "skipped": 0, "excluded": 0},
        }
    for child in sorted(tags_dir.iterdir()):
        if not child.is_dir():
            continue
        if any(child.name.startswith(p) for p in EXCLUDED_PREFIXES):
            excluded.append({"subtree": child.name, "reason": "excluded-prefix"})
            continue
        existing = _has_existing_readme(child)
        if existing:
            skipped.append({"subtree": child.name, "existing_readme": existing})
            continue
        summary = _summarise_subtree(child)
        body = render_readme(
            child.name,
            summary,
            context_pack_id=context_pack_id,
            context_pack_hash=context_pack_hash,
            today=today,
        )
        target = child / "README.md"
        if not dry_run:
            target.write_text(body, encoding="utf-8")
        created.append(
            {
                "subtree": child.name,
                "path": str(target),
                "record_count": summary["record_count"],
                "sample_url_count": len(summary["sample_urls"]),
                "dry_run": dry_run,
            }
        )
    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "created": created,
        "skipped": skipped,
        "excluded": excluded,
        "totals": {
            "created": len(created),
            "skipped": len(skipped),
            "excluded": len(excluded),
        },
    }


def _render_human(envelope: dict[str, Any]) -> str:
    lines = []
    lines.append(f"# hackerman subtree README scaffolder ({envelope['schema']})")
    lines.append("")
    lines.append(f"tags_dir: {envelope['tags_dir']}")
    t = envelope["totals"]
    lines.append(
        f"totals: created={t['created']} skipped={t['skipped']} excluded={t['excluded']}"
    )
    lines.append("")
    if envelope["created"]:
        lines.append("## Created")
        for row in envelope["created"]:
            mark = " (dry-run)" if row.get("dry_run") else ""
            lines.append(
                f"- {row['subtree']}: {row['record_count']} records, "
                f"{row['sample_url_count']} sample URLs{mark}"
            )
        lines.append("")
    if envelope["skipped"]:
        lines.append("## Skipped (existing README)")
        for row in envelope["skipped"]:
            lines.append(f"- {row['subtree']}: {row['existing_readme']}")
        lines.append("")
    if envelope["excluded"]:
        lines.append("## Excluded (quarantine / deprecated)")
        for row in envelope["excluded"]:
            lines.append(f"- {row['subtree']}: {row['reason']}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Scaffold per-subtree README.md files for hackerman corpus tags."
    )
    p.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory containing the per-subtree dirs (default: %(default)s).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be created but don't write files.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON envelope to stdout instead of human render.",
    )
    p.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help="Also write the JSON envelope to this path.",
    )
    p.add_argument(
        "--context-pack-id",
        default=DEFAULT_CONTEXT_PACK_ID,
        help="MCP context pack id to embed in scaffolded READMEs.",
    )
    p.add_argument(
        "--context-pack-hash",
        default=DEFAULT_CONTEXT_PACK_HASH,
        help="MCP context pack hash to embed in scaffolded READMEs.",
    )
    args = p.parse_args(argv)

    envelope = scaffold(
        args.tags_dir,
        dry_run=args.dry_run,
        context_pack_id=args.context_pack_id,
        context_pack_hash=args.context_pack_hash,
    )
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8"
        )
    if args.json:
        print(json.dumps(envelope, indent=2, sort_keys=True))
    else:
        print(_render_human(envelope))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
