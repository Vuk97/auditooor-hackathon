#!/usr/bin/env python3
# r36-rebuttal: CAPABILITY-GAP-CLOSURE-2026-05-26 lane (X1 closure)
"""corpus-inventory.py - what corpora already exist + how big are they.

Closes capability gap X1 (codified 2026-05-26 docs/CAPABILITY_GAPS_2026-05-26_ITER_FROM_CHAT.md):
orchestrator (= me / Claude / Codex) creates new corpus subdirs without first
querying what exists, leading to the 2026-05-26 verified_exploits_2026/ rebuild
when bridge_incidents/ already had 26 records in canonical format.

This tool walks audit/corpus_tags/{tags,derived}/* and emits {subdir → record_count,
sample_record_id, last_modified, schema_version_hits}. Output is machine-readable
JSON intended to be:

  1. Read by the universal-rule-enforce hook BEFORE allowing any Write/Edit
     under audit/corpus_tags/tags/<NEW_subdir>/ — see check-new-corpus-dir.sh.
  2. Cited in the Layer-1 recall block in CLAUDE.md for orchestrator session
     start; orchestrator MUST consult this before any "add corpus record" intent.
  3. Cross-referenced by canonical-inventory.py for the full system snapshot.

USAGE
    python3 tools/corpus-inventory.py
        # JSON summary to stdout

    python3 tools/corpus-inventory.py --check <subdir_name>
        # Print just that one subdir's stats; exit 0 if exists+populated,
        # exit 1 if exists+empty, exit 2 if doesn't exist (= caller should
        # consider whether to use an existing subdir instead).

    python3 tools/corpus-inventory.py --out reference/corpus_inventory_snapshot.json
        # Persist snapshot
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOL_NAME = "corpus-inventory"
TOOL_VERSION = "1.0.0"
SCHEMA = "auditooor.corpus_inventory.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent

ROOTS = [
    REPO_ROOT / "audit" / "corpus_tags" / "tags",
    REPO_ROOT / "audit" / "corpus_tags" / "derived",
]


def inventory_dir(d: Path, sample_limit: int = 3) -> Dict[str, Any]:
    """Return {record_count, sample_record_ids, last_modified, schema_hits}."""
    entry: Dict[str, Any] = {
        "name": d.name,
        "path": str(d.relative_to(REPO_ROOT)),
        "record_count": 0,
        "sample_record_ids": [],
        "last_modified_utc": None,
        "schema_version_hits": {},
    }
    if not d.is_dir():
        return entry
    files = []
    for ext in ("*.yaml", "*.yml", "*.json", "*.jsonl"):
        files.extend(d.rglob(ext))
    files = files[:50000]  # cap to avoid scanning massive trees
    if not files:
        # Also count subdirs as records (some corpora use 1 dir = 1 record)
        subdirs = [s for s in d.iterdir() if s.is_dir()]
        entry["record_count"] = len(subdirs)
        entry["sample_record_ids"] = [s.name for s in subdirs[:sample_limit]]
        if subdirs:
            try:
                entry["last_modified_utc"] = max(s.stat().st_mtime for s in subdirs)
            except Exception:
                pass
        return entry
    entry["record_count"] = len(files)
    sample_ids = []
    max_mtime = 0.0
    schema_hits: Dict[str, int] = {}
    for f in files[:sample_limit]:
        sample_ids.append(f.stem[:80])
    entry["sample_record_ids"] = sample_ids
    for f in files[:200]:  # sample-scan for schema versions
        try:
            mtime = f.stat().st_mtime
            if mtime > max_mtime:
                max_mtime = mtime
            # Cheap schema-version detection (first 500 bytes)
            head = f.read_text(encoding="utf-8", errors="replace")[:500]
            import re
            for m in re.finditer(r'schema_version:\s*["\']?([a-z0-9._-]+)', head):
                k = m.group(1)
                schema_hits[k] = schema_hits.get(k, 0) + 1
            for m in re.finditer(r'"schema_version"\s*:\s*"([^"]+)"', head):
                k = m.group(1)
                schema_hits[k] = schema_hits.get(k, 0) + 1
        except Exception:
            continue
    if max_mtime > 0:
        entry["last_modified_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max_mtime))
    entry["schema_version_hits"] = dict(sorted(schema_hits.items(), key=lambda x: -x[1])[:5])
    return entry


def build_snapshot() -> Dict[str, Any]:
    by_root: Dict[str, List[Dict[str, Any]]] = {}
    totals = {"record_count": 0, "subdir_count": 0}
    for root in ROOTS:
        if not root.is_dir():
            continue
        root_key = str(root.relative_to(REPO_ROOT))
        entries = []
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            ent = inventory_dir(d)
            entries.append(ent)
            totals["record_count"] += ent["record_count"]
            totals["subdir_count"] += 1
        by_root[root_key] = entries
    return {
        "schema": SCHEMA,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totals": totals,
        "by_root": by_root,
    }


def main() -> int:
    p = argparse.ArgumentParser(prog=TOOL_NAME)
    p.add_argument("--check", help="Check one subdir name; exit 0=exists+populated, 1=empty, 2=missing")
    p.add_argument("--out", help="Write snapshot to file")
    p.add_argument("--summary", action="store_true", help="Just print top counts, not full JSON")
    args = p.parse_args()

    snapshot = build_snapshot()

    if args.check:
        for root_key, entries in snapshot["by_root"].items():
            for e in entries:
                if e["name"] == args.check:
                    print(json.dumps(e, indent=2))
                    if e["record_count"] > 0:
                        return 0
                    return 1
        print(f"corpus subdir not found: {args.check}", file=sys.stderr)
        print(f"hint: existing subdirs in audit/corpus_tags/tags/:", file=sys.stderr)
        for e in snapshot["by_root"].get("audit/corpus_tags/tags", [])[:30]:
            print(f"  {e['name']:50s} {e['record_count']:6d} records", file=sys.stderr)
        return 2

    out_json = json.dumps(snapshot, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out_json + "\n", encoding="utf-8")
        print(f"wrote snapshot to {args.out}", file=sys.stderr)

    if args.summary:
        print(f"=== corpus inventory (totals: {snapshot['totals']}) ===")
        for root_key, entries in snapshot["by_root"].items():
            print(f"\n{root_key}/ ({len(entries)} subdirs):")
            for e in sorted(entries, key=lambda x: -x["record_count"])[:25]:
                print(f"  {e['name']:50s} {e['record_count']:7d} records")
    elif not args.out:
        print(out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
