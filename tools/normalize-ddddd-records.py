#!/usr/bin/env python3
"""Normalize the 22 DDDDD methodology/persona corpus records.

Lane WWWWW iter17 fix. DDDDD created 22 records under
audit/corpus_tags/tags/agent_briefs_methodology/ and agent_briefs_persona/
that fail v1.1 schema validation on 8 controlled-vocab fields.

Two-part fix:
  (1) Schema extension (done out-of-band in the v1.1 .schema.json) adds
      the new enum values for the synthetic-taxonomy-anchor record class
      (tier-3) - audit-process / process-doc / auditor-or-detector /
      methodology-coverage / audit-engagement / agent-brief-methodology-anchor /
      informational. These are additive backward-compatible extensions per
      Wave-2/Wave-4 precedent and preserve DDDDD's semantic content.

  (2) This script fixes the single remaining record-side issue:
      target_repo: 'auditooor' -> 'auditooor/agent-briefs' so it satisfies
      the schema's existing org/repo pattern. (Substance unchanged: still
      points at the auditooor agent-briefs corpus.)

Per L34 + the task spec: schema-only fix; class assignments and rationales
preserved verbatim. Idempotent: re-running is a no-op if records already
normalized.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TAGS_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "tags"
SUBTREES = [
    TAGS_ROOT / "agent_briefs_methodology",
    TAGS_ROOT / "agent_briefs_persona",
]


def _patch_yaml_target_repo(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    needle = "target_repo: auditooor\n"
    if needle not in text:
        return False
    new = text.replace(needle, "target_repo: auditooor/agent-briefs\n")
    path.write_text(new, encoding="utf-8")
    return True


def _patch_json_target_repo(path: Path) -> bool:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("target_repo") != "auditooor":
        return False
    doc["target_repo"] = "auditooor/agent-briefs"
    path.write_text(
        json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return True


def main() -> int:
    yaml_changed = 0
    json_changed = 0
    record_dirs = []
    for subtree in SUBTREES:
        if not subtree.exists():
            print(f"[skip] subtree missing: {subtree}", file=sys.stderr)
            continue
        for record_dir in sorted(p for p in subtree.iterdir() if p.is_dir()):
            record_dirs.append(record_dir)
            yaml_path = record_dir / "record.yaml"
            json_path = record_dir / "record.json"
            if yaml_path.exists() and _patch_yaml_target_repo(yaml_path):
                yaml_changed += 1
                print(f"[patched-yaml] {yaml_path.relative_to(REPO_ROOT)}")
            if json_path.exists() and _patch_json_target_repo(json_path):
                json_changed += 1
                print(f"[patched-json] {json_path.relative_to(REPO_ROOT)}")
    print(
        f"\n[summary] record_dirs={len(record_dirs)} "
        f"yaml_patched={yaml_changed} json_patched={json_changed}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
