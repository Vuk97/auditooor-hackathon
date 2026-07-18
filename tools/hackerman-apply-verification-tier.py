#!/usr/bin/env python3
"""hackerman-apply-verification-tier.

Reads `.auditooor/verification-tier-candidates.jsonl` (produced by
`tools/hackerman-stratify-verification-tier.py`) and adds the corresponding
`verification_tier:<tier>` tag into each record's `function_shape.shape_tags`
array.

The rewrite is:

  - Additive only. All existing fields are preserved byte-for-byte except for
    the small slice inside `function_shape.shape_tags` that is extended by a
    single tag.
  - Idempotent. Re-running the tool detects an existing
    `verification_tier:tier-N-...` tag and either leaves it in place (when it
    matches the candidate) or skips the rewrite. With `--force` an existing
    tier tag is replaced with the candidate value.
  - Schema-safe. The hackerman v1 schema already declares `shape_tags` as a
    string array (minItems 1, uniqueItems true), so adding a string tag is
    inside the schema. No schema migration is required.

Usage:

    python3 tools/hackerman-apply-verification-tier.py --dry-run
    python3 tools/hackerman-apply-verification-tier.py --apply
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"
DEFAULT_INPUT = REPO_ROOT_GUESS / ".auditooor" / "verification-tier-candidates.jsonl"

VERIFICATION_TIER_PREFIX = "verification_tier:"
VERIFICATION_TIER_RE = re.compile(r"^verification_tier:tier-[1-5]-[a-z0-9-]+$")

# Anchors for the YAML block we need to mutate. The canonical hackerman writer
# emits records with this exact shape (top-level key, two-space indent for the
# shape_tags list, dash-prefixed items). Matching it directly avoids a YAML
# dependency.
FUNCTION_SHAPE_HEADER_RE = re.compile(r"^function_shape:\s*$")
SHAPE_TAGS_HEADER_RE = re.compile(r"^(?P<indent> +)shape_tags:\s*$")
SHAPE_TAG_ITEM_RE = re.compile(r"^(?P<indent> +)-\s+(?P<value>.+?)\s*$")


def load_candidates(path: Path) -> Dict[str, Dict[str, str]]:
    candidates: Dict[str, Dict[str, str]] = {}
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            file_field = entry.get("file")
            if not file_field:
                continue
            candidates[file_field] = entry
    return candidates


def _strip_yaml_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1]
    return v


def apply_tier_to_json_text(text: str, tier: str, *, force: bool = False) -> Tuple[str, str]:
    """JSON sibling of apply_tier_to_record_text.

    Parses the JSON record, adds the verification_tier tag inside
    `function_shape.shape_tags`, and re-serialises with deterministic
    formatting (sorted keys, 2-space indent, trailing newline). Status values
    match the YAML path.
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return text, "no-shape"
    if not isinstance(payload, dict):
        return text, "no-shape"
    shape = payload.get("function_shape")
    if not isinstance(shape, dict):
        return text, "no-shape"
    tags = shape.get("shape_tags")
    if not isinstance(tags, list):
        return text, "no-shape"

    candidate_tag = f"{VERIFICATION_TIER_PREFIX}{tier}"
    existing = [t for t in tags if isinstance(t, str) and VERIFICATION_TIER_RE.match(t)]
    if existing:
        if candidate_tag in existing:
            return text, "noop"
        if not force:
            return text, "skipped"
        new_tags: List[str] = []
        replaced = False
        for t in tags:
            if isinstance(t, str) and VERIFICATION_TIER_RE.match(t):
                if not replaced:
                    new_tags.append(candidate_tag)
                    replaced = True
            else:
                new_tags.append(t)
        shape["shape_tags"] = new_tags
        return json.dumps(payload, indent=2, sort_keys=True) + "\n", "replaced"

    shape["shape_tags"] = list(tags) + [candidate_tag]
    return json.dumps(payload, indent=2, sort_keys=True) + "\n", "added"


def apply_tier_to_record_text(text: str, tier: str, *, force: bool = False) -> Tuple[str, str]:
    """Add (or replace) `verification_tier:<tier>` inside `shape_tags`.

    Returns (new_text, status) where status is one of:
      - "added"     : tag inserted; file changed
      - "noop"      : matching tier tag already present; file unchanged
      - "replaced"  : different tier tag replaced (only when force=True)
      - "skipped"   : different tier tag present and force=False
      - "no-shape"  : record has no parseable shape_tags block (rare)
    """
    lines = text.splitlines(keepends=True)
    in_function_shape = False
    shape_tag_indent: Optional[str] = None
    shape_tag_indices: List[int] = []
    shape_tag_values: List[str] = []
    shape_tag_block_end: Optional[int] = None  # index AFTER last shape_tag item

    for idx, raw in enumerate(lines):
        line = raw.rstrip("\n")
        if FUNCTION_SHAPE_HEADER_RE.match(line):
            in_function_shape = True
            continue
        if in_function_shape:
            # If we hit a new top-level key (no leading whitespace, non-empty),
            # the function_shape block is over.
            if line and not line.startswith(" ") and not line.startswith("\t"):
                in_function_shape = False
            elif SHAPE_TAGS_HEADER_RE.match(line):
                shape_tag_indent = SHAPE_TAGS_HEADER_RE.match(line).group("indent")
                # Continue scanning subsequent lines for items. YAML accepts
                # list items at the same indent level as the parent key OR
                # nested deeper, so we accept items whose `-` indent is >=
                # the header indent. The block ends at the first line whose
                # indent drops below the header (a sibling key) or which is
                # not a list item.
                for j in range(idx + 1, len(lines)):
                    sub = lines[j].rstrip("\n")
                    m = SHAPE_TAG_ITEM_RE.match(sub)
                    if m and len(m.group("indent")) >= len(shape_tag_indent):
                        shape_tag_indices.append(j)
                        shape_tag_values.append(_strip_yaml_quotes(m.group("value")))
                        shape_tag_block_end = j + 1
                        continue
                    # Tolerate blank line inside the block (uncommon)
                    if not sub.strip():
                        continue
                    break
                # Stop searching once we found the shape_tags block.
                break

    if not shape_tag_indices or shape_tag_indent is None or shape_tag_block_end is None:
        return text, "no-shape"

    candidate_tag = f"{VERIFICATION_TIER_PREFIX}{tier}"
    # Detect existing verification_tier tags
    existing_indices = [
        i for i, v in zip(shape_tag_indices, shape_tag_values) if VERIFICATION_TIER_RE.match(v)
    ]
    existing_values = [
        v for v in shape_tag_values if VERIFICATION_TIER_RE.match(v)
    ]

    if existing_values:
        if candidate_tag in existing_values:
            return text, "noop"
        if not force:
            return text, "skipped"
        # Replace the first existing one and drop any duplicates.
        out_lines = list(lines)
        replaced_idx = existing_indices[0]
        original = lines[replaced_idx]
        # Preserve trailing newline shape
        out_lines[replaced_idx] = re.sub(
            r"-\s+.+",
            f"- {candidate_tag}",
            original,
            count=1,
        )
        # Remove any further verification_tier entries (in reverse order).
        for extra_idx in reversed(existing_indices[1:]):
            del out_lines[extra_idx]
        return "".join(out_lines), "replaced"

    # No existing verification_tier tag — append one inside the block.
    item_indent = shape_tag_indent + "  "
    if shape_tag_indices:
        # Match the indentation of the first existing item exactly (handles
        # legacy 2-space vs 4-space indented blocks).
        first_match = SHAPE_TAG_ITEM_RE.match(lines[shape_tag_indices[0]].rstrip("\n"))
        if first_match:
            item_indent = first_match.group("indent")
    new_line = f"{item_indent}- {candidate_tag}\n"
    out_lines = list(lines)
    # Insert AFTER the last existing shape_tag item so we stay inside the block.
    out_lines.insert(shape_tag_block_end, new_line)
    return "".join(out_lines), "added"


def apply(
    candidates_path: Path,
    tags_dir: Path,
    *,
    apply_changes: bool,
    force: bool = False,
) -> Dict[str, int]:
    candidates = load_candidates(candidates_path)
    status_counter: Counter[str] = Counter()
    missing_files: List[str] = []

    workspace_root = tags_dir.parent.parent.parent

    for file_field, entry in candidates.items():
        tier = entry.get("verification_tier")
        if not tier:
            status_counter["no-tier"] += 1
            continue
        # `file` may be either repo-relative ("audit/corpus_tags/tags/foo.yaml")
        # or absolute. Normalise.
        candidate_path = Path(file_field)
        if not candidate_path.is_absolute():
            candidate_path = workspace_root / file_field
        if not candidate_path.exists():
            # Try alt: directly under tags_dir using basename
            alt = tags_dir / Path(file_field).name
            if alt.exists():
                candidate_path = alt
            else:
                missing_files.append(file_field)
                status_counter["missing"] += 1
                continue
        original = candidate_path.read_text(encoding="utf-8")
        if candidate_path.suffix.lower() == ".json":
            new_text, status = apply_tier_to_json_text(original, tier, force=force)
        else:
            new_text, status = apply_tier_to_record_text(original, tier, force=force)
        status_counter[status] += 1
        if apply_changes and new_text != original:
            candidate_path.write_text(new_text, encoding="utf-8")

    return dict(status_counter)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--candidates",
        type=Path,
        default=DEFAULT_INPUT,
        help="JSONL produced by hackerman-stratify-verification-tier.py.",
    )
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Hackerman YAML records directory.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change; do NOT modify files.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persist additive edits (default when --dry-run absent).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing verification_tier:<...> tags when they disagree with the candidate.",
    )
    args = parser.parse_args(argv)

    if not args.candidates.exists():
        print(f"error: candidates JSONL missing: {args.candidates}", file=sys.stderr)
        return 2
    if not args.tags_dir.exists():
        print(f"error: tags dir missing: {args.tags_dir}", file=sys.stderr)
        return 2

    apply_changes = args.apply or not args.dry_run

    summary = apply(
        args.candidates,
        args.tags_dir,
        apply_changes=apply_changes,
        force=args.force,
    )

    print("# hackerman verification-tier apply")
    print("status counts:")
    for key in sorted(summary.keys()):
        print(f"  {key:<12} {summary[key]:>7}")
    if apply_changes:
        print()
        print("changes persisted.")
    else:
        print()
        print("(dry-run; no files modified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
