#!/usr/bin/env python3
"""Emit a JSONL sidecar of cross-language analogue pairs for Hackerman v1 records."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from hackerman_query_common import (
    DEFAULT_TAGS_DIR,
    normalized_record,
    record_attack_classes,
    record_sites,
    slug,
    stable_hash,
    utc_now,
    yaml_load,
)


SCHEMA = "auditooor.hackerman.cross_language_analogues.v1"
MANIFEST_SCHEMA = "auditooor.hackerman.cross_language_analogues.manifest.v1"
VALID_SCHEMAS = {"auditooor.hackerman_record.v1", "auditooor.hackerman_record.v1.1"}
DEFAULT_SHARD_TARGET_BYTES = 8 * 1024 * 1024  # 8 MiB per shard


def _manifest_path(out_path: Path) -> Path:
    return out_path.with_name(f"{out_path.stem}.manifest.json")


def _shard_dir(out_path: Path) -> Path:
    return out_path.with_name(f"{out_path.stem}.d")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_sharded_sidecar(
    tags_dir: Path,
    out_path: Path,
    *,
    shard_target_bytes: int = DEFAULT_SHARD_TARGET_BYTES,
) -> dict[str, Any]:
    """Build the cross_language_analogues sidecar in the sharded layout.

    Writes ``<stem>.manifest.json`` and ``<stem>.d/shard-NNNNN.jsonl`` shards.
    No individual shard file exceeds ``shard_target_bytes``.
    Consumers call ``read_jsonl`` (hackerman_query_common) which auto-detects
    the manifest and streams shards transparently.
    """
    rows = build_rows(tags_dir)
    manifest_path = _manifest_path(out_path)
    shard_dir = _shard_dir(out_path)
    tmp_dir = shard_dir.with_name(f".{shard_dir.name}.{os.getpid()}.tmp")
    if tmp_dir.exists():
        for old in tmp_dir.glob("*"):
            old.unlink()
        tmp_dir.rmdir()
    tmp_dir.mkdir(parents=True, exist_ok=True)

    shard_target_bytes = max(1024, int(shard_target_bytes))
    shards: list[dict[str, Any]] = []
    current_fh = None
    current_path: Path | None = None
    current_records = 0
    current_bytes = 0
    first_record_id = ""
    last_record_id = ""

    def close_current() -> None:
        nonlocal current_fh, current_path, current_records, current_bytes
        nonlocal first_record_id, last_record_id
        if current_fh is None or current_path is None:
            return
        current_fh.close()
        shards.append(
            {
                "path": current_path.name,
                "records_emitted": current_records,
                "size_bytes": current_path.stat().st_size,
                "sha256": _sha256_file(current_path),
                "first_record_id": first_record_id,
                "last_record_id": last_record_id,
            }
        )
        current_fh = None
        current_path = None
        current_records = 0
        current_bytes = 0
        first_record_id = ""
        last_record_id = ""

    try:
        for row in rows:
            line = json.dumps(row, sort_keys=True) + "\n"
            encoded_len = len(line.encode("utf-8"))
            if current_fh is None or (
                current_records > 0 and current_bytes + encoded_len > shard_target_bytes
            ):
                close_current()
                current_path = tmp_dir / f"shard-{len(shards):05d}.jsonl"
                current_fh = current_path.open("w", encoding="utf-8")
            rid = str(row.get("source_record_id") or "")
            if not first_record_id:
                first_record_id = rid
            last_record_id = rid
            current_fh.write(line)
            current_records += 1
            current_bytes += encoded_len
        close_current()

        total_shard_bytes = sum(int(s["size_bytes"]) for s in shards)
        manifest: dict[str, Any] = {
            "schema_version": MANIFEST_SCHEMA,
            "sidecar_schema": SCHEMA,
            "sidecar_layout": "sharded-jsonl",
            "sidecar_path": str(out_path),
            "manifest_path": str(manifest_path),
            "shard_dir": shard_dir.name,
            "shard_count": len(shards),
            "shard_target_bytes": shard_target_bytes,
            "shard_total_size_bytes": total_shard_bytes,
            "records_emitted": sum(s["records_emitted"] for s in shards),
            "generated_at_utc": utc_now(),
            "shards": shards,
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_manifest = manifest_path.with_name(f".{manifest_path.name}.{os.getpid()}.tmp")
        tmp_manifest.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")

        if shard_dir.exists():
            for old in shard_dir.glob("*.jsonl"):
                old.unlink()
        else:
            shard_dir.mkdir(parents=True, exist_ok=True)
        for shard in shards:
            (tmp_dir / shard["path"]).replace(shard_dir / shard["path"])
        tmp_dir.rmdir()
        tmp_manifest.replace(manifest_path)
        # Truncate monolith to 0-byte stub so the committed file is within budget.
        out_path.write_bytes(b"")
        return manifest
    except Exception:
        if current_fh is not None:
            current_fh.close()
        for old in tmp_dir.glob("*"):
            old.unlink()
        if tmp_dir.exists():
            tmp_dir.rmdir()
        raise
VERIFIED_OUTCOMES = {"ACCEPTED", "FILED", "SUBMITTED"}
DEFAULT_WRITEBACK_LIMIT = 8

_TRANSLATION_TEMPLATES: dict[str, dict[tuple[str, str], str]] = {
    "access-control": {
        ("solidity", "go"): "modifier/role gate -> keeper sender/authority check",
        ("go", "solidity"): "keeper sender/authority check -> modifier/role gate",
        ("go", "go"): "sender/authority check -> sender/authority check",
    },
    "accounting-drift": {
        ("solidity", "go"): "share/balance accounting drift -> bank/reward bookkeeping reconciliation",
        ("go", "solidity"): "bank/reward bookkeeping reconciliation -> share/balance accounting drift",
        ("go", "go"): "bank/reward bookkeeping reconciliation -> bank/reward bookkeeping reconciliation",
    },
    "replay-domain": {
        ("solidity", "go"): "EIP-712 nonce/domain binding -> sign-bytes/chain-id binding",
        ("go", "solidity"): "sign-bytes/chain-id binding -> EIP-712 nonce/domain binding",
        ("go", "go"): "nonce/domain binding -> nonce/domain binding",
    },
    "oracle": {
        ("solidity", "go"): "stale price feed guard -> freshness/quorum guard",
        ("go", "solidity"): "freshness/quorum guard -> stale price feed guard",
        ("go", "go"): "freshness/quorum guard -> freshness/quorum guard",
    },
    "consensus-state": {
        ("solidity", "go"): "state transition guard -> EndBlock/consensus-state gate",
        ("go", "solidity"): "EndBlock/consensus-state gate -> state transition guard",
        ("go", "go"): "EndBlock/consensus-state gate -> EndBlock/consensus-state gate",
    },
}


def _family_for_record(record: dict[str, Any], attack_class: str) -> str:
    haystack = " ".join(
        str(record.get(field) or "")
        for field in (
            "attack_class",
            "bug_class",
            "target_component",
            "target_domain",
            "notes",
            "attacker_action_sequence",
        )
    ).lower()
    tokens = set(re.findall(r"[a-z0-9]+", haystack))
    cls_tokens = set(re.findall(r"[a-z0-9]+", slug(attack_class)))
    family_terms = {
        "access-control": ("access", "auth", "permission", "role", "admin"),
        "replay-domain": ("replay", "nonce", "domain", "signature", "permit"),
        "oracle": ("oracle", "price", "feed", "median", "stale", "manipulated"),
        "accounting-drift": ("account", "balance", "fee", "drift", "supply"),
        "consensus-state": ("consensus", "finality", "endblock", "commit", "ordering", "state"),
    }
    for family, terms in family_terms.items():
        if family in cls_tokens or any(term in tokens for term in terms):
            return family
    return ""


def _specificity_score(record: dict[str, Any], norm: dict[str, Any]) -> float:
    score = 0.0
    if norm.get("target_component"):
        score += 1.0
    if norm.get("target_repo"):
        score += 0.5
    if norm.get("notes"):
        score += 0.5
    if record_sites(record):
        score += 1.0
    if str(record.get("verdict_class") or "").upper() in VERIFIED_OUTCOMES:
        score += 0.5
    if str(record.get("triager_outcome") or "").upper() in VERIFIED_OUTCOMES:
        score += 0.5
    attack_classes = record_attack_classes(record)
    if attack_classes:
        score += min(len(attack_classes), 3) * 0.1
    return score


def _pair_confidence(
    source_record: dict[str, Any],
    source_norm: dict[str, Any],
    analogue_record: dict[str, Any],
    analogue_norm: dict[str, Any],
    attack_class: str,
) -> float:
    confidence = 0.82
    if source_norm.get("target_language") and analogue_norm.get("target_language"):
        if source_norm["target_language"] != analogue_norm["target_language"]:
            confidence += 0.06
    if _family_for_record(source_record, attack_class):
        confidence += 0.04
    if _specificity_score(source_record, source_norm) >= 1.5:
        confidence += 0.03
    if _specificity_score(analogue_record, analogue_norm) >= 1.5:
        confidence += 0.03
    return round(min(0.99, confidence), 3)


def _pattern_translation(source_language: str, target_language: str, attack_class: str, family: str) -> str:
    template = _TRANSLATION_TEMPLATES.get(family, {})
    pair = (source_language or "unknown", target_language or "unknown")
    text = template.get(pair)
    if text is None and family:
        text = template.get((target_language or "unknown", source_language or "unknown"))
    if text is None:
        text = f"{family or slug(attack_class) or 'cross-language'} invariant"
    return f"{pair[0]}->{pair[1]}: {text}"


def _reason(
    source_language: str,
    target_language: str,
    attack_class: str,
    family: str,
    analogue_record_id: str,
) -> str:
    parts = [f"shared attack_class={attack_class}"]
    if family:
        parts.append(f"template_family={family}")
    parts.append(f"{source_language or 'unknown'}->{target_language or 'unknown'}")
    parts.append(f"analogue={analogue_record_id}")
    return "; ".join(parts)


def _load_records(tags_dir: Path) -> list[tuple[dict[str, Any], dict[str, Any], list[str]]]:
    loaded: list[tuple[dict[str, Any], dict[str, Any], list[str]]] = []
    for path in sorted(list(tags_dir.glob("*.yaml")) + list(tags_dir.glob("*.yml"))):
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        if str(doc.get("schema_version") or "") not in VALID_SCHEMAS:
            continue
        norm = normalized_record(doc, {"tag_file": path.name})
        classes = record_attack_classes(doc) or ([norm.get("attack_class")] if norm.get("attack_class") else [])
        classes = [str(value) for value in classes if str(value).strip()]
        if not classes or not norm.get("record_id"):
            continue
        loaded.append((doc, norm, classes))
    return loaded


def build_rows(tags_dir: Path) -> list[dict[str, Any]]:
    records = _load_records(tags_dir)
    by_class: dict[str, list[tuple[dict[str, Any], dict[str, Any], list[str]]]] = {}
    for record, norm, classes in records:
        for attack_class in classes:
            by_class.setdefault(attack_class, []).append((record, norm, classes))

    rows: list[dict[str, Any]] = []
    for attack_class, bucket in sorted(by_class.items(), key=lambda item: slug(item[0])):
        languages: dict[str, list[tuple[dict[str, Any], dict[str, Any], list[str]]]] = {}
        for item in bucket:
            lang = str(item[1].get("target_language") or item[0].get("language") or "")
            languages.setdefault(lang, []).append(item)

        for source_record, source_norm, _ in sorted(bucket, key=lambda item: (str(item[1].get("record_id") or ""), str(item[1].get("target_language") or ""))):
            source_id = str(source_norm.get("record_id") or "")
            source_language = str(source_norm.get("target_language") or "")
            family = _family_for_record(source_record, attack_class)
            for target_language, candidates in sorted(languages.items(), key=lambda item: item[0]):
                if not target_language or target_language == source_language:
                    continue
                same_attack_class_candidates = [
                    candidate
                    for candidate in candidates
                    if str(candidate[1].get("record_id") or "") != source_id
                ]
                if not same_attack_class_candidates:
                    continue
                analogue_record, analogue_norm, _ = sorted(
                    same_attack_class_candidates,
                    key=lambda item: (
                        -_specificity_score(item[0], item[1]),
                        str(item[1].get("record_id") or ""),
                    ),
                )[0]
                analogue_id = str(analogue_norm.get("record_id") or "")
                row = {
                    "source_record_id": source_id,
                    "source_language": source_language,
                    "target_language": target_language,
                    "analogue_record_id": analogue_id,
                    "attack_class": attack_class,
                    "confidence": _pair_confidence(source_record, source_norm, analogue_record, analogue_norm, attack_class),
                    "reason": _reason(source_language, target_language, attack_class, family, analogue_id),
                    "pattern_translation": _pattern_translation(source_language, target_language, attack_class, family),
                }
                rows.append(row)

    rows.sort(key=lambda row: (row["source_record_id"], row["target_language"], row["analogue_record_id"], row["attack_class"]))
    return rows


def _write_jsonl(rows: list[dict[str, Any]], out: Any) -> None:
    for row in rows:
        out.write(json.dumps(row, sort_keys=True) + "\n")


def _record_analogues_from_rows(rows: list[dict[str, Any]], *, limit: int) -> dict[str, list[dict[str, str]]]:
    by_record: dict[str, list[dict[str, str]]] = {}
    seen: dict[str, set[tuple[str, str]]] = {}
    for row in rows:
        source_id = str(row.get("source_record_id") or "").strip()
        language = str(row.get("target_language") or "").strip()
        translation = str(row.get("pattern_translation") or "").strip()
        if not source_id or not language or not translation:
            continue
        key = (language, translation)
        record_seen = seen.setdefault(source_id, set())
        if key in record_seen:
            continue
        items = by_record.setdefault(source_id, [])
        if len(items) >= limit:
            continue
        record_seen.add(key)
        items.append({"target_language": language, "pattern_translation": translation})
    return by_record


def _normalise_record_analogues(raw: Any, *, limit: int) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        language = str(item.get("target_language") or "").strip()
        translation = str(item.get("pattern_translation") or "").strip()
        if not language or not translation:
            continue
        key = (language, translation)
        if key in seen:
            continue
        seen.add(key)
        out.append({"target_language": language, "pattern_translation": translation})
        if len(out) >= limit:
            break
    return out


def _dump_cross_language_block(items: list[dict[str, str]]) -> str:
    if not items:
        return "cross_language_analogues: []"
    try:
        import yaml  # type: ignore

        class IndentedSafeDumper(yaml.SafeDumper):  # type: ignore[attr-defined]
            def increase_indent(self, flow: bool = False, indentless: bool = False) -> Any:
                return super().increase_indent(flow, False)

        return yaml.dump(
            {"cross_language_analogues": items},
            Dumper=IndentedSafeDumper,
            sort_keys=False,
            default_flow_style=False,
            width=120,
        ).rstrip()
    except Exception:
        lines = ["cross_language_analogues:"]
        for item in items:
            lines.append(f"  - target_language: {json.dumps(item['target_language'])}")
            lines.append(f"    pattern_translation: {json.dumps(item['pattern_translation'])}")
        return "\n".join(lines)


def _replace_or_insert_cross_language_block(text: str, block: str) -> str:
    lines = text.splitlines()
    start = next((idx for idx, line in enumerate(lines) if line.startswith("cross_language_analogues:")), -1)
    if start >= 0:
        end = start + 1
        while end < len(lines):
            line = lines[end]
            if line and not line.startswith((" ", "\t")):
                break
            end += 1
        new_lines = lines[:start] + block.splitlines() + lines[end:]
    else:
        insert = next((idx for idx, line in enumerate(lines) if line.startswith("related_records:")), len(lines))
        new_lines = lines[:insert] + block.splitlines() + lines[insert:]
    return "\n".join(new_lines) + "\n"


def writeback_tags(tags_dir: Path, rows: list[dict[str, Any]], *, limit: int, dry_run: bool = False) -> dict[str, Any]:
    """Populate each Hackerman record's schema-native cross_language_analogues field."""
    by_record = _record_analogues_from_rows(rows, limit=limit)
    changed: list[str] = []
    scanned = 0
    for path in sorted(list(tags_dir.glob("*.yaml")) + list(tags_dir.glob("*.yml"))):
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict) or str(doc.get("schema_version") or "") not in VALID_SCHEMAS:
            continue
        record_id = str(doc.get("record_id") or "").strip()
        if not record_id:
            continue
        new_items = by_record.get(record_id)
        if not new_items:
            continue
        scanned += 1
        existing = _normalise_record_analogues(doc.get("cross_language_analogues"), limit=limit)
        merged: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in existing + new_items:
            key = (item["target_language"], item["pattern_translation"])
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
            if len(merged) >= limit:
                break
        if existing == merged:
            continue
        text = path.read_text(encoding="utf-8")
        updated = _replace_or_insert_cross_language_block(text, _dump_cross_language_block(merged))
        if updated != text:
            changed.append(str(path))
            if not dry_run:
                path.write_text(updated, encoding="utf-8")
    return {
        "schema": "auditooor.hackerman.cross_language_analogues.writeback.v1",
        "tags_dir": str(tags_dir),
        "records_with_derived_analogues": len(by_record),
        "records_scanned_for_writeback": scanned,
        "records_changed": len(changed),
        "changed_files_sample": changed[:50],
        "changed_files_omitted": max(0, len(changed) - 50),
        "dry_run": dry_run,
        "limit_per_record": limit,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR), help="Directory containing Hackerman v1 tag YAML files")
    parser.add_argument("--out", default="-", help="Output file or - for stdout")
    parser.add_argument(
        "--shard-target-mb",
        type=float,
        default=None,
        help="Emit sharded layout with this target MiB per shard (default: 8). "
             "Writes <stem>.manifest.json + <stem>.d/shard-*.jsonl and truncates the monolith.",
    )
    parser.add_argument(
        "--writeback-tags",
        action="store_true",
        help="Populate each tag record's cross_language_analogues field from the derived rows",
    )
    parser.add_argument("--writeback-limit", type=int, default=DEFAULT_WRITEBACK_LIMIT, help="Maximum analogues written per record")
    parser.add_argument("--dry-run", action="store_true", help="Plan writeback without modifying tag YAML files")
    parser.add_argument("--writeback-summary", default="", help="Optional JSON summary path for writeback results")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tags_dir = Path(args.tags_dir)

    # Sharded emit path (J3e pattern).
    if args.shard_target_mb is not None and args.out != "-":
        out_path = Path(args.out)
        shard_target_bytes = int(float(args.shard_target_mb) * 1024 * 1024)
        manifest = build_sharded_sidecar(tags_dir, out_path, shard_target_bytes=shard_target_bytes)
        print(json.dumps({"schema": MANIFEST_SCHEMA, "shard_count": manifest["shard_count"],
                          "records_emitted": manifest["records_emitted"],
                          "shard_total_size_bytes": manifest["shard_total_size_bytes"],
                          "shard_dir": manifest["shard_dir"]}, sort_keys=True))
        return 0

    rows = build_rows(tags_dir) if tags_dir.is_dir() else []
    digest = stable_hash({"schema": SCHEMA, "tags_dir": str(tags_dir), "rows": [(r["source_record_id"], r["analogue_record_id"], r["attack_class"]) for r in rows]})
    header = {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "generated_at_utc": utc_now(),
        "source_tags_dir": str(tags_dir),
        "total_rows": len(rows),
        "degraded": not tags_dir.is_dir(),
        "rows": rows,
    }
    out_rows = rows
    if args.out == "-":
        _write_jsonl(out_rows, sys.stdout)
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            "\n".join(json.dumps(row, sort_keys=True) for row in out_rows) + ("\n" if out_rows else ""),
            encoding="utf-8",
        )
    if args.writeback_tags:
        summary = writeback_tags(
            tags_dir,
            rows,
            limit=max(1, int(args.writeback_limit)),
            dry_run=bool(args.dry_run),
        )
        if args.writeback_summary:
            Path(args.writeback_summary).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            print(json.dumps(summary, sort_keys=True), file=sys.stderr)
    if not tags_dir.is_dir():
        print(json.dumps(header, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
