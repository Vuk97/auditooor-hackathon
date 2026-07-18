#!/usr/bin/env python3
"""Build bounded detector-to-Hackerman relationship rows from local corpus data.

This is a deterministic bridge between detector hits and Hackerman records:
detector slug -> attack classes / bug class / component / record ids.

It is intentionally advisory-only. Relationships rank useful historical records
for source review and proof planning, but they do not prove exploitability,
impact, severity, duplicate status, or submission readiness.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import (  # noqa: E402
    DEFAULT_TAGS_DIR,
    attack_class_query_terms,
    clamp_limit,
    iter_corpus_record_paths,
    record_attack_classes,
    stable_hash,
    utc_now,
    yaml_load,
)


SCHEMA = "auditooor.hackerman.detector_relationships.v1"
HACKERMAN_SCHEMA = "auditooor.hackerman_record.v1"
# Wave-2-A (2026-05-16) migrated the corpus to schema v1.1 (additive,
# backward-compatible). Accept both so this tool does not silently reject
# ~99.98% of the migrated corpus. Mirrors RECOGNISED_SCHEMA_VERSIONS in
# tools/hackerman-record-validate.py.
HACKERMAN_SCHEMA_V1_1 = "auditooor.hackerman_record.v1.1"
RECOGNISED_HACKERMAN_SCHEMAS = (HACKERMAN_SCHEMA, HACKERMAN_SCHEMA_V1_1)
BUG_CLASS_MAP = REPO_ROOT / "audit" / "bug_class_to_attack_classes_map.yaml"
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "by",
    "call",
    "check",
    "checks",
    "contract",
    "contracts",
    "ctx",
    "external",
    "file",
    "for",
    "from",
    "function",
    "go",
    "hook",
    "in",
    "is",
    "keeper",
    "lacks",
    "lock",
    "msg",
    "no",
    "not",
    "of",
    "on",
    "or",
    "path",
    "set",
    "sol",
    "src",
    "state",
    "the",
    "to",
    "update",
    "using",
    "with",
}
CLUSTER_RE = re.compile(r"^###(?:\s+Cluster:)?\s*`?([^`(]+?)`?\s*(?:\((\d+)\s+hits?\))?\s*$")
SIMPLE_HIT_RE = re.compile(r"^- (.+:\d+): (.+)$")


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _slug(value: str) -> str:
    text = _as_text(value).lower()
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"[^a-z0-9-]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")


def _uniq(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _as_text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _split_words(value: str) -> list[str]:
    text = _as_text(value)
    if not text:
        return []
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"[^A-Za-z0-9]+", " ", text)
    parts = []
    for token in text.lower().split():
        if len(token) <= 1 or token in STOPWORDS:
            continue
        parts.append(token)
    return parts


def _token_set(values: list[str]) -> set[str]:
    out: set[str] = set()
    for value in values:
        out.update(_split_words(value))
    return out


def _attack_class_terms(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        for term in attack_class_query_terms(value) or [value]:
            key = _slug(term)
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(term)
    return out


def _relation_strength(query_texts: list[str], candidate_text: str) -> tuple[int, list[str]]:
    candidate = _as_text(candidate_text)
    if not candidate:
        return 0, []
    query_slug_blob = " ".join(_slug(text) for text in query_texts if _as_text(text))
    candidate_slug = _slug(candidate)
    if candidate_slug and candidate_slug in query_slug_blob:
        return 5, _uniq(candidate_slug.split("-"))
    query_tokens = _token_set(query_texts)
    candidate_tokens = _token_set([candidate])
    overlap = sorted(query_tokens & candidate_tokens)
    if not overlap:
        return 0, []
    if len(overlap) >= 3:
        return 4, overlap
    if len(overlap) == 2:
        return 3, overlap
    token = overlap[0]
    if len(token) >= 8:
        return 2, overlap
    return 1, overlap


def _load_bug_class_map(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    try:
        payload = yaml_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    mappings = payload.get("mappings") if isinstance(payload, dict) else None
    if not isinstance(mappings, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, values in mappings.items():
        if not isinstance(values, list):
            continue
        norm_key = _slug(str(key))
        out[norm_key] = _uniq([_as_text(value) for value in values if _as_text(value)])
    return out


def _is_record(doc: Any) -> bool:
    return isinstance(doc, dict) and doc.get("schema_version") in RECOGNISED_HACKERMAN_SCHEMAS


def _normalize_record(
    path: Path,
    record: dict[str, Any],
    bug_map: dict[str, list[str]],
    *,
    tag_file: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    record_id = _as_text(record.get("record_id"))
    bug_class = _as_text(record.get("bug_class"))
    attack_classes = _uniq(record_attack_classes(record))
    component = _as_text(record.get("target_component"))
    if not record_id:
        return None, "missing record_id"
    if not bug_class:
        return None, "missing bug_class"
    if not attack_classes:
        return None, "missing attack_class"
    if not component:
        return None, "missing target_component"
    mapped_attack_classes = bug_map.get(_slug(bug_class), [])
    attack_terms = _attack_class_terms(attack_classes + mapped_attack_classes)
    return (
        {
            "record_id": record_id,
            "source_audit_ref": _as_text(record.get("source_audit_ref")),
            "target_repo": _as_text(record.get("target_repo")),
            "target_language": _as_text(record.get("target_language")),
            "target_domain": _as_text(record.get("target_domain")),
            "target_component": component,
            "bug_class": bug_class,
            "attack_classes": attack_classes,
            "mapped_attack_classes": mapped_attack_classes,
            "attack_terms": attack_terms,
            "file_name": tag_file or path.name,
        },
        None,
    )


def _load_records(tag_dir: Path, bug_map: dict[str, list[str]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    invalid_records: list[dict[str, str]] = []
    scanned = 0
    skipped_non_record = 0
    for item in iter_corpus_record_paths(tag_dir):
        path = item.path
        scanned += 1
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            invalid_records.append({"file": path.name, "reason": f"unparseable YAML: {exc}"})
            continue
        if not _is_record(doc):
            skipped_non_record += 1
            continue
        row, error = _normalize_record(path, doc, bug_map, tag_file=item.relative_path)
        if error:
            invalid_records.append({"file": path.name, "reason": error})
            continue
        records.append(row)
    summary = {
        "tag_files_scanned": scanned,
        "records_loaded": len(records),
        "records_skipped_invalid": len(invalid_records),
        "records_skipped_non_record": skipped_non_record,
        "invalid_records": invalid_records[:10],
    }
    return records, summary


def _severity(value: str) -> str:
    text = _as_text(value).upper()
    return text if text in SEVERITY_ORDER else "UNKNOWN"


def _workspace_relative(path_text: str) -> str:
    text = _as_text(path_text).replace("\\", "/")
    if not text:
        return ""
    line_suffix = ""
    match = re.match(r"^(.+?)(:\d+(?::\d+)?)$", text)
    if match:
        text = match.group(1)
        line_suffix = match.group(2)
    path = Path(text)
    if path.is_absolute():
        return path.name + line_suffix
    return text + line_suffix


def _normalize_cluster(detector_slug: str, hits: list[dict[str, Any]]) -> dict[str, Any] | None:
    slug = _slug(detector_slug)
    if not slug:
        return None
    cleaned_hits: list[dict[str, Any]] = []
    severities: list[str] = []
    cluster_texts = [slug]
    for hit in hits:
        severity = _severity(hit.get("severity"))
        file_path = _workspace_relative(_as_text(hit.get("file_path")))
        snippet = _as_text(hit.get("snippet"))
        cleaned_hit = {
            "severity": severity,
            "file_path": file_path,
            "snippet": snippet,
        }
        cleaned_hits.append(cleaned_hit)
        severities.append(severity)
        cluster_texts.extend([file_path, snippet])
    return {
        "detector_slug": slug,
        "hit_count": len(cleaned_hits),
        "severities": _uniq(severities),
        "hits": cleaned_hits,
        "context_texts": cluster_texts,
    }


def _parse_engage_report_json(path: Path) -> list[dict[str, Any]] | None:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    raw_clusters = payload.get("clusters")
    if not isinstance(raw_clusters, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw_clusters:
        if not isinstance(item, dict):
            continue
        detector = _as_text(item.get("detector_slug") or item.get("detector"))
        if not detector:
            continue
        hits: list[dict[str, Any]] = []
        for hit in item.get("hits") or []:
            if not isinstance(hit, dict):
                continue
            hits.append(
                {
                    "severity": hit.get("severity") or hit.get("severity_class") or hit.get("sev") or "UNKNOWN",
                    "file_path": hit.get("file_path") or hit.get("path") or hit.get("file") or hit.get("location") or "",
                    "snippet": hit.get("snippet") or hit.get("message") or hit.get("excerpt") or "",
                }
            )
        row = _normalize_cluster(detector, hits)
        if row is not None:
            out.append(row)
    return out


def _parse_engage_report_markdown(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    clusters: list[dict[str, Any]] = []
    current_detector = ""
    current_hits: list[dict[str, Any]] = []

    def flush() -> None:
        nonlocal current_detector, current_hits
        row = _normalize_cluster(current_detector, current_hits)
        if row is not None:
            clusters.append(row)
        current_detector = ""
        current_hits = []

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        cluster_match = CLUSTER_RE.match(line)
        if cluster_match:
            if current_detector:
                flush()
            current_detector = cluster_match.group(1).strip()
            continue
        if not current_detector:
            continue
        rich_match = re.match(
            r"^- \*\*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN)\]\s*`?([^`]+?)`?\*\*\s*[—–-]\s*`?([^`]+?)`?\s*$",
            line,
        )
        if rich_match:
            current_hits.append(
                {
                    "severity": rich_match.group(1),
                    "file_path": rich_match.group(3),
                    "snippet": "",
                }
            )
            continue
        simple_match = SIMPLE_HIT_RE.match(line)
        if simple_match:
            current_hits.append(
                {
                    "severity": "UNKNOWN",
                    "file_path": simple_match.group(1),
                    "snippet": simple_match.group(2),
                }
            )
            continue
        if current_hits and line.startswith("- snippet:"):
            current_hits[-1]["snippet"] = line.split(":", 1)[1].strip().strip("`")
    if current_detector:
        flush()
    return clusters


def _load_engage_report(engage_report_arg: str | None) -> tuple[list[dict[str, Any]], list[str]]:
    if not engage_report_arg:
        return [], []
    report_path = Path(engage_report_arg).expanduser().resolve()
    warnings: list[str] = []
    if not report_path.exists():
        warnings.append(f"engage report path not found: {report_path}")
        return [], warnings
    if report_path.suffix.lower() == ".json":
        json_rows = _parse_engage_report_json(report_path)
        if json_rows is None:
            warnings.append(f"invalid JSON engage report: {report_path}")
            return [], warnings
        return json_rows, warnings
    if report_path.suffix.lower() == ".md":
        json_sidecar = report_path.with_suffix(".json")
        if json_sidecar.exists():
            json_rows = _parse_engage_report_json(json_sidecar)
            if json_rows is not None:
                return json_rows, warnings
            warnings.append(f"invalid adjacent JSON sidecar ignored: {json_sidecar}")
        return _parse_engage_report_markdown(report_path), warnings
    warnings.append(f"engage report path not found or unsupported: {report_path}")
    return [], warnings


def _detector_sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
    max_sev = max((SEVERITY_ORDER.get(sev, 0) for sev in row.get("severities", [])), default=0)
    return (-int(row.get("hit_count") or 0), -max_sev, str(row.get("detector_slug") or ""))


def _relationship_rows(detector: dict[str, Any], records: list[dict[str, Any]], per_detector_limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    detector_texts = list(detector.get("context_texts") or [])
    for record in records:
        attack_matches: list[dict[str, Any]] = []
        best_attack_strength = 0
        for attack_class in record["attack_classes"]:
            strength, tokens = _relation_strength(detector_texts, attack_class)
            if strength <= 0:
                continue
            best_attack_strength = max(best_attack_strength, strength)
            attack_matches.append(
                {
                    "attack_class": attack_class,
                    "strength": strength,
                    "matched_tokens": tokens,
                    "source": "record_attack_class",
                }
            )
        for attack_class in record["mapped_attack_classes"]:
            strength, tokens = _relation_strength(detector_texts, attack_class)
            if strength <= 0:
                continue
            best_attack_strength = max(best_attack_strength, strength)
            attack_matches.append(
                {
                    "attack_class": attack_class,
                    "strength": strength,
                    "matched_tokens": tokens,
                    "source": "bug_class_map",
                }
            )
        bug_strength, bug_tokens = _relation_strength(detector_texts, record["bug_class"])
        component_strength, component_tokens = _relation_strength(detector_texts, record["target_component"])
        if best_attack_strength <= 0 and bug_strength <= 0 and component_strength <= 0:
            continue
        score = (best_attack_strength * 100) + (bug_strength * 35) + (component_strength * 20)
        relationship_id = stable_hash(
            {
                "detector_slug": detector["detector_slug"],
                "record_id": record["record_id"],
                "score": score,
            }
        )[:16]
        rows.append(
            {
                "relationship_id": relationship_id,
                "detector_slug": detector["detector_slug"],
                "record_id": record["record_id"],
                "source_audit_ref": record["source_audit_ref"],
                "target_repo": record["target_repo"],
                "target_language": record["target_language"],
                "target_domain": record["target_domain"],
                "target_component": record["target_component"],
                "bug_class": record["bug_class"],
                "attack_classes": record["attack_classes"],
                "mapped_attack_classes": record["mapped_attack_classes"],
                "score": score,
                "attack_matches": sorted(
                    attack_matches,
                    key=lambda item: (-int(item["strength"]), str(item["attack_class"]), str(item["source"])),
                ),
                "bug_match": {
                    "bug_class": record["bug_class"],
                    "strength": bug_strength,
                    "matched_tokens": bug_tokens,
                },
                "component_match": {
                    "target_component": record["target_component"],
                    "strength": component_strength,
                    "matched_tokens": component_tokens,
                },
                "match_reasons": _uniq(
                    [
                        "attack_class overlap" if best_attack_strength > 0 else "",
                        "bug_class overlap" if bug_strength > 0 else "",
                        "component overlap" if component_strength > 0 else "",
                    ]
                ),
            }
        )
    rows.sort(key=lambda item: (-int(item["score"]), str(item["record_id"])))
    return rows[:per_detector_limit]


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    limit = clamp_limit(args.limit, default=5, maximum=50)
    bug_map = _load_bug_class_map(BUG_CLASS_MAP)
    records, record_summary = _load_records(tag_dir, bug_map) if tag_dir.is_dir() else ([], {
        "tag_files_scanned": 0,
        "records_loaded": 0,
        "records_skipped_invalid": 0,
        "records_skipped_non_record": 0,
        "invalid_records": [{"file": str(tag_dir), "reason": "tag dir not found"}] if not tag_dir.is_dir() else [],
    })
    detectors, warnings = _load_engage_report(args.engage_report)
    detectors.sort(key=_detector_sort_key)
    selected_detectors = detectors[:limit]
    detector_rows: list[dict[str, Any]] = []
    relationship_total = 0
    for detector in selected_detectors:
        relationships = _relationship_rows(detector, records, per_detector_limit=limit)
        relationship_total += len(relationships)
        detector_rows.append(
            {
                "detector_slug": detector["detector_slug"],
                "hit_count": detector["hit_count"],
                "severities": detector["severities"],
                "hits": detector["hits"],
                "relationships": relationships,
            }
        )
    digest = stable_hash(
        {
            "schema": SCHEMA,
            "tag_dir": str(tag_dir),
            "engage_report": args.engage_report or "",
            "limit": limit,
            "detectors": [row["detector_slug"] for row in detector_rows],
            "relationship_ids": [
                rel["relationship_id"]
                for row in detector_rows
                for rel in row["relationships"]
            ],
        }
    )
    return {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "generated_at_utc": utc_now(),
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
        "inputs": {
            "tag_dir": str(tag_dir),
            "engage_report": _as_text(args.engage_report),
            "limit": limit,
        },
        "summary": {
            **record_summary,
            "detectors_scanned": len(detectors),
            "detectors_returned": len(detector_rows),
            "relationship_rows_returned": relationship_total,
        },
        "warnings": warnings,
        "detectors": detector_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Hackerman Detector Relationships",
        "",
        f"- schema: `{payload.get('schema', SCHEMA)}`",
        f"- advisory_only: `{str(bool(payload.get('advisory_only'))).lower()}`",
        f"- submission_posture: `{payload.get('submission_posture', 'NOT_SUBMIT_READY')}`",
        f"- tag_dir: `{payload.get('inputs', {}).get('tag_dir', '')}`",
        f"- engage_report: `{payload.get('inputs', {}).get('engage_report', '') or '-'}`",
        f"- detectors_returned: `{payload.get('summary', {}).get('detectors_returned', 0)}`",
        f"- relationship_rows_returned: `{payload.get('summary', {}).get('relationship_rows_returned', 0)}`",
        "",
    ]
    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
    detectors = payload.get("detectors") or []
    if not detectors:
        lines.append("No detector clusters were loaded, so no detector-to-record relationships were emitted.")
        return "\n".join(lines) + "\n"
    for detector in detectors:
        lines.extend(
            [
                f"## Detector `{detector['detector_slug']}`",
                "",
                f"- hits: `{detector['hit_count']}`",
                f"- severities: `{', '.join(detector['severities']) or 'UNKNOWN'}`",
            ]
        )
        relationships = detector.get("relationships") or []
        if not relationships:
            lines.append("- relationships: none")
            lines.append("")
            continue
        lines.append("- top relationships:")
        for row in relationships:
            attack_preview = ", ".join(row["attack_classes"][:3]) or "-"
            lines.append(
                f"  - `{row['record_id']}` score={row['score']} bug_class=`{row['bug_class']}` "
                f"attack_classes=`{attack_preview}` component=`{row['target_component']}`"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR), help="Directory of hackerman_record YAML files.")
    parser.add_argument(
        "--engage-report",
        default=None,
        help="Optional engage_report.json or engage_report.md path used to source detector slugs.",
    )
    parser.add_argument("--limit", type=int, default=5, help="Max detectors returned and max relationships per detector.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    parser.add_argument("--out", default="-", help="Write output to this path. Use '-' for stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = build_payload(args)
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n" if args.json else render_markdown(payload)
    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
