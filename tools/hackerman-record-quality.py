#!/usr/bin/env python3
"""Emit derived quality/tier rows for Hackerman corpus records."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hackerman_query_common import DEFAULT_TAGS_DIR, yaml_load


DEFAULT_OUT = Path("audit") / "corpus_tags" / "derived" / "record_quality.jsonl"
# Wave-3 W3.3: accept both v1 (legacy) and v1.1 (Phase-3 schema migration).
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
SCHEMA_VERSION_V1_1 = "auditooor.hackerman_record.v1.1"
ACCEPTED_SCHEMAS = (SCHEMA_VERSION, SCHEMA_VERSION_V1_1)
SCHEMA_NATIVE_FIELDS = (
    "record_tier",
    "record_quality_score",
    "source_extraction_method",
    "source_extraction_confidence",
)
FUNCTION_NAME_HINT_RE = re.compile(r"^function-name-hint:\s*[A-Za-z_][A-Za-z0-9_]*$", re.IGNORECASE)
# Wave-3 W3.3: well-formed external-provenance identifiers.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
GHSA_ID_RE = re.compile(
    r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE
)
HTTPS_URL_RE = re.compile(r"^https://[^\s]+$")


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _is_hackerman_record(doc: Any) -> bool:
    # Wave-3 W3.3: accept v1 and v1.1.  Phase-3 schema migration
    # (commit 5ac7108d01) bumps schema_version v1 -> v1.1; the legacy
    # check rejected every migrated record, capping coverage at 0.
    return isinstance(doc, dict) and doc.get("schema_version") in ACCEPTED_SCHEMAS


def _should_skip_path(path: Path) -> bool:
    sp = str(path)
    return "/_deprecated/" in sp or "_QUARANTINE_" in sp


def iter_records(tag_dir: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    # Wave-3 W3.3: recursive scan.  Phase-3 reorganised tags/ into
    # per-topic subdirectories; flat glob skipped ~8.5k records.
    for path in sorted(tag_dir.rglob("*.yaml")):
        if _should_skip_path(path):
            continue
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _is_hackerman_record(doc):
            yield path, doc


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(needle in lowered for needle in needles)


def yaml_scalar(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _v11_provenance_bonus(
    record: dict[str, Any], reasons: list[str]
) -> tuple[float, float]:
    """Wave-3 W3.3: credit v1.1 provenance fields.

    Bonuses reflect real external corroboration:
      - first-class ``verification_tier`` (Rule 37 anchor)
      - well-formed ``cve_id`` matching NVD format
      - well-formed ``ghsa_id`` matching GHSA format
      - ``record_source_url`` with HTTPS scheme (external archive)
      - non-empty ``related_records`` (cross-record corroboration)
      - ``verification_method`` field present (Rule 37 evidence stamp)

    Returns ``(score_delta, confidence_delta)``.
    """
    score_delta = 0.0
    conf_delta = 0.0

    vt = _as_text(record.get("verification_tier"))
    if vt == "tier-1-verified-realtime-api":
        score_delta += 0.8
        conf_delta += 0.1
        reasons.append("verification_tier tier-1 (live-API verified)")
    elif vt == "tier-1-officially-disclosed":
        score_delta += 0.8
        conf_delta += 0.1
        reasons.append("verification_tier tier-1 (officially disclosed)")
    elif vt == "tier-2-verified-public-archive":
        # Tier-2 means the record was extracted from a verified public
        # archive (audit PDF, public post-mortem, fix commit) with >=3
        # mandatory shape fields per Rule 37.  That is real, structural
        # provenance: bump the bonus so a typical tier-2 record clears
        # the gate-full floor (score >= 3.0) when paired with any one
        # additional positive signal (recent year, language, source url).
        score_delta += 0.55
        conf_delta += 0.08
        reasons.append("verification_tier tier-2 (public-archive verified)")
    elif vt == "tier-3-synthetic-taxonomy-anchored":
        # No bonus; tier-3 is breadth, not depth.  Documented as a
        # neutral signal so downstream consumers see the tag.
        reasons.append("verification_tier tier-3 (synthetic taxonomy anchor)")
    elif vt == "tier-4-bundled-fixture":
        # Bundled fixtures seed detectors, not findings.  Mild penalty
        # so they cluster below tier-2 records of equivalent shape.
        score_delta -= 0.2
        reasons.append("verification_tier tier-4 (bundled fixture)")
    elif vt == "tier-5-quarantine":
        # Quarantined records must not lift over the gate floor.
        score_delta -= 1.0
        conf_delta -= 0.2
        reasons.append("verification_tier tier-5 (quarantined)")

    cve_id = _as_text(record.get("cve_id"))
    if cve_id and CVE_ID_RE.match(cve_id):
        score_delta += 0.4
        conf_delta += 0.05
        reasons.append(f"well-formed cve_id ({cve_id})")

    ghsa_id = _as_text(record.get("ghsa_id"))
    if ghsa_id and GHSA_ID_RE.match(ghsa_id):
        score_delta += 0.4
        conf_delta += 0.05
        reasons.append(f"well-formed ghsa_id ({ghsa_id})")

    source_url = _as_text(record.get("record_source_url"))
    if source_url and HTTPS_URL_RE.match(source_url):
        score_delta += 0.15
        reasons.append("record_source_url (HTTPS external archive)")

    rr = record.get("related_records")
    if isinstance(rr, list) and len(rr) > 0:
        # Cap the bonus at 0.2 regardless of count; we are crediting
        # the presence of cross-record corroboration, not the volume.
        score_delta += 0.15
        reasons.append(f"related_records corroboration (n={len(rr)})")

    vmethod = _as_text(record.get("verification_method"))
    if vmethod:
        score_delta += 0.1
        reasons.append(f"verification_method recorded ({vmethod})")

    return score_delta, conf_delta


def score_record(record: dict[str, Any], tag_path: Path | None = None) -> dict[str, Any]:
    record_id = _as_text(record.get("record_id"))
    source_ref = _as_text(record.get("source_audit_ref"))
    target_repo = _as_text(record.get("target_repo"))
    verdict_class = _as_text(record.get("verdict_class")).upper()
    language = _as_text(record.get("target_language"))
    year = record.get("year")
    function_shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    raw_signature = _as_text(function_shape.get("raw_signature"))
    source_blob = " ".join([record_id, source_ref, target_repo, _as_text(tag_path)])

    tier = "public-corpus"
    method = "regex-derived"
    confidence = 0.65
    score = 2.5
    reasons: list[str] = []

    if verdict_class == "CANDIDATE" or _contains_any(
        source_blob,
        ("dsl_pattern", "dsl-pattern", "canonical-dsl", "patterns/dsl", "patterns.dsl"),
    ):
        score = 1.0
        method = "dsl-synthetic"
        confidence = 0.35
        reasons.append("synthetic candidate or DSL-derived pattern")
    elif _contains_any(source_blob, ("submission", "paste_ready", "filed", "cantina-")):
        tier = "submission-derived"
        score = 4.4
        method = "human-curated"
        confidence = 0.9
        reasons.append("submission-derived or filed-finding provenance")
    elif source_ref.startswith("prior-audit"):
        tier = "local-workspace"
        score = 3.7
        method = "human-curated"
        confidence = 0.78
        reasons.append("prior-audit extraction")
    elif source_ref.startswith("solodit-spec"):
        score = 2.9
        method = "corpus-etl"
        confidence = 0.7
        reasons.append("public Solodit finding/spec provenance")
    elif source_ref.startswith("corpus-mined"):
        score = 2.6
        method = "regex-derived"
        confidence = 0.6
        reasons.append("corpus-mined extraction")
    elif source_ref.startswith("git-mining"):
        score = 2.5
        method = "regex-derived"
        confidence = 0.58
        reasons.append("git-mining extraction")

    if "dydxprotocol/v4-chain" == target_repo or _contains_any(source_blob, ("dydx", "v4-chain")):
        tier = "dydx-filed" if score >= 4.0 else "local-workspace"
        score += 0.35
        confidence = min(0.95, confidence + 0.05)
        reasons.append("dYdX/Cosmos-relevant provenance")
    elif _contains_any(source_blob, ("mezo", "musd")):
        tier = "mezo-filed" if score >= 4.0 else tier
        score += 0.2
        reasons.append("Mezo-relevant provenance")

    if language == "go":
        score += 0.25
        reasons.append("Go record useful for Cosmos hunts")
    elif language == "solidity":
        score += 0.05

    if year == 2000:
        score -= 0.25
        confidence = max(0.25, confidence - 0.05)
        reasons.append("unknown audit year sentinel")
    elif isinstance(year, int) and year >= 2024:
        score += 0.15
        reasons.append("recent audit year")

    if FUNCTION_NAME_HINT_RE.match(raw_signature):
        score -= 0.35
        confidence = max(0.25, confidence - 0.1)
        reasons.append("function-name hint, not source-extracted signature")

    # Wave-3 W3.3: v1.1 provenance bonuses (verification_tier first-class,
    # cve_id/ghsa_id, source_url, related_records, verification_method).
    bonus_score, bonus_conf = _v11_provenance_bonus(record, reasons)
    score += bonus_score
    confidence += bonus_conf

    score = max(1.0, min(5.0, round(score, 2)))
    confidence = max(0.0, min(1.0, round(confidence, 2)))
    if not reasons:
        reasons.append("default corpus quality heuristic")

    return {
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "record_tier": tier,
        "record_quality_score": score,
        "source_extraction_method": method,
        "source_extraction_confidence": confidence,
        "target_language": language,
        "target_repo": target_repo,
        "reason": "; ".join(reasons),
    }


def build_rows(tag_dir: Path, limit: int | None = None) -> list[dict[str, Any]]:
    rows = [score_record(record, path) for path, record in iter_records(tag_dir)]
    rows.sort(key=lambda row: (-float(row["record_quality_score"]), row["record_id"]))
    if limit is not None:
        rows = rows[: max(0, limit)]
    return rows


def write_jsonl(rows: Iterable[dict[str, Any]], out_path: Path | None) -> int:
    lines = [json.dumps(row, sort_keys=True) for row in rows]
    payload = "\n".join(lines) + ("\n" if lines else "")
    if out_path is None:
        sys.stdout.write(payload)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload, encoding="utf-8")
    return len(lines)


def render_quality_field(field: str, row: dict[str, Any]) -> str:
    return f"{field}: {yaml_scalar(row[field])}"


def update_record_text(text: str, row: dict[str, Any]) -> tuple[str, bool]:
    lines = text.splitlines()
    present = {field: False for field in SCHEMA_NATIVE_FIELDS}
    insert_after = -1
    out: list[str] = []
    changed = False

    for index, line in enumerate(lines):
        if line.startswith("source_audit_ref:"):
            insert_after = len(out)
        replaced = False
        for field in SCHEMA_NATIVE_FIELDS:
            if line.startswith(f"{field}:"):
                present[field] = True
                replacement = render_quality_field(field, row)
                out.append(replacement)
                changed = changed or replacement != line
                replaced = True
                break
        if not replaced:
            out.append(line)
        if index == len(lines) - 1 and text.endswith("\n"):
            pass

    missing = [field for field, seen in present.items() if not seen and field in row]
    if missing:
        insertion = [render_quality_field(field, row) for field in missing]
        offset = insert_after + 1 if insert_after >= 0 else min(3, len(out))
        out[offset:offset] = insertion
        changed = True

    rendered = "\n".join(out) + ("\n" if text.endswith("\n") else "")
    return rendered, changed


def writeback_tags(tag_dir: Path) -> dict[str, int]:
    updated = 0
    scanned = 0
    for path, record in iter_records(tag_dir):
        scanned += 1
        row = score_record(record, path)
        text = path.read_text(encoding="utf-8")
        rendered, changed = update_record_text(text, row)
        if changed:
            path.write_text(rendered, encoding="utf-8")
            updated += 1
    return {"records_scanned_for_writeback": scanned, "records_updated": updated}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Output JSONL path. Use '-' for stdout.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--writeback-tags", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    args = parser.parse_args(argv)

    tag_dir = Path(args.tag_dir)
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2
    out_path = None if args.out == "-" else Path(args.out)
    rows = build_rows(tag_dir, args.limit)
    written = write_jsonl(rows, out_path)
    writeback_summary = writeback_tags(tag_dir) if args.writeback_tags else {}
    if args.json_summary:
        payload = {"records_scored": len(rows), "rows_written": written, "out": args.out}
        payload.update(writeback_summary)
        print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
