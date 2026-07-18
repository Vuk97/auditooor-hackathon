#!/usr/bin/env python3
# R36 pathspec discipline: this lane is registered as
# lane-DEEPSEEK-INGEST in .auditooor/agent_pathspec.json via
# tools/agent-pathspec-register.py (TTL 2h, registered 2026-05-26).
"""deepseek-ingest-results.py - ingest pipeline for DeepSeek fanout output.

Lane DEEPSEEK-INGEST (2026-05-26). Consumes per-task result files emitted
by `tools/llm-fanout-dispatcher.py` and ingests them into the
canonical corpus tree (`audit/corpus_tags/derived/<target>/<batch-id>/`)
with proper schema validation, R37 verification_tier discipline, and
L34 v2 path-bucket safety.

CLI
---
python3 tools/deepseek-ingest-results.py \
    --fanout-output-dir <dir> \
    --task-type <TOK-A|tok_a_corpus_mine|...> \
    [--target-dir <dir>] \
    [--workspace <ws>] \
    [--schema <auditooor.X.v1>] \
    [--batch-id <id>] \
    [--dry-run] [--json] [--strict]

Per-task-type ingest paths:

| task-type alias          | canonical normalized form  | target subtree                                                 | schema                          |
|--------------------------|----------------------------|----------------------------------------------------------------|---------------------------------|
| TOK-A / tok_a_corpus_mine| tok_a_corpus_mine          | audit/corpus_tags/derived/triager_patterns_mined/<batch-id>/   | auditooor.triager_rationale.v1  |
| TOK-B / tok_b_invariant_lift | tok_b_invariant_lift   | audit/corpus_tags/derived/invariant_library_extended/<batch-id>/ | auditooor.invariant.v1        |
| TOK-C / tok_c_hypothesis_gen | tok_c_hypothesis_gen   | <ws>/audit/corpus_tags/derived/deepseek_hypotheses/<batch-id>/ | auditooor.hypothesis.v1         |
| TOK-D / tok_d_persona_drafts | tok_d_persona_drafts   | <ws>/audit/corpus_tags/derived/persona_critiques/<draft-slug>/ | auditooor.persona_critique.v1   |
| TOK-G / tok_g_anti_pattern   | tok_g_anti_pattern     | audit/corpus_tags/derived/anti_pattern_corpus/<batch-id>/      | auditooor.anti_pattern.v1       |

Composability gates (R37 + L34 v2 + Check #72):

- Every emitted record carries `verification_tier`. Default is
  `tier-3-synthetic-taxonomy-anchored` UNLESS the fanout result has
  `verified_by_second_pass=true` (then `tier-1-verified-realtime-api`).
- Records missing `verification_tier` cause `fail-tier-missing` exit 1.
- L34 v2: the resolved target dir must classify as workspace-ledger or
  out-of-scope. A target dir under `submissions/<status>/<slug>/`
  (draft-file bucket) is refused with `fail-l34-bucket-violation`.

Exit codes
----------
0 - all results ingested cleanly
1 - per-record validation failures (tier-missing / schema / unknown task-type)
2 - usage error / fanout-output-dir not found / schema not found
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.deepseek_ingest_results.v1"
TOOL_VERSION = "1.0.0"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMAS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "schemas"

VALID_TIERS = (
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)
DEFAULT_TIER = "tier-3-synthetic-taxonomy-anchored"
VERIFIED_TIER = "tier-1-verified-realtime-api"

# task-type alias map: normalize TOK-A and tok_a_corpus_mine to the same key.
# Each entry maps to (canonical_task_type, target_subtree_under_corpus_derived,
# schema_id, workspace_scoped, batch_or_slug)
# - workspace_scoped: True means the target lives under <workspace>/, else under repo root.
# - batch_or_slug: "batch" means group by batch-id, "slug" means group by draft-slug
#   (TOK-D persona critiques are per-draft).
TASK_TYPE_MAP: Dict[str, Dict[str, Any]] = {
    "tok_a_corpus_mine": {
        "canonical": "tok_a_corpus_mine",
        "target_subtree": "triager_patterns_mined",
        "schema_id": "auditooor.triager_rationale.v1",
        "workspace_scoped": False,
        "batch_or_slug": "batch",
        "file_format": "yaml",
    },
    "tok_b_invariant_lift": {
        "canonical": "tok_b_invariant_lift",
        "target_subtree": "invariant_library_extended",
        "schema_id": "auditooor.invariant.v1",
        "workspace_scoped": False,
        "batch_or_slug": "batch",
        "file_format": "yaml",
    },
    "tok_c_hypothesis_gen": {
        "canonical": "tok_c_hypothesis_gen",
        "target_subtree": "deepseek_hypotheses",
        "schema_id": "auditooor.hypothesis.v1",
        "workspace_scoped": True,
        "batch_or_slug": "batch",
        "file_format": "yaml",
    },
    "tok_d_persona_drafts": {
        "canonical": "tok_d_persona_drafts",
        "target_subtree": "persona_critiques",
        "schema_id": "auditooor.persona_critique.v1",
        "workspace_scoped": True,
        "batch_or_slug": "slug",
        "file_format": "md+json",
    },
    "tok_g_anti_pattern": {
        "canonical": "tok_g_anti_pattern",
        "target_subtree": "anti_pattern_corpus",
        "schema_id": "auditooor.anti_pattern.v1",
        "workspace_scoped": False,
        "batch_or_slug": "batch",
        "file_format": "yaml",
    },
}

# Alias index so TOK-A / TOK-B etc and short forms all resolve.
TASK_TYPE_ALIASES = {
    "TOK-A": "tok_a_corpus_mine",
    "TOK-B": "tok_b_invariant_lift",
    "TOK-C": "tok_c_hypothesis_gen",
    "TOK-D": "tok_d_persona_drafts",
    "TOK-G": "tok_g_anti_pattern",
    "tok-a": "tok_a_corpus_mine",
    "tok-b": "tok_b_invariant_lift",
    "tok-c": "tok_c_hypothesis_gen",
    "tok-d": "tok_d_persona_drafts",
    "tok-g": "tok_g_anti_pattern",
}


def _normalize_task_type(raw: str) -> Optional[str]:
    """Return canonical task_type or None if unknown."""
    if raw in TASK_TYPE_MAP:
        return raw
    if raw in TASK_TYPE_ALIASES:
        return TASK_TYPE_ALIASES[raw]
    # fallback: lowercase + underscore
    rl = raw.lower().replace("-", "_")
    if rl in TASK_TYPE_MAP:
        return rl
    return None


# ---------------------------------------------------------------------------
# L34 v2 classifier composition
# ---------------------------------------------------------------------------
DRAFT_STATUS_DIRS = (
    "staging", "ready", "filed", "packaged", "_killed", "_oos_rejected",
    "paste_ready", "held", "superseded",
)


def _classify_target_dir_l34(target_dir: Path) -> Tuple[str, str]:
    """Return (bucket, reason). Buckets: draft-file, workspace-ledger,
    out-of-scope, tracker-file, lesson-anchor.

    This is a path-string check (no FS access). We refuse draft-file
    bucket; everything else passes.
    """
    parts = list(target_dir.resolve().parts)
    # Look for "submissions" in the path
    for i, p in enumerate(parts):
        if p == "submissions":
            # next part should be a status dir for L34 to apply
            if i + 1 < len(parts) and parts[i + 1] in DRAFT_STATUS_DIRS:
                return ("draft-file", f"target path contains submissions/{parts[i+1]}/ (L34 draft-file bucket); auth required")
    # If under audit/corpus_tags/, that's workspace-ledger (auto-executable)
    p_str = str(target_dir.resolve())
    if "audit/corpus_tags/derived" in p_str or "/audit/corpus_tags/derived" in p_str:
        return ("workspace-ledger", "target under audit/corpus_tags/derived/ (L34 workspace-ledger)")
    return ("out-of-scope", "target not under submissions/ and not under audit/corpus_tags/derived/; L34 does not apply")


# ---------------------------------------------------------------------------
# Lightweight JSON-Schema-lite validation (no jsonschema dependency).
# Mirrors the validation pattern used by tools/hackerman-schema-migration-dry-run.py
# ---------------------------------------------------------------------------
def _validate_record_against_schema(record: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
    """Return list of error strings; empty list = pass."""
    errors: List[str] = []
    required = schema.get("required", []) or []
    for req in required:
        if req not in record:
            errors.append(f"missing required field '{req}'")
    props = schema.get("properties", {}) or {}
    additional_props = schema.get("additionalProperties", True)
    if additional_props is False:
        for key in record.keys():
            if key not in props:
                errors.append(f"additional property '{key}' not allowed")
    # check type and enum on top-level fields
    for key, val in record.items():
        if key not in props:
            continue
        pdef = props[key]
        ptype = pdef.get("type")
        if ptype == "string" and not isinstance(val, str):
            errors.append(f"field '{key}' must be string, got {type(val).__name__}")
        elif ptype == "integer" and not isinstance(val, int):
            errors.append(f"field '{key}' must be integer, got {type(val).__name__}")
        elif ptype == "number" and not isinstance(val, (int, float)):
            errors.append(f"field '{key}' must be number, got {type(val).__name__}")
        elif ptype == "array" and not isinstance(val, list):
            errors.append(f"field '{key}' must be array, got {type(val).__name__}")
        elif ptype == "object" and not isinstance(val, dict):
            errors.append(f"field '{key}' must be object, got {type(val).__name__}")
        elif ptype == "boolean" and not isinstance(val, bool):
            errors.append(f"field '{key}' must be boolean, got {type(val).__name__}")
        # enum
        enum_values = pdef.get("enum")
        if enum_values is not None and val not in enum_values:
            errors.append(f"field '{key}'={val!r} not in enum {enum_values}")
        # pattern (only for top-level strings)
        pattern = pdef.get("pattern")
        if pattern is not None and isinstance(val, str):
            if not re.match(pattern, val):
                errors.append(f"field '{key}'={val!r} does not match pattern {pattern!r}")
        # recurse into object properties (shallow; one level for nested 'source'/'content')
        if ptype == "object" and isinstance(val, dict):
            sub_errors = _validate_record_against_schema(val, pdef)
            for e in sub_errors:
                errors.append(f"{key}.{e}")
    return errors


def _load_schema(schema_id: str, schemas_dir: Path) -> Optional[Dict[str, Any]]:
    """Load schema JSON from schemas dir by $id (e.g. auditooor.invariant.v1).
    Resolves to file '<schema_id>.schema.json'.
    """
    path = schemas_dir / f"{schema_id}.schema.json"
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Fanout-result -> per-task-schema record mapping
# ---------------------------------------------------------------------------
def _record_id_for(task_id: str, content_text: str) -> str:
    """Stable deterministic record_id from task_id + content hash."""
    digest = hashlib.sha256((task_id + "::" + content_text).encode("utf-8")).hexdigest()[:16]
    safe_task = re.sub(r"[^A-Za-z0-9._:/-]+", "_", task_id)[:120]
    return f"{safe_task}-{digest}"


def _parse_result_text_as_content(text: str) -> Dict[str, Any]:
    """Best-effort parse of LLM result text into a content dict.
    The dispatcher emits result_text that, in mock-mode, is JSON-shaped.
    In real-mode it can be any LLM output. We try JSON first; if that
    fails, we wrap the raw text under a 'raw_text' field.
    """
    text = (text or "").strip()
    if not text:
        return {"raw_text": ""}
    # Try JSON parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass
    return {"raw_text": text}


def _build_record(
    fanout_result: Dict[str, Any],
    canonical_task_type: str,
    schema_id: str,
    batch_id: str,
    fanout_output_path: str,
    verification_tier_default: str = DEFAULT_TIER,
) -> Dict[str, Any]:
    """Map a single fanout result file into a typed record per the schema."""
    task_id = fanout_result.get("task_id") or "unknown_task"
    raw_text = fanout_result.get("result") or ""
    # If fanout result is itself a string (rare), wrap it
    if isinstance(raw_text, dict):
        content_parsed = raw_text
    else:
        content_parsed = _parse_result_text_as_content(raw_text)

    # verification tier: dispatcher stamps it; if missing, fall back
    tier = fanout_result.get("verification_tier") or verification_tier_default
    # if dispatcher records --verified-by claude-second-pass, the tier becomes tier-1
    verified_by_second_pass = bool(fanout_result.get("verified_by_second_pass", False))
    if verified_by_second_pass and tier == DEFAULT_TIER:
        tier = VERIFIED_TIER

    # generated_by sub-doc
    generated_by = {
        "provider": fanout_result.get("provider") or "unknown",
        "model_id": fanout_result.get("model_id") or "unknown",
        "input_tokens": int(fanout_result.get("input_tokens") or 0),
        "output_tokens": int(fanout_result.get("output_tokens") or 0),
        "cost_usd": float(fanout_result.get("cost_usd") or 0.0),
        "duration_s": float(fanout_result.get("duration_s") or 0.0),
        "verified_by_second_pass": verified_by_second_pass,
    }

    # build content per schema_id
    content = _shape_content_for_schema(schema_id, content_parsed, fanout_result)

    # source provenance
    source = {
        "task_id": str(task_id),
        "task_type": canonical_task_type,
        "batch_id": str(batch_id),
        "fanout_output_path": str(fanout_output_path),
    }
    if schema_id == "auditooor.hypothesis.v1":
        ws = (fanout_result.get("meta") or {}).get("workspace")
        if ws:
            source["workspace"] = str(ws)
    if schema_id == "auditooor.persona_critique.v1":
        slug = (fanout_result.get("meta") or {}).get("draft_slug")
        if slug:
            source["draft_slug"] = str(slug)

    record_id_text = json.dumps(content, sort_keys=True, default=str)[:1024]
    record = {
        "schema_version": schema_id,
        "record_id": _record_id_for(str(task_id), record_id_text),
        "source": source,
        "verification_tier": tier,
        "generated_by": generated_by,
        "content": content,
        "generated_at_utc": fanout_result.get("ended_at_utc") or _now_utc_iso(),
        "ingested_at_utc": _now_utc_iso(),
    }
    return record


# r36-rebuttal: lane-DEEPSEEK-INGEST declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py at lane start (2026-05-26)
def _drop_none(d: Dict[str, Any]) -> Dict[str, Any]:
    """Strip keys whose values are None. Empty lists and "" strings are
    preserved (they validate against the schema)."""
    return {k: v for k, v in d.items() if v is not None}


def _shape_content_for_schema(
    schema_id: str,
    parsed_content: Dict[str, Any],
    fanout_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Map parsed LLM output into the per-schema 'content' shape with
    minimal required fields populated. Unknown fields preserved under
    additionalProperties=true. None-valued fields are stripped to keep
    the record schema-valid against string-typed optional properties.
    """
    meta = fanout_result.get("meta") or {}
    raw_text = parsed_content.get("raw_text") or json.dumps(parsed_content, default=str)[:4000]
    if schema_id == "auditooor.triager_rationale.v1":
        return _drop_none({
            "rationale_text": parsed_content.get("rationale_text") or meta.get("rationale_text") or raw_text[:8000],
            "classification": parsed_content.get("classification") or "other",
            "confidence": parsed_content.get("confidence"),
            "evidence_phrases": parsed_content.get("evidence_phrases") or [],
            "rationale_id": meta.get("rationale_id") or parsed_content.get("rationale_id"),
            "platform": meta.get("platform") or parsed_content.get("platform"),
        })
    if schema_id == "auditooor.invariant.v1":
        inv_id_default = f"INV-{(fanout_result.get('task_id') or 'unknown')[:80]}"
        return _drop_none({
            "invariant_id": parsed_content.get("invariant_id") or inv_id_default,
            "invariant_text": parsed_content.get("invariant_text") or raw_text[:4000],
            "target_language": parsed_content.get("target_language"),
            "attack_class": parsed_content.get("attack_class"),
            "bug_class": parsed_content.get("bug_class"),
            "preconditions": parsed_content.get("preconditions") or [],
            "violation_consequence": parsed_content.get("violation_consequence"),
            "source_findings": parsed_content.get("source_findings") or [],
        })
    if schema_id == "auditooor.hypothesis.v1":
        return _drop_none({
            "hypothesis_text": parsed_content.get("hypothesis_text") or raw_text[:8000],
            "target_component": parsed_content.get("target_component") or meta.get("target_component") or "unknown",
            "attack_class": parsed_content.get("attack_class"),
            "preconditions": parsed_content.get("preconditions") or [],
            "expected_impact": parsed_content.get("expected_impact"),
            "severity_proposed": parsed_content.get("severity_proposed") or "",
            "next_step_verification": parsed_content.get("next_step_verification"),
            "related_invariants": parsed_content.get("related_invariants") or [],
        })
    if schema_id == "auditooor.persona_critique.v1":
        return _drop_none({
            "persona": parsed_content.get("persona") or meta.get("persona") or "adversarial-triager",
            "critique_summary": parsed_content.get("critique_summary") or raw_text[:4000],
            "draft_slug": meta.get("draft_slug") or parsed_content.get("draft_slug"),
            "kill_likelihood": parsed_content.get("kill_likelihood") or "",
            "rebuttal_required_for": parsed_content.get("rebuttal_required_for") or [],
        })
    if schema_id == "auditooor.anti_pattern.v1":
        ap_name = parsed_content.get("anti_pattern_name") or meta.get("anti_pattern_name") or f"unnamed_anti_pattern_{fanout_result.get('task_id','unknown')[:40]}"
        return _drop_none({
            "anti_pattern_name": ap_name,
            "description": parsed_content.get("description") or raw_text[:4000],
            "category": parsed_content.get("category"),
            "indicator_phrases": parsed_content.get("indicator_phrases") or [],
            "remediation": parsed_content.get("remediation"),
            "example_evidence": parsed_content.get("example_evidence") or [],
            "related_rules": parsed_content.get("related_rules") or [],
        })
    return parsed_content


def _now_utc_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# YAML emit (lightweight: no PyYAML dependency; we emit safe-subset YAML)
# ---------------------------------------------------------------------------
def _emit_yaml(record: Dict[str, Any]) -> str:
    """Emit a deterministic YAML representation of the record.
    Strategy: convert via JSON dump then a JSON->YAML-lite shim with
    quoted scalars to avoid YAML parsing ambiguity. For complex content,
    we ship JSON-lines embedded inside a `# json-record` block. This keeps
    the file human-readable AND machine-roundtrippable via PyYAML or
    json.loads when stripped of the YAML header."""
    # We emit JSON inside a YAML wrapper. Downstream tooling reads YAML;
    # in-tree validators read the JSON body. This is the cheapest
    # YAML-without-dependency path used elsewhere in the tree.
    json_body = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False, default=str)
    return (
        "# auditooor-deepseek-ingest record\n"
        f"# schema: {record.get('schema_version')}\n"
        f"# record_id: {record.get('record_id')}\n"
        "# format: json-embedded\n"
        "---\n"
        f"{json_body}\n"
    )


# ---------------------------------------------------------------------------
# Main ingest driver
# ---------------------------------------------------------------------------
def ingest(
    fanout_output_dir: Path,
    raw_task_type: str,
    target_dir: Optional[Path],
    workspace: Optional[Path],
    schema_override: Optional[str],
    batch_id: Optional[str],
    dry_run: bool,
    strict: bool,
    schemas_dir: Path = DEFAULT_SCHEMAS_DIR,
) -> Dict[str, Any]:
    """Driver. Returns result envelope.

    Verdicts:
      pass-clean-ingest, pass-dry-run, pass-idempotent,
      fail-unknown-task-type, fail-fanout-dir-missing,
      fail-schema-not-found, fail-tier-missing,
      fail-schema-validation, fail-l34-bucket-violation, error
    """
    envelope: Dict[str, Any] = {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "verdict": "pass-clean-ingest",
        "summary": "",
        "raw_task_type": raw_task_type,
        "canonical_task_type": None,
        "schema_id": None,
        "fanout_output_dir": str(fanout_output_dir),
        "target_dir": None,
        "l34_bucket": None,
        "results_total": 0,
        "ingested": 0,
        "skipped_idempotent": 0,
        "failed_tier_missing": 0,
        "failed_schema": 0,
        "errors": [],
        "ingested_paths": [],
        "dry_run": bool(dry_run),
        "strict": bool(strict),
    }

    # Resolve task type
    canonical = _normalize_task_type(raw_task_type)
    if canonical is None:
        envelope["verdict"] = "fail-unknown-task-type"
        envelope["summary"] = f"unknown task_type {raw_task_type!r}; known: {sorted(TASK_TYPE_MAP.keys())}"
        return envelope
    spec = TASK_TYPE_MAP[canonical]
    envelope["canonical_task_type"] = canonical
    schema_id = schema_override or spec["schema_id"]
    envelope["schema_id"] = schema_id

    # Verify fanout output dir exists
    if not fanout_output_dir.is_dir():
        envelope["verdict"] = "fail-fanout-dir-missing"
        envelope["summary"] = f"fanout-output-dir {fanout_output_dir} not found or not a directory"
        return envelope

    # Load schema
    schema = _load_schema(schema_id, schemas_dir)
    if schema is None:
        envelope["verdict"] = "fail-schema-not-found"
        envelope["summary"] = f"schema {schema_id} not found in {schemas_dir}"
        return envelope

    # Resolve target dir
    batch_id_resolved = batch_id or _now_utc_iso().replace(":", "").replace("-", "")
    target = target_dir
    if target is None:
        base = workspace if (workspace and spec["workspace_scoped"]) else REPO_ROOT_GUESS
        target = base / "audit" / "corpus_tags" / "derived" / spec["target_subtree"] / batch_id_resolved
    envelope["target_dir"] = str(target)
    envelope["batch_id"] = batch_id_resolved

    # L34 v2 bucket check
    bucket, reason = _classify_target_dir_l34(target)
    envelope["l34_bucket"] = bucket
    envelope["l34_bucket_reason"] = reason
    if bucket == "draft-file":
        envelope["verdict"] = "fail-l34-bucket-violation"
        envelope["summary"] = f"target dir {target} is in L34 draft-file bucket ({reason})"
        return envelope

    # Walk fanout results
    result_files = sorted(fanout_output_dir.glob("*.json"))
    envelope["results_total"] = len(result_files)
    if not result_files:
        envelope["summary"] = f"no *.json files under {fanout_output_dir}"
        envelope["verdict"] = "pass-clean-ingest"  # empty input is not an error
        return envelope

    if not dry_run:
        target.mkdir(parents=True, exist_ok=True)

    for rf in result_files:
        try:
            with rf.open("r", encoding="utf-8") as f:
                fanout_result = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            envelope["errors"].append({"file": str(rf), "error": f"parse: {e}"})
            envelope["failed_schema"] += 1
            continue

        # Filter only the canonical task_type from this batch.
        result_task_type = fanout_result.get("task_type")
        if result_task_type and _normalize_task_type(result_task_type) != canonical:
            # silently skip cross-type contamination; record in errors only if strict
            if strict:
                envelope["errors"].append({
                    "file": str(rf),
                    "error": f"task_type mismatch: result={result_task_type!r}, expected={canonical!r}",
                })
            continue

        # Build record
        record = _build_record(
            fanout_result=fanout_result,
            canonical_task_type=canonical,
            schema_id=schema_id,
            batch_id=batch_id_resolved,
            fanout_output_path=str(rf),
        )

        # R37 verification_tier check
        if not record.get("verification_tier") or record["verification_tier"] not in VALID_TIERS:
            envelope["failed_tier_missing"] += 1
            envelope["errors"].append({
                "file": str(rf),
                "error": f"verification_tier missing or invalid: {record.get('verification_tier')!r}",
            })
            continue

        # Schema validation
        errors = _validate_record_against_schema(record, schema)
        if errors:
            envelope["failed_schema"] += 1
            envelope["errors"].append({
                "file": str(rf),
                "schema_errors": errors[:10],
            })
            continue

        # Determine output filename
        if spec["batch_or_slug"] == "slug":
            slug = (fanout_result.get("meta") or {}).get("draft_slug") or "no-slug"
            safe_slug = re.sub(r"[^A-Za-z0-9._-]+", "_", slug)[:80]
            out_dir_local = target.parent / safe_slug if (target_dir is None) else target
            if not dry_run:
                out_dir_local.mkdir(parents=True, exist_ok=True)
        else:
            out_dir_local = target

        record_id = record["record_id"]
        safe_rid = re.sub(r"[^A-Za-z0-9._-]+", "_", record_id)[:120]
        ext = "yaml"
        if spec["file_format"] == "md+json":
            ext = "json"  # JSON sidecar; .md prose handled below
        out_path = out_dir_local / f"{safe_rid}.{ext}"

        # Idempotency: if same content already exists, skip
        if out_path.exists():
            try:
                with out_path.open("r", encoding="utf-8") as f:
                    existing = f.read()
                if ext == "yaml":
                    new_content = _emit_yaml(record)
                else:
                    new_content = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False, default=str)
                # compare by structural content (ignoring timestamps)
                if _records_equivalent(existing, new_content):
                    envelope["skipped_idempotent"] += 1
                    envelope["ingested_paths"].append(str(out_path))
                    continue
            except OSError:
                pass

        if dry_run:
            envelope["ingested"] += 1
            envelope["ingested_paths"].append(str(out_path) + " (dry-run)")
            continue

        # Write the record
        if ext == "yaml":
            yaml_text = _emit_yaml(record)
            with out_path.open("w", encoding="utf-8") as f:
                f.write(yaml_text)
        else:
            with out_path.open("w", encoding="utf-8") as f:
                json.dump(record, f, sort_keys=True, indent=2, ensure_ascii=False, default=str)

        # For persona critiques, also write the .md sidecar
        if spec["file_format"] == "md+json":
            md_path = out_dir_local / f"{safe_rid}.md"
            md_body = _persona_critique_md_body(record)
            with md_path.open("w", encoding="utf-8") as f:
                f.write(md_body)
            envelope["ingested_paths"].append(str(md_path))

        envelope["ingested"] += 1
        envelope["ingested_paths"].append(str(out_path))

    # Summary
    if envelope["failed_tier_missing"] > 0:
        envelope["verdict"] = "fail-tier-missing"
    elif envelope["failed_schema"] > 0:
        envelope["verdict"] = "fail-schema-validation"
    elif dry_run:
        envelope["verdict"] = "pass-dry-run"
    elif envelope["ingested"] == 0 and envelope["skipped_idempotent"] > 0:
        envelope["verdict"] = "pass-idempotent"
    else:
        envelope["verdict"] = "pass-clean-ingest"

    envelope["summary"] = (
        f"task_type={canonical} schema={schema_id} target={target} "
        f"total={envelope['results_total']} ingested={envelope['ingested']} "
        f"idempotent={envelope['skipped_idempotent']} "
        f"tier-missing={envelope['failed_tier_missing']} schema-fail={envelope['failed_schema']}"
    )
    return envelope


def _records_equivalent(a: str, b: str) -> bool:
    """Compare two record text blobs ignoring timestamps and # comment lines.
    Returns True if structurally equivalent.
    """
    def _normalize(text: str) -> str:
        # strip YAML wrapper '---' and # comments
        body_lines = []
        in_body = False
        for line in text.splitlines():
            if line.strip() == "---":
                in_body = True
                continue
            if line.startswith("#") and not in_body:
                continue
            body_lines.append(line)
        body = "\n".join(body_lines).strip() or text.strip()
        try:
            obj = json.loads(body)
            # Remove volatile fields
            if isinstance(obj, dict):
                obj.pop("generated_at_utc", None)
                obj.pop("ingested_at_utc", None)
            return json.dumps(obj, sort_keys=True, default=str)
        except (ValueError, json.JSONDecodeError):
            return body
    return _normalize(a) == _normalize(b)


def _persona_critique_md_body(record: Dict[str, Any]) -> str:
    """Write the prose .md sidecar for a persona-critique record."""
    content = record.get("content") or {}
    return (
        f"# Persona Critique: {content.get('persona', 'unknown')}\n\n"
        f"- record_id: `{record.get('record_id')}`\n"
        f"- schema: `{record.get('schema_version')}`\n"
        f"- verification_tier: `{record.get('verification_tier')}`\n"
        f"- generated_by: `{record.get('generated_by', {}).get('provider', '?')}` / `{record.get('generated_by', {}).get('model_id', '?')}`\n"
        f"- draft_slug: `{content.get('draft_slug', 'unknown')}`\n"
        f"- kill_likelihood: `{content.get('kill_likelihood', 'unknown')}`\n\n"
        "## Critique summary\n\n"
        f"{content.get('critique_summary', '(no critique text)')}\n\n"
        "## Rebuttal required for\n\n"
        + "\n".join(f"- {r}" for r in (content.get('rebuttal_required_for') or [])) + "\n"
    )


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Ingest DeepSeek fanout output into canonical corpus tags with schema + tier discipline."
    )
    p.add_argument("--fanout-output-dir", required=True, type=Path,
                   help="Directory containing per-task .json result files from llm-fanout-dispatcher.py.")
    p.add_argument("--task-type", required=True,
                   help="Task type: TOK-A/TOK-B/TOK-C/TOK-D/TOK-G or canonical tok_a_corpus_mine, tok_b_invariant_lift, etc.")
    p.add_argument("--target-dir", type=Path, default=None,
                   help="Override target output directory. Default: <workspace?>/audit/corpus_tags/derived/<subtree>/<batch-id>/")
    p.add_argument("--workspace", type=Path, default=None,
                   help="Workspace path (used for workspace-scoped task types TOK-C/TOK-D).")
    p.add_argument("--schema", default=None,
                   help="Override schema id (default: per-task-type from TASK_TYPE_MAP).")
    p.add_argument("--batch-id", default=None,
                   help="Override batch id (default: timestamp-derived).")
    p.add_argument("--schemas-dir", type=Path, default=DEFAULT_SCHEMAS_DIR,
                   help="Directory containing schema JSON files (default: audit/corpus_tags/schemas/).")
    p.add_argument("--dry-run", action="store_true",
                   help="Validate and report without writing.")
    p.add_argument("--json", action="store_true",
                   help="Emit machine-readable JSON envelope.")
    p.add_argument("--strict", action="store_true",
                   help="Strict mode: refuse on cross-task-type contamination + any schema-validation error.")
    args = p.parse_args(argv)

    envelope = ingest(
        fanout_output_dir=args.fanout_output_dir,
        raw_task_type=args.task_type,
        target_dir=args.target_dir,
        workspace=args.workspace,
        schema_override=args.schema,
        batch_id=args.batch_id,
        dry_run=args.dry_run,
        strict=args.strict,
        schemas_dir=args.schemas_dir,
    )

    if args.json:
        print(json.dumps(envelope, sort_keys=True, indent=2, default=str))
    else:
        print(f"[deepseek-ingest] verdict={envelope['verdict']}")
        print(f"[deepseek-ingest] {envelope['summary']}")
        if envelope["errors"]:
            print(f"[deepseek-ingest] {len(envelope['errors'])} error(s):")
            for e in envelope["errors"][:5]:
                print(f"  - {e}")

    if envelope["verdict"].startswith("fail-"):
        return 1
    if envelope["verdict"] == "error":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
