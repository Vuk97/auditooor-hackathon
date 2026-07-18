#!/usr/bin/env python3
# r36-rebuttal: lane-CLAUDE-CAP-GAP-97AB declared 2 files via tools/agent-pathspec-register.py at lane start
"""promote-mined-to-canonical.py - bridge mined records to MCP-readable paths.

Closes capability gap X3 + NEW-3 (codified 2026-05-26) plus
CAP-GAP-97a (extended source routers) and CAP-GAP-97b (YAML wrapper fix,
codified 2026-05-27).

  Mining lands records in audit/corpus_tags/derived/<class>/<batch>/*.{yaml,json}
  MCP reads from canonical paths like invariants_pilot_audited.jsonl,
  obsidian-vault/anti-patterns/*.md, exploit_predicates.jsonl, etc.

  These paths don't talk by default. This tool promotes mined records into
  canonical MCP-readable form.

USAGE
    python3 tools/promote-mined-to-canonical.py --dry-run --json
    python3 tools/promote-mined-to-canonical.py --min-confidence medium
    python3 tools/promote-mined-to-canonical.py --batch-id <name>
    python3 tools/promote-mined-to-canonical.py --skip-router hacker_questions

CAP-GAP-97a: 2 -> ~20 source routers via SOURCE_ROUTERS registry.
CAP-GAP-97b: _extract_record_content_from_ingested_yaml now handles three shapes:
    (a) header+yaml-frontmatter (original anti_pattern_corpus shape)
    (b) flat YAML (top-level keys = fields)            -- invariant_library_extended
    (c) flat JSON (json.loads on file body)            -- dispatch-ledger derived/*.json

EXIT CODES
    0 = at least one record promoted OR --dry-run finished cleanly
    2 = no records found
    3 = error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "promote-mined-to-canonical"
TOOL_VERSION = "2.0.0"

REPO_ROOT = Path(__file__).resolve().parent.parent

# Legacy paths (preserved for backward compatibility)
INV_SRC_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariant_library_extended"
INV_DST = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl"

ANTI_PATTERN_SRC_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "anti_pattern_corpus"
ANTI_PATTERN_DST_DIR = REPO_ROOT / "obsidian-vault" / "anti-patterns"

CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}


def _ts_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# D2-promotion-enricher: hacker_question rows promoted from dispatch-ledger
# expansions were born flat (no routing patterns), so corpus-driven-hunt -
# which drops empty-needle rows - silently could not route them. We seed
# question_text and run the canonical LIFT-28 per-function enricher so each
# promoted hacker_question gains target_function_patterns/roles/scope.
_PFTP_MODULE = None  # cached module handle (None = not yet loaded; False = unavailable)


def _load_pftp():
    """Lazily import lib/per_function_target_patterns by file path.

    Returns the module, or ``None`` if it cannot be imported (enrichment is
    then skipped - additive, never fatal). Mirrors the importlib-by-path
    pattern used by tools/backfill-promoted-hackerq-routing.py.
    """
    global _PFTP_MODULE
    if _PFTP_MODULE is not None:
        return _PFTP_MODULE or None
    import importlib.util

    lib_path = REPO_ROOT / "tools" / "lib" / "per_function_target_patterns.py"
    try:
        spec = importlib.util.spec_from_file_location(
            "pftp_promote", str(lib_path)
        )
        if spec is None or spec.loader is None:
            _PFTP_MODULE = False
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _PFTP_MODULE = mod
        return mod
    except Exception:
        _PFTP_MODULE = False
        return None


def _stderr(msg: str) -> None:
    sys.stderr.write(f"[{TOOL_NAME} {_ts_utc()}] {msg}\n")
    sys.stderr.flush()


def _parse_yaml_lite(text: str) -> Dict[str, Any]:
    """Minimal YAML parser sufficient for our mined records.

    Supports string scalars, block scalars (| and >), simple lists
    (`- "value"` indented under a key), and quoted/unquoted scalar values.
    """
    out: Dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        m = re.match(r'^(\w[\w_]*):\s*(.*)$', line)
        if not m:
            i += 1
            continue
        key, value = m.group(1), m.group(2).strip()
        if value == "|" or value == ">":
            block_lines: List[str] = []
            i += 1
            # Detect indent of first non-empty content line
            block_indent = None
            while i < len(lines):
                nxt = lines[i]
                if nxt.strip() == "":
                    block_lines.append("")
                    i += 1
                    continue
                lstripped = nxt.lstrip(" \t")
                cur_indent = len(nxt) - len(lstripped)
                if block_indent is None:
                    if cur_indent == 0:
                        break  # no indented block contents
                    block_indent = cur_indent
                if cur_indent < block_indent:
                    break
                block_lines.append(nxt[block_indent:])
                i += 1
            out[key] = "\n".join(block_lines).strip()
            continue
        if value == "":
            # could be a list following (indented `- item` lines), OR a
            # nested mapping. Try list first.
            list_items: List[str] = []
            nested_map_lines: List[str] = []
            j = i + 1
            saw_list = False
            saw_map = False
            while j < len(lines):
                nxt = lines[j]
                if not nxt.strip():
                    j += 1
                    continue
                ls = nxt.lstrip(" \t")
                indent = len(nxt) - len(ls)
                if indent == 0:
                    break
                if ls.startswith("- "):
                    saw_list = True
                    item = ls[2:].strip()
                    list_items.append(item.strip('"\''))
                    j += 1
                elif re.match(r"^\w[\w_]*:", ls):
                    saw_map = True
                    nested_map_lines.append(ls)
                    j += 1
                else:
                    j += 1
            if saw_list:
                out[key] = list_items
                i = j
                continue
            if saw_map:
                # nested-map -> recurse via parsed dict
                out[key] = _parse_yaml_lite("\n".join(nested_map_lines))
                i = j
                continue
            out[key] = ""
            i += 1
            continue
        out[key] = value.strip('"\'')
        i += 1
    return out


def _extract_record_content_from_ingested_yaml(path: Path) -> Optional[Dict[str, Any]]:
    """CAP-GAP-97b: handle three record shapes uniformly.

    Shape (a) - header + yaml frontmatter + JSON body (original
    anti_pattern_corpus / deepseek-ingest format):

        # auditooor-deepseek-ingest record
        # schema: ...
        ---
        { "content": { ... }, ... }

    Shape (b) - flat YAML (top-level keys = record fields). Used by
    invariant_library_extended/*/*.yaml. Returns dict with the YAML keys
    promoted directly; callers using ``rec.get("content", {})`` get the
    same dict back so legacy access paths still work.

    Shape (c) - flat JSON (json.loads on the entire file body). Used by
    dispatch-ledger JSON in derived/<router>/*.json. Returns the parsed
    JSON dict directly.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        _stderr(f"read failed {path}: {exc}")
        return None
    suffix = path.suffix.lower()
    stripped = text.strip()

    # Shape (a): explicit header + frontmatter delimiter
    if "\n---\n" in text:
        json_body = text.split("\n---\n", 1)[1].strip()
        try:
            parsed = json.loads(json_body)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            # Fall through to YAML parse of the body
            try:
                yaml_body = _parse_yaml_lite(json_body)
                if yaml_body:
                    if "content" not in yaml_body:
                        yaml_body = {"content": yaml_body, **yaml_body}
                    return yaml_body
            except Exception:
                pass
            return None

    # Shape (c): JSON body (file is pure JSON)
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                # bare array: wrap as a record with a `_list` key
                return {"_list": parsed}
            return None
        except json.JSONDecodeError:
            pass

    # Shape (b): flat YAML
    if suffix in (".yaml", ".yml") or any(re.match(r'^\w[\w_]*:\s', ln) for ln in text.splitlines()[:5]):
        try:
            yaml_body = _parse_yaml_lite(text)
            if yaml_body:
                # Ensure legacy `content`-accessor still finds fields
                if "content" not in yaml_body:
                    return {"content": yaml_body, **yaml_body}
                return yaml_body
        except Exception:
            pass

    return None


def _record_confidence(rec: Dict[str, Any]) -> str:
    """Pull confidence from a mined record. Supports nested + flat shapes."""
    if not isinstance(rec, dict):
        return "low"
    content = rec.get("content", {}) if isinstance(rec.get("content"), dict) else {}
    # Try both flat (rec) and nested (content)
    for src in (content, rec):
        if not isinstance(src, dict):
            continue
        conf = (src.get("confidence_self_assessment")
                or src.get("confidence")
                or src.get("confidence_level")
                or "")
        if conf:
            return str(conf).lower()
    # Try nested in invariant_text / anti_pattern_text JSON-string
    for src in (content, rec):
        if not isinstance(src, dict):
            continue
        for key in ("invariant_text", "anti_pattern_text", "description", "result"):
            v = src.get(key, "")
            if isinstance(v, str) and "confidence" in v.lower():
                m = re.search(r'"?confidence(?:_self_assessment|_level)?"?\s*[:=]\s*"?(\w+)"?',
                              v, re.IGNORECASE)
                if m:
                    val = m.group(1).lower()
                    if val in CONFIDENCE_ORDER:
                        return val
    # quality-audited flat YAML records get medium by default (tier-2)
    tier = (rec.get("verification_tier") or content.get("verification_tier") or "").lower()
    if "tier-2" in tier or "tier-1" in tier:
        return "medium"
    return "low"


def _meets_min_confidence(rec: Dict[str, Any], min_conf: str) -> bool:
    if min_conf == "low":
        return True
    have = _record_confidence(rec)
    return CONFIDENCE_ORDER.get(have, 0) >= CONFIDENCE_ORDER.get(min_conf, 1)


def _slugify(text: str, max_len: int = 80) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(text).lower()).strip("-")
    return s[:max_len] or "untitled"


def _parse_result_string(rec: Dict[str, Any]) -> Optional[Any]:
    """Dispatch-ledger records have a `result` field (or schema-specific
    sibling) with JSON-encoded body.

    Recognizes status values {None, "ok", "done", "completed"}. Sibling
    result-field names: tok_a_result, tok_b_result, tok_c_result,
    tok_d_result, tok_g_result, hypothesis_result, finding_result.
    """
    if not isinstance(rec, dict):
        return None
    status = rec.get("status")
    if status not in (None, "ok", "done", "completed"):
        return None
    result = rec.get("result")
    for alt in ("tok_a_result", "tok_b_result", "tok_c_result",
                "tok_d_result", "tok_g_result", "hypothesis_result",
                "finding_result"):
        if result is None and alt in rec:
            result = rec.get(alt)
            break
    if result is None:
        return None
    if isinstance(result, (dict, list)):
        return result
    if isinstance(result, str):
        s = result.strip()
        # Strip ```json ... ``` wrappers some LLMs emit
        if s.startswith("```"):
            m = re.search(r"```(?:json)?\s*\n(.*)\n```\s*$", s, re.DOTALL)
            if m:
                s = m.group(1).strip()
            else:
                s = s.strip("`").strip()
        if not s:
            return None
        # The result may be truncated mid-string; try permissive parsing
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            # Truncated JSON: try to recover the longest valid prefix by
            # walking back to the last balanced brace/bracket.
            recovered = _recover_truncated_json(s)
            if recovered is not None:
                return recovered
            return None
    return None


def _recover_truncated_json(s: str) -> Optional[Any]:
    """Best-effort recovery of truncated JSON.

    Strategy: walk forward, track brace/bracket depth + string state, and
    when we hit EOF mid-string just close all open structures at the last
    fully-balanced character. For object arrays this typically yields the
    list of fully-parsed objects up to the truncation point.
    """
    if not s:
        return None
    depth_stack: List[str] = []
    in_str = False
    escape = False
    last_balanced = -1
    for i, ch in enumerate(s):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch in "[{":
            depth_stack.append(ch)
        elif ch in "]}":
            if depth_stack:
                depth_stack.pop()
            if not depth_stack:
                last_balanced = i
    if last_balanced > 0:
        # First try to parse the prefix up to and including last_balanced
        try:
            return json.loads(s[: last_balanced + 1])
        except json.JSONDecodeError:
            pass

    # Single-object recovery: walk back to last key-value boundary and close
    # all open structures. Pattern: `"key": "value..."` mid-string truncation.
    if s.lstrip().startswith("{"):
        depth = 0
        in_str = False
        escape = False
        last_comma = -1  # last comma at object-level (depth==1, not in string)
        for i, ch in enumerate(s):
            if escape:
                escape = False
                continue
            if ch == "\\" and in_str:
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 1:
                last_comma = i
        if last_comma > 0:
            # Truncate at last_comma, then close the object with `}` (and
            # bracket-stack residue if any). Use depth as of last_comma.
            depth_at = 0
            in_str_at = False
            escape_at = False
            for i, ch in enumerate(s[: last_comma]):
                if escape_at:
                    escape_at = False
                    continue
                if ch == "\\" and in_str_at:
                    escape_at = True
                    continue
                if ch == '"':
                    in_str_at = not in_str_at
                    continue
                if in_str_at:
                    continue
                if ch in "[{":
                    depth_at += 1
                elif ch in "]}":
                    depth_at -= 1
            close = ""
            for _ in range(depth_at):
                close += "}"
            try:
                return json.loads(s[: last_comma] + close)
            except json.JSONDecodeError:
                pass
    # Try array-with-partial-tail recovery: if the original starts with
    # '[' close it at last complete object boundary.
    if s.lstrip().startswith("["):
        # Find positions where depth returns to 1 (inside the array, between
        # objects). The last such position + closing ']' is a recovery.
        depth = 0
        in_str = False
        escape = False
        last_obj_end = -1
        for i, ch in enumerate(s):
            if escape:
                escape = False
                continue
            if ch == "\\" and in_str:
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
                if depth == 1 and ch == "}":
                    last_obj_end = i
        if last_obj_end > 0:
            try:
                return json.loads(s[: last_obj_end + 1] + "]")
            except json.JSONDecodeError:
                return None
    return None


# ---------------------------------------------------------------------------
# Existing-key tracking (per-dst dedup)
# ---------------------------------------------------------------------------

def _existing_jsonl_keys(dst_path: Path, key_field: str) -> set:
    out: set = set()
    if not dst_path.exists():
        return out
    try:
        with dst_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = rec.get(key_field)
                if key:
                    out.add(str(key))
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Per-router record extractors
# Each extractor takes (parsed_record, source_path, batch_dir_name) and
# returns a list of dicts in canonical destination shape, or [].
# ---------------------------------------------------------------------------

def _extract_invariant_library_extended(rec: Dict[str, Any], src: Path, batch: str) -> List[Dict[str, Any]]:
    """Flat-YAML invariant records (CAP-GAP-97b primary fixture)."""
    if not isinstance(rec, dict):
        return []
    content = rec.get("content") if isinstance(rec.get("content"), dict) else rec
    inv_id = content.get("invariant_id") or rec.get("invariant_id") or ""
    statement = content.get("statement") or content.get("invariant_text") or ""
    if not inv_id or not statement:
        return []
    out = {
        "schema_version": "auditooor.invariant_pilot.v1",
        "invariant_id": str(inv_id),
        "category": content.get("category") or content.get("attack_class") or "deepseek-mined",
        "statement": str(statement)[:3500],
        "target_lang": content.get("target_lang") or content.get("target_language") or "any",
        "source_finding_ids": (content.get("source_incident_ids")
                                or content.get("source_findings", [])
                                or []),
        "verification_tier": content.get("verification_tier")
            or rec.get("verification_tier")
            or "tier-3-synthetic-taxonomy-anchored",
        "audit_status": f"promoted-from-mined:{batch}",
        "ts_utc": _ts_utc(),
    }
    return [out]


def _extract_anti_pattern_corpus(rec: Dict[str, Any], src: Path, batch: str) -> List[Dict[str, Any]]:
    """Anti-pattern records emit markdown via promote_anti_patterns; this
    extractor is a no-op stub - anti_patterns are handled by their own
    legacy path (kept for parity with SOURCE_ROUTERS schema only)."""
    return []


def _extract_dispatch_ledger_generic(
    rec: Dict[str, Any],
    src: Path,
    batch: str,
    *,
    primary_key_candidates: Tuple[str, ...] = ("invariant_id", "hypothesis_id", "anti_pattern_title", "frame_id"),
    category_candidates: Tuple[str, ...] = ("attack_class", "category", "bug_class"),
    statement_candidates: Tuple[str, ...] = ("lifted_statement_any", "lifted_statement_rust",
                                              "lifted_statement_go", "lifted_statement_solidity",
                                              "lifted_statement_move", "lifted_statement_cairo",
                                              "root_cause_one_sentence", "invariant_statement",
                                              "statement", "description"),
    kind: str = "hypothesis",
) -> List[Dict[str, Any]]:
    """Generic extractor for dispatch-ledger derived/<router>/*.json files.

    Reads `rec["result"]` (string-encoded JSON), parses it, and returns one
    or more canonical records. Handles both single-dict and list-of-dicts
    results.
    """
    parsed = _parse_result_string(rec)
    if parsed is None:
        return []
    items = parsed if isinstance(parsed, list) else [parsed]
    out: List[Dict[str, Any]] = []
    task_id = rec.get("task_id") or src.stem
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        # Synthesize a stable ID
        rec_id = None
        for k in primary_key_candidates:
            if item.get(k):
                rec_id = str(item.get(k))
                break
        if not rec_id:
            rec_id = f"{task_id}-{idx}"
        else:
            # Suffix with task_id to keep IDs unique across files even when
            # the LLM reused a generic label like "INV-001"
            rec_id = f"{task_id}-{rec_id}" if rec_id and not rec_id.startswith(task_id) else rec_id
        category = None
        for k in category_candidates:
            if item.get(k):
                category = item.get(k)
                break
        statement = None
        for k in statement_candidates:
            if item.get(k):
                statement = item.get(k)
                break
        if not statement:
            # Fall back to stringified item, capped
            statement = json.dumps(item)[:1500]
        record = {
            "schema_version": f"auditooor.{kind}.v1",
            "record_id": rec_id,
            "kind": kind,
            "router": batch,
            "category": category or "deepseek-mined",
            "statement": str(statement)[:3500],
            "target_lang": item.get("target_lang") or item.get("target_language") or "any",
            "raw_keys": sorted(list(item.keys()))[:24],
            "verification_tier": rec.get("verification_tier", "tier-3-synthetic-taxonomy-anchored"),
            "source_task_id": task_id,
            "audit_status": f"promoted-from-mined:{batch}",
            "ts_utc": _ts_utc(),
        }
        # Preserve a few useful raw fields
        for k in ("exploitability_score_0_to_5", "impact_score_0_to_5",
                  "known_corpus_anchor", "minimum_evidence_to_file",
                  "worklist_predicate_sketch", "canonical_violation_pattern",
                  "negative_control_pattern", "detector_sketch",
                  "applicability_caveats", "frame_id"):
            if k in item and item[k] not in (None, "", []):
                record[k] = item[k]
        # D2-promotion-enricher: ONLY hacker_question rows get per-function
        # routing fields. Other kinds (detector_seed, invariant,
        # cross_lang_invariant, chain_candidate, ...) are untouched - additive.
        if kind == "hacker_question":
            pftp = _load_pftp()
            if pftp is not None:
                # The enricher reads question_text + attack_class_anchor to
                # back-derive routing for grep-less rows; seed question_text
                # from the lifted statement and the anchor from category.
                record.setdefault("question_text", record["statement"])
                record.setdefault(
                    "attack_class_anchor",
                    item.get("attack_class_anchor") or record["category"],
                )
                try:
                    enriched = pftp.enrich_hacker_question_record(record)
                except Exception:
                    enriched = None
                if isinstance(enriched, dict):
                    for fld in (
                        "target_function_patterns",
                        "target_function_roles",
                        "target_contract_patterns",
                        "target_modifier_patterns",
                        "scope_specificity",
                        "non_targetable_meta",
                    ):
                        if fld in enriched:
                            record[fld] = enriched[fld]
        out.append(record)
    return out


# ---------------------------------------------------------------------------
# CAP-GAP-97a SOURCE_ROUTERS registry
# ---------------------------------------------------------------------------

DERIVED_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "derived"


def _dst(name: str) -> Path:
    return DERIVED_ROOT / name


SOURCE_ROUTERS: List[Dict[str, Any]] = [
    # --- 97b primary fixture (flat YAML) ---
    {
        "name": "invariant_library_extended",
        "kind": "invariant",
        "source_dir": DERIVED_ROOT / "invariant_library_extended",
        "glob": "**/*.yaml",
        "dst_path": INV_DST,
        "key_field": "invariant_id",
        "extractor": _extract_invariant_library_extended,
    },
    # --- dispatch-ledger routers (97a primary) ---
    {
        "name": "hacker_q_full_expansions",
        "kind": "hacker_question",
        "source_dir": DERIVED_ROOT / "hacker_q_full_expansions",
        "glob": "*.json",
        "dst_path": _dst("hacker_questions_library_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="hacker_question"),
    },
    {
        "name": "hacker_q_expansions",
        "kind": "hacker_question",
        "source_dir": DERIVED_ROOT / "hacker_q_expansions",
        "glob": "*.json",
        "dst_path": _dst("hacker_questions_library_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="hacker_question"),
    },
    {
        "name": "detector_synthesis_v2",
        "kind": "detector_seed",
        "source_dir": DERIVED_ROOT / "detector_synthesis_v2",
        # ``**/*.json`` so batch-subdir layouts (e.g. the zkbugs-dataset miner
        # writes detector seeds into <batch>/*.json) are picked up alongside
        # the legacy flat ``detector_synth_v2_*.json`` files. The batch-filter
        # logic in _run_generic_router already derives the batch from the
        # immediate parent dir, so recursive glob is safe and idempotent.
        "glob": "**/*.json",
        "dst_path": _dst("detector_seed_library_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="detector_seed"),
    },
    {
        "name": "tok_b_full_library_lifted",
        "kind": "cross_lang_invariant",
        "source_dir": DERIVED_ROOT / "tok_b_full_library_lifted",
        "glob": "*.json",
        "dst_path": _dst("cross_lang_invariants_lifted_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="cross_lang_invariant"),
    },
    {
        "name": "tok_b_lifted_v2",
        "kind": "cross_lang_invariant",
        "source_dir": DERIVED_ROOT / "tok_b_lifted_v2",
        "glob": "*.json",
        "dst_path": _dst("cross_lang_invariants_lifted_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="cross_lang_invariant"),
    },
    {
        "name": "multi_hop_chains",
        "kind": "chain_candidate",
        "source_dir": DERIVED_ROOT / "multi_hop_chains",
        "glob": "*.json",
        "dst_path": _dst("chain_candidates_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="chain_candidate"),
    },
    {
        "name": "hq_quality_audits",
        "kind": "quality_audit",
        "source_dir": DERIVED_ROOT / "hq_quality_audits",
        "glob": "*.json",
        "dst_path": _dst("hacker_q_quality_audit_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="quality_audit"),
    },
    {
        "name": "per_contract_hypotheses",
        "kind": "exploit_predicate",
        "source_dir": DERIVED_ROOT / "per_contract_hypotheses",
        "glob": "*.json",
        "dst_path": _dst("exploit_predicates_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="exploit_predicate"),
    },
    {
        "name": "per_contract_hyperbridge_full",
        "kind": "exploit_predicate",
        "source_dir": DERIVED_ROOT / "per_contract_hyperbridge_full",
        "glob": "*.json",
        "dst_path": _dst("exploit_predicates_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="exploit_predicate"),
    },
    {
        "name": "per_contract_mezo_full",
        "kind": "exploit_predicate",
        "source_dir": DERIVED_ROOT / "per_contract_mezo_full",
        "glob": "*.json",
        "dst_path": _dst("exploit_predicates_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="exploit_predicate"),
    },
    {
        "name": "hb_non_pallet_deep",
        "kind": "hyperbridge_hypothesis",
        "source_dir": DERIVED_ROOT / "hb_non_pallet_deep",
        "glob": "*.json",
        "dst_path": _dst("hyperbridge_deep_hypotheses_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="hyperbridge_hypothesis"),
    },
    {
        "name": "hyperbridge_pallet_deep",
        "kind": "hyperbridge_hypothesis",
        "source_dir": DERIVED_ROOT / "hyperbridge_pallet_deep",
        "glob": "*.json",
        "dst_path": _dst("hyperbridge_deep_hypotheses_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="hyperbridge_hypothesis"),
    },
    {
        "name": "lead_fp_verifications",
        "kind": "lead_fp_verification",
        "source_dir": DERIVED_ROOT / "lead_fp_verifications",
        "glob": "*.json",
        "dst_path": _dst("lead_fp_verifications_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="lead_fp_verification"),
    },
    {
        "name": "tok_a_enrichment",
        "kind": "tok_a_enriched_record",
        "source_dir": DERIVED_ROOT / "tok_a_enrichment",
        "glob": "**/*.json",
        "dst_path": _dst("tok_a_enriched_records_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(
            r, s, b, kind="tok_a_enriched_record",
            primary_key_candidates=("finding_handle", "invariant_id", "hypothesis_id"),
        ),
    },
    {
        "name": "tok_c_hypotheses",
        "kind": "tok_c_hypothesis",
        "source_dir": DERIVED_ROOT / "tok_c_hypotheses",
        "glob": "*.json",
        "dst_path": _dst("tok_c_hypotheses_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(r, s, b, kind="tok_c_hypothesis"),
    },
    {
        "name": "tok_d_personas",
        "kind": "tok_d_persona",
        "source_dir": DERIVED_ROOT / "tok_d_personas",
        "glob": "*.json",
        "dst_path": _dst("tok_d_personas_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(
            r, s, b, kind="tok_d_persona",
            primary_key_candidates=("frame_id", "persona_id"),
            statement_candidates=("scenario_narrative", "frame_id", "description"),
        ),
    },
    {
        "name": "tok_g_expansion",
        "kind": "tok_g_antipattern_expansion",
        "source_dir": DERIVED_ROOT / "tok_g_expansion",
        "glob": "*.json",
        "dst_path": _dst("tok_g_antipattern_expansion_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_dispatch_ledger_generic(
            r, s, b, kind="tok_g_antipattern_expansion",
            primary_key_candidates=("anti_pattern_title", "anti_pattern_name"),
            statement_candidates=("anti_pattern_title", "description", "lesson"),
        ),
    },
    # 2026-05-27 session-late additions: Tier-B/D/E mining outputs from the
    # full-plan burn. Each session's Tier-B (CAP-GAP code-gen), Tier-D (AGI
    # Lane B-F deliverables), Tier-E (Hyperbridge salvage) lands sidecars in
    # these dirs. Result field is raw text (python/markdown/bash) NOT JSON,
    # so we use a passthrough raw-text extractor instead of the dispatch-ledger
    # parser which assumes JSON-formatted result.
    {
        "name": "tier_B_capgap_outputs",
        "kind": "tier_b_capgap_codegen",
        "source_dir": DERIVED_ROOT / "tier_B_capgap_outputs",
        "glob": "*.json",
        "dst_path": _dst("tier_b_capgap_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_raw_text_result(r, s, b, kind="tier_b_capgap_codegen"),
    },
    {
        "name": "tier_D_agi_lane_outputs",
        "kind": "tier_d_agi_lane_deliverable",
        "source_dir": DERIVED_ROOT / "tier_D_agi_lane_outputs",
        "glob": "*.json",
        "dst_path": _dst("tier_d_agi_lane_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_raw_text_result(r, s, b, kind="tier_d_agi_lane_deliverable"),
    },
    {
        "name": "tier_E_hyperbridge_salvage",
        "kind": "tier_e_hyperbridge_salvage",
        "source_dir": DERIVED_ROOT / "tier_E_hyperbridge_salvage",
        "glob": "*.json",
        "dst_path": _dst("tier_e_hyperbridge_salvage_promoted.jsonl"),
        "key_field": "record_id",
        "extractor": lambda r, s, b: _extract_raw_text_result(r, s, b, kind="tier_e_hyperbridge_salvage"),
    },
]


def _extract_raw_text_result(
    rec: Dict[str, Any],
    src: Path,
    batch: str,
    *,
    kind: str = "raw_text",
) -> List[Dict[str, Any]]:
    """Extractor for sidecars whose `result` is raw text (markdown/python/bash)
    rather than JSON-formatted. Used by Tier-B/D/E code-gen and spec-gen
    outputs. Returns one record per sidecar with the raw text preserved as
    statement (capped at 3500 chars; full body remains in the source sidecar).
    """
    if rec.get("status") != "ok":
        return []
    result = rec.get("result")
    if not isinstance(result, str) or not result.strip():
        return []
    task_id = rec.get("task_id") or src.stem
    return [{
        "schema_version": f"auditooor.{kind}.v1",
        "record_id": task_id,
        "kind": kind,
        "router": batch,
        "category": rec.get("verification_tier", "tier-3-synthetic-taxonomy-anchored"),
        "statement": result[:3500],
        "statement_truncated": len(result) > 3500,
        "statement_full_len": len(result),
        "source_sidecar": str(src.relative_to(REPO_ROOT)) if src.is_absolute() else str(src),
        "input_tokens": rec.get("input_tokens"),
        "output_tokens": rec.get("output_tokens"),
        "cost_usd": rec.get("cost_usd"),
        "duration_s": rec.get("duration_s"),
        "model_id": rec.get("model_id"),
        "provider": rec.get("provider"),
        "verification_tier": rec.get("verification_tier", "tier-3-synthetic-taxonomy-anchored"),
        "source_task_id": task_id,
        "audit_status": f"promoted-from-mined:{batch}",
        "ts_utc": _ts_utc(),
    }]


# ---------------------------------------------------------------------------
# CAP-GAP-97c: faithful JSONL-source routers
# ---------------------------------------------------------------------------
#
# Some ETL miners emit a single line-delimited JSONL file of fully-formed
# records (e.g. tools/hackerman-etl-from-zebra-advisories.py writes
# invariants_zebra_advisories.jsonl + detector_seeds_zebra_advisories.jsonl).
# Routing those through the dir-of-YAML-files path (SOURCE_ROUTERS) loses
# content because the lite-YAML parser truncates multi-line scalars and drops
# list fields. The JSONL records already carry perfect content, so the
# faithful path below copies them verbatim into canonical shape with no
# YAML round-trip. (Codified 2026-05-29, zebra-advisory promotion anchor.)


def _extract_zebra_invariant_jsonl(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Faithful extractor for invariants_zebra_advisories.jsonl records.

    The source record has shape {content:{invariant_id, invariant_text,
    attack_class, ...}, verification_tier, ...}. Copy verbatim into the
    invariants_pilot_audited.jsonl canonical shape - NO truncation, full
    statement + source_finding_ids preserved.
    """
    if not isinstance(rec, dict):
        return []
    c = rec.get("content") if isinstance(rec.get("content"), dict) else rec
    inv_id = c.get("invariant_id") or ""
    statement = c.get("invariant_text") or c.get("statement") or ""
    if not inv_id or not statement:
        return []
    tier = (rec.get("verification_tier")
            or c.get("verification_tier")
            or "tier-3-synthetic-taxonomy-anchored")
    src = rec.get("source", {}) if isinstance(rec.get("source"), dict) else {}
    batch = src.get("task_type") or rec.get("source", {}).get("task_id") or "jsonl"
    out = {
        "schema_version": "auditooor.invariant_pilot.v1",
        "invariant_id": str(inv_id),
        "category": c.get("attack_class") or c.get("category") or "jsonl-mined",
        "statement": str(statement)[:3500],
        "target_lang": c.get("target_language") or c.get("target_lang") or "any",
        "source_finding_ids": list(c.get("source_findings") or c.get("source_incident_ids") or []),
        "verification_tier": tier,
        "audit_status": f"promoted-from-mined:{batch}",
        "ts_utc": _ts_utc(),
    }
    # Preserve a few high-value advisory fields verbatim so the canonical
    # record stays hunt-usable across targets (bug class, preconditions,
    # violation consequence). These are copied, never synthesized.
    for k in ("bug_class", "preconditions", "violation_consequence"):
        v = c.get(k)
        if v not in (None, "", []):
            out[k] = v
    return [out]


def _extract_zebra_detector_jsonl(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Faithful extractor for detector_seeds_zebra_advisories.jsonl records.

    The source record has a `statement` field that is a JSON-encoded inner
    detector body (ast_query_hint, regex_pattern, positive_fixture_snippet,
    fp_reduction_strategy, ...). Copy verbatim into the
    detector_seed_library_promoted.jsonl canonical shape.
    """
    if not isinstance(rec, dict):
        return []
    rec_id = rec.get("record_id") or rec.get("source_task_id") or ""
    statement = rec.get("statement") or ""
    if not rec_id or not statement:
        return []
    tier = rec.get("verification_tier") or "tier-3-synthetic-taxonomy-anchored"
    batch = rec.get("router") or "jsonl"
    out = {
        "schema_version": "auditooor.detector_seed.v1",
        "record_id": str(rec_id),
        "kind": rec.get("kind") or "detector_seed",
        "router": batch,
        "category": rec.get("category") or rec.get("attack_class") or "jsonl-mined",
        "attack_class": rec.get("attack_class") or "",
        "statement": str(statement)[:3500],
        "target_lang": rec.get("target_lang") or "any",
        "raw_keys": list(rec.get("raw_keys") or []),
        "verification_tier": tier,
        "source_audit_ref": rec.get("source_audit_ref") or "",
        "source_task_id": rec.get("source_task_id") or str(rec_id),
        "audit_status": rec.get("audit_status") or f"promoted-from-mined:{batch}",
        "ts_utc": _ts_utc(),
    }
    return [out]


# The zebra extractors above are source-agnostic: they operate purely on the
# advisory-JSONL record shape, not on any zebra-specific field. Expose
# target-neutral aliases so future callers read intent correctly. (Codified
# 2026-05-29, hyperbridge-advisory promotion anchor - generalized the
# previously zebra-only JSONL router set to glob-discover every
# invariants_*_advisories.jsonl / detector_seeds_*_advisories.jsonl emitted by
# any hackerman-etl-from-*-advisories.py miner.)
_extract_advisory_invariant_jsonl = _extract_zebra_invariant_jsonl
_extract_advisory_detector_jsonl = _extract_zebra_detector_jsonl


def _discover_advisory_jsonl_routers() -> List[Dict[str, Any]]:
    """Glob-discover every advisory-JSONL source file under derived/ and build
    a faithful-copy router for each. Covers any target (zebra, hyperbridge,
    nearcore, aztec, midnight, ...) whose ETL miner emits the canonical
    invariants_<target>_advisories.jsonl / detector_seeds_<target>_advisories.jsonl
    shape. Deterministic (sorted) so router ordering is stable across runs."""
    routers: List[Dict[str, Any]] = []
    if not DERIVED_ROOT.exists():
        return routers
    for f in sorted(DERIVED_ROOT.glob("invariants_*_advisories.jsonl")):
        target = f.stem[len("invariants_"):-len("_advisories")]
        routers.append({
            "name": f"invariants_{target}_advisories_jsonl",
            "source_file": f,
            "dst_path": INV_DST,
            "key_field": "invariant_id",
            "extractor": _extract_advisory_invariant_jsonl,
        })
    for f in sorted(DERIVED_ROOT.glob("detector_seeds_*_advisories.jsonl")):
        target = f.stem[len("detector_seeds_"):-len("_advisories")]
        routers.append({
            "name": f"detector_seeds_{target}_advisories_jsonl",
            "source_file": f,
            "dst_path": _dst("detector_seed_library_promoted.jsonl"),
            "key_field": "record_id",
            "extractor": _extract_advisory_detector_jsonl,
        })
    return routers


JSONL_SOURCE_ROUTERS: List[Dict[str, Any]] = _discover_advisory_jsonl_routers()


def promote_from_jsonl_router(
    router: Dict[str, Any],
    min_conf: str,
    dry_run: bool,
) -> Tuple[int, int]:
    """Promote every line of a single JSONL source file via a faithful
    extractor. Dedups against existing canonical keys. Returns (promoted,
    skipped)."""
    src_file: Path = router["source_file"]
    if not src_file.exists():
        return (0, 0)
    dst_path: Path = router["dst_path"]
    key_field: str = router["key_field"]
    extractor = router["extractor"]
    existing = _existing_jsonl_keys(dst_path, key_field)
    promoted = 0
    skipped = 0
    new_lines: List[str] = []
    with src_file.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if not _meets_min_confidence(rec, min_conf):
                skipped += 1
                continue
            for out_rec in extractor(rec):
                key = str(out_rec.get(key_field, "")).strip()
                if not key:
                    skipped += 1
                    continue
                if key in existing:
                    skipped += 1
                    continue
                new_lines.append(json.dumps(out_rec))
                existing.add(key)
                promoted += 1
    if not dry_run and new_lines:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        with dst_path.open("a", encoding="utf-8") as fh:
            for line in new_lines:
                fh.write(line + "\n")
    return (promoted, skipped)


# ---------------------------------------------------------------------------
# Generic router promoter
# ---------------------------------------------------------------------------

def promote_from_router(
    router: Dict[str, Any],
    min_conf: str,
    only_batch: Optional[str],
    dry_run: bool,
) -> Tuple[int, int]:
    """Promote every file matching router["glob"] under router["source_dir"].

    Returns (promoted, skipped).
    """
    src_dir: Path = router["source_dir"]
    if not src_dir.exists():
        return (0, 0)
    dst_path: Path = router["dst_path"]
    key_field: str = router["key_field"]
    extractor: Callable[[Dict[str, Any], Path, str], List[Dict[str, Any]]] = router["extractor"]
    existing = _existing_jsonl_keys(dst_path, key_field)
    promoted = 0
    skipped = 0
    new_lines: List[str] = []
    for f in sorted(src_dir.glob(router["glob"])):
        if not f.is_file():
            continue
        # Batch dir is the immediate parent if nested, else router name
        try:
            rel = f.relative_to(src_dir)
            batch = rel.parts[0] if len(rel.parts) > 1 else router["name"]
        except ValueError:
            batch = router["name"]
        if only_batch and batch != only_batch:
            continue
        rec = _extract_record_content_from_ingested_yaml(f)
        if not rec:
            skipped += 1
            continue
        if not _meets_min_confidence(rec, min_conf):
            skipped += 1
            continue
        out_records = extractor(rec, f, batch)
        if not out_records:
            skipped += 1
            continue
        for out_rec in out_records:
            key = str(out_rec.get(key_field, "")).strip()
            if not key:
                skipped += 1
                continue
            if key in existing:
                skipped += 1
                continue
            new_lines.append(json.dumps(out_rec))
            existing.add(key)
            promoted += 1
    if not dry_run and new_lines:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        with dst_path.open("a", encoding="utf-8") as fh:
            for line in new_lines:
                fh.write(line + "\n")
    return (promoted, skipped)


# ---------------------------------------------------------------------------
# Legacy invariant + anti-pattern promotion (preserved verbatim)
# ---------------------------------------------------------------------------

def _existing_invariant_ids() -> set:
    out: set = set()
    if not INV_DST.exists():
        return out
    with INV_DST.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                out.add(json.loads(line).get("invariant_id", ""))
            except Exception:
                pass
    out.discard("")
    return out


def _content_to_invariant_text(content: Dict[str, Any]) -> str:
    txt = content.get("invariant_text", "")
    if isinstance(txt, str) and txt.strip().startswith("{"):
        try:
            inner = json.loads(txt)
            for k in ("lifted_statement_rust", "lifted_statement_go", "lifted_statement_move",
                      "lifted_statement_solidity", "lifted_statement_cairo",
                      "invariant_statement", "statement", "lifted_statement"):
                if inner.get(k):
                    return str(inner[k])
            return json.dumps(inner)[:2000]
        except json.JSONDecodeError:
            pass
    if isinstance(txt, str):
        return txt[:2000]
    return ""


def promote_invariants(min_conf: str, only_batch: Optional[str], dry_run: bool) -> Tuple[int, int]:
    """Legacy invariant promoter (original behavior preserved verbatim).

    Note: with CAP-GAP-97a/97b, this is superseded by the
    `invariant_library_extended` router in SOURCE_ROUTERS which handles flat
    YAML correctly. This function is now an alias that routes through the
    new generic promoter so legacy callers + CLI flags keep working.
    """
    for router in SOURCE_ROUTERS:
        if router["name"] == "invariant_library_extended":
            return promote_from_router(router, min_conf, only_batch, dry_run)
    return (0, 0)


def _existing_anti_pattern_slugs() -> set:
    out: set = set()
    if not ANTI_PATTERN_DST_DIR.exists():
        return out
    for f in ANTI_PATTERN_DST_DIR.glob("*.md"):
        out.add(f.stem)
    return out


def _content_to_anti_pattern_md(content: Dict[str, Any], batch: str, src_path: Path) -> Tuple[str, str]:
    name = content.get("anti_pattern_name") or content.get("name") or src_path.stem
    slug = _slugify(f"mined__{batch}__{name}", max_len=150)
    title = str(name).replace("-", " ").title()
    description = content.get("description") or ""
    if isinstance(description, str) and description.strip().startswith("{"):
        try:
            inner = json.loads(description)
            description = inner.get("description", description)
        except json.JSONDecodeError:
            pass
    recommendation = content.get("remediation") or content.get("recommendation") or ""
    indicators = content.get("indicator_phrases", []) or []
    related = content.get("related_rules", []) or []
    confidence = _record_confidence({"content": content})

    md = f"""---
title: "{title}"
recommendation: {json.dumps(str(recommendation)[:500])}
sample_size: 1
confidence: {confidence}
counter_examples: 0
last_validated_at: {_dt.date.today().isoformat()}
source_kind: "deepseek-mined-batch:{batch}"
source_id: "{src_path.name}"
generated_by: "tools/promote-mined-to-canonical.py"
---

# {title}

## Recommendation
{recommendation}

## Lesson
{description}

## Primary Evidence
- DeepSeek-mined record from batch `{batch}`, source path `audit/corpus_tags/derived/anti_pattern_corpus/{batch}/{src_path.name}`.

## Indicator Phrases
""" + ("\n".join(f"- `{p}`" for p in indicators) if indicators else "- (none enumerated by miner)") + """

## Related Rules
""" + ("\n".join(f"- {r}" for r in related) if related else "- (none cited by miner)") + "\n"
    return (slug, md)


def promote_anti_patterns(min_conf: str, only_batch: Optional[str], dry_run: bool) -> Tuple[int, int]:
    if not ANTI_PATTERN_SRC_ROOT.exists():
        _stderr(f"no anti-pattern source root: {ANTI_PATTERN_SRC_ROOT}")
        return (0, 0)
    if not dry_run:
        ANTI_PATTERN_DST_DIR.mkdir(parents=True, exist_ok=True)
    existing = _existing_anti_pattern_slugs()
    promoted = 0
    skipped = 0
    batch_dirs = [d for d in ANTI_PATTERN_SRC_ROOT.iterdir() if d.is_dir()]
    if only_batch:
        batch_dirs = [d for d in batch_dirs if d.name == only_batch]
    for batch_dir in sorted(batch_dirs):
        for f in sorted(batch_dir.glob("*.yaml")):
            rec = _extract_record_content_from_ingested_yaml(f)
            if not rec:
                skipped += 1
                continue
            if not _meets_min_confidence(rec, min_conf):
                skipped += 1
                continue
            content = rec.get("content") if isinstance(rec, dict) else {}
            if not isinstance(content, dict):
                # Flat-YAML anti-pattern shape (manual_zetachain_2026-04-26):
                # the lite parser may have parsed nested content: as a
                # scalar; fall back to the rec-level keys for extraction.
                content = rec if isinstance(rec, dict) else {}
            slug, md_body = _content_to_anti_pattern_md(content, batch_dir.name, f)
            if slug in existing:
                skipped += 1
                continue
            if not dry_run:
                (ANTI_PATTERN_DST_DIR / f"{slug}.md").write_text(md_body, encoding="utf-8")
            existing.add(slug)
            promoted += 1
    return (promoted, skipped)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Promote mined records to canonical MCP-readable paths.")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--batch-id", default=None)
    p.add_argument("--min-confidence", default="medium", choices=("low", "medium", "high"))
    p.add_argument("--skip-invariants", action="store_true",
                   help="Skip the invariant_library_extended router")
    p.add_argument("--skip-anti-patterns", action="store_true",
                   help="Skip the legacy anti-pattern markdown emitter")
    p.add_argument("--skip-router", action="append", default=[],
                   help="Skip a specific router by name (repeatable)")
    p.add_argument("--only-router", action="append", default=[],
                   help="Only run the named router(s) (repeatable)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    router_stats: Dict[str, Dict[str, int]] = {}
    total_promoted = 0
    total_skipped = 0

    for router in SOURCE_ROUTERS:
        if args.skip_router and router["name"] in args.skip_router:
            continue
        if args.only_router and router["name"] not in args.only_router:
            continue
        if args.skip_invariants and router["name"] == "invariant_library_extended":
            continue
        promoted, skipped = promote_from_router(
            router, min_conf=args.min_confidence,
            only_batch=args.batch_id, dry_run=args.dry_run,
        )
        router_stats[router["name"]] = {"promoted": promoted, "skipped": skipped}
        total_promoted += promoted
        total_skipped += skipped

    # CAP-GAP-97c: faithful JSONL-source routers (verbatim copy, no YAML
    # round-trip). Honor --only-router / --skip-router by name.
    for router in JSONL_SOURCE_ROUTERS:
        if args.skip_router and router["name"] in args.skip_router:
            continue
        if args.only_router and router["name"] not in args.only_router:
            continue
        promoted, skipped = promote_from_jsonl_router(
            router, min_conf=args.min_confidence, dry_run=args.dry_run,
        )
        router_stats[router["name"]] = {"promoted": promoted, "skipped": skipped}
        total_promoted += promoted
        total_skipped += skipped

    ap_promoted = ap_skipped = 0
    if not args.skip_anti_patterns and (not args.only_router):
        ap_promoted, ap_skipped = promote_anti_patterns(
            min_conf=args.min_confidence, only_batch=args.batch_id, dry_run=args.dry_run,
        )
        router_stats["anti_patterns_markdown"] = {"promoted": ap_promoted, "skipped": ap_skipped}
        total_promoted += ap_promoted
        total_skipped += ap_skipped

    inv_router = router_stats.get("invariant_library_extended", {"promoted": 0, "skipped": 0})

    summary = {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "ts_utc": _ts_utc(),
        "dry_run": args.dry_run,
        "min_confidence": args.min_confidence,
        "batch_id_filter": args.batch_id,
        "invariants_promoted": inv_router["promoted"],
        "invariants_skipped": inv_router["skipped"],
        "anti_patterns_promoted": ap_promoted,
        "anti_patterns_skipped": ap_skipped,
        "total_promoted": total_promoted,
        "total_skipped": total_skipped,
        "per_router": router_stats,
        "invariant_dst": str(INV_DST.relative_to(REPO_ROOT)),
        "anti_pattern_dst": str(ANTI_PATTERN_DST_DIR.relative_to(REPO_ROOT)),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        _stderr(
            f"total: promoted={total_promoted} skipped={total_skipped} "
            f"(invariants={inv_router['promoted']}, anti-patterns={ap_promoted}) "
            f"dry_run={args.dry_run} min_conf={args.min_confidence}"
        )
    if total_promoted == 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
