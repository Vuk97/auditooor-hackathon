#!/usr/bin/env python3
"""Build minimal causal-chain rows from local predicate records.

The MVP is intentionally conservative: it rewrites existing Hackerman exploit
predicate records (and similarly-shaped JSON/YAML records) into normalized
chain rows without inventing missing evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "auditooor.causal_chain.v1"
STRICT_PROJECTION_SCHEMA = "auditooor.causal_chain_strict_projection.v1"
DEFAULT_INPUT = Path("audit/corpus_tags/derived/exploit_predicates.d")
DEFAULT_CANONICAL_OUTPUT = Path("audit/corpus_tags/derived/causal_chains.jsonl")
DEFAULT_CANONICAL_INDEX = Path("audit/corpus_tags/derived/causal_chain_index.json")
DEFAULT_CANONICAL_REVERSE_SQLITE = Path(
    "audit/corpus_tags/derived/causal_chain_reverse_lookup.sqlite"
)
DEFAULT_CANONICAL_STRICT_PROJECTION = Path(
    "audit/corpus_tags/derived/causal_chain_strict_projection.jsonl"
)
DEFAULT_REPORT_DIR = Path(
    "reports/v3_iter_2026-05-24/lane_V3_P2_CAUSAL_CHAIN_MVP"
)
DEFAULT_REPORT = DEFAULT_REPORT_DIR / "report.md"
DEFAULT_SAMPLE_OUTPUT = DEFAULT_REPORT_DIR / "causal_chains_sample.jsonl"
DEFAULT_SAMPLE_INDEX = DEFAULT_REPORT_DIR / "index.json"

VERIFICATION_TIER_RE = re.compile(r"\bverification_tier=([A-Za-z0-9_.:-]+)")
MITIGATION_RE = re.compile(r"\b(mitigat(?:e|ed|ion)|patch(?:ed|es)?|workaround|consider)\b", re.I)
PRECONDITION_PLACEHOLDER_RE = re.compile(r"\b(tbd|todo)\b", re.I)
TEXT_PLACEHOLDER_RE = re.compile(r"\b(not stated in source record|unknown|tbd|todo)\b", re.I)
FUNCTION_SIGNATURE_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", re.I)
FALLBACK_DEFENSE = "not stated in source record"
QUALITY_PROFILES = ("none", "canonical", "strict")


def stable_id(*parts: str) -> str:
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"chain:{digest}"


def load_records(paths: Iterable[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        if path.is_dir():
            children = sorted(
                p for p in path.rglob("*") if p.suffix.lower() in {".json", ".jsonl", ".yaml", ".yml"}
            )
            records.extend(load_records(children))
            continue
        if not path.exists():
            raise FileNotFoundError(path)
        if path.suffix.lower() == ".jsonl":
            records.extend(_load_jsonl(path))
        elif path.suffix.lower() == ".json":
            records.extend(_load_json(path))
        elif path.suffix.lower() in {".yaml", ".yml"}:
            records.append(_load_yaml_minimal(path))
    return [r for r in records if isinstance(r, dict)]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSONL: {exc}") from exc
            if isinstance(row, dict):
                row.setdefault("_source_path", str(path))
                row.setdefault("_source_line", lineno)
                out.append(row)
    return out


def _load_json(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict) and isinstance(data.get("records"), list):
        rows = [r for r in data["records"] if isinstance(r, dict)]
    elif isinstance(data, dict):
        rows = [data]
    else:
        rows = []
    for row in rows:
        row.setdefault("_source_path", str(path))
    return rows


def _load_yaml_minimal(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError:
        return _load_yaml_minimal_fallback(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    data.setdefault("_source_path", str(path))
    return data


def _load_yaml_minimal_fallback(path: Path) -> dict[str, Any]:
    row: dict[str, Any] = {"_source_path": str(path)}
    current_key: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = raw.strip()
        if stripped.startswith("- ") and current_key:
            row.setdefault(current_key, []).append(stripped[2:].strip().strip('"'))
            continue
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        value = value.strip()
        if not value:
            current_key = key
            row[key] = []
        else:
            current_key = None
            row[key] = value.strip('"')
    return row


def causal_chain_from_record(record: dict[str, Any]) -> dict[str, Any] | None:
    record_id = first_text(record, "record_id", "id", "pattern_id", "finding_id")
    if not record_id:
        return None

    actions = text_list(record.get("actions")) or predicate_values(record, "action")
    preconditions = (
        text_list(record.get("preconditions"))
        or text_list(record.get("required_preconditions"))
        or predicate_values(record, "precondition")
    )
    impacts = normalize_impacts(record)
    source_refs = normalize_source_refs(record)
    verification_tier = infer_verification_tier(record, preconditions + actions + source_refs)
    defense = infer_defense(record, actions)
    trigger = infer_trigger(actions, record)

    row = {
        "schema_version": SCHEMA_VERSION,
        "chain_id": stable_id(str(record_id), trigger),
        "source_record_id": str(record_id),
        "source_refs": source_refs,
        "preconditions": preconditions,
        "trigger": trigger,
        "defense": defense,
        "impact": impacts,
        "verification_tier": verification_tier,
    }
    optional = {
        "attack_class": first_text(record, "attack_class"),
        "bug_class": first_text(record, "bug_class", "category"),
        "target_component": first_text(record, "target_component", "component"),
        "target_domain": first_text(record, "target_domain", "domain"),
        "target_language": first_text(record, "target_language", "language"),
        "requires_state": text_list(record.get("requires_state")),
        "produces_state": text_list(record.get("produces_state")),
    }
    row.update({k: v for k, v in optional.items() if v})
    return row


def predicate_values(record: dict[str, Any], predicate_type: str) -> list[str]:
    values: list[tuple[int, str]] = []
    for pred in record.get("predicates") or []:
        if not isinstance(pred, dict) or pred.get("predicate_type") != predicate_type:
            continue
        value = pred.get("value")
        if value is None:
            continue
        values.append((int(pred.get("ordinal") or 0), compact_text(value)))
    return [v for _, v in sorted(values)]


def normalize_source_refs(record: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("source_refs", "source_audit_ref", "source_finding_ids", "tag_file", "_source_path"):
        refs.extend(text_list(record.get(key)))
    line = record.get("_source_line")
    if line and refs and refs[-1] == record.get("_source_path"):
        refs[-1] = f"{refs[-1]}:{line}"
    return unique_nonempty(refs)


def normalize_impacts(record: dict[str, Any]) -> list[dict[str, Any]]:
    raw = record.get("impacts") or record.get("impact") or []
    rows = raw if isinstance(raw, list) else [raw]
    impacts: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            kept = {
                k: row[k]
                for k in ("impact_class", "impact_actor", "impact_dollar_class", "severity_at_finding")
                if row.get(k) is not None
            }
            if kept:
                impacts.append(kept)
        elif row:
            impacts.append({"summary": compact_text(row)})
    return impacts or [{"summary": FALLBACK_DEFENSE}]


def infer_verification_tier(record: dict[str, Any], texts: list[str]) -> str:
    explicit = first_text(record, "verification_tier")
    if explicit:
        return explicit
    for text in texts:
        match = VERIFICATION_TIER_RE.search(text)
        if match:
            return match.group(1)
    tier = first_text(record, "record_tier")
    if tier:
        return tier
    return "unknown"


def infer_defense(record: dict[str, Any], actions: list[str]) -> str:
    for key in ("defense", "mitigation", "recommendation", "remediation"):
        value = first_text(record, key)
        if value:
            return value
    for action in reversed(actions):
        if MITIGATION_RE.search(action):
            return compact_text(action, max_chars=360)
    return FALLBACK_DEFENSE


def infer_trigger(actions: list[str], record: dict[str, Any]) -> str:
    for action in actions:
        text = compact_text(action, max_chars=360)
        if text:
            return text
    for key in ("title", "name", "description", "summary"):
        text = first_text(record, key)
        if text:
            return compact_text(text, max_chars=360)
    return FALLBACK_DEFENSE


def first_text(record: dict[str, Any], *keys: str) -> str:
    for key in keys:
        values = text_list(record.get(key))
        if values:
            return values[0]
    return ""


def text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [compact_text(v) for v in value if compact_text(v)]
    if isinstance(value, dict):
        return [compact_text(value)]
    return [compact_text(value)] if compact_text(value) else []


def compact_text(value: Any, max_chars: int = 900) -> str:
    text = json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def unique_nonempty(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = compact_text(value)
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def normalize_lookup_text(value: Any) -> str:
    text = compact_text(value, max_chars=420).lower()
    text = re.sub(r"`+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def normalize_entry_signature(value: Any) -> str:
    text = compact_text(value, max_chars=420)
    match = FUNCTION_SIGNATURE_RE.search(text)
    if not match:
        return normalize_lookup_text(text)
    name = match.group(1).lower()
    params = []
    for raw_param in match.group(2).split(","):
        param = raw_param.strip()
        if not param:
            continue
        param = re.sub(r"\b(memory|calldata|storage|payable)\b", "", param, flags=re.I)
        pieces = [piece for piece in re.split(r"\s+", param.strip()) if piece]
        if not pieces:
            continue
        params.append(pieces[0].lower())
    return f"{name}({','.join(params)})"


def raw_entry_signature_for_row(row: dict[str, Any]) -> str:
    entry_point = row.get("entry_point")
    if isinstance(entry_point, dict):
        for key in ("function_signature", "signature", "entry_signature", "name"):
            value = entry_point.get(key)
            if value:
                return compact_text(value, max_chars=420)
    for key in ("entry_signature", "target_component", "trigger"):
        value = row.get(key)
        if value:
            return compact_text(value, max_chars=420)
    return ""


def entry_signature_for_row(row: dict[str, Any]) -> str:
    entry_point = row.get("entry_point")
    if isinstance(entry_point, dict):
        for key in ("function_signature", "signature", "entry_signature", "name"):
            value = entry_point.get(key)
            if value:
                return normalize_entry_signature(value)
    for key in ("entry_signature", "target_component", "trigger"):
        value = row.get(key)
        if value:
            return normalize_entry_signature(value)
    return ""


def mutation_texts_for_row(row: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    mutations = row.get("mutations")
    if isinstance(mutations, list):
        for mutation in mutations:
            if not isinstance(mutation, dict):
                continue
            for key in ("state_field_modified", "state_field", "postcondition"):
                value = mutation.get(key)
                if value:
                    texts.append(str(value))
                    break
    if not texts:
        for key in ("produces_state", "requires_state"):
            value = row.get(key)
            if isinstance(value, list):
                texts.extend(str(item) for item in value if item not in ("", None))
    return unique_nonempty(normalize_lookup_text(text) for text in texts)


def impact_actor_for_row(row: dict[str, Any]) -> str:
    impact = row.get("impact")
    if isinstance(impact, dict) and impact.get("impact_actor"):
        return compact_text(impact.get("impact_actor"))
    if isinstance(impact, list):
        for item in impact:
            if isinstance(item, dict) and item.get("impact_actor"):
                return compact_text(item.get("impact_actor"))
    return ""


def caller_capability_for_row(row: dict[str, Any]) -> str:
    texts = text_list(row.get("preconditions")) + text_list(row.get("requires_state"))
    normalized = " ".join(text.lower() for text in texts)
    if "privileged" in normalized or "admin" in normalized or "owner" in normalized:
        return "privileged-caller-context"
    if "arbitrary" in normalized or impact_actor_for_row(row) == "arbitrary-user":
        return "arbitrary-user"
    return "unspecified-by-source"


def invariant_id_for_row(row: dict[str, Any]) -> str:
    explicit = first_text(row, "invariant_id")
    if explicit:
        return explicit
    produced = text_list(row.get("produces_state"))
    if produced:
        return produced[0]
    bug_class = compact_text(row.get("bug_class"))
    if bug_class:
        return f"bug-class:{bug_class}"
    attack_class = compact_text(row.get("attack_class"))
    if attack_class:
        return f"attack-class:{attack_class}"
    return "invariant:unspecified-by-source"


def projected_mutations_for_row(row: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    actor = impact_actor_for_row(row) or caller_capability_for_row(row)
    preconditions = text_list(row.get("preconditions"))
    mutations = row.get("mutations")
    if isinstance(mutations, list) and mutations:
        projected: list[dict[str, Any]] = []
        for index, mutation in enumerate(mutations, 1):
            if not isinstance(mutation, dict):
                warnings.append("non_object_mutation_skipped")
                continue
            state_field = first_text(
                mutation,
                "state_field_modified",
                "state_field",
                "postcondition",
            )
            if not state_field:
                warnings.append("mutation_missing_state_field")
                continue
            projected.append(
                {
                    "step": int(mutation.get("step") or index),
                    "state_field_modified": state_field,
                    "precondition": compact_text(
                        mutation.get("precondition")
                        or (preconditions[min(index - 1, len(preconditions) - 1)] if preconditions else "")
                    ),
                    "postcondition": compact_text(mutation.get("postcondition") or state_field),
                    "actor": compact_text(mutation.get("actor") or actor),
                    "is_irrecoverable_commit": bool(mutation.get("is_irrecoverable_commit")),
                    "source": "record.mutations",
                }
            )
        return projected, warnings

    produced = text_list(row.get("produces_state"))
    required = text_list(row.get("requires_state"))
    states = produced or required
    projected = []
    for index, state in enumerate(states, 1):
        projected.append(
            {
                "step": index,
                "state_field_modified": state,
                "precondition": required[index - 1] if index - 1 < len(required) else (
                    preconditions[0] if preconditions else "unspecified-by-source"
                ),
                "postcondition": state,
                "actor": actor,
                "is_irrecoverable_commit": bool(produced and index == len(produced)),
                "source": "compact_state_projection",
            }
        )
    if projected:
        warnings.append("mutations_projected_from_compact_state_fields")
        if produced:
            warnings.append("irrecoverable_commit_projected_from_final_produced_state")
    return projected, warnings


def strict_projection_for_row(row: dict[str, Any]) -> dict[str, Any]:
    source_refs = text_list(row.get("source_refs"))
    preconditions = text_list(row.get("preconditions"))
    mutations, warnings = projected_mutations_for_row(row)
    invariant_id = invariant_id_for_row(row)
    violation_step = violation_step_for_row(row)
    if violation_step is None and mutations:
        violation_step = mutations[-1]["step"]
        warnings.append("violation_step_projected_from_last_mutation")
    entry_signature = raw_entry_signature_for_row(row)
    if not entry_signature:
        warnings.append("entry_point_missing")
    if not mutations:
        warnings.append("mutations_missing")
    if invariant_id == "invariant:unspecified-by-source":
        warnings.append("invariant_id_missing")
    return {
        "schema": STRICT_PROJECTION_SCHEMA,
        "source_schema_version": compact_text(row.get("schema_version")),
        "chain_id": compact_text(row.get("chain_id")),
        "source_record_id": compact_text(row.get("source_record_id")),
        "source_refs": source_refs,
        "projection_status": "compatibility_projection",
        "entry_point": {
            "function_signature": entry_signature,
            "function_signature_norm": entry_signature_for_row(row),
            "caller_capability_required": caller_capability_for_row(row),
            "guards_traversed_before_entry": preconditions,
            "source_evidence": source_refs[:5],
        },
        "mutations": mutations,
        "invariant_violation": {
            "invariant_id": invariant_id,
            "violation_step": violation_step,
            "source_evidence": {
                "trigger": compact_text(row.get("trigger")),
                "source_refs": source_refs[:5],
            },
        },
        "impact": row.get("impact") or [],
        "projection_warnings": unique_nonempty(warnings),
    }


def validate_strict_projection(projection: dict[str, Any]) -> None:
    if projection.get("schema") != STRICT_PROJECTION_SCHEMA:
        raise ValueError(f"schema must be {STRICT_PROJECTION_SCHEMA}")
    for key in ("chain_id", "source_record_id", "entry_point", "mutations", "invariant_violation", "impact"):
        if key not in projection:
            raise ValueError(f"missing strict projection key: {key}")
    if not isinstance(projection["entry_point"], dict):
        raise TypeError("entry_point must be object")
    if not isinstance(projection["mutations"], list):
        raise TypeError("mutations must be list")
    if not isinstance(projection["invariant_violation"], dict):
        raise TypeError("invariant_violation must be object")


def impact_field(row: dict[str, Any], key: str) -> str:
    impact = row.get("impact")
    if isinstance(impact, dict):
        return compact_text(impact.get(key))
    if isinstance(impact, list):
        for item in impact:
            if isinstance(item, dict) and item.get(key):
                return compact_text(item.get(key))
    return ""


def violation_step_for_row(row: dict[str, Any]) -> int | None:
    invariant_violation = row.get("invariant_violation")
    if isinstance(invariant_violation, dict):
        value = invariant_violation.get("violation_step")
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    mutations = row.get("mutations")
    if isinstance(mutations, list):
        for index, mutation in enumerate(mutations, 1):
            if isinstance(mutation, dict) and mutation.get("is_irrecoverable_commit") is True:
                try:
                    return int(mutation.get("step") or index)
                except (TypeError, ValueError):
                    return index
    return None


def recoverable_for_row(row: dict[str, Any]) -> int | None:
    impact = row.get("impact")
    values: list[Any] = []
    if isinstance(impact, dict):
        values.append(impact.get("recoverable"))
    elif isinstance(impact, list):
        values.extend(item.get("recoverable") for item in impact if isinstance(item, dict))
    invariant_violation = row.get("invariant_violation")
    if isinstance(invariant_violation, dict):
        values.append(invariant_violation.get("recoverable"))
    for value in values:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
            return 1 if value.strip().lower() == "true" else 0
    return None


def has_placeholder_precondition(text: str) -> bool:
    normalized = compact_text(text).lower()
    if not normalized:
        return True
    return bool(PRECONDITION_PLACEHOLDER_RE.search(normalized))


_HEADER_LABELS = {
    "patch", "mitigation", "mitigations", "fix", "fixes", "remediation",
    "recommendation", "recommendations", "recommended mitigation steps",
    "recommended mitigation", "solution", "resolution", "the fix", "the patch",
}


def _is_bare_markdown_header(normalized: str) -> bool:
    """True when the text is just a markdown section header (e.g. '## Patch',
    '### Recommended Mitigation Steps') with no real body - the auto-miner grabbed
    the heading line but not the mitigation prose. Keeps a header FOLLOWED by real
    content (compact_text collapses the newline, so a long body survives)."""
    t = normalized.strip()
    if not t.startswith("#"):
        return False
    body = t.lstrip("#").strip(" :#-").strip()
    if not body:
        return True
    if body in _HEADER_LABELS:
        return True
    # a bare heading is short with no sentence body
    return len(body.split()) <= 4


_JUNK_DEFENSE_RE = re.compile(
    r"\bnot (specified|stated|provided|available|mentioned|described)\b"
    r"|consider the following (scenario|example)"
    r"|see (the )?(scenario|example|poc|proof)\b",
    re.IGNORECASE,
)


def is_placeholder_text(text: str) -> bool:
    normalized = compact_text(text).lower()
    if not normalized:
        return True
    if _is_bare_markdown_header(normalized):
        return True
    if _JUNK_DEFENSE_RE.search(normalized):
        return True
    return bool(TEXT_PLACEHOLDER_RE.search(normalized))


def quality_rejections(row: dict[str, Any], profile: str) -> list[str]:
    if profile not in QUALITY_PROFILES:
        raise ValueError(f"unsupported quality profile: {profile}")
    if profile == "none":
        return []

    rejected: list[str] = []
    preconditions = row.get("preconditions") or []
    verification_tier = compact_text(row.get("verification_tier"))
    defense = compact_text(row.get("defense"))
    trigger = compact_text(row.get("trigger"))

    if verification_tier == "unknown":
        rejected.append("verification_tier_unknown")
    if not preconditions:
        rejected.append("preconditions_empty")
    elif any(has_placeholder_precondition(text) for text in preconditions):
        rejected.append("preconditions_placeholder")

    if profile in {"canonical", "strict"}:
        if defense == FALLBACK_DEFENSE or is_placeholder_text(defense):
            rejected.append("defense_fallback_or_placeholder")

    if profile == "strict":
        if defense == trigger:
            rejected.append("defense_equals_trigger")
        if is_placeholder_text(trigger):
            rejected.append("trigger_placeholder")
    return rejected


def apply_quality_gate(
    rows: list[dict[str, Any]],
    profile: str,
    limit: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    accepted: list[dict[str, Any]] = []
    rejected_counts: Counter[str] = Counter()
    scanned = 0
    for row in rows:
        scanned += 1
        rejected = quality_rejections(row, profile)
        if rejected:
            rejected_counts.update(rejected)
            continue
        accepted.append(row)
        if limit is not None and len(accepted) >= limit:
            break

    summary = {
        "profile": profile,
        "scanned_rows": scanned,
        "accepted_rows": len(accepted),
        "rejected_rows": max(scanned - len(accepted), 0),
        "rejected_by_reason": dict(sorted(rejected_counts.items())),
        "acceptance_ratio": round((len(accepted) / scanned), 6) if scanned else 0.0,
    }
    if profile == "none":
        summary["requirements"] = []
    elif profile == "canonical":
        summary["requirements"] = [
            "verification_tier != unknown",
            "preconditions non-empty",
            "preconditions exclude placeholder tbd/todo",
            "defense must not be fallback/placeholder",
        ]
    else:
        summary["requirements"] = [
            "verification_tier != unknown",
            "preconditions non-empty",
            "preconditions exclude placeholder tbd/todo",
            "defense must not be fallback/placeholder",
            "defense must differ from trigger",
            "trigger must not be placeholder",
        ]
    return accepted, summary


def validate_chain(row: dict[str, Any]) -> None:
    required = {
        "schema_version": str,
        "chain_id": str,
        "source_record_id": str,
        "source_refs": list,
        "preconditions": list,
        "trigger": str,
        "defense": str,
        "impact": list,
        "verification_tier": str,
    }
    for key, typ in required.items():
        if key not in row:
            raise ValueError(f"missing required causal-chain key: {key}")
        if not isinstance(row[key], typ):
            raise TypeError(f"{key} must be {typ.__name__}")
    if row["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    if not row["source_refs"]:
        raise ValueError("source_refs must not be empty")
    if not row["trigger"]:
        raise ValueError("trigger must not be empty")
    if not row["defense"]:
        raise ValueError("defense must not be empty")
    if not row["impact"]:
        raise ValueError("impact must not be empty")


def build_chains(records: Iterable[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    for record in records:
        row = causal_chain_from_record(record)
        if row is None:
            continue
        validate_chain(row)
        chains.append(row)
        if limit is not None and len(chains) >= limit:
            break
    return chains


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def write_strict_projection_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    projected_rows = 0
    warning_counts: Counter[str] = Counter()
    four_block_rows = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            if limit is not None and projected_rows >= limit:
                break
            projection = strict_projection_for_row(row)
            validate_strict_projection(projection)
            warnings = projection.get("projection_warnings") or []
            warning_counts.update(warnings)
            if (
                projection.get("entry_point")
                and projection.get("mutations")
                and projection.get("invariant_violation")
                and projection.get("impact")
            ):
                four_block_rows += 1
            fh.write(json.dumps(projection, sort_keys=True) + "\n")
            projected_rows += 1
    return {
        "schema": "auditooor.causal_chain_strict_projection_summary.v1",
        "path": path.as_posix(),
        "row_count": projected_rows,
        "four_block_rows": four_block_rows,
        "projection_status": "compatibility_projection",
        "warning_counts": dict(sorted(warning_counts.items())),
        "block_order": ["entry_point", "mutations", "invariant_violation", "impact"],
        "strict_boundary": (
            "Projection is derived from existing compact causal-chain rows. It creates "
            "the section-10 four-block shape for review/R43 wiring, but warnings mark "
            "fields that still need source-grounded hand verification."
        ),
    }


def write_report(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    quality: dict[str, Any] | None = None,
    extracted_rows: int | None = None,
    reverse_lookup: dict[str, Any] | None = None,
    strict_projection: dict[str, Any] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tiers: dict[str, int] = {}
    for row in rows:
        tiers[row["verification_tier"]] = tiers.get(row["verification_tier"], 0) + 1
    quality = quality or {}
    lines = [
        "# P2 Causal Chain MVP Run",
        "",
        f"- schema: `{SCHEMA_VERSION}`",
        f"- extracted rows (pre-gate): {extracted_rows if extracted_rows is not None else len(rows)}",
        f"- rows: {len(rows)}",
        f"- quality profile: `{quality.get('profile', 'none')}`",
        f"- quality acceptance ratio: {quality.get('acceptance_ratio', 1.0)}",
        f"- verification tiers: {json.dumps(tiers, sort_keys=True)}",
        "",
        "## Quality Gate",
        "",
    ]
    requirements = quality.get("requirements") or []
    if requirements:
        lines.extend(f"- {requirement}" for requirement in requirements)
    else:
        lines.append("- no quality gate requirements (`none` profile)")
    rejected = quality.get("rejected_by_reason") or {}
    lines.append(f"- rejected rows: {quality.get('rejected_rows', 0)}")
    if rejected:
        lines.append(f"- rejected by reason: {json.dumps(rejected, sort_keys=True)}")
    if reverse_lookup:
        lines.extend(
            [
                "",
                "## Reverse Lookup SQLite",
                "",
                f"- path: `{reverse_lookup.get('path', '')}`",
                f"- chains_by_prefix_2 rows: {reverse_lookup.get('chains_by_prefix_2_rows', 0)}",
                f"- chains_by_prefix_3 rows: {reverse_lookup.get('chains_by_prefix_3_rows', 0)}",
                f"- chains_by_state_field rows: {reverse_lookup.get('chains_by_state_field_rows', 0)}",
            ]
        )
    if strict_projection:
        lines.extend(
            [
                "",
                "## Strict Four-Block Projection",
                "",
                f"- path: `{strict_projection.get('path', '')}`",
                f"- projected rows: {strict_projection.get('row_count', 0)}",
                f"- four-block rows: {strict_projection.get('four_block_rows', 0)}",
                f"- projection status: `{strict_projection.get('projection_status', '')}`",
                f"- warnings: {json.dumps(strict_projection.get('warning_counts', {}), sort_keys=True)}",
                f"- boundary: {strict_projection.get('strict_boundary', '')}",
            ]
        )
    lines.extend(
        [
            "",
        "## Sample Rows",
        "",
        ]
    )
    for row in rows[:10]:
        lines.append(f"- `{row['chain_id']}` from `{row['source_record_id']}`: {row['trigger']}")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def build_index(
    rows: list[dict[str, Any]],
    *,
    quality: dict[str, Any] | None = None,
    extracted_rows: int | None = None,
    reverse_lookup: dict[str, Any] | None = None,
    strict_projection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    by_tier: dict[str, int] = {}
    by_language: dict[str, int] = {}
    by_domain: dict[str, int] = {}
    chain_refs: dict[str, dict[str, str]] = {}
    for row in rows:
        by_tier[row["verification_tier"]] = by_tier.get(row["verification_tier"], 0) + 1
        language = row.get("target_language") or "unknown"
        domain = row.get("target_domain") or "unknown"
        by_language[language] = by_language.get(language, 0) + 1
        by_domain[domain] = by_domain.get(domain, 0) + 1
        chain_refs[row["chain_id"]] = {
            "source_record_id": row["source_record_id"],
            "verification_tier": row["verification_tier"],
        }
    quality = quality or {"profile": "none", "requirements": []}
    accepted_rows = len(rows)
    scanned_rows = int(quality.get("scanned_rows") or extracted_rows or accepted_rows)
    quality_met = False
    if quality.get("profile") == "none":
        quality_met = accepted_rows > 0
    else:
        quality_met = accepted_rows >= 100
    return {
        "schema_version": f"{SCHEMA_VERSION}.index",
        "schema": "auditooor.causal_chain_index.v1",
        "row_count": len(rows),
        "extracted_row_count": extracted_rows if extracted_rows is not None else scanned_rows,
        "by_verification_tier": dict(sorted(by_tier.items())),
        "by_target_language": dict(sorted(by_language.items())),
        "by_target_domain": dict(sorted(by_domain.items())),
        "quality_gate": {
            "schema_version": "auditooor.causal_chain_quality_gate.v1",
            "profile": quality.get("profile", "none"),
            "requirements": quality.get("requirements") or [],
            "scanned_rows": scanned_rows,
            "accepted_rows": accepted_rows,
            "rejected_rows": int(quality.get("rejected_rows") or max(scanned_rows - accepted_rows, 0)),
            "rejected_by_reason": quality.get("rejected_by_reason") or {},
            "acceptance_ratio": quality.get("acceptance_ratio"),
            "target_records": 100,
            "met": quality_met,
        },
        "reverse_lookup": reverse_lookup or {},
        "strict_projection": strict_projection or {},
        "chains": chain_refs,
    }


def write_index(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    quality: dict[str, Any] | None = None,
    extracted_rows: int | None = None,
    reverse_lookup: dict[str, Any] | None = None,
    strict_projection: dict[str, Any] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_index(
        rows,
        quality=quality,
        extracted_rows=extracted_rows,
        reverse_lookup=reverse_lookup,
        strict_projection=strict_projection,
    )
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_reverse_lookup_sqlite(path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE chains_by_prefix_2 (
              entry_signature_norm TEXT NOT NULL,
              mutation_0_norm TEXT NOT NULL,
              chain_id TEXT NOT NULL,
              severity TEXT,
              impact_class TEXT,
              violation_step INT,
              recoverable BOOL,
              PRIMARY KEY (entry_signature_norm, mutation_0_norm, chain_id)
            );
            CREATE TABLE chains_by_prefix_3 (
              entry_signature_norm TEXT NOT NULL,
              mutation_0_norm TEXT NOT NULL,
              mutation_1_norm TEXT NOT NULL,
              chain_id TEXT NOT NULL,
              severity TEXT,
              impact_class TEXT,
              violation_step INT,
              recoverable BOOL,
              PRIMARY KEY (entry_signature_norm, mutation_0_norm, mutation_1_norm, chain_id)
            );
            CREATE TABLE chains_by_state_field (
              state_field_norm TEXT NOT NULL,
              chain_id TEXT NOT NULL,
              step INT NOT NULL,
              PRIMARY KEY (state_field_norm, chain_id, step)
            );
            CREATE INDEX idx_chains_by_prefix_2_chain_id
              ON chains_by_prefix_2(chain_id);
            CREATE INDEX idx_chains_by_prefix_3_chain_id
              ON chains_by_prefix_3(chain_id);
            CREATE INDEX idx_chains_by_state_field_chain_id
              ON chains_by_state_field(chain_id);
            """
        )
        prefix2_rows = 0
        prefix3_rows = 0
        state_rows = 0
        source_rows = 0
        for row in rows:
            chain_id = compact_text(row.get("chain_id"))
            if not chain_id:
                continue
            entry_signature = entry_signature_for_row(row)
            mutation_texts = mutation_texts_for_row(row)
            severity = impact_field(row, "severity_at_finding")
            impact_class = impact_field(row, "impact_class") or impact_field(row, "summary")
            violation_step = violation_step_for_row(row)
            recoverable = recoverable_for_row(row)
            if entry_signature and mutation_texts:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO chains_by_prefix_2
                    (entry_signature_norm, mutation_0_norm, chain_id, severity, impact_class, violation_step, recoverable)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry_signature,
                        mutation_texts[0],
                        chain_id,
                        severity,
                        impact_class,
                        violation_step,
                        recoverable,
                    ),
                )
                if conn.total_changes > prefix2_rows + prefix3_rows + state_rows:
                    prefix2_rows += 1
            if entry_signature and len(mutation_texts) >= 2:
                before = conn.total_changes
                conn.execute(
                    """
                    INSERT OR IGNORE INTO chains_by_prefix_3
                    (entry_signature_norm, mutation_0_norm, mutation_1_norm, chain_id, severity, impact_class, violation_step, recoverable)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry_signature,
                        mutation_texts[0],
                        mutation_texts[1],
                        chain_id,
                        severity,
                        impact_class,
                        violation_step,
                        recoverable,
                    ),
                )
                if conn.total_changes > before:
                    prefix3_rows += 1
            for step, mutation_text in enumerate(mutation_texts, 1):
                before = conn.total_changes
                conn.execute(
                    """
                    INSERT OR IGNORE INTO chains_by_state_field
                    (state_field_norm, chain_id, step)
                    VALUES (?, ?, ?)
                    """,
                    (mutation_text, chain_id, step),
                )
                if conn.total_changes > before:
                    state_rows += 1
            source_rows += 1
        conn.commit()

    return {
        "schema": "auditooor.causal_chain_reverse_lookup_sqlite.v1",
        "path": path.as_posix(),
        "source_row_count": source_rows,
        "chains_by_prefix_2_rows": prefix2_rows,
        "chains_by_prefix_3_rows": prefix3_rows,
        "chains_by_state_field_rows": state_rows,
        "tables": [
            "chains_by_prefix_2",
            "chains_by_prefix_3",
            "chains_by_state_field",
        ],
        "projection_note": (
            "Uses strict entry_point/mutations fields when present; compact MVP rows "
            "fall back to target_component plus produces_state/requires_state tokens. "
            "This materializes the reverse lookup tables without claiming full four-block "
            "R43 projection coverage."
        ),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--index-json", type=Path, default=None)
    parser.add_argument(
        "--reverse-sqlite",
        type=Path,
        default=None,
        help=(
            "Write the three-table reverse lookup SQLite index. "
            "Canonical runs default to audit/corpus_tags/derived/causal_chain_reverse_lookup.sqlite."
        ),
    )
    parser.add_argument(
        "--no-reverse-sqlite",
        action="store_true",
        help="Disable the default canonical reverse lookup SQLite output.",
    )
    parser.add_argument(
        "--strict-projection-output",
        type=Path,
        default=None,
        help=(
            "Write a section-10 four-block compatibility projection JSONL. "
            "Canonical runs default to audit/corpus_tags/derived/causal_chain_strict_projection.jsonl."
        ),
    )
    parser.add_argument(
        "--no-strict-projection",
        action="store_true",
        help="Disable the default canonical strict projection sidecar.",
    )
    parser.add_argument(
        "--strict-projection-limit",
        type=int,
        default=None,
        help="Limit rows written to the strict projection sidecar.",
    )
    parser.add_argument("--report-md", type=Path, default=None)
    parser.add_argument("--canonical", action="store_true")
    parser.add_argument("--quality-profile", choices=QUALITY_PROFILES, default="none")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    inputs = args.input or [DEFAULT_INPUT]
    if args.canonical:
        output_path = args.output or DEFAULT_CANONICAL_OUTPUT
        index_path = args.index_json or DEFAULT_CANONICAL_INDEX
        report_path = args.report_md or DEFAULT_REPORT
        reverse_sqlite_path = args.reverse_sqlite
        if reverse_sqlite_path is None and not args.no_reverse_sqlite:
            reverse_sqlite_path = DEFAULT_CANONICAL_REVERSE_SQLITE
        strict_projection_path = args.strict_projection_output
        if strict_projection_path is None and not args.no_strict_projection:
            strict_projection_path = DEFAULT_CANONICAL_STRICT_PROJECTION
    else:
        output_path = args.output
        index_path = args.index_json
        report_path = args.report_md
        reverse_sqlite_path = None if args.no_reverse_sqlite else args.reverse_sqlite
        strict_projection_path = None if args.no_strict_projection else args.strict_projection_output

    if args.canonical and args.quality_profile == "none":
        args.quality_profile = "canonical"

    records = load_records(inputs)
    extracted_rows = build_chains(records, limit=None)
    rows, quality = apply_quality_gate(extracted_rows, profile=args.quality_profile, limit=args.limit)

    if output_path:
        write_jsonl(output_path, rows)
    else:
        for row in rows:
            if args.pretty:
                print(json.dumps(row, indent=2, sort_keys=True))
            else:
                print(json.dumps(row, sort_keys=True))

    reverse_lookup = None
    if reverse_sqlite_path:
        reverse_lookup = write_reverse_lookup_sqlite(reverse_sqlite_path, rows)

    strict_projection = None
    if strict_projection_path:
        strict_projection = write_strict_projection_jsonl(
            strict_projection_path,
            rows,
            limit=args.strict_projection_limit,
        )

    if report_path:
        write_report(
            report_path,
            rows,
            quality=quality,
            extracted_rows=len(extracted_rows),
            reverse_lookup=reverse_lookup,
            strict_projection=strict_projection,
        )
    if index_path:
        write_index(
            index_path,
            rows,
            quality=quality,
            extracted_rows=len(extracted_rows),
            reverse_lookup=reverse_lookup,
            strict_projection=strict_projection,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
