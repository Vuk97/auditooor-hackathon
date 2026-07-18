#!/usr/bin/env python3
"""Rank Hackerman corpus records that may compose into chained exploits."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import iter_corpus_record_paths  # noqa: E402

DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
SCHEMA = "auditooor.hackerman.chain_candidates.v1"
HACKERMAN_SCHEMA = "auditooor.hackerman_record.v1"
MAX_LIMIT = 100
MAX_RECORDS_PER_CANDIDATE = 6
MAX_PATTERNS_PER_CANDIDATE = 12
MAX_PROOF_OBLIGATIONS_PER_CANDIDATE = 10
GENERIC_COMPONENT_ANCHORS = {
    "",
    "evm",
    "unknown-component",
    "synthetic-from-regex",
}
GENERIC_FUNCTION_ANCHORS = {
    "",
    "evm",
    "function-evm",
    "txt",
    "md",
    "pdf",
}


def yaml_load(text: str) -> Any:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except Exception as exc:  # pragma: no cover - depends on local dependency set
        raise RuntimeError("PyYAML is required to read Hackerman tag YAML files") from exc


def slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")


def stable_hash(payload: Any, length: int = 16) -> str:
    data = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:length]


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _compact_text(value: Any, max_len: int = 220) -> str:
    text = re.sub(r"\s+", " ", _text(value))
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "..."


def _first_mapping(items: Any) -> dict[str, Any]:
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                return item
    return {}


def _severity_weight(value: str) -> float:
    return {
        "critical": 5.0,
        "high": 4.0,
        "medium": 2.5,
        "low": 1.0,
        "info": 0.25,
    }.get(slug(value), 0.5)


def _outcome_weight(value: str) -> float:
    outcome = _text(value).upper()
    if outcome in {"ACCEPTED", "FILED", "SUBMITTED"}:
        return 1.0
    if outcome in {"CANDIDATE", "STAGING"}:
        return 0.25
    if outcome in {"REJECTED", "DUPLICATE", "NOT_A_BUG", "OOS", "DROPPED"}:
        return -0.75
    return 0.0


def _quality_weight(record: dict[str, Any]) -> float:
    try:
        return float(record.get("record_quality_score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _repo_is_specific(repo: str) -> bool:
    lowered = repo.lower()
    return bool(repo) and lowered not in {"unknown", "unknown/dsl-synthetic", "unknown/unknown"}


def _workspace_from_source(source_ref: str, tag_file: str) -> str:
    text = source_ref or tag_file
    for prefix in ("prior-audit:", "audit:"):
        if text.startswith(prefix):
            rest = text[len(prefix) :]
            return slug(rest.split(":", 1)[0])
    if text.startswith("staging_"):
        return slug(text[len("staging_") :].split("-", 1)[0])
    if text.startswith("prior-audit-"):
        rest = text[len("prior-audit-") :]
        return slug(rest.split("-", 1)[0])
    if text.startswith("git-mining-"):
        parts = text.split("-")
        if len(parts) >= 4:
            return slug(parts[2])
    return ""


def _function_name_from_signature(signature: str) -> str:
    sig = _text(signature)
    if not sig:
        return ""
    patterns = (
        r"\bfunction-name-hint:\s*([A-Za-z_$][A-Za-z0-9_$]*)",
        r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    )
    for pattern in patterns:
        match = re.search(pattern, sig)
        if match:
            return match.group(1)
    regex_alternation = re.match(r"^\^\(([^)]+)\)", sig)
    if regex_alternation:
        return regex_alternation.group(1).split("|", 1)[0]
    dotted = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:\(|$)", sig)
    return dotted.group(1) if dotted else ""


def _component_anchor(record: dict[str, Any], first_site: dict[str, Any]) -> str:
    component = _text(record.get("target_component")) or _text(first_site.get("file_path"))
    if not component:
        return "unknown-component"
    return slug(component)


def _function_anchor(record: dict[str, Any], first_site: dict[str, Any]) -> str:
    function_shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    raw_signature = _text(function_shape.get("raw_signature")) or _text(first_site.get("function_signature"))
    explicit = _text(first_site.get("function_name"))
    name = explicit if explicit and not explicit.startswith("(") else _function_name_from_signature(raw_signature)
    if name:
        return slug(name)
    if raw_signature:
        return slug(raw_signature)[:80]
    return ""


def _attack_classes(record: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for field in ("attack_class", "attack_classes", "attack_classes_to_try"):
        values.extend(_as_list(record.get(field)))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _text(value)
        key = slug(text)
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _pattern_tags(record: dict[str, Any], first_site: dict[str, Any]) -> list[str]:
    patterns: list[Any] = []
    function_shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    patterns.extend(_as_list(function_shape.get("shape_tags")))
    for field in ("pattern", "pattern_id", "detector_slug", "extraction_provenance"):
        patterns.extend(_as_list(record.get(field)))
    verdict_id = _text(record.get("verdict_id") or record.get("record_id"))
    if verdict_id.startswith("dsl_pattern/"):
        patterns.append(verdict_id.split("/", 1)[1])
    for field in ("shape_hash", "shape_hash_fine"):
        value = _text(first_site.get(field))
        if value:
            patterns.append(f"{field}:{value}")
    out: list[str] = []
    seen: set[str] = set()
    for value in patterns:
        text = _text(value)
        key = slug(text)
        if text and key not in seen:
            seen.add(key)
            out.append(text)
    return out


@dataclass(frozen=True)
class ChainRecord:
    tag_file: str
    record_id: str
    source_ref: str
    repo: str
    workspace: str
    scope_type: str
    scope: str
    language: str
    component_anchor: str
    function_anchor: str
    bug_class: str
    attack_classes: tuple[str, ...]
    patterns: tuple[str, ...]
    severity: str
    impact_class: str
    quality: float
    outcome: str
    action_summary: str
    attacker_role: str = ""
    required_preconditions: tuple[str, ...] = ()
    proof_artifact_path: str = ""

    def brief(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "tag_file": self.tag_file,
            "source_ref": self.source_ref,
            "target_language": self.language,
            "bug_class": self.bug_class,
            "attack_classes": list(self.attack_classes),
            "patterns": list(self.patterns[:4]),
            "severity": self.severity,
            "impact_class": self.impact_class,
        }


def normalize_record(path: Path, doc: dict[str, Any], tag_file: str | None = None) -> ChainRecord | None:
    first_site = _first_mapping(doc.get("sites"))
    record_id = _text(doc.get("record_id") or doc.get("verdict_id") or path.stem)
    if not record_id:
        return None
    source_ref = _text(doc.get("source_audit_ref") or doc.get("verdict_id") or record_id)
    repo = _text(doc.get("target_repo"))
    workspace = _workspace_from_source(source_ref, path.name)
    if _repo_is_specific(repo):
        scope_type = "repo"
        scope = repo
    elif workspace:
        scope_type = "workspace"
        scope = workspace
    else:
        scope_type = "repo"
        scope = repo or "unknown"
    attack_classes = tuple(_attack_classes(doc))
    patterns = tuple(_pattern_tags(doc, first_site))
    bug_class = _text(doc.get("bug_class"))
    if not (bug_class or attack_classes or patterns):
        return None
    severity = _text(doc.get("severity_at_finding") or doc.get("severity_final") or doc.get("severity_claimed"))
    outcome = _text(doc.get("triager_outcome") or doc.get("verdict_class"))
    return ChainRecord(
        tag_file=tag_file or path.name,
        record_id=record_id,
        source_ref=source_ref,
        repo=repo or "unknown",
        workspace=workspace,
        scope_type=scope_type,
        scope=scope,
        language=_text(doc.get("target_language") or doc.get("language")),
        component_anchor=_component_anchor(doc, first_site),
        function_anchor=_function_anchor(doc, first_site),
        bug_class=bug_class,
        attack_classes=attack_classes,
        patterns=patterns,
        severity=severity,
        impact_class=_text(doc.get("impact_class")),
        quality=_quality_weight(doc),
        outcome=outcome,
        action_summary=_text(doc.get("attacker_action_sequence") or doc.get("notes"))[:280],
        attacker_role=_text(doc.get("attacker_role")),
        required_preconditions=tuple(
            _compact_text(value)
            for value in _as_list(doc.get("required_preconditions"))
            if _compact_text(value)
        ),
        proof_artifact_path=_text(doc.get("proof_artifact_path")),
    )


def load_records(tag_dir: Path) -> tuple[list[ChainRecord], list[dict[str, str]]]:
    records: list[ChainRecord] = []
    skipped: list[dict[str, str]] = []
    for item in iter_corpus_record_paths(tag_dir):
        path = item.path
        try:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            skipped.append({"tag_file": path.name, "reason": f"yaml_parse_error: {exc}"})
            continue
        if not isinstance(doc, dict):
            skipped.append({"tag_file": path.name, "reason": "top_level_not_mapping"})
            continue
        record = normalize_record(path, doc, tag_file=item.relative_path)
        if record is None:
            skipped.append({"tag_file": path.name, "reason": "missing_chain_signals"})
            continue
        records.append(record)
    return records, skipped


def bucket_keys(record: ChainRecord) -> list[tuple[str, str, str, str, str]]:
    base = (record.scope_type, record.scope, record.component_anchor)
    keys = [(base[0], base[1], base[2], "", "component")]
    if record.function_anchor:
        keys.append((base[0], base[1], base[2], record.function_anchor, "function"))
    return keys


def _sorted_slugs(values: Iterable[str]) -> list[str]:
    return sorted({slug(value) for value in values if slug(value)})


def _candidate_signal_sets(records: list[ChainRecord]) -> tuple[list[str], list[str], list[str]]:
    bug_families = _sorted_slugs(record.bug_class for record in records)
    attack_classes = _sorted_slugs(cls for record in records for cls in record.attack_classes)
    patterns = _sorted_slugs(pattern for record in records for pattern in record.patterns)
    return bug_families, attack_classes, patterns


def _composable(records: list[ChainRecord]) -> bool:
    if len(records) < 2:
        return False
    bug_families, attack_classes, patterns = _candidate_signal_sets(records)
    return max(len(bug_families), len(attack_classes), len(patterns)) >= 2


def _record_strength(record: ChainRecord) -> float:
    return (
        _severity_weight(record.severity)
        + _outcome_weight(record.outcome)
        + min(record.quality, 5.0) * 0.35
        + (0.25 if record.language else 0.0)
    )


def _proof_key(obligation: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(obligation.get("kind") or ""),
        str(obligation.get("record_id") or ""),
        slug(obligation.get("obligation") or ""),
    )


def _build_proof_obligations(
    records: list[ChainRecord],
    *,
    scope: str,
    component: str,
    function: str,
    anchor_level: str,
) -> list[dict[str, Any]]:
    anchor = f"{scope}/{component}" + (f"/{function}" if function else "")
    obligations: list[dict[str, Any]] = [
        {
            "kind": "chain_ordering",
            "record_id": "",
            "source_ref": "",
            "obligation": (
                "Demonstrate an ordered exploit path where at least two records "
                "compose through producer/consumer state; co-location on the "
                f"{anchor_level} anchor `{anchor}` is not sufficient."
            ),
            "evidence_hint": "source-level control/data-flow trace or executable harness assertion",
            "submission_gate": "required_before_submission",
        },
        {
            "kind": "anchor_reachability",
            "record_id": "",
            "source_ref": "",
            "obligation": (
                f"Map `{anchor}` to audited source lines and show the path is reachable "
                "by the claimed attacker role in the target under review."
            ),
            "evidence_hint": "file:line citation plus caller/permission trace",
            "submission_gate": "required_before_submission",
        },
    ]
    for record in sorted(records, key=lambda item: (-_record_strength(item), item.record_id)):
        where = record.function_anchor or record.component_anchor
        for precondition in record.required_preconditions:
            obligations.append(
                {
                    "kind": "record_precondition",
                    "record_id": record.record_id,
                    "source_ref": record.source_ref,
                    "obligation": (
                        f"Prove analogue precondition for `{record.record_id}` at `{where}`: "
                        f"{precondition}"
                    ),
                    "evidence_hint": "target-specific source trace, state setup, or harness assertion",
                    "submission_gate": "required_before_submission",
                }
            )
        if record.proof_artifact_path:
            obligations.append(
                {
                    "kind": "proof_artifact",
                    "record_id": record.record_id,
                    "source_ref": record.source_ref,
                    "obligation": (
                        f"Verify proof artifact path `{record.proof_artifact_path}` still maps "
                        f"to the target code path for `{record.record_id}`."
                    ),
                    "evidence_hint": "checked-in artifact path plus command or source citation",
                    "submission_gate": "required_before_submission",
                }
            )
        if not record.required_preconditions and record.action_summary and record.action_summary.lower() != "tbd":
            obligations.append(
                {
                    "kind": "action_trace",
                    "record_id": record.record_id,
                    "source_ref": record.source_ref,
                    "obligation": (
                        f"Translate analogue action for `{record.record_id}` into a target-specific "
                        f"trace: {_compact_text(record.action_summary, 180)}"
                    ),
                    "evidence_hint": "minimal transaction/call sequence or code-path walkthrough",
                    "submission_gate": "required_before_submission",
                }
            )

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for obligation in obligations:
        key = _proof_key(obligation)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(obligation)
        if len(deduped) >= MAX_PROOF_OBLIGATIONS_PER_CANDIDATE:
            break
    return deduped


def _proof_actionability_score(obligations: list[dict[str, Any]]) -> float:
    weights = {
        "chain_ordering": 1.0,
        "anchor_reachability": 1.0,
        "record_precondition": 1.2,
        "proof_artifact": 1.4,
        "action_trace": 0.7,
    }
    return round(sum(weights.get(str(item.get("kind")), 0.5) for item in obligations), 3)


def build_candidate(
    key: tuple[str, str, str, str, str],
    records: list[ChainRecord],
    *,
    include_generic: bool = False,
) -> dict[str, Any] | None:
    scope_type, scope, component, function, anchor_level = key
    if not include_generic and _is_generic_candidate(scope, component, function):
        return None
    if scope == "unknown/dsl-synthetic":
        return None
    if scope == "unknown" and component.endswith("unknown-component") and anchor_level == "component":
        return None
    if component == "synthetic-from-regex" and function in {"", "synthetic"}:
        return None
    if not _composable(records):
        return None
    records = sorted(records, key=lambda record: record.record_id)
    bug_families, attack_classes, patterns = _candidate_signal_sets(records)
    languages = _sorted_slugs(record.language for record in records)
    impacts = _sorted_slugs(record.impact_class for record in records)
    severities = _sorted_slugs(record.severity for record in records)
    diversity_score = len(bug_families) * 1.4 + len(attack_classes) * 1.6 + min(len(patterns), 8) * 0.45
    strength_score = sum(_record_strength(record) for record in records) / max(len(records), 1)
    specificity_score = 2.0 if anchor_level == "function" else 1.0
    count_score = min(len(records), 6) * 0.65
    impact_score = len(impacts) * 0.35
    score = round(diversity_score + strength_score * 0.75 + specificity_score + count_score + impact_score, 3)
    record_ids = [record.record_id for record in records]
    candidate_id = f"chain:{stable_hash({'key': key, 'records': record_ids}, 12)}"
    primary_classes = attack_classes[:3] or bug_families[:3] or patterns[:3]
    rationale = (
        f"{anchor_level} anchor {scope}/{component}"
        + (f"/{function}" if function else "")
        + f" has {len(records)} records spanning "
        + ", ".join(primary_classes)
        + "; validate whether their preconditions can be ordered into one exploit path."
    )
    steps: list[str] = []
    for record in sorted(records, key=lambda item: (-_record_strength(item), item.record_id))[:4]:
        label = record.bug_class or (record.attack_classes[0] if record.attack_classes else "pattern")
        where = record.function_anchor or record.component_anchor
        steps.append(f"Probe {label} at {where} using {record.record_id} as the analogue.")
    proof_obligations = _build_proof_obligations(
        records,
        scope=scope,
        component=component,
        function=function,
        anchor_level=anchor_level,
    )
    return {
        "candidate_id": candidate_id,
        "score": score,
        "submission_posture": "candidate_not_submit_ready",
        "actionability_score": _proof_actionability_score(proof_obligations),
        "group": {
            "anchor_level": anchor_level,
            "scope_type": scope_type,
            "scope": scope,
            "component_anchor": component,
            "function_anchor": function,
        },
        "record_count": len(records),
        "bug_families": bug_families,
        "attack_classes": attack_classes,
        "patterns": patterns[:MAX_PATTERNS_PER_CANDIDATE],
        "patterns_omitted": max(0, len(patterns) - MAX_PATTERNS_PER_CANDIDATE),
        "target_languages": languages,
        "impact_classes": impacts,
        "severities": severities,
        "records": [record.brief() for record in records[:MAX_RECORDS_PER_CANDIDATE]],
        "records_omitted": max(0, len(records) - MAX_RECORDS_PER_CANDIDATE),
        "chain_rationale": rationale,
        "suggested_validation_steps": steps,
        "proof_obligations": proof_obligations,
        "proof_obligations_omitted": max(
            0,
            (
                2
                + sum(
                    len(record.required_preconditions)
                    + (1 if record.proof_artifact_path else 0)
                    + (
                        1
                        if not record.required_preconditions
                        and record.action_summary
                        and record.action_summary.lower() != "tbd"
                        else 0
                    )
                    for record in records
                )
            )
            - len(proof_obligations),
        ),
        "not_submit_ready_until": [
            "all proof_obligations have source-level citations or executable assertions",
            "the chain_ordering obligation shows producer/consumer state composition across records",
        ],
    }


def _is_generic_candidate(scope: str, component: str, function: str) -> bool:
    if scope not in {"unknown", "unknown/dsl-synthetic", "unknown/unknown"}:
        return False
    if component in GENERIC_COMPONENT_ANCHORS:
        return True
    if component.endswith((".txt", ".md", ".pdf")):
        return True
    return function in GENERIC_FUNCTION_ANCHORS


def build_candidates(
    records: list[ChainRecord],
    limit: int,
    *,
    include_generic: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    buckets: dict[tuple[str, str, str, str, str], dict[str, ChainRecord]] = {}
    for record in records:
        for key in bucket_keys(record):
            buckets.setdefault(key, {})[record.record_id] = record

    raw: list[dict[str, Any]] = []
    for key, bucket in sorted(buckets.items(), key=lambda item: item[0]):
        candidate = build_candidate(key, list(bucket.values()), include_generic=include_generic)
        if candidate is not None:
            raw.append(candidate)

    # The same member set can appear in both component and function buckets.
    # Keep the higher-scoring, more specific candidate for that member set.
    by_members: dict[tuple[str, ...], dict[str, Any]] = {}
    for candidate in raw:
        members = tuple(sorted(str(record["record_id"]) for record in candidate["records"]))
        existing = by_members.get(members)
        if existing is None:
            by_members[members] = candidate
            continue
        existing_level = 1 if existing["group"]["anchor_level"] == "function" else 0
        new_level = 1 if candidate["group"]["anchor_level"] == "function" else 0
        if (candidate["score"], new_level, candidate["candidate_id"]) > (
            existing["score"],
            existing_level,
            existing["candidate_id"],
        ):
            by_members[members] = candidate

    candidates = list(by_members.values())
    candidates.sort(
        key=lambda item: (
            -float(item["score"]),
            -int(item["record_count"]),
            item["group"]["scope"],
            item["group"]["component_anchor"],
            item["group"]["function_anchor"],
            item["candidate_id"],
        )
    )
    for rank, candidate in enumerate(candidates, start=1):
        candidate["rank"] = rank
    return candidates[:limit], len(buckets)


def clamp_limit(value: int) -> int:
    return max(0, min(int(value), MAX_LIMIT))


def build_payload(tag_dir: Path, limit: int, *, include_generic: bool = False) -> dict[str, Any]:
    records, skipped = load_records(tag_dir)
    candidates, groups_considered = build_candidates(records, limit, include_generic=include_generic)
    digest = stable_hash(
        {
            "schema": SCHEMA,
            "tag_dir": str(tag_dir),
            "records": [record.record_id for record in records],
            "candidates": [(candidate["candidate_id"], candidate["score"]) for candidate in candidates],
        },
        64,
    )
    return {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "source_tag_dir": str(tag_dir),
        "total_records_loaded": len(records),
        "total_files_skipped": len(skipped),
        "skipped_sample": skipped[:20],
        "groups_considered": groups_considered,
        "include_generic": include_generic,
        "total_candidates": len(candidates),
        "limit": limit,
        "candidates": candidates,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Hackerman Chained Exploit Candidates",
        "",
        f"- Schema: `{payload['schema']}`",
        f"- Source tag dir: `{payload['source_tag_dir']}`",
        f"- Records loaded: {payload['total_records_loaded']}",
        f"- Groups considered: {payload['groups_considered']}",
        f"- Candidates emitted: {payload['total_candidates']}",
        "",
        "These are offline corpus-derived leads. Treat each as a hypothesis until source-level control/data-flow proves the records compose.",
        "",
        "## What changed",
        "",
        "- Added `tools/hackerman-chain-candidates.py`, an offline CLI that reads Hackerman v1 and legacy verdict-tag YAMLs, normalizes repo/workspace/component/function-ish anchors, and ranks only multi-signal groups as chained exploit candidates.",
        "- Broad `unknown/evm` and text-file buckets are filtered by default; pass `--include-generic` when intentionally inspecting noisy corpus-mined anchors.",
        "- Candidate output includes proof obligations and explicit `candidate_not_submit_ready` posture so co-location is not mistaken for a proven chain.",
        "- Added focused unit coverage for ranking, mixed legacy/v1 grouping, and empty-corpus behavior.",
        "",
        "## How to run",
        "",
        "```bash",
        "python3 tools/hackerman-chain-candidates.py --limit 20",
        "python3 tools/hackerman-chain-candidates.py --tag-dir audit/corpus_tags/tags --limit 20 --json",
        "python3 tools/hackerman-chain-candidates.py --limit 20 --include-generic --json",
        "python3 tools/hackerman-chain-candidates.py --limit 20 --out agent_outputs/hackerman_chain_candidates_2026-05-14.md",
        "```",
        "",
        "## Validation",
        "",
        "```bash",
        "python3 -m unittest tools.tests.test_hackerman_chain_candidates",
        "python3 -m py_compile tools/hackerman-chain-candidates.py tools/tests/test_hackerman_chain_candidates.py",
        "```",
    ]
    if not payload.get("candidates"):
        lines.extend(["", "No chained exploit candidates were found."])
        return "\n".join(lines) + "\n"

    for candidate in payload["candidates"]:
        group = candidate["group"]
        anchor = f"{group['scope']}/{group['component_anchor']}"
        if group.get("function_anchor"):
            anchor += f"/{group['function_anchor']}"
        lines.extend(
            [
                "",
                f"## {candidate['rank']}. {candidate['candidate_id']} score={candidate['score']}",
                "",
                f"- Anchor: `{group['anchor_level']}` `{anchor}`",
                f"- Submission posture: `{candidate.get('submission_posture', 'candidate_not_submit_ready')}`",
                f"- Actionability score: {candidate.get('actionability_score', 0)}",
                f"- Records: {candidate['record_count']}",
                f"- Bug families: {', '.join(candidate['bug_families']) or 'n/a'}",
                f"- Attack classes: {', '.join(candidate['attack_classes']) or 'n/a'}",
                f"- Patterns: {', '.join(candidate['patterns']) or 'n/a'}",
                f"- Rationale: {candidate['chain_rationale']}",
                "- Validation steps:",
            ]
        )
        for step in candidate["suggested_validation_steps"]:
            lines.append(f"  - {step}")
        lines.append("- Proof obligations:")
        for obligation in candidate.get("proof_obligations", []):
            record_suffix = f" `{obligation['record_id']}`" if obligation.get("record_id") else ""
            lines.append(
                f"  - [{obligation.get('kind', 'proof')}]"
                f"{record_suffix} {obligation.get('obligation', '')}"
            )
            lines.append(f"    Evidence: {obligation.get('evidence_hint', 'source-level proof')}")
        if candidate.get("proof_obligations_omitted"):
            lines.append(f"  - ... {candidate['proof_obligations_omitted']} more omitted")
        lines.append("- Not submit ready until:")
        for gate in candidate.get("not_submit_ready_until", []):
            lines.append(f"  - {gate}")
        lines.append("- Records:")
        for record in candidate["records"]:
            classes = ", ".join(record.get("attack_classes") or [])
            lines.append(
                f"  - `{record['record_id']}` [{record.get('target_language') or 'unknown'}] "
                f"{record.get('bug_class') or classes or 'pattern'} severity={record.get('severity') or 'unknown'}"
            )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR), help="Directory containing corpus tag YAML files")
    parser.add_argument("--limit", type=int, default=20, help=f"Maximum candidates to emit, capped at {MAX_LIMIT}")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument("--out", default="-", help="Output path, or - for stdout")
    parser.add_argument(
        "--include-generic",
        action="store_true",
        help="Include broad unknown/evm or text-file buckets that are normally filtered as noisy.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tag_dir = Path(args.tag_dir)
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2
    payload = build_payload(tag_dir, clamp_limit(args.limit), include_generic=args.include_generic)
    rendered = (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if args.json
        else render_markdown(payload)
    )
    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
