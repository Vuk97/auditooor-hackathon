#!/usr/bin/env python3
"""global-chain-template-library-build.py - Phase 3 P3.1 deterministic composer.

<!-- r36-rebuttal: pathspec registered via agent-pathspec-register.py for lane LIFT-PHASE-3-CODEX-TAKEOVER -->

DETERMINISTIC chain-template composer (no LLM, no network, stdlib-only).

Reads invariant + predicate + anti-pattern + incident corpora and emits N-tuples
of invariants (pairs, triples, 4-tuples) that compose into a "chain template"
when their members share enough signal (commit-point patterns, target_lang,
co-occurrence in incidents, defense-layer coupling).

Outputs:
    audit/corpus_tags/derived/global_chain_templates.jsonl
    (one chain template per line)
    audit/corpus_tags/derived/global_chain_templates.manifest.json

Schema emitted: auditooor.global_chain_template.v1
Manifest schema: auditooor.global_chain_template_manifest.v1

Composition rules (deterministic, rule-based, NO LLM):
  R1. Group invariants by category + attack_class to form clusters.
  R2. For each candidate tuple (size in 2..max-tuple-size), score by:
        - Shared commit_point_pattern keywords (+0.30 per shared keyword, max +0.60)
        - Shared target_lang (+0.20 if all members share, partial credit otherwise)
        - Cross-incident co-occurrence (+0.10 per incident where >=2 member
          commit_point_pattern keywords appear, max +0.30)
        - Defense-layer coupling (+0.20 if defense_layer keywords overlap, max +0.20)
  R3. Keep tuples whose score >= min-composition-score (default 0.6).
  R4. Emit chain_template_id = sha256(member_invariant_ids sorted)[:16].
  R5. verification_tier = weakest member tier (tier-1 strongest, tier-5 weakest).
  R6. kill_conditions / falsification_requirements = UNION of member fields
        (with deterministic ordering, deduped).
  R7. state_machine = ordered chain: each member produces preconditions for
        the next member (deterministically ordered by invariant_id).

Manual ZetaChain 4-tuple anchor at
    audit/corpus_tags/derived/invariant_library_extended/manual_zetachain_2026-04-26/
is loaded as a separate input source. Its 4 invariants
(INV-BRIDGE-ALLOWANCE-001 + INV-BRIDGE-ARBCALL-001 +
INV-BRIDGE-SELECTOR-DENY-001 + INV-BRIDGE-SENDER-ZEROING-001) form the
ground-truth 4-tuple the composer is expected to (re)produce; the manual
emission is added to the output as a tier-2 anchor regardless of score.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import itertools
import json
import pathlib
import re
import sys
from collections import defaultdict
from typing import Any, Iterable

SCHEMA = "auditooor.global_chain_template.v1"
MANIFEST_SCHEMA = "auditooor.global_chain_template_manifest.v1"

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_INVARIANTS_JSONL = (
    REPO_ROOT / "audit/corpus_tags/derived/invariants_pilot_audited.jsonl"
)

# Tier strength ordering (used to derive weakest-member tier).
TIER_STRENGTH = {
    "tier-1-verified-realtime-api": 1,
    "tier-1-officially-disclosed": 1,
    "tier-2-verified-public-archive": 2,
    "tier-3-synthetic-taxonomy-anchored": 3,
    "tier-4-bundled-fixture": 4,
    "tier-5-quarantine": 5,
}

_SOURCE_REF_RE = re.compile(r"^(.+?):([0-9]+)(?:-[0-9]+)?$")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_ADVISORY_MARKERS = (
    "advisory",
    "advisories",
    "advisory-invariant",
)
_BLOCKED_MARKERS = (
    "blocked",
    "not_submit_ready",
    "not-submit-ready",
    "not submit ready",
    "unresolved",
    "needs-research",
    "needs research",
)
_STALE_MARKERS = (
    "stale",
    "expired",
    "superseded",
)


def _weakest_tier(tiers: Iterable[str]) -> str:
    """Return the WEAKEST (numerically highest) tier from member tiers."""
    valid = [t for t in tiers if t in TIER_STRENGTH]
    if not valid:
        return "tier-3-synthetic-taxonomy-anchored"
    return max(valid, key=lambda t: TIER_STRENGTH[t])


# ---------------------------------------------------------------------------
# Loaders (stdlib-only YAML parsing via a tiny safe subset; we mostly hit JSON)
# ---------------------------------------------------------------------------


def _read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except json.JSONDecodeError:
                continue
    return rows


def _as_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                text = item.strip()
                if text:
                    out.append(text)
            elif isinstance(item, dict):
                for key in ("state", "token", "id", "value"):
                    text = str(item.get(key) or "").strip()
                    if text:
                        out.append(text)
                        break
        return out
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _stringify_status_values(row: dict[str, Any]) -> str:
    content = row.get("content") if isinstance(row.get("content"), dict) else {}
    pieces: list[str] = []
    for obj in (row, content):
        for key in (
            "record_id",
            "schema_version",
            "status",
            "record_status",
            "readiness_status",
            "candidate_status",
            "submission_posture",
            "audit_verdict",
            "verdict",
            "freshness",
            "role",
            "fixture_role",
            "record_role",
            "source_kind",
            "source_type",
            "_source_path",
        ):
            value = obj.get(key)
            if isinstance(value, list):
                pieces.extend(str(item) for item in value)
            elif value is not None:
                pieces.append(str(value))
        tags = obj.get("tags")
        if isinstance(tags, list):
            pieces.extend(str(item) for item in tags)
    return " ".join(pieces).lower().replace("_", "-")


def _has_marker(text: str, markers: Iterable[str]) -> bool:
    normalized = text.lower().replace("_", "-")
    return any(marker.replace("_", "-") in normalized for marker in markers)


def _source_roots(workspace: pathlib.Path | None) -> list[pathlib.Path]:
    roots: list[pathlib.Path] = []
    if workspace is not None:
        roots.append(workspace.expanduser().resolve(strict=False))
    roots.append(REPO_ROOT)
    return roots


def _parse_source_ref(ref: Any) -> tuple[str, int] | None:
    if isinstance(ref, dict):
        raw_path = str(ref.get("path") or ref.get("file") or "").strip()
        raw_line = ref.get("line_start") or ref.get("line") or ref.get("lineno")
        try:
            line = int(raw_line)
        except (TypeError, ValueError):
            line = 0
        if raw_path and line > 0:
            return raw_path, line
        return None
    if not isinstance(ref, str):
        return None
    text = ref.strip()
    if not text:
        return None
    match = _SOURCE_REF_RE.match(text)
    if not match:
        return None
    try:
        line = int(match.group(2))
    except ValueError:
        return None
    if line <= 0:
        return None
    return match.group(1).strip(), line


def _source_ref_resolves(
    raw_path: str,
    line: int,
    *,
    workspace: pathlib.Path | None,
) -> bool:
    if not raw_path or line <= 0 or _URL_RE.match(raw_path):
        return False
    if workspace is None:
        return True
    candidates: list[pathlib.Path] = []
    candidate = pathlib.Path(raw_path).expanduser()
    if candidate.is_absolute():
        candidates.append(candidate)
    else:
        for root in _source_roots(workspace):
            candidates.append(root / raw_path)
    for path in candidates:
        try:
            resolved = path.resolve(strict=False)
        except OSError:
            continue
        if not resolved.is_file():
            continue
        try:
            with resolved.open(encoding="utf-8", errors="ignore") as fh:
                for idx, _line in enumerate(fh, start=1):
                    if idx >= line:
                        return True
        except OSError:
            continue
    return False


def _normalize_source_refs(
    raw_refs: Iterable[Any],
    *,
    workspace: pathlib.Path | None,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for ref in raw_refs:
        parsed = _parse_source_ref(ref)
        if parsed is None:
            continue
        raw_path, line = parsed
        if not _source_ref_resolves(raw_path, line, workspace=workspace):
            continue
        normalized = f"{raw_path}:{line}"
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def _collect_source_ref_candidates(*objs: dict[str, Any]) -> list[Any]:
    out: list[Any] = []
    for obj in objs:
        for key in ("source_refs", "source_ref", "source_paths", "source_path"):
            value = obj.get(key)
            if isinstance(value, list):
                out.extend(value)
            elif value:
                out.append(value)
        state_evidence = obj.get("state_evidence")
        if isinstance(state_evidence, dict):
            out.extend(_collect_source_ref_candidates(state_evidence))
    return out


def _collect_linkage_refs(
    row: dict[str, Any],
    content: dict[str, Any],
    *,
    role: str,
    fallback_refs: list[str],
    workspace: pathlib.Path | None,
) -> list[str]:
    raw_refs: list[Any] = []
    keys = (
        ("producer_source_refs", "producer_source_ref", "producer_linkage", "producer")
        if role == "producer"
        else ("consumer_source_refs", "consumer_source_ref", "consumer_linkage", "consumer")
    )
    for obj in (row, content):
        for key in keys:
            value = obj.get(key)
            if isinstance(value, list):
                raw_refs.extend(value)
            elif isinstance(value, dict):
                raw_refs.extend(_collect_source_ref_candidates(value))
            elif value:
                raw_refs.append(value)
    normalized = _normalize_source_refs(raw_refs, workspace=workspace)
    return normalized or fallback_refs


def _collect_state_tokens(
    row: dict[str, Any],
    content: dict[str, Any],
    *,
    role: str,
) -> list[str]:
    keys = (
        ("produces_state", "producer_state", "produced_state", "output_state")
        if role == "producer"
        else ("requires_state", "consumer_state", "required_state", "input_state")
    )
    linkage_keys = (
        ("producer_linkage", "producer")
        if role == "producer"
        else ("consumer_linkage", "consumer")
    )
    out: list[str] = []
    seen: set[str] = set()
    for obj in (row, content):
        for key in keys:
            for token in _as_text_list(obj.get(key)):
                if token not in seen:
                    seen.add(token)
                    out.append(token)
        state_evidence = obj.get("state_evidence")
        if isinstance(state_evidence, dict):
            for key in keys:
                for token in _as_text_list(state_evidence.get(key)):
                    if token not in seen:
                        seen.add(token)
                        out.append(token)
        for key in linkage_keys:
            value = obj.get(key)
            if not isinstance(value, dict):
                continue
            for nested_key in ("state", "states", "token", "tokens", *keys):
                for token in _as_text_list(value.get(nested_key)):
                    if token not in seen:
                        seen.add(token)
                        out.append(token)
    return out


def _state_key(token: str) -> str:
    text = str(token or "").strip().lower()
    if text.startswith("state:"):
        text = text[len("state:") :]
    return re.sub(r"\s+", " ", text)


def _source_leads(inv: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for key in (
        "source_finding_ids",
        "source_record_ids",
        "lead_ids",
        "finding_ids",
    ):
        out.update(_as_text_list(inv.get(key)))
    for key in ("source_record_id", "lead_id", "finding_id", "record_id"):
        value = inv.get(key)
        if isinstance(value, str) and value.strip():
            out.add(value.strip())
    if not out:
        out.update(_as_text_list(inv.get("source_refs")))
    return out


def _record_rejection_reason(row: dict[str, Any]) -> str | None:
    status_text = _stringify_status_values(row)
    if bool(row.get("advisory_only")) or _has_marker(
        status_text,
        _ADVISORY_MARKERS,
    ):
        return "advisory"
    if (
        bool(row.get("is_stale"))
        or bool(row.get("stale"))
        or _has_marker(status_text, _STALE_MARKERS)
    ):
        return "stale"
    if _has_marker(status_text, _BLOCKED_MARKERS):
        return "blocked"
    if not _as_text_list(row.get("source_refs")):
        return "source-unbacked"
    if (
        not _as_text_list(row.get("produces_state"))
        or not _as_text_list(row.get("requires_state"))
        or not _as_text_list(row.get("producer_source_refs"))
        or not _as_text_list(row.get("consumer_source_refs"))
    ):
        return "missing-producer-consumer-linkage"
    return None


def _is_negative_control_record(row: dict[str, Any]) -> bool:
    content = row.get("content") if isinstance(row.get("content"), dict) else {}
    pieces: list[str] = []
    for obj in (row, content):
        for key in (
            "invariant_id",
            "record_id",
            "bug_class",
            "attack_class",
            "role",
            "fixture_role",
            "record_role",
            "control_type",
            "test_role",
            "audit_verdict",
            "verdict",
            "tags",
        ):
            value = obj.get(key)
            if isinstance(value, list):
                pieces.extend(str(item) for item in value)
            elif value is not None:
                pieces.append(str(value))
    text = " ".join(pieces).lower().replace("_", "-")
    return "negative-control" in text or "negative control" in text


def _normalize_invariant_record(
    row: dict[str, Any],
    *,
    source_path: pathlib.Path | None = None,
    workspace: pathlib.Path | None = None,
) -> dict[str, Any] | None:
    if not isinstance(row, dict) or _is_negative_control_record(row):
        return None
    content = row.get("content") if isinstance(row.get("content"), dict) else {}
    src = content if content else row
    inv_id = str(src.get("invariant_id") or row.get("invariant_id") or "").strip()
    if not inv_id:
        return None
    source_findings = src.get("source_findings") or row.get("source_finding_ids") or []
    if isinstance(source_findings, str):
        source_findings = [source_findings]
    preconditions = src.get("preconditions") or row.get("preconditions") or []
    if isinstance(preconditions, str):
        preconditions = [preconditions]
    raw_source_refs = _collect_source_ref_candidates(row, content)
    source_refs = _normalize_source_refs(raw_source_refs, workspace=workspace)
    produces_state = _collect_state_tokens(row, content, role="producer")
    requires_state = _collect_state_tokens(row, content, role="consumer")
    producer_source_refs = _collect_linkage_refs(
        row,
        content,
        role="producer",
        fallback_refs=source_refs,
        workspace=workspace,
    )
    consumer_source_refs = _collect_linkage_refs(
        row,
        content,
        role="consumer",
        fallback_refs=source_refs,
        workspace=workspace,
    )
    normalized = dict(row)
    normalized.update(
        {
            "invariant_id": inv_id,
            "category": (
                src.get("category")
                or src.get("attack_class")
                or src.get("bug_class")
                or src.get("impact_class")
                or row.get("category")
                or "uncategorized"
            ),
            "statement": (
                src.get("statement")
                or src.get("invariant_text")
                or row.get("statement")
                or ""
            ),
            "target_lang": (
                src.get("target_lang")
                or src.get("target_language")
                or row.get("target_lang")
                or "any"
            ),
            "attack_signature": (
                src.get("attack_signature")
                or src.get("attack_class")
                or src.get("bug_class")
                or row.get("attack_signature")
                or ""
            ),
            "commit_point_pattern": (
                src.get("commit_point_pattern")
                or src.get("missing_upstream_fix")
                or src.get("violation_consequence")
                or src.get("bug_class")
                or row.get("commit_point_pattern")
                or ""
            ),
            "defense_layer": (
                src.get("defense_layer")
                or src.get("missing_upstream_fix")
                or row.get("defense_layer")
                or "advisory-invariant"
            ),
            "verification_tier": (
                row.get("verification_tier")
                or src.get("verification_tier")
                or "tier-2-verified-public-archive"
            ),
            "source_finding_ids": source_findings,
            "preconditions": preconditions,
            "source_refs": source_refs,
            "produces_state": produces_state,
            "requires_state": requires_state,
            "producer_source_refs": producer_source_refs,
            "consumer_source_refs": consumer_source_refs,
        }
    )
    if source_path is not None:
        normalized["_source_path"] = str(source_path)
    return normalized


def _yaml_safe_load(path: pathlib.Path) -> dict[str, Any]:
    """Load YAML using PyYAML if available; fallback to a minimal parser.

    The minimal parser handles top-level scalar keys, simple ``key: value``
    pairs, and lists of strings introduced as ``key:`` followed by ``- item``
    lines - enough for the incident records in this composer.
    """
    if not path.exists():
        return {}
    try:
        import yaml  # type: ignore
        with path.open(encoding="utf-8") as fh:
            obj = yaml.safe_load(fh)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        out: dict[str, Any] = {}
        current_list_key: str | None = None
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.rstrip("\n")
                    if not stripped or stripped.lstrip().startswith("#"):
                        continue
                    if line.startswith("  ") or line.startswith("\t"):
                        m = re.match(r"\s*-\s*(.*)$", stripped)
                        if m and current_list_key is not None:
                            val = m.group(1).strip().strip("'").strip('"')
                            out.setdefault(current_list_key, []).append(val)
                        continue
                    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", stripped)
                    if not m:
                        current_list_key = None
                        continue
                    key, val = m.group(1), m.group(2).strip()
                    if not val:
                        current_list_key = key
                        out[key] = []
                    else:
                        current_list_key = None
                        val = val.strip("'").strip('"')
                        out[key] = val
        except OSError:
            return {}
        return out


def _load_invariants(
    path: pathlib.Path,
    *,
    workspace: pathlib.Path | None = None,
) -> list[dict[str, Any]]:
    rows = _read_jsonl(path)
    # Filter to TRUE-POSITIVE (skip SIBLING duplicates and NEEDS-RESEARCH).
    # Dedupe by invariant_id (source corpus contains duplicate entries from
    # the LLM-sweep + manual-audit round-trips) - keep first occurrence.
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row in rows:
        normalized = _normalize_invariant_record(
            row,
            source_path=path,
            workspace=workspace,
        )
        if normalized is None:
            continue
        row = normalized
        verdict = (row.get("audit_verdict") or "").strip().upper()
        if verdict not in ("TRUE-POSITIVE", ""):
            continue
        inv_id = str(row.get("invariant_id") or "")
        if inv_id and inv_id in seen_ids:
            continue
        if inv_id:
            seen_ids.add(inv_id)
        out.append(row)
    return out


def _load_advisory_invariants(
    pattern: str,
    *,
    workspace: pathlib.Path | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    pattern_path = pathlib.Path(pattern)
    if pattern_path.is_absolute():
        paths = sorted(pattern_path.parent.glob(pattern_path.name))
    else:
        rooted = REPO_ROOT / pattern
        paths = sorted(rooted.parent.glob(rooted.name))
    out: list[dict[str, Any]] = []
    source_paths: list[str] = []
    seen_ids: set[str] = set()
    for path in paths:
        if not path.is_file():
            continue
        source_paths.append(str(path))
        for row in _read_jsonl(path):
            normalized = _normalize_invariant_record(
                row,
                source_path=path,
                workspace=workspace,
            )
            if normalized is None:
                continue
            inv_id = str(normalized.get("invariant_id") or "")
            if inv_id and inv_id in seen_ids:
                continue
            if inv_id:
                seen_ids.add(inv_id)
            out.append(normalized)
    return out, source_paths


def _load_zetachain_anchors(
    extended_dir: pathlib.Path,
    *,
    workspace: pathlib.Path | None = None,
) -> list[dict[str, Any]]:
    """Load the 4 manual ZetaChain INV-BRIDGE-* anchors as invariant records."""
    out: list[dict[str, Any]] = []
    if not extended_dir.is_dir():
        return out
    for yaml_path in sorted(extended_dir.glob("*.yaml")):
        raw = _yaml_safe_load(yaml_path)
        if not raw:
            continue
        content = raw.get("content") or {}
        inv_text = content.get("invariant_text")
        if not isinstance(inv_text, str):
            inv_text = ""
        inv_id = content.get("invariant_id") or raw.get("record_id")
        if not inv_id:
            continue
        source_refs = _normalize_source_refs(
            _collect_source_ref_candidates(raw, content),
            workspace=workspace,
        )
        out.append(
            {
                "invariant_id": inv_id,
                "category": content.get("attack_class")
                    or content.get("bug_class")
                    or "bridge",
                "statement": inv_text,
                "target_lang": content.get("target_language", "solidity"),
                "attack_signature": content.get("attack_class", "bridge"),
                "commit_point_pattern": (
                    str(content.get("attack_class") or "bridge").replace("-", "_")
                ),
                "defense_layer": "bridge-deposit-allowance-and-arbitrary-call-perimeter",
                "verification_tier": raw.get(
                    "verification_tier", "tier-2-verified-public-archive"
                ),
                "source_finding_ids": (content.get("source_findings") or []),
                "source_refs": source_refs,
                "produces_state": _collect_state_tokens(
                    raw,
                    content,
                    role="producer",
                ),
                "requires_state": _collect_state_tokens(
                    raw,
                    content,
                    role="consumer",
                ),
                "producer_source_refs": _collect_linkage_refs(
                    raw,
                    content,
                    role="producer",
                    fallback_refs=source_refs,
                    workspace=workspace,
                ),
                "consumer_source_refs": _collect_linkage_refs(
                    raw,
                    content,
                    role="consumer",
                    fallback_refs=source_refs,
                    workspace=workspace,
                ),
                "_source": "zetachain_manual_anchor",
            }
        )
    return out


def _load_anti_patterns(directory: pathlib.Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not directory.is_dir():
        return out
    for md_path in directory.rglob("*.md"):
        try:
            text = md_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        first_h1 = next(
            (
                line.lstrip("# ").strip()
                for line in text.splitlines()
                if line.startswith("# ")
            ),
            md_path.stem.replace("-", " "),
        )
        try:
            rel_path = str(md_path.relative_to(REPO_ROOT))
        except ValueError:
            rel_path = str(md_path)
        out.append(
            {
                "anti_pattern_id": md_path.stem,
                "title": first_h1,
                "_text": text[:4000],
                "_path": rel_path,
            }
        )
    return out


def _load_incidents(directories: list[pathlib.Path]) -> list[dict[str, Any]]:
    # r36-rebuttal: bugfix-inventory-claude-20260610
    out: list[dict[str, Any]] = []
    for d in directories:
        if not d.is_dir():
            continue
        # Sort rglob results by path string to eliminate filesystem-inode nondeterminism.
        # Without this, --max-incidents truncation can produce different evidence_incidents
        # across identical runs depending on OS directory iteration order.
        for yaml_path in sorted(d.rglob("*.yaml"), key=lambda p: str(p)):
            raw = _yaml_safe_load(yaml_path)
            if not raw or not isinstance(raw, dict):
                continue
            try:
                rel_path = str(yaml_path.relative_to(REPO_ROOT))
            except ValueError:
                rel_path = str(yaml_path)
            out.append(
                {
                    "incident_id": raw.get("record_id") or yaml_path.stem,
                    "attack_class": (raw.get("attack_class") or "").strip(),
                    "title": (
                        raw.get("title") or raw.get("target_project") or ""
                    ).strip(),
                    "target_lang": (
                        raw.get("target_language")
                        or raw.get("chain_or_language")
                        or ""
                    ).strip(),
                    "tier": raw.get(
                        "verification_tier", "tier-2-verified-public-archive"
                    ),
                    "_text_blob": _stringify_for_co_occurrence(raw),
                    "_source_dir": d.name,
                    "_path": rel_path,
                }
            )
    # Final sort by incident_id ensures deterministic order regardless of
    # multi-directory aggregation order or per-directory inode ordering.
    return sorted(out, key=lambda x: x.get("incident_id") or "")


def _stringify_for_co_occurrence(raw: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "title",
        "attack_vector_summary",
        "attacker_action_sequence",
        "target_component",
        "attack_class",
        "bug_class",
        "fix_pattern",
        "exploit_preconditions",
    ):
        val = raw.get(key)
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    parts.append(v)
    return " ".join(parts).lower()


# ---------------------------------------------------------------------------
# Composition scoring
# ---------------------------------------------------------------------------


_TOKENIZE_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    text = (text or "").lower()
    return set(t for t in _TOKENIZE_RE.findall(text) if len(t) >= 4)


def _commit_point_tokens(inv: dict[str, Any]) -> set[str]:
    return _tokens(str(inv.get("commit_point_pattern") or ""))


def _defense_tokens(inv: dict[str, Any]) -> set[str]:
    return _tokens(str(inv.get("defense_layer") or ""))


def _attack_signature_tokens(inv: dict[str, Any]) -> set[str]:
    return _tokens(
        str(inv.get("attack_signature") or inv.get("category") or "")
    )


def _target_lang(inv: dict[str, Any]) -> str:
    return (inv.get("target_lang") or "").strip().lower()


def _incident_co_occurrence_score(
    members: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
) -> tuple[float, list[str]]:
    """+0.10 per incident where >=2 members' commit_point keywords appear."""
    member_tokens = [
        _commit_point_tokens(m) | _attack_signature_tokens(m) for m in members
    ]
    if not any(member_tokens):
        return 0.0, []
    evidence: list[str] = []
    for inc in incidents:
        text = inc["_text_blob"]
        hits = 0
        for toks in member_tokens:
            for tok in toks:
                if tok in text:
                    hits += 1
                    break
        if hits >= 2:
            evidence.append(inc["incident_id"])
        if len(evidence) >= 50:
            break
    return min(0.30, 0.10 * len(evidence)), evidence[:50]


def _score_tuple(
    members: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
) -> tuple[float, dict[str, Any], list[str]]:
    cp_token_sets = [_commit_point_tokens(m) for m in members]
    shared_cp = (
        set.intersection(*cp_token_sets) if all(cp_token_sets) else set()
    )
    cp_score = min(0.60, 0.30 * len(shared_cp))
    langs = {_target_lang(m) for m in members if _target_lang(m)}
    if len(langs) == 1 and langs != {""}:
        lang_score = 0.20
    elif len(langs) == 2:
        lang_score = 0.10
    else:
        lang_score = 0.0
    co_score, evidence = _incident_co_occurrence_score(members, incidents)
    df_token_sets = [_defense_tokens(m) for m in members]
    shared_df = (
        set.intersection(*df_token_sets) if all(df_token_sets) else set()
    )
    df_score = 0.20 if shared_df else 0.0
    total = cp_score + lang_score + co_score + df_score
    breakdown = {
        "shared_commit_point_keywords": sorted(shared_cp),
        "shared_target_lang_count": len(langs),
        "co_occurrence_incident_count": len(evidence),
        "defense_layer_keywords_shared": sorted(shared_df),
        "score_commit_point": round(cp_score, 4),
        "score_target_lang": round(lang_score, 4),
        "score_co_occurrence": round(co_score, 4),
        "score_defense_layer": round(df_score, 4),
    }
    return round(total, 4), breakdown, evidence


# ---------------------------------------------------------------------------
# Cluster grouping
# ---------------------------------------------------------------------------


def _cluster_key(inv: dict[str, Any]) -> tuple[str]:
    """Cluster invariants by category alone.

    Invariant records use ``category`` as the broad bucket. ``attack_signature``
    is narrower; clustering on both fields produces single-member clusters
    and skips all cross-signature composition. Clustering on ``category``
    alone discovers NEW signature combinations within a category.
    """
    cat = str(inv.get("category") or "uncategorized").lower().strip()
    return (cat,)


# ---------------------------------------------------------------------------
# Template emission
# ---------------------------------------------------------------------------


def _chain_template_id(member_ids: list[str]) -> str:
    norm = sorted([str(m) for m in member_ids])
    digest = hashlib.sha256("|".join(norm).encode("utf-8")).hexdigest()
    return f"GCT-{digest[:16]}"


def _compose_kill_conditions(members: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in members:
        for key in ("kill_conditions", "falsification_requirements"):
            val = m.get(key)
            if isinstance(val, list):
                for s in val:
                    if isinstance(s, str) and s and s not in seen:
                        seen.add(s)
                        out.append(s)
    return out


def _compose_state_machine(
    members: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    sorted_members = sorted(
        members, key=lambda m: str(m.get("invariant_id", ""))
    )
    for i, m in enumerate(sorted_members):
        out.append(
            {
                "step": i + 1,
                "invariant_id": m.get("invariant_id"),
                "precondition_summary": str(m.get("statement", ""))[:200],
                "commit_point_pattern": m.get("commit_point_pattern"),
                "produces_state": f"state:{m.get('commit_point_pattern','unknown_state')}",
            }
        )
    return out


def _compose_producer_consumer_links(
    members: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for producer in members:
        producer_id = str(producer.get("invariant_id") or "")
        produced = {
            _state_key(token): token
            for token in _as_text_list(producer.get("produces_state"))
            if _state_key(token)
        }
        if not produced:
            continue
        for consumer in members:
            consumer_id = str(consumer.get("invariant_id") or "")
            if not producer_id or not consumer_id or producer_id == consumer_id:
                continue
            required = {
                _state_key(token): token
                for token in _as_text_list(consumer.get("requires_state"))
                if _state_key(token)
            }
            shared = sorted(set(produced) & set(required))
            for state_key in shared:
                link_key = (producer_id, consumer_id, state_key)
                if link_key in seen:
                    continue
                seen.add(link_key)
                links.append(
                    {
                        "producer_invariant_id": producer_id,
                        "consumer_invariant_id": consumer_id,
                        "state_token": produced[state_key],
                        "producer_source_refs": _as_text_list(
                            producer.get("producer_source_refs")
                        )[:5],
                        "consumer_source_refs": _as_text_list(
                            consumer.get("consumer_source_refs")
                        )[:5],
                    }
                )
    return links


def _tuple_rejection_reason(members: list[dict[str, Any]]) -> str | None:
    for member in members:
        reason = _record_rejection_reason(member)
        if reason is not None:
            return reason
    all_leads: set[str] = set()
    for member in members:
        all_leads.update(_source_leads(member))
    if len(all_leads) < 2:
        return "single-lead-restatement"
    if not _compose_producer_consumer_links(members):
        return "missing-producer-consumer-link"
    return None


def _compose_template(
    members: list[dict[str, Any]],
    score: float,
    breakdown: dict[str, Any],
    evidence_incidents: list[str],
) -> dict[str, Any]:
    member_ids = [str(m.get("invariant_id")) for m in members]
    template_id = _chain_template_id(member_ids)
    tiers = [
        str(m.get("verification_tier", "tier-3-synthetic-taxonomy-anchored"))
        for m in members
    ]
    member_tier = _weakest_tier(tiers)
    producer_consumer_links = _compose_producer_consumer_links(members)
    source_refs: list[str] = []
    seen_source_refs: set[str] = set()
    for member in members:
        for ref in _as_text_list(member.get("source_refs")):
            if ref not in seen_source_refs:
                seen_source_refs.add(ref)
                source_refs.append(ref)
    rationale_parts = [
        f"Composition score {score:.3f} from members [{', '.join(member_ids)}]",
        (
            f"Shared commit_point keywords: {breakdown['shared_commit_point_keywords']}"
            if breakdown["shared_commit_point_keywords"]
            else "No shared commit_point keywords"
        ),
        f"Shared target_lang count: {breakdown['shared_target_lang_count']}",
        (
            f"Cross-incident co-occurrence: {breakdown['co_occurrence_incident_count']} incidents"
        ),
        (
            f"Defense-layer keywords shared: {breakdown['defense_layer_keywords_shared']}"
            if breakdown["defense_layer_keywords_shared"]
            else "No shared defense-layer keywords"
        ),
    ]
    return {
        "schema_version": SCHEMA,
        "chain_template_id": template_id,
        "member_invariant_ids": sorted(member_ids),
        "tuple_size": len(members),
        "composition_score": score,
        "composition_breakdown": breakdown,
        "composition_rationale": "; ".join(rationale_parts),
        "kill_conditions": _compose_kill_conditions(members),
        "falsification_requirements": _compose_kill_conditions(members),
        "state_machine": _compose_state_machine(members),
        "producer_consumer_links": producer_consumer_links,
        "source_refs": source_refs[:20],
        "evidence_incidents": evidence_incidents[:20],
        "verification_tier": member_tier,
        "advisory_only": False,
        "submission_posture": "TEMPLATE_LIBRARY_READY",
        "promotion_guard": "source_backed_multi_lead_producer_consumer_linked",
        "member_categories": sorted(
            {str(m.get("category", "")) for m in members if m.get("category")}
        ),
        "member_target_langs": sorted(
            {
                str(m.get("target_lang", ""))
                for m in members
                if m.get("target_lang")
            }
        ),
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


def _manual_zetachain_template(
    anchors: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if len(anchors) < 4:
        return None
    if _tuple_rejection_reason(anchors) is not None:
        return None
    template = _compose_template(
        anchors,
        score=1.00,
        breakdown={
            "shared_commit_point_keywords": ["bridge"],
            "shared_target_lang_count": 1,
            "co_occurrence_incident_count": 1,
            "defense_layer_keywords_shared": ["bridge"],
            "score_commit_point": 0.60,
            "score_target_lang": 0.20,
            "score_co_occurrence": 0.10,
            "score_defense_layer": 0.20,
            "_manual_anchor": True,
        },
        evidence_incidents=[
            "zetachain:2026-04-26-arbcall-allowance-residue-drain"
        ],
    )
    template["_manual_anchor"] = True
    template["composition_rationale"] = (
        "MANUAL ANCHOR (ZetaChain 2026-04-26 incident): 4 cross-domain "
        "invariants compose into the documented arbitrary-call selector-"
        "deny-list + unlimited allowance residue + sender-zeroing chain "
        "that drained $333,868. Manually curated tier-2 anchor; included "
        "regardless of mechanical score."
    )
    return template


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def _emit_tuples(
    invariants: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    max_tuple_size: int,
    min_score: float,
) -> list[dict[str, Any]]:
    clusters: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for inv in invariants:
        if _record_rejection_reason(inv) is not None:
            continue
        clusters[_cluster_key(inv)].append(inv)

    templates: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for _key, group in clusters.items():
        if len(group) < 2:
            continue
        group_sorted = sorted(
            group,
            key=lambda m: (
                -int(m.get("source_count", 0) or 0),
                str(m.get("invariant_id", "")),
            ),
        )
        capped = group_sorted[:12]
        for k in range(2, min(max_tuple_size, len(capped)) + 1):
            for combo in itertools.combinations(capped, k):
                members = list(combo)
                if _tuple_rejection_reason(members) is not None:
                    continue
                score, breakdown, evidence = _score_tuple(members, incidents)
                if score < min_score:
                    continue
                tpl = _compose_template(members, score, breakdown, evidence)
                if tpl["chain_template_id"] in seen_ids:
                    continue
                seen_ids.add(tpl["chain_template_id"])
                templates.append(tpl)
    return templates


def _write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def _write_manifest(
    path: pathlib.Path,
    *,
    output_path: pathlib.Path,
    template_count: int,
    by_tuple_size: dict[int, int],
    inputs: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    try:
        output_rel = str(output_path.relative_to(REPO_ROOT))
    except ValueError:
        output_rel = str(output_path)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "output_path": output_rel,
        "template_count_total": template_count,
        "template_count_by_tuple_size": {
            str(k): v for k, v in sorted(by_tuple_size.items())
        },
        "inputs": inputs,
        "config": {
            "max_tuple_size": args.max_tuple_size,
            "min_composition_score": args.min_composition_score,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--invariants-jsonl",
        type=pathlib.Path,
        default=DEFAULT_INVARIANTS_JSONL,
    )
    parser.add_argument(
        "--advisory-invariants-glob",
        type=str,
        default=None,
        help=(
            "Optional advisory invariant JSONL glob. Defaults to "
            "audit/corpus_tags/derived/invariants_*_advisories.jsonl only "
            "when --invariants-jsonl uses the default corpus."
        ),
    )
    parser.add_argument(
        "--predicates-jsonl",
        type=pathlib.Path,
        default=REPO_ROOT
        / "audit/corpus_tags/derived/exploit_predicates.jsonl",
        help="Optional - predicates corpus (reserved for future use)",
    )
    parser.add_argument(
        "--anti-patterns-dir",
        type=pathlib.Path,
        default=REPO_ROOT / "obsidian-vault/anti-patterns",
    )
    parser.add_argument(
        "--incident-corpus-dirs",
        type=str,
        default=",".join(
            [
                "audit/corpus_tags/tags/bridge_incidents",
                "audit/corpus_tags/tags/darknavy_web3_incidents",
                "audit/corpus_tags/tags/rekt_news_incidents",
                "audit/corpus_tags/tags/defimon_telegram_incidents",
                "audit/corpus_tags/tags/defimon_blog_incidents",
                "audit/corpus_tags/tags/mev_exploits",
                "audit/corpus_tags/tags/case_studies_local",
            ]
        ),
        help="Comma-separated list of incident corpus directories.",
    )
    parser.add_argument(
        "--zetachain-anchors-dir",
        type=pathlib.Path,
        default=REPO_ROOT
        / "audit/corpus_tags/derived/invariant_library_extended/manual_zetachain_2026-04-26",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=REPO_ROOT
        / "audit/corpus_tags/derived/global_chain_templates.jsonl",
    )
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=None,
        help="Manifest output path (defaults to <output>.manifest.json sibling).",
    )
    parser.add_argument(
        "--workspace",
        type=pathlib.Path,
        default=None,
        help=(
            "Optional workspace root. When set, source refs in promoted "
            "templates must resolve to local file:line anchors."
        ),
    )
    parser.add_argument("--max-tuple-size", type=int, default=4)
    parser.add_argument("--min-composition-score", type=float, default=0.6)
    parser.add_argument(
        "--max-incidents",
        type=int,
        default=2000,
        help="Cap incidents loaded (to bound memory / runtime). 0 = no cap (all incidents).",
    )
    parser.add_argument(
        "--allow-shrink",
        action="store_true",
        help="Override the safety guard that refuses to overwrite an existing library with "
             "<50%% as many templates (protects against a malformed/repurposed input).",
    )
    parser.add_argument(
        "--max-invariants",
        type=int,
        default=0,
        help="Cap invariants loaded (0 = no cap).",
    )
    parser.add_argument(
        "--json-summary",
        type=pathlib.Path,
        default=None,
        help="Optional file to write the manifest summary to (JSON).",
    )
    parser.add_argument(
        "--no-manual-anchor",
        action="store_true",
        help="Skip the manual ZetaChain 4-tuple anchor injection (for tests).",
    )

    args = parser.parse_args(argv)
    workspace = args.workspace.expanduser().resolve(strict=False) if args.workspace else None

    # Resolve incident dirs.
    incident_dirs: list[pathlib.Path] = []
    for raw in str(args.incident_corpus_dirs).split(","):
        raw = raw.strip()
        if not raw:
            continue
        p = pathlib.Path(raw)
        if not p.is_absolute():
            p = REPO_ROOT / p
        incident_dirs.append(p)

    # Load corpora.
    invariants = _load_invariants(args.invariants_jsonl, workspace=workspace)
    advisory_paths: list[str] = []
    try:
        default_invariants_selected = args.invariants_jsonl.resolve() == DEFAULT_INVARIANTS_JSONL.resolve()
    except OSError:
        default_invariants_selected = args.invariants_jsonl == DEFAULT_INVARIANTS_JSONL
    advisory_glob = args.advisory_invariants_glob
    if advisory_glob is None and default_invariants_selected:
        advisory_glob = "audit/corpus_tags/derived/invariants_*_advisories.jsonl"
    if advisory_glob:
        advisory_invariants, advisory_paths = _load_advisory_invariants(
            advisory_glob,
            workspace=workspace,
        )
        invariants.extend(advisory_invariants)
    if args.max_invariants:
        invariants = invariants[: args.max_invariants]
    incidents = _load_incidents(incident_dirs)
    if args.max_incidents:  # 0 = no cap (symmetric with --max-invariants); a bare
        # incidents[:0] would have loaded ZERO incidents, not "all".
        incidents = incidents[: args.max_incidents]
    zetachain_anchors = _load_zetachain_anchors(
        args.zetachain_anchors_dir,
        workspace=workspace,
    )
    anti_patterns = _load_anti_patterns(args.anti_patterns_dir)

    # Inject the ZetaChain anchors into the invariant pool.
    for inv in zetachain_anchors:
        invariants.append(inv)

    # Run composition.
    templates = _emit_tuples(
        invariants,
        incidents,
        max_tuple_size=args.max_tuple_size,
        min_score=args.min_composition_score,
    )

    if not args.no_manual_anchor:
        manual = _manual_zetachain_template(zetachain_anchors)
        if manual is not None:
            existing = {t["chain_template_id"] for t in templates}
            if manual["chain_template_id"] not in existing:
                templates.append(manual)

    templates.sort(
        key=lambda t: (
            -int(t.get("tuple_size", 0)),
            -float(t.get("composition_score", 0.0)),
            str(t.get("chain_template_id", "")),
        )
    )

    # SAFETY GUARD (2026-07-07): refuse to overwrite a non-trivial existing library with 0
    # or a drastically-smaller set. A repurposed/malformed input (e.g. invariants_pilot_
    # audited.jsonl re-materialized as RAW per-fn fuel, dropping the causal-linkage schema
    # the composer needs -> every row source-unbacked -> 0 templates) would otherwise
    # SILENTLY WIPE the last-good library. Pass --allow-shrink to override intentionally.
    _prior = 0
    if args.output.is_file():
        try:
            _prior = sum(1 for _l in args.output.read_text(encoding="utf-8").splitlines() if _l.strip())
        except OSError:
            _prior = 0
    if _prior >= 100 and len(templates) < max(1, _prior // 2) and not getattr(args, "allow_shrink", False):
        sys.stderr.write(
            f"REFUSING to overwrite {args.output} ({_prior} templates) with {len(templates)} "
            f"(< 50%). Likely a malformed/repurposed input (all invariants source-unbacked -> "
            f"0 composable tuples). Fix the enriched-invariant feed, or pass --allow-shrink.\n")
        return 2

    _write_jsonl(args.output, templates)

    by_size: dict[int, int] = defaultdict(int)
    for tpl in templates:
        by_size[int(tpl["tuple_size"])] += 1

    inputs = {
        "invariants_jsonl": str(args.invariants_jsonl),
        "invariants_loaded_count": len(invariants),
        "workspace": str(workspace) if workspace is not None else None,
        "advisory_invariants_glob": advisory_glob,
        "advisory_invariants_paths": advisory_paths,
        "predicates_jsonl": str(args.predicates_jsonl),
        "anti_patterns_dir": str(args.anti_patterns_dir),
        "anti_patterns_loaded_count": len(anti_patterns),
        "incident_corpus_dirs": [str(p) for p in incident_dirs],
        "incidents_loaded_count": len(incidents),
        "zetachain_anchors_dir": str(args.zetachain_anchors_dir),
        "zetachain_anchors_loaded_count": len(zetachain_anchors),
    }

    manifest_path = args.manifest or args.output.parent / (
        args.output.stem + ".manifest.json"
    )
    manifest = _write_manifest(
        manifest_path,
        output_path=args.output,
        template_count=len(templates),
        by_tuple_size=dict(by_size),
        inputs=inputs,
        args=args,
    )

    summary = {
        "schema_version": MANIFEST_SCHEMA + ".summary",
        "template_count_total": len(templates),
        "template_count_by_tuple_size": {
            str(k): v for k, v in sorted(by_size.items())
        },
        "output_path": str(args.output),
        "manifest_path": str(manifest_path),
        "inputs": inputs,
    }
    if args.json_summary:
        args.json_summary.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
