#!/usr/bin/env python3
"""Build an index-backed hackerman brief for a hunt lane."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from hackerman_query_common import (
    DEFAULT_INDEX_DIR,
    DEFAULT_PROOF_HARDENING_SIDECAR,
    DEFAULT_RECORD_QUALITY_SIDECAR,
    DEFAULT_TAGS_DIR,
    attach_proof_hardening,
    attach_record_quality,
    clamp_limit,
    collect_scope_files,
    cross_language_analogues_for_record,
    dedupe_records,
    infer_domain,
    infer_language_from_files,
    load_cross_language_analogue_index,
    load_proof_hardening_index,
    load_record_quality_index,
    normalized_record,
    query_index,
    read_jsonl,
    record_quality_sort_key,
    records_for_rows,
    sidecar_status,
    slug,
    stable_hash,
    utc_now,
)


SCHEMA = "auditooor.hackerman.brief_for_lane.v1"
DEFAULT_QUALITY_SIDECAR = DEFAULT_RECORD_QUALITY_SIDECAR
DEFAULT_PROOF_SIDECAR = DEFAULT_PROOF_HARDENING_SIDECAR

# B2: language-extension -> language label for span detection.
# Mirrors infer_language_from_files() in hackerman_query_common but exposes
# the per-file map so the autolift trigger can detect 2+ languages on the
# same lane (auto-invocation hook for cross-language analogues).
CROSS_LANGUAGE_FILE_EXT_MAP: dict[str, str] = {
    ".go": "go",
    ".sol": "solidity",
    ".rs": "rust",
    ".vy": "vyper",
    ".move": "move",
    ".cairo": "cairo",
    ".ts": "typescript-onchain",
    ".js": "typescript-onchain",
}

# Sibling-language pairings known to be exploit-class adjacent. Used both
# (a) by the autolift trigger so a single-language lane that touches a
# "known sibling-pattern" repo still receives the cross-language section,
# and (b) by the aggregator to order analogues that are most likely to
# translate. Bidirectional pairs are expressed as two ordered tuples.
CROSS_LANGUAGE_PAIRS: tuple[tuple[str, str], ...] = (
    ("solidity", "rust"),
    ("rust", "solidity"),
    ("solidity", "go"),
    ("go", "solidity"),
    ("solidity", "vyper"),
    ("vyper", "solidity"),
    ("go", "rust"),
    ("rust", "go"),
    ("solidity", "move"),
    ("move", "solidity"),
    ("solidity", "cairo"),
    ("cairo", "solidity"),
)

# Repos/components whose presence in the lane scope is a strong trigger
# for cross-language analogue lift even when the lane scope itself is
# single-language. Each entry is a substring match against workspace name,
# target_repo, or any file path token. (Conservative list - extend via
# operator audit, not via mining LLM output.)
CROSS_LANGUAGE_TRIGGER_REPOS: tuple[str, ...] = (
    "dydxprotocol/v4-chain",
    "cosmos-sdk",
    "cometbft",
    "tendermint",
    "ibc-go",
    "cosmwasm",
    "solana-program-library",
    "anchor-lang",
    "openzeppelin-contracts",
    "polkadot-sdk",
    "substrate",
    "starknet",
    "ethereum-optimism/optimism",
    "ethereum-optimism/op-succinct",
    "buildonspark/spark",
)
_PRODUCTION_PROFILE_LANE_RE = re.compile(
    r"\b(iavl|nodedb|rootmulti|goleveldb|pebbledb|rocksdb|memdb|db|storage|"
    r"commit|finalizeblock|baseapp|cometbft|validator|consensus|"
    r"apphash|state-sync|matching-engine|batch\.write|timing|latency|race)\b",
    re.IGNORECASE,
)
_PERSISTENCE_LANE_RE = re.compile(
    r"\b(permanent|persistent|restart|halt|chain halt|validator halt|"
    r"block production|apphash|freeze|freezing|hardfork)\b",
    re.IGNORECASE,
)

_RANK_TERM_STOPWORDS = {
    "audit",
    "audits",
    "bool",
    "cmd",
    "code",
    "common",
    "contract",
    "contracts",
    "ctx",
    "error",
    "event",
    "external",
    "fork",
    "func",
    "function",
    "generic",
    "impl",
    "import",
    "internal",
    "lane",
    "language",
    "lib",
    "library",
    "msg",
    "package",
    "protocol",
    "public",
    "return",
    "returns",
    "scope",
    "server",
    "sol",
    "solidity",
    "src",
    "test",
    "tests",
    "type",
    "types",
    "uint",
    "uint256",
    "version",
}


def _read_scope_text(workspace: Path, files: list[str], max_bytes: int = 20000) -> str:
    chunks: list[str] = []
    total = 0
    for file_name in files[:25]:
        path = Path(file_name)
        if not path.is_absolute():
            path = workspace / file_name
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        remaining = max_bytes - total
        if remaining <= 0:
            break
        chunks.append(text[:remaining])
        total += min(len(text), remaining)
    return "\n".join(chunks)


def _identifier_terms(text: str) -> list[str]:
    terms: list[str] = []
    for raw in re.findall(r"[A-Za-z0-9]+", text or ""):
        split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", raw)
        candidates = [raw.lower()]
        candidates.extend(part.lower() for part in split.split())
        for term in candidates:
            if len(term) < 3 or term in _RANK_TERM_STOPWORDS:
                continue
            terms.append(term)
    return terms


def _add_rank_terms(out: dict[str, float], text: str, weight: float) -> None:
    seen: set[str] = set()
    for term in _identifier_terms(text):
        if term in seen:
            continue
        seen.add(term)
        out[term] = out.get(term, 0.0) + weight


def _lane_rank_terms(lane_id: str, workspace: Path, files: list[str], scope_text: str) -> dict[str, float]:
    terms: dict[str, float] = {}
    _add_rank_terms(terms, lane_id, 50.0)
    _add_rank_terms(terms, workspace.name, 3.0)
    _add_rank_terms(terms, " ".join(files), 2.0)
    _add_rank_terms(terms, scope_text[:12000], 0.1)
    return terms


def _record_rank_field_texts(row: dict[str, Any], record: dict[str, Any]) -> list[tuple[str, float]]:
    sites = record.get("sites") if isinstance(record.get("sites"), list) else []
    site_text = " ".join(
        json.dumps(site, sort_keys=True, default=str)
        for site in sites
        if isinstance(site, dict)
    )
    function_shape = record.get("function_shape") if isinstance(record.get("function_shape"), dict) else {}
    return [
        (
            " ".join(
                str(record.get(field) or "")
                for field in ("target_repo", "target_component", "source_audit_ref")
            ),
            4.0,
        ),
        (site_text, 4.0),
        (json.dumps(function_shape, sort_keys=True, default=str), 3.0),
        (
            " ".join(
                str(record.get(field) or "")
                for field in (
                    "bug_class",
                    "attack_class",
                    "target_domain",
                    "target_language",
                    "attacker_role",
                    "attacker_action_sequence",
                    "required_preconditions",
                    "impact_class",
                    "fix_pattern",
                    "notes",
                )
            ),
            1.5,
        ),
        (json.dumps(row, sort_keys=True, default=str), 0.5),
    ]


def _record_specificity_score(
    row: dict[str, Any],
    record: dict[str, Any],
    rank_terms: dict[str, float],
) -> float:
    if not rank_terms:
        return 0.0
    score = 0.0
    matched: set[str] = set()
    for text, field_weight in _record_rank_field_texts(row, record):
        field_terms = set(_identifier_terms(text))
        for term, term_weight in rank_terms.items():
            if term in field_terms:
                score += term_weight * field_weight
                matched.add(term)
    raw_haystack = slug(
        json.dumps({"row": row, "record": record}, sort_keys=True, default=str)
    )
    for term, term_weight in rank_terms.items():
        if term_weight >= 30.0 and term in raw_haystack:
            score += term_weight * 20.0
            matched.add(term)
    if len(matched) >= 2:
        score += len(matched) * 0.25
    return score


def _rank_records_for_lane(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    lane_id: str,
    workspace: Path,
    files: list[str],
    scope_text: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    rank_terms = _lane_rank_terms(lane_id, workspace, files, scope_text)
    return [
        pair
        for _, pair in sorted(
            enumerate(pairs),
            key=lambda item: (
                -_record_specificity_score(item[1][0], item[1][1], rank_terms),
                item[0],
            ),
        )
    ]


def _quality_ordered_records(
    records: list[dict[str, Any]],
    *,
    language: str,
    target_repo: str,
    files: list[str] | None = None,
) -> list[dict[str, Any]]:
    return [
        record
        for _, record in sorted(
            enumerate(records),
            key=lambda item: (
                _record_file_match_rank(item[1], files or []),
                *record_quality_sort_key(
                    item[1],
                    language=language,
                    target_repo=target_repo,
                    stable_index=item[0],
                ),
            ),
        )
    ]


def _norm_scope_path(path: str) -> str:
    return str(path or "").strip().lstrip("./")


def _record_file_match_rank(record: dict[str, Any], files: list[str]) -> int:
    """Prefer records tied to the lane's exact source files.

    Quality/tier is still valuable, but it should not lift an unrelated local
    precedent above the file actually being hunted.
    """
    wanted = {_norm_scope_path(path) for path in files if _norm_scope_path(path)}
    if not wanted:
        return 2
    candidates: list[str] = []
    for field in ("target_component", "file_path"):
        value = _norm_scope_path(str(record.get(field) or ""))
        if value:
            candidates.append(value)
    sites = record.get("sites") if isinstance(record.get("sites"), list) else []
    for site in sites:
        if not isinstance(site, dict):
            continue
        value = _norm_scope_path(str(site.get("file_path") or ""))
        if value:
            candidates.append(value)
    for candidate in candidates:
        if candidate in wanted:
            return 0
        if any(scope.endswith(candidate) or candidate.endswith(scope) for scope in wanted):
            return 0
    candidate_basenames = {Path(candidate).name for candidate in candidates if candidate}
    wanted_basenames = {Path(scope).name for scope in wanted if scope}
    if candidate_basenames & wanted_basenames:
        return 1
    return 2


def _lane_claim_hardening(
    *,
    lane_id: str,
    workspace: Path,
    files: list[str],
    scope_text: str,
    language: str,
    domain: str,
    target_repo: str,
) -> dict[str, Any]:
    text = " ".join([lane_id, workspace.name, " ".join(files), scope_text[:12000], language, domain, target_repo])
    triggered_gates = ["L29-FILING"]
    required_before_high_critical = [
        "rubric verbatim match for the selected impact",
        "title and selected impact must be subsets of runnable PoC proven_impacts",
        "each proven impact needs an exact PoC path, test name, command, and PASS transcript",
        "known not_proven_impacts must not appear in title or selected impact",
    ]
    if _PRODUCTION_PROFILE_LANE_RE.search(text) and (
        language == "go" or "dydx" in target_repo.lower() or "cosmos" in text.lower()
    ):
        triggered_gates.extend(["R18", "R19", "R20", "R22", "R30"])
        required_before_high_critical.extend(
            [
                "production path proof through FinalizeBlock/Commit/app.RunTx or equivalent",
                "real persistent backend such as goleveldb/pebbledb/rocksdb, not MemDB",
                "no DB fault/timing shim, scheduler knob, reflection write, or unsafe private-state mutation",
                "restart behavior transcript: survives restart or honestly walks back persistence",
                "multi-validator proof for network-level liveness/AppHash/chain-halt claims",
            ]
        )
    if _PERSISTENCE_LANE_RE.search(text) and "R22" not in triggered_gates:
        triggered_gates.append("R22")
        required_before_high_critical.append("restart-survival evidence or restart-heals severity walk-back")
    return {
        "source": "codified_rules_l29_r30",
        "claim_boundary": "Hackerman brief is recall and challenge logic only; it is not submission readiness.",
        "triggered_gates": list(dict.fromkeys(triggered_gates)),
        "required_before_high_critical": list(dict.fromkeys(required_before_high_critical)),
    }


def _query_index_contains(
    *,
    index_name: str,
    terms: list[str],
    index_dir: Path,
    tags_dir: Path,
    limit: int,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    path = index_dir / f"{index_name}.jsonl"
    if not path.is_file() or not terms:
        return []
    wanted = [slug(term) for term in terms if len(slug(term)) >= 4]
    if not wanted:
        return []
    rows: list[dict[str, Any]] = []
    for row in read_jsonl(path):
        haystack = slug(json.dumps(row, sort_keys=True, default=str))
        if any(term in haystack for term in wanted):
            rows.append(row)
        if len(rows) >= limit:
            break
    return records_for_rows(rows, tags_dir)


def _collect_records(
    args: argparse.Namespace,
    language: str,
    domain: str,
    limit: int,
    *,
    workspace: Path,
    files: list[str],
    scope_text: str,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    index_dir = Path(args.index_dir)
    tags_dir = Path(args.tags_dir)
    query_limit = max(limit * 50, 1000)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    lane_terms = [
        term
        for term, weight in _lane_rank_terms(args.lane_id, workspace, files, scope_text[:12000]).items()
        if weight >= 3.0 and len(term) >= 4
    ][:30]
    for index_name in ("by_target_repo", "by_attack_class", "by_bug_class", "by_language"):
        pairs.extend(
            _query_index_contains(
                index_name=index_name,
                terms=lane_terms,
                index_dir=index_dir,
                tags_dir=tags_dir,
                limit=query_limit,
            )
        )
    if args.target_repo:
        pairs.extend(
            query_index(
                index_name="by_target_repo",
                key=args.target_repo,
                index_dir=index_dir,
                tags_dir=tags_dir,
                limit=query_limit,
                fuzzy_slug=False,
            )
        )
    if domain and (index_dir / "by_target_domain.jsonl").exists():
        pairs.extend(
            query_index(
                index_name="by_target_domain",
                key=domain,
                index_dir=index_dir,
                tags_dir=tags_dir,
                limit=query_limit,
            )
        )
    if language:
        pairs.extend(
            query_index(
                index_name="by_language",
                key=language,
                index_dir=index_dir,
                tags_dir=tags_dir,
                limit=query_limit,
            )
        )
    if args.attack_class:
        pairs.extend(
            query_index(
                index_name="by_attack_class",
                key=args.attack_class,
                index_dir=index_dir,
                tags_dir=tags_dir,
                limit=query_limit,
            )
        )
    return dedupe_records(pairs)


def _detect_language_span(files: list[str]) -> list[str]:
    """B2 helper. Return the sorted list of distinct languages spanned by
    the lane's file scope. Empty list means no language could be inferred.
    """
    seen: set[str] = set()
    for file_name in files:
        suffix = Path(str(file_name)).suffix.lower()
        lang = CROSS_LANGUAGE_FILE_EXT_MAP.get(suffix)
        if lang:
            seen.add(lang)
    return sorted(seen)


def _cross_language_repo_trigger_hits(
    workspace_name: str,
    target_repo: str,
    files: list[str],
) -> list[str]:
    """B2 helper. Return matched CROSS_LANGUAGE_TRIGGER_REPOS substrings."""
    hits: list[str] = []
    haystack_parts = [str(workspace_name or ""), str(target_repo or "")]
    haystack_parts.extend(str(f) for f in files)
    haystack = " | ".join(haystack_parts).lower()
    for token in CROSS_LANGUAGE_TRIGGER_REPOS:
        if token.lower() in haystack:
            hits.append(token)
    return hits


def _cross_language_autolift_trigger(
    *,
    files: list[str],
    workspace_name: str,
    target_repo: str,
    primary_language: str,
) -> tuple[bool, list[str], list[str], list[str]]:
    """B2 helper. Returns (trigger_fires, languages_span, trigger_repos,
    reasons). The trigger fires when EITHER the file extensions span 2+
    distinct languages OR the lane workspace / repo / files match a known
    cross-language trigger repo."""
    languages = _detect_language_span(files)
    trigger_repos = _cross_language_repo_trigger_hits(workspace_name, target_repo, files)
    reasons: list[str] = []
    if len(languages) >= 2:
        reasons.append(f"file-extension-span={','.join(languages)}")
    if trigger_repos:
        reasons.append(f"trigger-repo-match={','.join(trigger_repos)}")
    # Single-language lanes still get the autolift if (a) the primary
    # language is in a known cross-language pair AND (b) at least one
    # trigger-repo match fires - otherwise the section would be noise.
    fires = bool(reasons)
    return fires, languages, trigger_repos, reasons


def _aggregate_cross_language_analogues(
    records: list[dict[str, Any]],
    *,
    primary_language: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """B2 helper. Aggregate de-duplicated cross-language analogues across
    all records in the brief. Prefers pairs where source_language matches
    the primary lane language and target_language is a known sibling.
    Caps at ``limit`` (default 20 per task spec)."""
    seen: set[tuple[str, str, str]] = set()
    pair_set = set(CROSS_LANGUAGE_PAIRS)
    primary = (primary_language or "").lower()
    ordered: list[tuple[int, dict[str, Any]]] = []
    for rec in records or []:
        analogues = rec.get("cross_language_analogues") or []
        if not isinstance(analogues, list):
            continue
        source_record_id = str(rec.get("record_id") or "")
        for analogue in analogues:
            if not isinstance(analogue, dict):
                continue
            source_lang = str(analogue.get("source_language") or "").lower().strip()
            target_lang = str(analogue.get("target_language") or "").lower().strip()
            translation = str(analogue.get("pattern_translation") or "").strip()
            analogue_record_id = str(analogue.get("analogue_record_id") or "").strip()
            if not target_lang or not translation:
                continue
            key = (source_lang or "*", target_lang, translation)
            if key in seen:
                continue
            seen.add(key)
            # Priority bucket:
            # 0 - source_language matches lane primary AND pair listed
            # 1 - pair listed (either direction)
            # 2 - target_language is in any known pair
            # 3 - other
            priority = 3
            if (source_lang, target_lang) in pair_set:
                priority = 1
                if primary and source_lang == primary:
                    priority = 0
            elif any(target_lang == p[1] for p in pair_set):
                priority = 2
            entry = {
                "source_language": analogue.get("source_language") or "",
                "target_language": analogue.get("target_language") or "",
                "pattern_translation": translation,
                "source_record_id": source_record_id or analogue.get("source_record_id") or "",
                "analogue_record_id": analogue_record_id,
                "attack_class": analogue.get("attack_class") or rec.get("attack_class") or "",
                "confidence": analogue.get("confidence"),
            }
            ordered.append((priority, entry))
        if len(seen) >= limit * 2:
            break
    ordered.sort(key=lambda pair: (pair[0], pair[1].get("target_language") or ""))
    return [entry for _, entry in ordered[:limit]]


def _render_markdown(payload: dict[str, Any]) -> str:
    target = payload["target"]
    lines = [
        f"# Hackerman Brief - {payload['lane_id']}",
        "",
        f"- Language: {target.get('language') or 'unknown'}",
        f"- Domain: {target.get('domain') or 'unknown'}",
        f"- Matched records: {payload['total_records_matched']}",
        "",
        "## Claim Hardening",
    ]
    hardening = payload.get("claim_hardening") or {}
    gates = hardening.get("triggered_gates") or []
    if gates:
        lines.append(f"- Gates: {', '.join(str(gate) for gate in gates)}")
    boundary = str(hardening.get("claim_boundary") or "").strip()
    if boundary:
        lines.append(f"- Boundary: {boundary}")
    requirements = hardening.get("required_before_high_critical") or []
    for item in requirements[:8]:
        lines.append(f"- Before High/Critical: {item}")
    # B2: auto-injected Cross-Language Analogues section. Fires when the
    # lane spans 2+ languages OR matches a known cross-language trigger
    # repo. Suppressed via --no-cross-language-autolift (the autolift
    # payload key is then absent and this branch falls through).
    autolift = payload.get("cross_language_analogues_autolift") or {}
    if isinstance(autolift, dict) and autolift.get("trigger_fires") and autolift.get("aggregated"):
        lines.extend(["", "## Cross-Language Analogues"])
        reasons = autolift.get("trigger_reasons") or []
        if reasons:
            lines.append(f"- Trigger: {'; '.join(str(r) for r in reasons)}")
        languages_span = autolift.get("languages_span") or []
        if languages_span:
            lines.append(f"- Languages in scope: {', '.join(str(l) for l in languages_span)}")
        for entry in autolift.get("aggregated") or []:
            if not isinstance(entry, dict):
                continue
            src = entry.get("source_language") or "*"
            tgt = entry.get("target_language") or "?"
            translation = str(entry.get("pattern_translation") or "")[:200]
            attack_class = entry.get("attack_class") or "unknown"
            lines.append(f"- {src} -> {tgt} ({attack_class}): {translation}")
    lines.extend([
        "",
        "## Prior Attacks",
    ])
    records = payload.get("records") or []
    verified, synthetic = _partition_records(records)
    if not records:
        lines.append("")
        lines.append("No corpus records matched the lane selectors.")
        return "\n".join(lines)
    if not verified:
        lines.append("")
        lines.append("No audit-verified corpus records matched the lane selectors.")
    for rec in verified:
        _append_record_markdown(lines, rec)
    prior_audit_records = payload.get("workspace_prior_audit_records") or []
    if prior_audit_records:
        selected_ids = {rec.get("record_id") for rec in records}
        visible_prior = [rec for rec in prior_audit_records if rec.get("record_id") not in selected_ids]
        if visible_prior:
            lines.append("")
            lines.append("## Workspace prior-audit context")
            for rec in visible_prior:
                _append_record_markdown(lines, rec)
    if synthetic:
        lines.append("")
        lines.append("## Synthetic pattern candidates (NOT audit-verified)")
        for rec in synthetic:
            _append_record_markdown(lines, rec)
    return "\n".join(lines)


def _is_synthetic_candidate(rec: dict[str, Any]) -> bool:
    return str(rec.get("verdict_class") or "").upper() == "CANDIDATE"


def _partition_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    verified: list[dict[str, Any]] = []
    synthetic: list[dict[str, Any]] = []
    for rec in records:
        if _is_synthetic_candidate(rec):
            synthetic.append(rec)
        else:
            verified.append(rec)
    return verified, synthetic


def _workspace_prior_audit_records(
    records: list[dict[str, Any]],
    *,
    workspace_name: str,
    limit: int,
) -> list[dict[str, Any]]:
    prefix = f"prior-audit:{workspace_name}:"
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        source_ref = str(record.get("source_audit_ref") or "")
        if not source_ref.startswith(prefix):
            continue
        record_id = str(record.get("record_id") or source_ref)
        if record_id in seen:
            continue
        seen.add(record_id)
        selected.append(record)
        if len(selected) >= limit:
            break
    return selected


def _append_record_markdown(lines: list[str], rec: dict[str, Any]) -> None:
    title = rec.get("record_id") or rec.get("source_audit_ref")
    lines.append("")
    lines.append(f"### {title}")
    lines.append(f"- Class: {rec.get('attack_class') or 'unknown'}")
    lines.append(f"- Target: {rec.get('target_repo') or 'unknown'} / {rec.get('target_component') or 'unknown'}")
    if rec.get("attacker_action_sequence"):
        lines.append(f"- Attacker sequence: {rec['attacker_action_sequence']}")
    elif rec.get("notes"):
        lines.append(f"- Notes: {rec['notes'].splitlines()[0][:240]}")
    if rec.get("record_quality_score"):
        tier = rec.get("record_tier") or "unknown"
        lines.append(f"- Quality: {tier} / {rec['record_quality_score']}")
    proof = rec.get("proof_hardening") if isinstance(rec.get("proof_hardening"), dict) else {}
    if proof:
        lines.append(
            "- Proof posture: "
            f"{proof.get('evidence_class') or 'unknown'} / "
            f"shape {proof.get('function_shape_confidence') or 'unknown'} / "
            f"maturity {proof.get('proof_maturity_score') or '?'} / "
            f"{proof.get('claim_boundary') or 'unknown boundary'}"
        )
        if proof.get("submission_posture") or proof.get("promotion_allowed") is not None:
            lines.append(
                "- Submission posture: "
                f"{proof.get('submission_posture') or 'unknown'}; "
                f"promotion_allowed={str(bool(proof.get('promotion_allowed'))).lower()}"
            )
        blockers = proof.get("promotion_blockers") or []
        if isinstance(blockers, list) and blockers:
            lines.append(f"- Promotion blockers: {'; '.join(str(item) for item in blockers[:3])}")
    analogues = rec.get("cross_language_analogues") or []
    if isinstance(analogues, list) and analogues:
        rendered = []
        for analogue in analogues[:3]:
            if not isinstance(analogue, dict):
                continue
            language = str(analogue.get("target_language") or "").strip()
            translation = str(analogue.get("pattern_translation") or "").strip()
            if language and translation:
                rendered.append(f"{language}: {translation[:180]}")
        if rendered:
            lines.append(f"- Cross-language analogues: {'; '.join(rendered)}")
    if rec.get("fix_pattern"):
        lines.append(f"- Fix pattern: {rec['fix_pattern']}")


def _normalised_record_with_analogues(
    row: dict[str, Any],
    record: dict[str, Any],
    analogue_index: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    norm = normalized_record(record, row)
    analogues = cross_language_analogues_for_record(record, row, analogue_index, limit=3)
    if analogues:
        norm["cross_language_analogues"] = analogues
    return norm


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    limit = clamp_limit(args.limit, default=20, maximum=100)
    ts = utc_now()
    workspace = Path(args.workspace).expanduser().resolve()
    files = collect_scope_files(workspace, args.scope_glob or [], args.files or [])
    scope_text = " ".join(files) + "\n" + _read_scope_text(workspace, files)
    language = args.language or infer_language_from_files(files)
    domain = args.domain or infer_domain(f"{args.lane_id} {workspace.name} {scope_text}")

    pairs = _rank_records_for_lane(
        _collect_records(
            args,
            language,
            domain,
            max(limit, 1),
            workspace=workspace,
            files=files,
            scope_text=scope_text,
        ),
        lane_id=args.lane_id,
        workspace=workspace,
        files=files,
        scope_text=scope_text,
    )
    quality_index = load_record_quality_index(Path(args.quality_sidecar))
    proof_index = load_proof_hardening_index(Path(args.proof_hardening_sidecar))
    cross_language_sidecar = Path(args.cross_language_sidecar) if args.cross_language_sidecar else (
        Path(args.tags_dir).parent / "derived" / "cross_language_analogues.jsonl"
    )
    analogue_index = load_cross_language_analogue_index(cross_language_sidecar)
    quality_sidecar_refs, quality_sidecar_gaps = sidecar_status(
        Path(args.quality_sidecar),
        bool(quality_index),
        "record_quality",
    )
    cross_language_sidecar_refs, cross_language_sidecar_gaps = sidecar_status(
        cross_language_sidecar,
        bool(analogue_index),
        "cross_language_analogues",
    )
    proof_sidecar_refs, proof_sidecar_gaps = sidecar_status(
        Path(args.proof_hardening_sidecar),
        bool(proof_index),
        "proof_hardening",
    )
    sidecar_gaps = quality_sidecar_gaps + cross_language_sidecar_gaps + proof_sidecar_gaps
    lane_ranked_records = [
        attach_proof_hardening(
            attach_record_quality(_normalised_record_with_analogues(row, record, analogue_index), quality_index),
            proof_index,
        )
        for row, record in pairs
    ]
    ranked_records = _quality_ordered_records(
        lane_ranked_records,
        language=language,
        target_repo=args.target_repo or "",
        files=files,
    )
    verified_records, synthetic_records = _partition_records(ranked_records)
    records = (verified_records + synthetic_records)[:limit]
    prior_audit_records = _workspace_prior_audit_records(
        lane_ranked_records,
        workspace_name=workspace.name,
        limit=min(max(limit, 1), 10),
    )
    selected_verified, selected_synthetic = _partition_records(records)
    degraded = False
    reason = ""
    if not any([language, domain, args.target_repo, args.attack_class]):
        degraded = True
        reason = "no_lane_selectors_detected"

    digest = stable_hash(
        {
            "schema": SCHEMA,
            "lane_id": args.lane_id,
            "language": language,
            "domain": domain,
            "record_ids": [r["record_id"] for r in records],
            "degraded": degraded,
        }
    )
    payload = {
        "schema": SCHEMA,
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        "degraded": degraded,
        "degraded_reason": reason,
        "lane_id": args.lane_id,
        "workspace_path": workspace.name,
        "files": files,
        "target": {
            "language": language,
            "domain": domain,
            "target_repo": args.target_repo or "",
            "attack_class": args.attack_class or "",
        },
        "claim_hardening": _lane_claim_hardening(
            lane_id=args.lane_id,
            workspace=workspace,
            files=files,
            scope_text=scope_text,
            language=language,
            domain=domain,
            target_repo=args.target_repo or "",
        ),
        "total_records_matched": len(pairs),
        "records": records,
        "workspace_prior_audit_records": prior_audit_records,
        "record_groups": {
            "audit_verified": len(selected_verified),
            "synthetic_candidates": len(selected_synthetic),
            "workspace_prior_audit": len(prior_audit_records),
        },
        "quality_sidecar_loaded": bool(quality_index),
        "quality_rows_loaded": len(
            {
                str(row.get("record_id") or "")
                for row in quality_index.values()
                if row.get("record_id")
            }
        ),
        "quality_index_keys_loaded": len(quality_index),
        "cross_language_sidecar_loaded": bool(analogue_index),
        "cross_language_sidecar_sources_loaded": len(analogue_index),
        "proof_hardening_sidecar_loaded": bool(proof_index),
        "proof_hardening_rows_loaded": len(
            {
                str(row.get("record_id") or "")
                for row in proof_index.values()
                if row.get("record_id")
            }
        ),
        "source_refs": [
            str(Path(args.index_dir) / "by_language.jsonl"),
            str(Path(args.index_dir) / "by_target_domain.jsonl"),
            str(Path(args.index_dir) / "by_target_repo.jsonl"),
            str(Path(args.index_dir) / "by_attack_class.jsonl"),
            str(Path(args.tags_dir)),
            *quality_sidecar_refs,
            *cross_language_sidecar_refs,
            *proof_sidecar_refs,
        ],
        "sidecar_gaps": sidecar_gaps,
        "generated_at_utc": ts,
    }
    # B2 autolift: aggregate top-level cross-language analogues section.
    # Suppressed when caller passes --no-cross-language-autolift.
    no_autolift = bool(getattr(args, "no_cross_language_autolift", False))
    fires, languages_span, trigger_repos, reasons = _cross_language_autolift_trigger(
        files=files,
        workspace_name=workspace.name,
        target_repo=args.target_repo or "",
        primary_language=language,
    )
    aggregated: list[dict[str, Any]] = []
    if fires and not no_autolift:
        aggregated = _aggregate_cross_language_analogues(
            records,
            primary_language=language,
            limit=20,
        )
    payload["cross_language_analogues_autolift"] = {
        "trigger_fires": bool(fires and not no_autolift),
        "trigger_reasons": reasons,
        "languages_span": languages_span,
        "trigger_repos": trigger_repos,
        "suppressed": no_autolift,
        "aggregated": aggregated,
        "aggregated_count": len(aggregated),
    }
    # B2 question-row attachment: every brief consumer that generates
    # auditooor.hacker_question.v1 rows from this payload (the vault MCP
    # callable / agent-prompt augmenter) reads records[*].cross_language_analogues
    # which is already populated at the per-record level by
    # _normalised_record_with_analogues above. The autolift block is the
    # additional top-level aggregate used by the markdown render and the
    # downstream "auditooor.hacker_question.v1" attacher.
    payload["brief_markdown"] = _render_markdown(payload)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", "--workspace-path", dest="workspace", required=True)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument("--scope-glob", action="append", default=[], help="Workspace-relative glob to inspect; may be repeated")
    parser.add_argument("--files", action="append", default=[], help="Comma-separated or repeated workspace-relative files")
    parser.add_argument("--language", default="", help="Override inferred language")
    parser.add_argument("--domain", default="", help="Override inferred target domain")
    parser.add_argument("--target-repo", default="", help="Optional target_repo selector")
    parser.add_argument("--attack-class", default="", help="Optional attack_class selector")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument("--quality-sidecar", default=str(DEFAULT_QUALITY_SIDECAR))
    parser.add_argument("--cross-language-sidecar", default="")
    parser.add_argument("--proof-hardening-sidecar", default=str(DEFAULT_PROOF_SIDECAR))
    parser.add_argument(
        "--no-cross-language-autolift",
        dest="no_cross_language_autolift",
        action="store_true",
        help=(
            "B2 opt-out: suppress the top-level Cross-Language Analogues "
            "section auto-injected when the lane spans 2+ languages or "
            "matches a known cross-language trigger repo."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = build_payload(args)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(payload["brief_markdown"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
