#!/usr/bin/env python3
"""
live-check-spec-synthesizer.py — generate angle-linked live-check specs.

This tool turns deployment topology + CCIA attack angles into a generated
workspace spec that `live-check-runner.py` can execute. It does two things:

1. normalizes any seeded manual spec into a workspace-local generated spec and
   annotates checks with `related_angle_ids` when they are missing
2. synthesizes simple relational address-equality checks for cross-contract
   angles so live topology evidence can sharpen mining instead of just existing
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
GENERIC_RELATION_TOKENS = {
    "address",
    "asset",
    "collateral",
    "factory",
    "implementation",
    "proxy",
    "safe",
    "token",
    "wrapped",
}


def parse_angles_from_md(text: str) -> List[Dict[str, Any]]:
    angles: List[Dict[str, Any]] = []
    for line in text.splitlines():
        match = re.match(r"###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)", line)
        if match:
            angles.append(
                {
                    "id": match.group(1),
                    "severity": match.group(2),
                    "title": match.group(3),
                }
            )
    return angles


def extract_contracts(angles: Iterable[Dict[str, Any]]) -> List[str]:
    ordered: List[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        value = name.strip()
        if not value or value in seen:
            return
        seen.add(value)
        ordered.append(value)

    for angle in angles:
        contracts = angle.get("contracts", [])
        if isinstance(contracts, list):
            for contract in contracts:
                if isinstance(contract, str):
                    add(contract)
        title = str(angle.get("title", ""))
        if not contracts:
            match = re.search(r":\s+([A-Za-z_][A-Za-z0-9_]*)(?:\.(\w+))?\s*$", title)
            if match:
                add(match.group(1))
    return ordered


def load_ccia_angles(workspace: Path) -> List[Dict[str, Any]]:
    json_path = workspace / "ccia_report.json"
    if json_path.exists():
        payload = json.loads(json_path.read_text())
        if isinstance(payload, dict):
            angles = payload.get("attack_angles", [])
            if isinstance(angles, list):
                return [angle for angle in angles if isinstance(angle, dict)]
    md_path = workspace / "ccia_report.md"
    if md_path.exists():
        return parse_angles_from_md(md_path.read_text())
    return []


def load_topology(workspace: Path) -> Dict[str, Dict[str, Any]]:
    path = workspace / "deployment_topology.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    entries = payload.get("entries", [])
    topology: Dict[str, Dict[str, Any]] = {}
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            contract = entry.get("contract")
            if isinstance(contract, str) and contract:
                topology[contract] = entry
    return topology


def load_semantic_graph(workspace: Path) -> Dict[str, Any]:
    path = workspace / ".auditooor" / "semantic_graph.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def split_identifier_tokens(value: str) -> List[str]:
    chunks = re.split(r"[^A-Za-z0-9]+", value)
    parts: List[str] = []
    for chunk in chunks:
        if not chunk:
            continue
        if chunk.isupper():
            parts.append(chunk.lower())
            continue
        parts.extend(re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z]|$)", chunk))
    return [part.lower() for part in parts if part]


def getter_variants(stem: str) -> List[str]:
    if not stem:
        return []
    cap = stem[0].upper() + stem[1:]
    return list(dict.fromkeys([stem, f"get{cap}"]))


def source_files_for_contract(workspace: Path, contract: str) -> List[Path]:
    src = workspace / "src"
    if not src.exists():
        return []
    patterns = (
        rf"\bcontract\s+{re.escape(contract)}\b",
        rf"\babstract\s+contract\s+{re.escape(contract)}\b",
        rf"\binterface\s+I?{re.escape(contract)}\b",
    )
    files: List[Path] = []
    for path in src.rglob("*.sol"):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if any(re.search(pattern, text) for pattern in patterns):
            files.append(path)
    return files


def contract_reference_variants(contract: str) -> Set[str]:
    variants = {contract}
    if not contract.startswith("I"):
        variants.add(f"I{contract}")
    return variants


def extract_address_getters_from_text(text: str) -> Set[str]:
    getters: Set[str] = set()
    function_pattern = re.compile(
        r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*"
        r"(?:[^{;]|\n)*?returns\s*\(\s*address\b",
        re.MULTILINE,
    )
    for match in function_pattern.finditer(text):
        getters.add(match.group(1))
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line or not line.endswith(";") or "(" in line or " public " not in f" {line} ":
            continue
        lhs = line[:-1].split("=", 1)[0].strip()
        tokens = lhs.split()
        if "public" not in tokens or len(tokens) < 2:
            continue
        type_name = tokens[0]
        name = tokens[-1]
        if type_name == "address" or re.match(r"^[A-Z][A-Za-z0-9_]*$", type_name):
            getters.add(name)
    return getters


def load_contract_getters_and_text(workspace: Path, contracts: Sequence[str]) -> Tuple[Dict[str, Set[str]], Dict[str, str]]:
    discovered: Dict[str, Set[str]] = {}
    texts: Dict[str, str] = {}
    for contract in contracts:
        getters: Set[str] = set()
        chunks: List[str] = []
        for path in source_files_for_contract(workspace, contract):
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            getters.update(extract_address_getters_from_text(text))
            chunks.append(text)
        discovered[contract] = getters
        texts[contract] = "\n".join(chunks)
    return discovered, texts


def resolve_seed_spec_path(workspace: Path, explicit: str | None) -> Optional[Path]:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        return path if path.exists() else None
    candidates = [
        workspace / "monitoring" / "live_checks.json",
        REPO / "projects" / workspace.name / "live_checks.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def load_seed_checks(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None:
        return []
    payload = json.loads(path.read_text())
    checks = payload.get("checks", [])
    if not isinstance(checks, list):
        return []
    return [dict(check) for check in checks if isinstance(check, dict)]


def infer_default_network(seed_checks: Sequence[Dict[str, Any]], workspace: Path) -> str:
    counts: Dict[str, int] = {}
    for check in seed_checks:
        network = str(check.get("network") or "").strip().lower()
        if network:
            counts[network] = counts.get(network, 0) + 1
    if counts:
        return max(counts.items(), key=lambda item: item[1])[0]
    env_keys = {path.name.upper() for path in (workspace / "env").glob("*.env")} if (workspace / "env").exists() else set()
    name = workspace.name.lower()
    if "polygon" in env_keys or "polymarket" in name:
        return "polygon"
    return "mainnet"


def angles_for_contracts(angles: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    mapping: Dict[str, List[Dict[str, Any]]] = {}
    for angle in angles:
        contracts = angle.get("contracts", [])
        if isinstance(contracts, list):
            for contract in contracts:
                if isinstance(contract, str) and contract:
                    mapping.setdefault(contract, []).append(angle)
    return mapping


def compatible_angle_ids(evidence_class: str, candidate_ids: Sequence[str]) -> List[str]:
    evidence = evidence_class.lower()
    preferred: List[str]
    if "oracle" in evidence:
        preferred = ["A-ORACLE", "A-RACE"]
    elif "role" in evidence or "auth" in evidence:
        preferred = ["A-AUTH", "A-DELEGATE", "A-TXORIGIN"]
    elif "pause" in evidence or "timing" in evidence:
        preferred = ["A-RACE", "A-TIMESTAMP", "A-AUTH"]
    elif "fee" in evidence or "exchange" in evidence:
        preferred = ["A-RACE", "A-AUTH", "A-FLASH"]
    elif "relation" in evidence or "topology" in evidence:
        preferred = ["A-RACE", "A-AUTH", "A-ORACLE", "A-DELEGATE"]
    else:
        preferred = []
    compatible = [angle_id for angle_id in candidate_ids if angle_id in preferred]
    ordered = compatible or list(candidate_ids)
    return list(dict.fromkeys(ordered))


def annotate_seed_checks(seed_checks: Sequence[Dict[str, Any]], angles: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_contract = angles_for_contracts(angles)
    annotated: List[Dict[str, Any]] = []
    for check in seed_checks:
        item = dict(check)
        if item.get("related_angle_ids"):
            ids = [
                str(angle_id).strip()
                for angle_id in item.get("related_angle_ids", [])
                if str(angle_id).strip()
            ]
            if ids:
                item["related_angle_ids"] = sorted(dict.fromkeys(ids))
        else:
            contract = str(item.get("contract") or "").strip()
            candidate_ids = [
                str(angle.get("id") or "").strip()
                for angle in by_contract.get(contract, [])
                if str(angle.get("id") or "").strip()
            ]
            evidence_class = str(item.get("evidence_class") or "")
            if candidate_ids:
                item["related_angle_ids"] = compatible_angle_ids(evidence_class, candidate_ids)
        item.setdefault("spec_source", "seed")
        annotated.append(item)
    return annotated


def is_explicit_address(value: Any) -> bool:
    text = str(value or "").strip()
    return text.startswith("0x") and len(text) >= 42


def build_seed_address_maps(seed_checks: Sequence[Dict[str, Any]]) -> Tuple[Dict[Tuple[str, str], str], Dict[Tuple[str, str], str]]:
    by_contract: Dict[Tuple[str, str], Set[str]] = {}
    by_expect_ref: Dict[Tuple[str, str], Set[str]] = {}
    for check in seed_checks:
        network = str(check.get("network") or "").strip().lower()
        contract = str(check.get("contract") or "").strip()
        address = str(check.get("address") or "").strip()
        if contract and is_explicit_address(address):
            by_contract.setdefault((network, contract), set()).add(address)

        expect_ref = str(check.get("expect_ref") or "").strip()
        expect = check.get("expect")
        if expect_ref and is_explicit_address(expect):
            by_expect_ref.setdefault((network, expect_ref), set()).add(str(expect).strip())

    resolved_by_contract = {
        key: next(iter(addresses))
        for key, addresses in by_contract.items()
        if len(addresses) == 1
    }
    resolved_by_expect_ref = {
        key: next(iter(addresses))
        for key, addresses in by_expect_ref.items()
        if len(addresses) == 1
    }
    return resolved_by_contract, resolved_by_expect_ref


def resolve_seed_address(
    direct_map: Dict[Tuple[str, str], str],
    ref_map: Dict[Tuple[str, str], str],
    network: str,
    contract: str,
) -> str:
    network_key = network.strip().lower()
    for key in ((network_key, contract), ("", contract)):
        if key in direct_map:
            return direct_map[key]
    for key in ((network_key, contract), ("", contract)):
        if key in ref_map:
            return ref_map[key]
    return ""


def source_mentions_target(source_text: str, target: str) -> bool:
    if not source_text:
        return False
    for variant in contract_reference_variants(target):
        if re.search(rf"\b{re.escape(variant)}\b", source_text):
            return True
    return False


def significant_target_overlap(getter: str, target: str) -> bool:
    target_tokens = set(split_identifier_tokens(target))
    getter_tokens = set(split_identifier_tokens(getter))
    overlap = target_tokens & getter_tokens
    if not overlap:
        return False
    meaningful = overlap - GENERIC_RELATION_TOKENS
    return len(meaningful) >= 2


def score_candidate_alias(
    *,
    source: str,
    target: str,
    alias: str,
    source_text: str,
    semantic_graph: Dict[str, Any] | None,
) -> Tuple[int, Dict[str, Any]]:
    """Score one candidate getter alias for a (source, target) relation.

    The score is intentionally a small integer so deterministic ordering
    by `(score, alias)` can pick a winner without floating point noise.
    Each contributing signal is recorded in the returned reasons dict so
    the synthesizer can cite the discriminator that broke a tie (or the
    fact that no discriminator exists at all).
    """
    normalized = alias[3:] if alias.startswith("get") and len(alias) > 3 else alias
    alias_tokens = set(split_identifier_tokens(normalized))
    target_tokens = set(split_identifier_tokens(target))
    overlap = sorted((alias_tokens & target_tokens) - GENERIC_RELATION_TOKENS)
    score = 0
    reasons: Dict[str, Any] = {
        "alias": alias,
        "meaningful_token_overlap": overlap,
        "exact_target_name_match": False,
        "matches_semantic_graph_method": False,
        "matches_semantic_graph_target": False,
        "is_explicit_get_prefixed": alias.startswith("get") and len(alias) > 3,
    }

    # Token overlap with the target type is the primary discriminator.
    score += 2 * len(overlap)

    # Bonus when the alias name (or its de-`get`-stemmed form) exactly
    # matches the target type's lower-case identifier.
    if normalized.lower() == target.lower() or normalized.lower() == target.lstrip("I").lower():
        score += 5
        reasons["exact_target_name_match"] = True

    # Semantic-graph relation edges that name this alias as the registry
    # method are the strongest available tie-breaker — when one candidate
    # is cited by a graph edge and the other is not, pick the cited one.
    edges = semantic_relation_edges_for_pair(semantic_graph or {}, source, target)
    for edge in edges:
        method = str(edge.get("method") or "")
        edge_target = str(edge.get("target") or "")
        if method and method == alias:
            score += 4
            reasons["matches_semantic_graph_method"] = True
        if edge_target and edge_target == alias:
            score += 3
            reasons["matches_semantic_graph_target"] = True

    # Public state-variable getters (no `get` prefix) get a tiny tiebreak
    # bias because Solidity's auto-generated getter is the more common
    # canonical accessor — but only as a tertiary signal.
    if not reasons["is_explicit_get_prefixed"]:
        score += 1

    if not source_text or not source_mentions_target(source_text, target):
        # No textual mention of the target type — drop one point so an
        # alias chosen purely on token co-occurrence ranks below one that
        # appears next to a real type reference. We keep the candidate so
        # the synthesizer can still emit it as ambiguous instead of
        # silently dropping it.
        score -= 1

    reasons["score"] = score
    return score, reasons


def rank_relation_alias_candidates(
    *,
    source: str,
    target: str,
    candidates: Sequence[str],
    source_text: str,
    semantic_graph: Dict[str, Any] | None,
) -> List[Dict[str, Any]]:
    """Return alias candidates sorted by score (desc) with a deterministic
    secondary sort on the alias name so ties are reproducible."""
    ranked: List[Dict[str, Any]] = []
    for alias in candidates:
        score, reasons = score_candidate_alias(
            source=source,
            target=target,
            alias=alias,
            source_text=source_text,
            semantic_graph=semantic_graph,
        )
        ranked.append({"alias": alias, "score": score, "reasons": reasons})
    ranked.sort(key=lambda item: (-item["score"], str(item["alias"])))
    return ranked


def guess_relation_aliases(
    source: str,
    target: str,
    available_getters: Set[str],
    source_text: str,
) -> List[str]:
    source_lower = source.lower()
    target_lower = target.lower()
    alias_stems: List[str] = []

    if "lib" in source_lower or "interface" in source_lower:
        return []
    if not available_getters:
        return []

    if "operator" in source_lower and "uma" in target_lower and "adapter" in target_lower:
        alias_stems.append("oracle")
    if "operator" in source_lower and split_identifier_tokens(target) == ["neg", "risk", "adapter"]:
        alias_stems.append("nrAdapter")
    if "adapter" in source_lower and "feemodule" in target_lower:
        alias_stems.append("feeModule")
    if "feemodule" in source_lower and "adapter" in target_lower:
        alias_stems.extend(["ctf", "adapter"])
    if "adapter" in source_lower and "operator" in target_lower:
        alias_stems.append("operator")
    if "uma" in source_lower and "adapter" in source_lower and "operator" in target_lower:
        alias_stems.extend(["ctf", "operator"])

    aliases: List[str] = []
    available_lower = {getter.lower(): getter for getter in available_getters}
    for stem in alias_stems:
        for candidate in getter_variants(stem):
            actual = available_lower.get(candidate.lower())
            if actual:
                aliases.append(actual)

    if not aliases and source_mentions_target(source_text, target):
        for getter in sorted(available_getters):
            normalized = getter[3:] if getter.startswith("get") and len(getter) > 3 else getter
            if significant_target_overlap(normalized, target):
                aliases.append(getter)

    ordered: List[str] = []
    seen: set[str] = set()
    for alias in aliases:
        if alias not in seen:
            seen.add(alias)
            ordered.append(alias)
    return ordered


def topology_has_signal(topology: Dict[str, Dict[str, Any]], contract: str) -> bool:
    entry = topology.get(contract, {})
    if entry.get("resolved_address"):
        return True
    candidates = entry.get("candidate_addresses", [])
    return isinstance(candidates, list) and bool(candidates)


def seed_address_matches_topology(
    topology: Dict[str, Dict[str, Any]],
    contract: str,
    address: str,
) -> bool:
    entry = topology.get(contract, {})
    resolved = str(entry.get("resolved_address") or "").strip()
    if resolved:
        return resolved.lower() == address.lower()
    candidates = entry.get("candidate_addresses", [])
    if isinstance(candidates, list):
        return any(str(candidate).strip().lower() == address.lower() for candidate in candidates)
    return False


def topology_signal_summary(topology: Dict[str, Dict[str, Any]], contract: str) -> Dict[str, Any]:
    entry = topology.get(contract, {})
    candidates = entry.get("candidate_addresses", [])
    if not isinstance(candidates, list):
        candidates = []
    return {
        "contract": contract,
        "status": str(entry.get("status") or ""),
        "has_resolved_address": bool(str(entry.get("resolved_address") or "").strip()),
        "candidate_count": len(
            [
                candidate
                for candidate in candidates
                if str(candidate).strip()
            ]
        ),
    }


def semantic_relation_edges_for_pair(
    semantic_graph: Dict[str, Any],
    source: str,
    target: str,
) -> List[Dict[str, Any]]:
    edges = semantic_graph.get("relation_edges")
    if not isinstance(edges, list):
        return []
    target_tokens = set(split_identifier_tokens(target))
    matched: List[Dict[str, Any]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("source_contract") or "") != source:
            continue
        edge_target = str(edge.get("target") or "")
        edge_method = str(edge.get("method") or "")
        edge_evidence = str(edge.get("evidence") or "")
        haystack = " ".join([edge_target, edge_method, edge_evidence])
        haystack_tokens = set(split_identifier_tokens(haystack))
        if edge_target == target or target_tokens.intersection(haystack_tokens):
            matched.append(
                {
                    "kind": edge.get("kind"),
                    "source_function": edge.get("source_function"),
                    "target": edge_target,
                    "method": edge_method,
                    "file": edge.get("file"),
                    "line": edge.get("line"),
                    "confidence": edge.get("confidence"),
                }
            )
    return matched[:5]


def build_heuristic_provenance(
    *,
    angle_id: str,
    source: str,
    target: str,
    alias: str,
    source_text: str,
    topology: Dict[str, Dict[str, Any]],
    semantic_graph: Dict[str, Any] | None = None,
    ranked_candidates: Sequence[Dict[str, Any]] | None = None,
    ambiguous: bool = False,
    discriminator: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    normalized_alias = alias[3:] if alias.startswith("get") and len(alias) > 3 else alias
    alias_tokens = sorted(set(split_identifier_tokens(normalized_alias)))
    target_tokens = sorted(set(split_identifier_tokens(target)))
    overlap = sorted((set(alias_tokens) & set(target_tokens)) - GENERIC_RELATION_TOKENS)
    source_mentions = source_mentions_target(source_text, target)
    semantic_edges = semantic_relation_edges_for_pair(semantic_graph or {}, source, target)
    limitations = [
        "getter selection is name/type heuristic, not semantic graph proof or compiler dataflow proof",
        "live execution must still resolve addresses and prove the edge at a pinned block",
    ]
    if not semantic_edges:
        limitations.insert(0, "no matching semantic-graph relation edge was found for this source/target pair")
    if ambiguous:
        limitations.insert(
            0,
            "multiple alias candidates tied at the top score — synthesizer refused to pick one",
        )
    candidates_payload: List[Dict[str, Any]] = []
    for entry in ranked_candidates or []:
        if not isinstance(entry, dict):
            continue
        candidate_alias = str(entry.get("alias") or "")
        if not candidate_alias:
            continue
        candidates_payload.append(
            {
                "alias": candidate_alias,
                "score": int(entry.get("score") or 0),
                "reasons": entry.get("reasons") if isinstance(entry.get("reasons"), dict) else {},
            }
        )
    return {
        "kind": "generated-relation-heuristic",
        "confidence": "source-shape" if semantic_edges else "heuristic",
        "angle_id": angle_id or None,
        "source_contract": source,
        "target_contract": target,
        "getter": alias,
        "ambiguous": bool(ambiguous),
        "discriminator": discriminator,
        "candidates": candidates_payload,
        "signals": {
            "contracts_co_occur_in_angle": True,
            "source_mentions_target_type": source_mentions,
            "getter_tokens": alias_tokens,
            "target_tokens": target_tokens,
            "meaningful_token_overlap": overlap,
            "source_topology": topology_signal_summary(topology, source),
            "target_topology": topology_signal_summary(topology, target),
            "semantic_graph_relation_edges": semantic_edges,
        },
        "limitations": limitations,
    }


def _resolve_ambiguity(
    *,
    source: str,
    target: str,
    aliases: Sequence[str],
    source_text: str,
    semantic_graph: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Score candidate aliases and report whether the top score is unique.

    Returns a dict with:
      - ranked: full ranked list (alias + score + reasons)
      - tied:   subset that shares the top score (>= 1 element)
      - ambiguous: True iff len(tied) > 1
      - winner: chosen alias (alphabetically-first of `tied`)
      - discriminator: signals the winner has that the runner-up lacks,
        or None when ambiguous (no discriminator exists by definition).
    """
    ranked = rank_relation_alias_candidates(
        source=source,
        target=target,
        candidates=list(aliases),
        source_text=source_text,
        semantic_graph=semantic_graph,
    )
    if not ranked:
        return {
            "ranked": [],
            "tied": [],
            "ambiguous": False,
            "winner": None,
            "discriminator": None,
        }
    top_score = ranked[0]["score"]
    tied = [entry for entry in ranked if entry["score"] == top_score]
    runner_up = next(
        (entry for entry in ranked if entry["score"] != top_score),
        None,
    )
    winner = tied[0]["alias"] if tied else None
    ambiguous = len(tied) > 1
    discriminator: Dict[str, Any] | None = None
    if not ambiguous and runner_up is not None:
        winner_reasons = tied[0].get("reasons", {}) if tied else {}
        runner_reasons = runner_up.get("reasons", {})
        unique_signals = []
        for key in (
            "exact_target_name_match",
            "matches_semantic_graph_method",
            "matches_semantic_graph_target",
        ):
            if winner_reasons.get(key) and not runner_reasons.get(key):
                unique_signals.append(key)
        winner_overlap = set(winner_reasons.get("meaningful_token_overlap") or [])
        runner_overlap = set(runner_reasons.get("meaningful_token_overlap") or [])
        only_in_winner = sorted(winner_overlap - runner_overlap)
        if only_in_winner:
            unique_signals.append("meaningful_token_overlap")
        discriminator = {
            "winner": winner,
            "runner_up": runner_up.get("alias"),
            "score_delta": int(top_score) - int(runner_up.get("score") or 0),
            "unique_signals": unique_signals,
            "extra_overlap_tokens": only_in_winner,
        }
    return {
        "ranked": ranked,
        "tied": tied,
        "ambiguous": ambiguous,
        "winner": winner,
        "discriminator": discriminator,
    }


def generate_relation_checks(
    angles: Sequence[Dict[str, Any]],
    topology: Dict[str, Dict[str, Any]],
    default_network: str,
    contract_getters: Dict[str, Set[str]],
    contract_text: Dict[str, str],
    seed_checks: Sequence[Dict[str, Any]],
    semantic_graph: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    generated: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    seed_contract_addresses, seed_expect_addresses = build_seed_address_maps(seed_checks)
    for angle in angles:
        angle_id = str(angle.get("id") or "").strip()
        contracts = [contract for contract in angle.get("contracts", []) if isinstance(contract, str) and contract]
        if len(contracts) < 2:
            continue
        generated_for_angle = 0
        for source in contracts:
            if not topology_has_signal(topology, source):
                continue
            available_getters = contract_getters.get(source, set())
            if not available_getters:
                continue
            source_text = contract_text.get(source, "")
            for target in contracts:
                if source == target or not topology_has_signal(topology, target):
                    continue
                aliases = guess_relation_aliases(source, target, available_getters, source_text)
                if not aliases:
                    # 0 candidates -> regression-pin: no row emitted. Live
                    # synthesis intentionally stays silent rather than
                    # invent a target for the operator.
                    continue
                resolution = _resolve_ambiguity(
                    source=source,
                    target=target,
                    aliases=aliases,
                    source_text=source_text,
                    semantic_graph=semantic_graph,
                )
                if resolution["ambiguous"]:
                    # Emit ONE explicitly-ambiguous row that names every
                    # tied candidate. Pre-submit-check fails closed on
                    # `synthesis_status == "ambiguous-source"` unless the
                    # operator passes an explicit override.
                    tied_aliases = [entry["alias"] for entry in resolution["tied"]]
                    chosen_alias = resolution["winner"] or tied_aliases[0]
                    check_id = (
                        f"gen-{angle_id.lower()}-{source.lower()}-"
                        f"ambiguous-{target.lower()}"
                    )
                    if check_id in seen_ids:
                        continue
                    seen_ids.add(check_id)
                    inherited_address = resolve_seed_address(
                        seed_contract_addresses,
                        seed_expect_addresses,
                        default_network,
                        source,
                    )
                    if inherited_address and not seed_address_matches_topology(topology, source, inherited_address):
                        inherited_address = ""
                    inherited_expect = resolve_seed_address(
                        seed_contract_addresses,
                        seed_expect_addresses,
                        default_network,
                        target,
                    )
                    if inherited_expect and not seed_address_matches_topology(topology, target, inherited_expect):
                        inherited_expect = ""
                    generated.append(
                        {
                            "id": check_id,
                            "title": (
                                f"{source}.<ambiguous getter> should resolve to {target} "
                                f"(candidates: {', '.join(tied_aliases)})"
                            ),
                            "contract": source,
                            "address": inherited_address or None,
                            "address_ref": source,
                            "network": default_network,
                            "call": f"{chosen_alias}()(address)",
                            "expect": inherited_expect or None,
                            "expect_ref": target,
                            "evidence_class": "topology-relation",
                            "related_angle_ids": [angle_id] if angle_id else [],
                            "rationale": (
                                f"Generated from {angle_id or 'cross-contract'} but synthesizer "
                                f"could not pick a single getter — {len(tied_aliases)} candidates "
                                f"({', '.join(tied_aliases)}) tie at the top heuristic score."
                            ),
                            "implication_if_match": (
                                "Operator must disambiguate the getter manually before this "
                                "row can be treated as live evidence."
                            ),
                            "heuristic_provenance": build_heuristic_provenance(
                                angle_id=angle_id,
                                source=source,
                                target=target,
                                alias=chosen_alias,
                                source_text=source_text,
                                topology=topology,
                                semantic_graph=semantic_graph,
                                ranked_candidates=resolution["ranked"],
                                ambiguous=True,
                                discriminator=None,
                            ),
                            "spec_source": "generated-relation",
                            "synthesis_status": "ambiguous-source",
                            "ambiguous_alias_candidates": tied_aliases,
                            "generated": True,
                        }
                    )
                    generated_for_angle += 1
                    if generated_for_angle >= 6:
                        break
                    continue

                # Deterministic single-winner path. We only ever emit ONE
                # row per (angle, source, target) under deterministic
                # synthesis — additional aliases would silently duplicate
                # the same edge and re-introduce ambiguity downstream.
                alias = resolution["winner"]
                check_id = f"gen-{angle_id.lower()}-{source.lower()}-{alias.lower()}-{target.lower()}"
                if check_id in seen_ids:
                    continue
                seen_ids.add(check_id)
                inherited_address = resolve_seed_address(
                    seed_contract_addresses,
                    seed_expect_addresses,
                    default_network,
                    source,
                )
                if inherited_address and not seed_address_matches_topology(topology, source, inherited_address):
                    inherited_address = ""
                inherited_expect = resolve_seed_address(
                    seed_contract_addresses,
                    seed_expect_addresses,
                    default_network,
                    target,
                )
                if inherited_expect and not seed_address_matches_topology(topology, target, inherited_expect):
                    inherited_expect = ""
                generated.append(
                    {
                        "id": check_id,
                        "title": f"{source}.{alias} should resolve to {target}",
                        "contract": source,
                        "address": inherited_address or None,
                        "address_ref": source,
                        "network": default_network,
                        "call": f"{alias}()(address)",
                        "expect": inherited_expect or None,
                        "expect_ref": target,
                        "evidence_class": "topology-relation",
                        "related_angle_ids": [angle_id] if angle_id else [],
                        "rationale": (
                            f"Generated from {angle_id or 'cross-contract'} because "
                            f"{source} and {target} co-occur in a cross-contract angle."
                        ),
                        "implication_if_match": (
                            f"{source}.{alias} points at the expected {target} deployment."
                        ),
                        "heuristic_provenance": build_heuristic_provenance(
                            angle_id=angle_id,
                            source=source,
                            target=target,
                            alias=alias,
                            source_text=source_text,
                            topology=topology,
                            semantic_graph=semantic_graph,
                            ranked_candidates=resolution["ranked"],
                            ambiguous=False,
                            discriminator=resolution["discriminator"],
                        ),
                        "spec_source": "generated-relation",
                        "synthesis_status": "ok",
                        "generated": True,
                    }
                )
                generated_for_angle += 1
                if generated_for_angle >= 6:
                    break
            if generated_for_angle >= 6:
                break
    return generated


def dedupe_checks(checks: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for check in checks:
        check_id = str(check.get("id") or "").strip()
        if not check_id or check_id in seen:
            continue
        seen.add(check_id)
        deduped.append(check)
    return deduped


def summarize(checks: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "declared": len(checks),
        "seeded": 0,
        "generated_relation": 0,
        "generated_with_heuristic_provenance": 0,
        "generated_ambiguous_source": 0,
        "angle_linked": 0,
    }
    for check in checks:
        source = str(check.get("spec_source") or "")
        if source == "seed":
            counts["seeded"] += 1
        elif source == "generated-relation":
            counts["generated_relation"] += 1
            if isinstance(check.get("heuristic_provenance"), dict):
                counts["generated_with_heuristic_provenance"] += 1
            if str(check.get("synthesis_status") or "") == "ambiguous-source":
                counts["generated_ambiguous_source"] += 1
        if check.get("related_angle_ids"):
            counts["angle_linked"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an angle-linked live-check spec")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--seed-spec", help="Optional explicit seed live-check spec path")
    parser.add_argument(
        "--out",
        help="Output path (default: <workspace>/monitoring/live_checks.generated.json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the generated spec to stdout",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"[live-check-synth] Workspace not found: {workspace}", file=sys.stderr)
        sys.exit(1)

    angles = load_ccia_angles(workspace)
    if not angles:
        print(f"[live-check-synth] No CCIA angles found for {workspace}", file=sys.stderr)
        sys.exit(2)

    topology = load_topology(workspace)
    semantic_graph = load_semantic_graph(workspace)
    contracts = extract_contracts(angles)
    contract_getters, contract_text = load_contract_getters_and_text(workspace, contracts)
    seed_path = resolve_seed_spec_path(workspace, args.seed_spec)
    try:
        seed_checks = load_seed_checks(seed_path)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[live-check-synth] Invalid seed spec: {exc}", file=sys.stderr)
        sys.exit(1)

    default_network = infer_default_network(seed_checks, workspace)
    annotated_seed = annotate_seed_checks(seed_checks, angles)
    generated_relations = generate_relation_checks(
        angles,
        topology,
        default_network,
        contract_getters,
        contract_text,
        seed_checks,
        semantic_graph,
    )
    checks = dedupe_checks([*annotated_seed, *generated_relations])
    payload = {
        "workspace": str(workspace),
        "seed_spec": str(seed_path) if seed_path else None,
        "default_network": default_network,
        "summary": summarize(checks),
        "checks": checks,
    }

    out_path = (
        Path(args.out).expanduser().resolve()
        if args.out
        else workspace / "monitoring" / "live_checks.generated.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n")

    summary = payload["summary"]
    summary_line = (
        f"[live-check-synth] wrote {out_path} "
        f"(declared={summary['declared']}, seeded={summary['seeded']}, "
        f"generated_relation={summary['generated_relation']}, "
        f"generated_with_heuristic_provenance={summary['generated_with_heuristic_provenance']}, "
        f"generated_ambiguous_source={summary['generated_ambiguous_source']}, "
        f"angle_linked={summary['angle_linked']})"
    )
    if args.json:
        print(json.dumps(payload, indent=2))
        print(summary_line, file=sys.stderr)
    else:
        print(summary_line)


if __name__ == "__main__":
    main()
