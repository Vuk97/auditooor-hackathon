#!/usr/bin/env python3
"""Build a lightweight workspace semantic graph.

This is intentionally conservative and stdlib-only. It is not a full Solidity
compiler. It gives downstream lanes one canonical, reviewable place to answer
the first production-path questions: what public/external functions exist, who
appears able to call them, what state names are written, and where value-like
effects or external calls occur.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "auditooor.semantic_graph.v1"
DEFAULT_SCOPED_TARGET = 400
DEFAULT_SCOPED_MIN = 300
DEFAULT_SCOPED_MAX = 500
MULTIHOP_STAGES = (
    "caller",
    "parser",
    "cache_provider",
    "validation",
    "state_root",
    "proof_dispute_bridge_finalization",
)
SOLIDITY_SUFFIX = ".sol"
DEFAULT_EXCLUDES = {
    "node_modules",
    "lib",
    "out",
    "cache",
    "broadcast",
    ".git",
    ".auditooor",
}

CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+is\s+([^{]+))?\s*\{",
    re.MULTILINE,
)
FUNCTION_RE = re.compile(
    r"\b(function|constructor|fallback|receive)\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)?\s*\([^(){};]*\)\s*([^;{}]*)\{",
    re.MULTILINE | re.DOTALL,
)
STATE_DECL_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+?\)|[A-Za-z_][A-Za-z0-9_<>,.\[\]]*)\s+"
    r"(?:public|private|internal|external|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)
STATE_DECL_TYPED_RE = re.compile(
    r"^\s*(mapping\s*\([^;]+?\)|[A-Za-z_][A-Za-z0-9_<>,.\[\]]*)\s+"
    r"(?:public|private|internal|external|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)
LOCAL_TYPED_VAR_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*|I[A-Z][A-Za-z0-9_]*)\s+"
    r"(?:memory\s+|storage\s+|calldata\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)"
)
TYPED_CAST_CALL_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*|I[A-Z][A-Za-z0-9_]*)\s*\([^;\n{}]*?\)\s*\.\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
WRITE_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*(?:=|\+=|-=|\*=|/=|\+\+|--)"
)
EXTERNAL_CALL_RE = re.compile(
    r"\.(?:call|delegatecall|staticcall|transfer|send|safeTransfer|safeTransferFrom|"
    r"transferFrom|approve|mint|burn)\s*(?:\{|\(|\s)"
)
EVENT_RE = re.compile(r"\bemit\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NEW_CONTRACT_RE = re.compile(r"\bnew\s+([A-Z][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_.$]*)?")
CLONE_CALL_RE = re.compile(
    r"\bClones\.(clone(?:Deterministic)?)\s*\(\s*([A-Za-z_][A-Za-z0-9_.$]*)?",
)
REGISTRY_CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*((?:register|set|mark|__mark)[A-Za-z0-9_]*)\s*\(",
)
VERIFIER_CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*((?:verify|validate|check)[A-Za-z0-9_]*(?:Proof|Signature|Attestation)?)\s*\(",
)
HIGH_LEVEL_CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
HIGH_LEVEL_CALL_SKIP_RECEIVERS = {
    "abi",
    "address",
    "block",
    "bytes",
    "console",
    "keccak256",
    "math",
    "msg",
    "revert",
    "string",
    "super",
    "this",
    "tx",
    "vm",
}
HIGH_LEVEL_CALL_SKIP_METHODS = {
    "add",
    "concat",
    "decode",
    "div",
    "encode",
    "encodePacked",
    "length",
    "mul",
    "pop",
    "push",
    "sub",
}
ROLE_MODIFIER_RE = re.compile(
    r"\b(onlyOwner|onlyRole|onlyGuardian|onlyGovernance|onlyAdmin|requiresAuth|auth|"
    r"nonReentrant|whenNotPaused|only[A-Z][A-Za-z0-9_]*)\b"
)
PRIVILEGED_RE = re.compile(
    r"\b(onlyOwner|onlyRole|onlyGuardian|onlyGovernance|onlyAdmin|requiresAuth|auth|"
    r"owner|guardian|governance|admin|multisig)\b",
    re.IGNORECASE,
)
VALUE_RE = re.compile(
    r"\b(msg\.value|address\s*\(\s*this\s*\)\.balance|balanceOf|transfer|"
    r"safeTransfer|transferFrom|mint|burn|withdraw|deposit|claim|redeem|sweep)\b",
    re.IGNORECASE,
)
SCOPE_LINE_RE = re.compile(
    r"\b(scope|asset|out of scope|oos|impact|critical|high|medium|low|known issue|"
    r"blacklist|privileged|admin|guardian|sequencer|oracle|verifier|TEE|ZK)\b",
    re.IGNORECASE,
)
PARSER_RE = re.compile(
    r"\b(abi\.decode|decode[A-Za-z0-9_]*|parse[A-Za-z0-9_]*|deserialize|"
    r"fromSsz|from_ssz|rlp\.decode)\b",
    re.IGNORECASE,
)
CACHE_PROVIDER_RE = re.compile(
    r"\b(cache|cached|provider|oracle|registry|get[A-Z][A-Za-z0-9_]*|"
    r"latest[A-Z][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
VALIDATION_RE = re.compile(
    r"\b(require|assert|revert|verify[A-Za-z0-9_]*|validate[A-Za-z0-9_]*|"
    r"check[A-Za-z0-9_]*|recover|isValidSignature)\b",
    re.IGNORECASE,
)
STATE_ROOT_RE = re.compile(
    r"\b([A-Za-z0-9_]*(?:stateRoot|outputRoot|rootClaim|storageRoot|withdrawalRoot)"
    r"[A-Za-z0-9_]*|state_root|output_root|root_claim|storage_root|withdrawal_root)\b",
    re.IGNORECASE,
)
PROOF_DISPUTE_BRIDGE_FINALIZATION_RE = re.compile(
    r"\b(proof|prove[A-Za-z0-9_]*|dispute|challenge|bridge|withdraw|withdrawal|"
    r"finali[sz]e[A-Za-z0-9_]*|relay|settle[A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
MULTIHOP_STAGE_PATTERNS = (
    ("parser", PARSER_RE),
    ("cache_provider", CACHE_PROVIDER_RE),
    ("validation", VALIDATION_RE),
    ("state_root", STATE_ROOT_RE),
    ("proof_dispute_bridge_finalization", PROOF_DISPUTE_BRIDGE_FINALIZATION_RE),
)

# ---------------------------------------------------------------------------
# Cross-domain edge detection
# ---------------------------------------------------------------------------
# These patterns identify Solidity code that dispatches a message or proof
# to a non-EVM domain (Cosmos / IBC app-chain) or crosses an EVM L1<->L2
# proof boundary. Detection is additive and conservative: a match only fires
# when the source file looks like a Solidity contract AND at least one of the
# indicators below appears in the function body.

# IBC / Cosmos inter-chain message dispatch (Solidity -> Cosmos path):
#   sendPacket, sendIBCPacket, IBCDispatcher.dispatch, CosmosMsg, IBCMsg,
#   dispatchMsg, sendCosmosTx, sendAtomicTransaction, sendToCosmosChain.
CROSS_DOMAIN_SOL_TO_COSMOS_RE = re.compile(
    r"\b(?:sendPacket|sendIBCPacket|IBCDispatcher|CosmosMsg|IBCMsg|"
    r"dispatchMsg|sendCosmosTx|sendAtomicTransaction|sendToCosmosChain|"
    r"ibc\.transfer|ibcTransfer|ibcDispatch)\b",
    re.IGNORECASE,
)

# EVM L1<->L2 bridge proof-domain crossings:
#   deposit/withdraw through OptimismPortal, L1/L2Bridge, CrossChainBridge,
#   relayMessage, proveWithdrawalTransaction, finalizeWithdrawalTransaction,
#   submitProof, relayProof. Also Polygon exit, Arbitrum retryable tickets.
CROSS_DOMAIN_EVM_BRIDGE_RE = re.compile(
    r"\b(?:depositTransaction|proveWithdrawalTransaction|"
    r"finalizeWithdrawalTransaction|relayMessage|relayProof|submitProof|"
    r"crossChainTransfer|L1Bridge|L2Bridge|CrossChainBridge|"
    r"OptimismPortal|ArbitrumBridge|PolygonBridge|"
    r"createRetryableTicket|outboundTransfer|inboundTransfer|"
    r"bridgeDeposit|bridgeWithdraw)\b",
    re.IGNORECASE,
)

# Domain identifier strings used when constructing cross-domain edge records.
# A Solidity source file that fires CROSS_DOMAIN_SOL_TO_COSMOS_RE is the
# "evm_solidity" side; its counterpart is "cosmos_appchain".
# A Solidity source file that fires CROSS_DOMAIN_EVM_BRIDGE_RE spans
# "evm_l1" and "evm_l2" (or the L2 proof domain).
_DOMAIN_SOL_TO_COSMOS = ("evm_solidity", "cosmos_appchain")
_DOMAIN_EVM_L1_L2 = ("evm_l1", "evm_l2")


def strip_comments(text: str) -> str:
    def blank_comment(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    text = re.sub(r"//[^\n]*", blank_comment, text)
    return re.sub(r"/\*.*?\*/", blank_comment, text, flags=re.DOTALL)


def find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text) - 1


def iter_solidity_files(workspace: Path, roots: list[Path] | None = None) -> Iterable[Path]:
    scan_roots = roots or [workspace]
    for root in scan_roots:
        resolved = root.expanduser()
        if not resolved.is_absolute():
            resolved = workspace / resolved
        if resolved.is_file():
            candidates = [resolved] if resolved.suffix == SOLIDITY_SUFFIX else []
        elif resolved.is_dir():
            candidates = sorted(resolved.rglob(f"*{SOLIDITY_SUFFIX}"))
        else:
            continue
        for path in candidates:
            try:
                rel = path.relative_to(workspace)
            except ValueError:
                continue
            parts = set(rel.parts[:-1])
            if parts & DEFAULT_EXCLUDES:
                continue
            if path.name.endswith((".t.sol", ".s.sol")):
                continue
            yield path


def semantic_item_count(graph: dict[str, Any]) -> int:
    return len(graph.get("relation_edges") or []) + len(graph.get("multi_hop_paths") or [])


def _component(contract: Any, function: Any) -> str:
    return "{}.{}".format(contract or "", function or "").strip(".")


def _contract(component: Any) -> str:
    text = str(component or "")
    return text.split(".", 1)[0] if text else ""


def _relation_score(edge: dict[str, Any]) -> tuple[int, str, int]:
    text = " ".join(
        str(edge.get(key) or "")
        for key in ("kind", "method", "target", "target_type", "evidence", "resolution")
    ).lower()
    source = str(edge.get("source_contract") or "").lower()
    target = str(edge.get("target_type") or edge.get("target") or "").lower()
    score = 0
    if target and source and target != source:
        score += 40
    for needle, weight in (
        ("proxy", 30),
        ("clone", 28),
        ("factory", 24),
        ("delegate", 24),
        ("bridge", 22),
        ("final", 18),
        ("withdraw", 18),
        ("verif", 18),
        ("proof", 18),
        ("registry", 12),
        ("typed", 10),
    ):
        if needle in text:
            score += weight
    if edge.get("target_type"):
        score += 10
    return (-score, str(edge.get("file") or ""), int(edge.get("line") or 0))


def _path_score(path: dict[str, Any]) -> tuple[int, str]:
    text = " ".join(
        str(path.get(key) or "")
        for key in ("impact_family", "source_component", "sink_component", "path_summary")
    ).lower()
    score = 20 + len(path.get("mapped_stages") or [])
    for needle, weight in (
        ("bridge", 35),
        ("final", 25),
        ("proof", 25),
        ("dispute", 22),
        ("state_root", 20),
        ("validation", 10),
    ):
        if needle in text:
            score += weight
    return (-score, str(path.get("path_id") or ""))


def _causal_edge_score(edge: dict[str, Any]) -> tuple[int, str]:
    text = " ".join(
        str(edge.get(key) or "")
        for key in (
            "impact_family",
            "relation_kind",
            "relation_sink_component",
            "path_summary",
            "relation_method",
        )
    ).lower()
    score = 15 + len(edge.get("path_stages") or [])
    for needle, weight in (
        ("bridge", 30),
        ("final", 24),
        ("proof", 22),
        ("verif", 18),
        ("root", 16),
        ("oracle", 14),
        ("validation", 10),
    ):
        if needle in text:
            score += weight
    return (-score, str(edge.get("edge_id") or ""))


def select_scoped_graph(
    graph: dict[str, Any],
    *,
    target_items: int = DEFAULT_SCOPED_TARGET,
    min_items: int = DEFAULT_SCOPED_MIN,
    max_items: int = DEFAULT_SCOPED_MAX,
    source_artifact: str = "",
) -> dict[str, Any]:
    """Return a bounded graph focused on semantic/live depth rows.

    The scoped graph preserves source-shape semantics while avoiding full-repo
    noise. The selected item count is relation_edges + multi_hop_paths, which is
    what semantic-live-depth consumes downstream.
    """
    max_items = max(0, max_items)
    target_items = min(max(0, target_items), max_items)
    relation_edges = [row for row in graph.get("relation_edges") or [] if isinstance(row, dict)]
    multi_hop_paths = [row for row in graph.get("multi_hop_paths") or [] if isinstance(row, dict)]
    causal_composition_edges = [
        row for row in graph.get("causal_composition_edges") or []
        if isinstance(row, dict)
    ]
    source_count = len(relation_edges) + len(multi_hop_paths)
    if source_count <= max_items:
        selected_edges = relation_edges
        selected_paths = multi_hop_paths
    else:
        edge_budget = min(len(relation_edges), max(1, int(target_items * 0.65)))
        path_budget = max(0, target_items - edge_budget)
        if len(multi_hop_paths) < path_budget:
            edge_budget = min(len(relation_edges), target_items - len(multi_hop_paths))
            path_budget = len(multi_hop_paths)
        selected_edges = sorted(relation_edges, key=_relation_score)[:edge_budget]
        selected_paths = sorted(multi_hop_paths, key=_path_score)[:path_budget]
    selected_components = {
        _component(edge.get("source_contract"), edge.get("source_function"))
        for edge in selected_edges
    }
    selected_components.update(str(path.get("source_component") or "") for path in selected_paths)
    selected_contracts = {_contract(component) for component in selected_components if component}
    selected_files = {
        str(edge.get("file") or "")
        for edge in selected_edges
        if edge.get("file")
    }
    for path in selected_paths:
        for evidence in path.get("evidence_edges") or []:
            if isinstance(evidence, dict) and evidence.get("file"):
                selected_files.add(str(evidence.get("file")))
    contracts = [
        contract for contract in graph.get("contracts") or []
        if isinstance(contract, dict)
        and (contract.get("name") in selected_contracts or contract.get("file") in selected_files)
    ]
    entrypoints = [
        entry for entry in graph.get("entrypoints") or []
        if isinstance(entry, dict)
        and (
            _component(entry.get("contract"), entry.get("function")) in selected_components
            or entry.get("contract") in selected_contracts
            or entry.get("file") in selected_files
        )
    ]
    evidence_edges = [
        edge for edge in graph.get("evidence_edges") or []
        if isinstance(edge, dict)
        and (
            _component(edge.get("source_contract"), edge.get("source_function")) in selected_components
            or edge.get("file") in selected_files
        )
    ]
    selected_causal_edges = [
        edge for edge in causal_composition_edges
        if (
            edge.get("source_component") in selected_components
            or edge.get("relation_file") in selected_files
            or any(
                isinstance(evidence, dict) and evidence.get("file") in selected_files
                for evidence in (edge.get("path_evidence_edges") or [])
            )
        )
    ]
    if source_count > max_items and selected_causal_edges:
        selected_causal_edges = sorted(selected_causal_edges, key=_causal_edge_score)[:max_items]
    # Cross-domain edges: pass through those whose source contract/file is
    # within the selected scope. These are always included untruncated because
    # they are low-cardinality (one per cross-domain function, not one per call).
    all_cross_domain = [
        row for row in graph.get("cross_domain_edges") or []
        if isinstance(row, dict)
    ]
    selected_cross_domain = [
        edge for edge in all_cross_domain
        if (
            _component(edge.get("source_contract"), edge.get("source_function"))
            in selected_components
            or str(edge.get("file") or "") in selected_files
            or not selected_components  # if selection is empty, keep all
        )
    ]
    scoped = dict(graph)
    scoped.update(
        {
            "schema_version": graph.get("schema_version") or SCHEMA_VERSION,
            "selection_mode": "scoped_semantic_live_depth",
            "selection_metadata": {
                "target_range": f"{min_items}-{max_items}",
                "target_items": target_items,
                "min_items": min_items,
                "max_items": max_items,
                "source_artifact": source_artifact,
                "source_semantic_item_count": source_count,
                "selected_semantic_item_count": len(selected_edges) + len(selected_paths),
                "status": (
                    "target_range_satisfied"
                    if min_items <= len(selected_edges) + len(selected_paths) <= max_items
                    else "under_min_source_exhausted"
                    if len(selected_edges) + len(selected_paths) < min_items
                    else "over_max"
                ),
            },
            "source_file_count": int(graph.get("source_file_count") or len(selected_files)),
            "contract_count": len(contracts),
            "entrypoint_count": len(entrypoints),
            "relation_edge_count": len(selected_edges),
            "evidence_edge_count": len(evidence_edges),
            "multi_hop_path_count": len(selected_paths),
            "causal_composition_edge_count": len(selected_causal_edges),
            "cross_domain_edge_count": len(selected_cross_domain),
            "contracts": contracts,
            "entrypoints": entrypoints,
            "relation_edges": selected_edges,
            "evidence_edges": evidence_edges,
            "multi_hop_paths": selected_paths,
            "causal_composition_edges": selected_causal_edges,
            "cross_domain_edges": selected_cross_domain,
        }
    )
    return scoped


def load_graph(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[semantic-graph] ERR unreadable graph sidecar: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[semantic-graph] ERR expected object graph sidecar: {path}")
    return payload


def default_scoped_graph_candidates(workspace: Path) -> list[Path]:
    audit_dir = workspace / ".auditooor"
    return [
        audit_dir / "semantic_graph.json",
        audit_dir / "callgraph_de_semantic_graph_fixtures.json",
    ]


def build_or_select_scoped_graph(
    workspace: Path,
    *,
    roots: list[Path] | None = None,
    from_graph: Path | None = None,
    target_items: int = DEFAULT_SCOPED_TARGET,
    min_items: int = DEFAULT_SCOPED_MIN,
    max_items: int = DEFAULT_SCOPED_MAX,
) -> dict[str, Any]:
    if from_graph:
        source = from_graph.expanduser().resolve()
        graph = load_graph(source)
        return select_scoped_graph(
            graph,
            target_items=target_items,
            min_items=min_items,
            max_items=max_items,
            source_artifact=str(source),
        )
    for candidate in default_scoped_graph_candidates(workspace):
        if candidate.is_file():
            graph = load_graph(candidate)
            return select_scoped_graph(
                graph,
                target_items=target_items,
                min_items=min_items,
                max_items=max_items,
                source_artifact=str(candidate),
            )
    return select_scoped_graph(
        build_graph(workspace, roots=roots),
        target_items=target_items,
        min_items=min_items,
        max_items=max_items,
        source_artifact="fresh_workspace_scan",
    )


def visibility_from_signature(signature_tail: str, kind: str) -> str:
    if kind in {"constructor", "fallback", "receive"}:
        return "external"
    for visibility in ("external", "public", "internal", "private"):
        if re.search(rf"\b{visibility}\b", signature_tail):
            return visibility
    return "public"


def modifiers_from_signature(signature_tail: str) -> list[str]:
    return sorted(set(ROLE_MODIFIER_RE.findall(signature_tail)))


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def classify_role(modifiers: list[str], signature_tail: str) -> str:
    joined = " ".join(modifiers + [signature_tail])
    if PRIVILEGED_RE.search(joined):
        return "privileged"
    return "permissionless"


def classify_new_contract_edge(target: str) -> str:
    lowered = target.lower()
    if "proxy" in lowered:
        return "proxy-deploy"
    if "verifier" in lowered or "proof" in lowered:
        return "verifier-adapter"
    return "factory-deploy"


def relation_edges_from_body(
    *,
    rel_path: str,
    source: str,
    function: str,
    role: str,
    state_types: dict[str, str],
    source_text: str,
    body_offset: int,
    fn_body: str,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    local_types = {
        match.group(2): match.group(1)
        for match in LOCAL_TYPED_VAR_RE.finditer(fn_body)
    }

    def add_edge(
        kind: str,
        match: re.Match[str],
        *,
        target: str = "",
        evidence: str = "",
        method: str = "",
        target_var: str = "",
        receiver: str = "",
        target_type: str = "",
        receiver_source: str = "",
    ) -> None:
        resolution = "unresolved"
        if target_type:
            resolution = "type-name-source-shape"
        elif receiver_source:
            resolution = f"{receiver_source}-name-source-shape"
        edges.append({
            "kind": kind,
            "source_contract": source,
            "source_function": function,
            "file": rel_path,
            "line": line_for_offset(source_text, body_offset + match.start()),
            "role": role,
            "target": target,
            "method": method,
            "evidence": evidence or match.group(0).strip()[:160],
            "confidence": "source-shape",
            "receiver": receiver or target,
            "target_type": target_type,
            "receiver_source": receiver_source,
            "resolution": resolution,
            "detector_hint": (
                "resolved_typed_receiver"
                if target_type else "receiver_name_only"
            ),
            # ``target_var`` records the FIRST-arg variable name passed to
            # ``new Proxy(varName, ...)`` or ``Clones.clone(varName)``.
            # It is the implementation-pointer link the dossier needs to
            # resolve clone/proxy reachability into the cloned implementation
            # contract (Base-Azul-FN1-style parent-loss / clone-via-proxy
            # paths). Empty when the first arg is a literal/expression
            # rather than a bare identifier.
            "target_var": target_var,
        })

    for match in NEW_CONTRACT_RE.finditer(fn_body):
        target = match.group(1)
        first_arg = match.group(2) or ""
        add_edge(
            classify_new_contract_edge(target),
            match,
            target=target,
            evidence=f"new {target}(",
            target_var=first_arg,
            target_type=target,
            receiver_source="constructor",
        )
    for match in CLONE_CALL_RE.finditer(fn_body):
        impl_var = match.group(2) or ""
        add_edge(
            "clone-deploy",
            match,
            target=impl_var,
            method=f"Clones.{match.group(1)}",
            target_var=impl_var,
            receiver="Clones",
            receiver_source="library",
        )
    for match in REGISTRY_CALL_RE.finditer(fn_body):
        receiver, method = match.group(1), match.group(2)
        if "registry" not in receiver.lower() and "register" not in method.lower() and "mark" not in method.lower():
            continue
        add_edge(
            "registry-write",
            match,
            target=receiver,
            method=method,
            receiver=receiver,
            target_type=state_types.get(receiver) or local_types.get(receiver) or "",
            receiver_source="state" if receiver in state_types else ("local" if receiver in local_types else ""),
        )
    for match in VERIFIER_CALL_RE.finditer(fn_body):
        receiver = match.group(1)
        add_edge(
            "verifier-adapter-call",
            match,
            target=receiver,
            method=match.group(2),
            receiver=receiver,
            target_type=state_types.get(receiver) or local_types.get(receiver) or "",
            receiver_source="state" if receiver in state_types else ("local" if receiver in local_types else ""),
        )
    for match in TYPED_CAST_CALL_RE.finditer(fn_body):
        target_type, method = match.group(1), match.group(2)
        if target_type in HIGH_LEVEL_CALL_SKIP_RECEIVERS or method in HIGH_LEVEL_CALL_SKIP_METHODS:
            continue
        add_edge(
            "typed-cast-call",
            match,
            target=target_type,
            method=method,
            receiver=target_type,
            target_type=target_type,
            receiver_source="typed-cast",
        )
    for match in HIGH_LEVEL_CALL_RE.finditer(fn_body):
        receiver, method = match.group(1), match.group(2)
        if receiver in HIGH_LEVEL_CALL_SKIP_RECEIVERS or method in HIGH_LEVEL_CALL_SKIP_METHODS:
            continue
        if receiver == "Clones":
            continue
        target_type = state_types.get(receiver) or local_types.get(receiver) or ""
        add_edge(
            "high-level-call",
            match,
            target=target_type or receiver,
            method=method,
            receiver=receiver,
            target_type=target_type,
            receiver_source="state" if receiver in state_types else ("local" if receiver in local_types else ""),
        )
    return edges


def evidence_edges_from_body(
    *,
    rel_path: str,
    source: str,
    function: str,
    role: str,
    visibility: str,
    source_text: str,
    fn_start_offset: int,
    body_offset: int,
    fn_body: str,
) -> list[dict[str, Any]]:
    """Return ordered evidence edges for multi-hop path inventory.

    This is intentionally syntactic. The goal is to preserve the exact source
    evidence agents use when they reason across caller -> parser -> validation
    -> root/proof/finalization paths, not to prove exploitability.
    """
    edges: list[dict[str, Any]] = []

    def add(stage: str, line: int, evidence: str) -> None:
        edges.append({
            "edge_id": f"{source}.{function}:{stage}:{len(edges) + 1}",
            "stage": stage,
            "source_contract": source,
            "source_function": function,
            "file": rel_path,
            "line": line,
            "role": role,
            "evidence": " ".join(evidence.split())[:180],
            "confidence": "source-shape",
        })

    if visibility in {"public", "external"}:
        add("caller", line_for_offset(source_text, fn_start_offset), f"{visibility} {function}")

    seen_stages: set[str] = set()
    for stage, pattern in MULTIHOP_STAGE_PATTERNS:
        for match in pattern.finditer(fn_body):
            if stage in seen_stages:
                continue
            seen_stages.add(stage)
            add(
                stage,
                line_for_offset(source_text, body_offset + match.start()),
                match.group(0),
            )
            break
    return edges


def parse_contract(rel_path: str, source: str, contract_match: re.Match[str]) -> dict[str, Any]:
    name = contract_match.group(1)
    inherits = [
        item.strip().split("(")[0].strip()
        for item in (contract_match.group(2) or "").split(",")
        if item.strip()
    ]
    body_start = source.find("{", contract_match.end() - 1)
    body_end = find_matching_brace(source, body_start)
    body = source[body_start + 1:body_end]
    state_body_chars = list(body)
    for fn in FUNCTION_RE.finditer(body):
        open_idx = body.find("{", fn.end() - 1)
        if open_idx == -1:
            continue
        close_idx = find_matching_brace(body, open_idx)
        for idx in range(fn.start(), min(close_idx + 1, len(state_body_chars))):
            state_body_chars[idx] = " "
    state_body = "".join(state_body_chars)
    state_names = sorted(set(STATE_DECL_RE.findall(state_body)))
    state_types = {
        match.group(2): match.group(1).strip()
        for match in STATE_DECL_TYPED_RE.finditer(state_body)
    }
    functions = []
    for fn in FUNCTION_RE.finditer(body):
        kind = fn.group(1)
        fn_name = fn.group(2) or kind
        sig_tail = " ".join((fn.group(3) or "").split())
        open_idx = body.find("{", fn.end() - 1)
        close_idx = find_matching_brace(body, open_idx)
        fn_body = body[open_idx + 1:close_idx]
        writes = sorted({
            w.split("[", 1)[0]
            for w in WRITE_RE.findall(fn_body)
            if w.split("[", 1)[0] in state_names
        })
        modifiers = modifiers_from_signature(sig_tail)
        visibility = visibility_from_signature(sig_tail, kind)
        role = classify_role(modifiers, sig_tail)
        external_calls = sorted(set(m.group(0).strip() for m in EXTERNAL_CALL_RE.finditer(fn_body)))
        events = sorted(set(EVENT_RE.findall(fn_body)))
        absolute_start = body_start + 1 + fn.start()
        absolute_body_start = body_start + 1 + open_idx + 1
        relation_edges = relation_edges_from_body(
            rel_path=rel_path,
            source=name,
            function=fn_name,
            role=role,
            state_types=state_types,
            source_text=source,
            body_offset=absolute_body_start,
            fn_body=fn_body,
        )
        evidence_edges = evidence_edges_from_body(
            rel_path=rel_path,
            source=name,
            function=fn_name,
            role=role,
            visibility=visibility,
            source_text=source,
            fn_start_offset=absolute_start,
            body_offset=absolute_body_start,
            fn_body=fn_body,
        )
        functions.append({
            "name": fn_name,
            "kind": kind,
            "line": line_for_offset(source, absolute_start),
            "visibility": visibility,
            "modifiers": modifiers,
            "role": role,
            "externally_reachable": visibility in {"public", "external"},
            "privileged": role == "privileged",
            "state_writes": writes,
            "external_calls": external_calls,
            "relation_edges": relation_edges,
            "evidence_edges": evidence_edges,
            "emits": events,
            "value_movement": bool(VALUE_RE.search(fn_body)),
        })
    return {
        "name": name,
        "file": rel_path,
        "line": line_for_offset(source, contract_match.start()),
        "inherits": inherits,
        "state_variables": state_names,
        "state_variable_types": state_types,
        "functions": functions,
    }


def parse_solidity_file(workspace: Path, path: Path) -> list[dict[str, Any]]:
    rel = str(path.relative_to(workspace))
    text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    return [parse_contract(rel, text, match) for match in CONTRACT_RE.finditer(text)]


def scope_annotations(workspace: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name in ("SCOPE.md", "OOS_CHECKLIST.md", "SEVERITY.md", "KNOWN_ISSUES.md"):
        path = workspace / name
        if not path.is_file():
            continue
        for idx, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if SCOPE_LINE_RE.search(line):
                out.append({"file": name, "line": idx, "text": line.strip()[:500]})
    return out[:200]


def test_anchors(workspace: Path) -> list[dict[str, Any]]:
    roots = ["test", "tests", "pocs", "poc-tests", "submissions/staging", "submissions/ready"]
    out: list[dict[str, Any]] = []
    for root_name in roots:
        root = workspace / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in {".sol", ".md", ".json", ".log"}:
                out.append({"file": str(path.relative_to(workspace)), "kind": root_name})
    return out[:500]


def impact_family_for_path(edges: list[dict[str, Any]]) -> str:
    blob = " ".join(str(edge.get("evidence") or "") for edge in edges).lower()
    stages = {str(edge.get("stage") or "") for edge in edges}
    if "proof_dispute_bridge_finalization" in stages:
        if "bridge" in blob or "withdraw" in blob or "final" in blob:
            return "bridge_finalization"
        if "dispute" in blob or "challenge" in blob:
            return "proof_dispute"
        return "proof_finalization"
    if "state_root" in stages:
        return "state_root_validation"
    if "validation" in stages:
        return "validation_path"
    if "cache_provider" in stages:
        return "cache_provider_path"
    return "source_multihop"


def relation_sink_component(edge: dict[str, Any]) -> str:
    method = str(edge.get("method") or "").strip()
    if "." in method:
        return method
    target = str(edge.get("target_type") or edge.get("target") or edge.get("receiver") or "").strip()
    return f"{target}.{method}".strip(".")


def build_multi_hop_paths(entrypoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for entry in entrypoints:
        edges = [
            edge for edge in entry.get("evidence_edges") or []
            if edge.get("stage") in MULTIHOP_STAGES
        ]
        ordered = sorted(
            edges,
            key=lambda edge: MULTIHOP_STAGES.index(edge.get("stage"))
            if edge.get("stage") in MULTIHOP_STAGES else len(MULTIHOP_STAGES),
        )
        stages = [str(edge.get("stage")) for edge in ordered]
        if len(set(stages)) < 2:
            continue
        missing = [stage for stage in MULTIHOP_STAGES if stage not in stages]
        source_component = f"{entry.get('contract')}.{entry.get('function')}"
        sink_edge = ordered[-1]
        path_id = f"SG-MH-{len(paths) + 1:03d}"
        paths.append({
            "path_id": path_id,
            "source": "semantic_graph",
            "candidate_id": "",
            "impact_family": impact_family_for_path(ordered),
            "source_component": source_component,
            "sink_component": str(sink_edge.get("stage") or ""),
            "path_summary": " -> ".join(stages),
            "evidence_edges": [
                {
                    "edge_id": edge.get("edge_id"),
                    "stage": edge.get("stage"),
                    "file": edge.get("file"),
                    "line": edge.get("line"),
                    "evidence": edge.get("evidence"),
                    "confidence": edge.get("confidence"),
                }
                for edge in ordered
            ],
            "mapped_stages": stages,
            "missing_stages": missing,
            "scanner_coverage": "not_measured",
            "source_reader_coverage": "mapped_by_semantic_graph",
            "impact_contract_id": "",
            "next_action": "route semantic path to exact-impact candidate or mark non-detectorizable",
        })
    return paths


def build_causal_composition_edges(
    entrypoints: list[dict[str, Any]],
    multi_hop_paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    path_by_source: dict[str, list[dict[str, Any]]] = {}
    for path in multi_hop_paths:
        source_component = str(path.get("source_component") or "")
        if not source_component:
            continue
        path_by_source.setdefault(source_component, []).append(path)

    rows: list[dict[str, Any]] = []
    for entry in entrypoints:
        source_component = f"{entry.get('contract')}.{entry.get('function')}"
        source_paths = path_by_source.get(source_component) or []
        relation_rows = [
            row for row in (entry.get("relation_edges") or [])
            if isinstance(row, dict) and relation_sink_component(row)
        ]
        if not source_paths or not relation_rows:
            continue
        for path in source_paths:
            path_evidence_edges = [
                evidence for evidence in (path.get("evidence_edges") or [])
                if isinstance(evidence, dict)
            ]
            for relation in relation_rows:
                rows.append(
                    {
                        "edge_id": f"SG-CC-{len(rows) + 1:03d}",
                        "source": "semantic_graph",
                        "hypothesis_strength": "weak_same_entrypoint_source_shape",
                        "proof_status": "unproved",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "promotion_allowed": False,
                        "impact_family": path.get("impact_family", ""),
                        "source_component": source_component,
                        "path_id": path.get("path_id", ""),
                        "path_summary": path.get("path_summary", ""),
                        "path_stages": path.get("mapped_stages") or [],
                        "path_missing_stages": path.get("missing_stages") or [],
                        "path_evidence_edges": path_evidence_edges,
                        "relation_kind": relation.get("kind", ""),
                        "relation_sink_component": relation_sink_component(relation),
                        "relation_target": relation.get("target_type") or relation.get("target") or "",
                        "relation_method": relation.get("method") or "",
                        "relation_file": relation.get("file", ""),
                        "relation_line": relation.get("line", 0),
                        "relation_evidence": relation.get("evidence", ""),
                        "proof_boundary": (
                            "Same-entrypoint co-occurrence only; no callgraph, runtime order, "
                            "or exploit causality is proven."
                        ),
                        "next_action": (
                            "Prove or kill this path-to-sink hypothesis with local source review "
                            "before detector promotion, harness work, or report drafting."
                        ),
                    }
                )
    return rows


def _cross_domain_kind(body: str) -> tuple[str, str, str] | None:
    """Return (edge_kind, source_domain, target_domain) if body crosses a domain.

    Returns None when neither cross-domain pattern fires, so ordinary
    same-domain edges are never annotated.
    """
    if CROSS_DOMAIN_SOL_TO_COSMOS_RE.search(body):
        return ("sol-to-cosmos-dispatch", _DOMAIN_SOL_TO_COSMOS[0], _DOMAIN_SOL_TO_COSMOS[1])
    if CROSS_DOMAIN_EVM_BRIDGE_RE.search(body):
        return ("evm-bridge-proof-domain", _DOMAIN_EVM_L1_L2[0], _DOMAIN_EVM_L1_L2[1])
    return None


def build_cross_domain_edges(
    contracts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Scan all contract function bodies for cross-domain dispatch patterns.

    For each function whose body contains a cross-domain indicator, emit one
    cross-domain edge record. The record is ADDITIVE - it does not replace or
    modify any existing relation_edge or evidence_edge.

    Schema (per edge):
      edge_id       : str  - "SG-CD-NNN"
      source        : str  - "semantic_graph"
      cross_domain  : true - always true; negative-control functions never appear
      edge_kind     : str  - one of "sol-to-cosmos-dispatch" | "evm-bridge-proof-domain"
      source_domain : str  - e.g. "evm_solidity" or "evm_l1"
      target_domain : str  - e.g. "cosmos_appchain" or "evm_l2"
      source_contract : str
      source_function : str
      file          : str
      line          : int
      evidence      : str  - snippet (first match, 120 chars)
      confidence    : "source-shape"
      hypothesis_strength : "weak_pattern_match"
      proof_status  : "unproved"
      submission_posture : "NOT_SUBMIT_READY"
    """
    rows: list[dict[str, Any]] = []
    for contract in contracts:
        for fn in contract.get("functions") or []:
            # Reconstruct approximate body text from evidence edges + external
            # call list to avoid re-reading source files. We use the function's
            # evidence text as a proxy - it contains the matched snippets. We
            # also join external_calls and the function name to get the widest
            # pattern surface from the already-parsed data.
            # NOTE: for the cross-domain patterns we need the ORIGINAL body
            # text. The contract dict carries no raw body, so we join all
            # available text fragments: evidence edge snippets, external_calls,
            # emits, state_writes. This is conservative (may miss some),
            # intentionally so - better a false-negative than a false-positive.
            body_proxy = " ".join([
                fn.get("name") or "",
                " ".join(fn.get("external_calls") or []),
                " ".join(fn.get("emits") or []),
                " ".join(
                    " ".join(filter(None, [edge.get("evidence"), edge.get("method"), edge.get("target")]))
                    for edge in (fn.get("relation_edges") or [])
                ),
                " ".join(
                    (edge.get("evidence") or "")
                    for edge in (fn.get("evidence_edges") or [])
                ),
            ])
            result = _cross_domain_kind(body_proxy)
            if result is None:
                continue
            edge_kind, source_domain, target_domain = result
            # Find first matching snippet for evidence field.
            m = (
                CROSS_DOMAIN_SOL_TO_COSMOS_RE.search(body_proxy)
                if edge_kind == "sol-to-cosmos-dispatch"
                else CROSS_DOMAIN_EVM_BRIDGE_RE.search(body_proxy)
            )
            evidence_snippet = (m.group(0) if m else edge_kind)[:120]
            rows.append({
                "edge_id": f"SG-CD-{len(rows) + 1:03d}",
                "source": "semantic_graph",
                "cross_domain": True,
                "edge_kind": edge_kind,
                "source_domain": source_domain,
                "target_domain": target_domain,
                "source_contract": contract.get("name") or "",
                "source_function": fn.get("name") or "",
                "file": contract.get("file") or "",
                "line": fn.get("line") or 0,
                "evidence": evidence_snippet,
                "confidence": "source-shape",
                "hypothesis_strength": "weak_pattern_match",
                "proof_status": "unproved",
                "submission_posture": "NOT_SUBMIT_READY",
            })
    return rows


def build_graph(workspace: Path, roots: list[Path] | None = None) -> dict[str, Any]:
    contracts: list[dict[str, Any]] = []
    for path in iter_solidity_files(workspace, roots=roots):
        try:
            contracts.extend(parse_solidity_file(workspace, path))
        except OSError:
            continue
    entrypoints = []
    relation_edges = []
    evidence_edges = []
    for contract in contracts:
        for fn in contract.get("functions", []):
            relation_edges.extend(fn.get("relation_edges") or [])
            evidence_edges.extend(fn.get("evidence_edges") or [])
            if fn.get("externally_reachable"):
                entrypoints.append({
                    "contract": contract["name"],
                    "file": contract["file"],
                    "function": fn["name"],
                    "line": fn["line"],
                    "role": fn["role"],
                    "privileged": fn["privileged"],
                    "state_writes": fn["state_writes"],
                    "value_movement": fn["value_movement"],
                    "external_calls": fn["external_calls"],
                    "relation_edges": fn.get("relation_edges") or [],
                    "evidence_edges": fn.get("evidence_edges") or [],
                })
    multi_hop_paths = build_multi_hop_paths(entrypoints)
    causal_composition_edges = build_causal_composition_edges(entrypoints, multi_hop_paths)
    cross_domain_edges = build_cross_domain_edges(contracts)
    return {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "source_file_count": sum(1 for _ in iter_solidity_files(workspace, roots=roots)),
        "contract_count": len(contracts),
        "entrypoint_count": len(entrypoints),
        "relation_edge_count": len(relation_edges),
        "evidence_edge_count": len(evidence_edges),
        "multi_hop_path_count": len(multi_hop_paths),
        "causal_composition_edge_count": len(causal_composition_edges),
        "cross_domain_edge_count": len(cross_domain_edges),
        "contracts": contracts,
        "entrypoints": entrypoints,
        "relation_edges": relation_edges,
        "evidence_edges": evidence_edges,
        "multi_hop_paths": multi_hop_paths,
        "causal_composition_edges": causal_composition_edges,
        "cross_domain_edges": cross_domain_edges,
        "scope_annotations": scope_annotations(workspace),
        "test_anchors": test_anchors(workspace),
    }


def render_markdown(graph: dict[str, Any]) -> str:
    lines = [
        "# Auditooor Semantic Graph",
        "",
        f"- schema: `{graph['schema_version']}`",
        f"- source files: {graph['source_file_count']}",
        f"- contracts: {graph['contract_count']}",
        f"- external/public entrypoints: {graph['entrypoint_count']}",
        f"- relation edges: {graph.get('relation_edge_count', 0)}",
        f"- evidence edges: {graph.get('evidence_edge_count', 0)}",
        f"- multi-hop paths: {graph.get('multi_hop_path_count', 0)}",
        f"- causal composition edges: {graph.get('causal_composition_edge_count', 0)}",
        f"- cross-domain edges: {graph.get('cross_domain_edge_count', 0)}",
        "",
        "## High-Impact Entry Points",
        "",
    ]
    interesting = [
        e for e in graph.get("entrypoints", [])
        if e.get("value_movement") or e.get("external_calls") or e.get("state_writes")
    ]
    if not interesting:
        lines.extend(["No high-impact entrypoints detected by the v1 graph.", ""])
        return "\n".join(lines)
    lines.extend(["| Contract | Function | Role | Writes | Value/Calls |", "|---|---|---|---|---|"])
    for row in interesting[:200]:
        value = []
        if row.get("value_movement"):
            value.append("value")
        if row.get("external_calls"):
            value.append("external-call")
        lines.append(
            "| {contract} | `{function}` | {role} | {writes} | {value} |".format(
                contract=row.get("contract", ""),
                function=row.get("function", ""),
                role=row.get("role", ""),
                writes=", ".join(row.get("state_writes") or []) or "-",
                value=", ".join(value) or "-",
            )
        )
    lines.append("")
    relation_edges = graph.get("relation_edges") if isinstance(graph.get("relation_edges"), list) else []
    if relation_edges:
        lines.extend([
            "## Cross-Contract Relation Edges",
            "",
            "| Kind | Source | Target | Evidence |",
            "|---|---|---|---|",
        ])
        for edge in relation_edges[:200]:
            lines.append(
                "| {kind} | `{source}.{function}` | `{target}` | `{evidence}` |".format(
                    kind=edge.get("kind", ""),
                    source=edge.get("source_contract", ""),
                    function=edge.get("source_function", ""),
                    target=edge.get("target") or "-",
                    evidence=edge.get("evidence") or edge.get("method") or "-",
                )
            )
        lines.append("")
    multi_hop_paths = graph.get("multi_hop_paths") if isinstance(graph.get("multi_hop_paths"), list) else []
    if multi_hop_paths:
        lines.extend([
            "## Multi-Hop Evidence Paths",
            "",
            "| Path | Impact Family | Source | Stages | Missing | Next Action |",
            "|---|---|---|---|---|---|",
        ])
        for path in multi_hop_paths[:200]:
            lines.append(
                "| `{path_id}` | {family} | `{source}` | {stages} | {missing} | {next_action} |".format(
                    path_id=path.get("path_id", ""),
                    family=path.get("impact_family", ""),
                    source=path.get("source_component", ""),
                    stages=" -> ".join(path.get("mapped_stages") or []),
                    missing=", ".join(path.get("missing_stages") or []) or "-",
                    next_action=path.get("next_action", ""),
                )
            )
        lines.append("")
    causal_edges = (
        graph.get("causal_composition_edges")
        if isinstance(graph.get("causal_composition_edges"), list)
        else []
    )
    if causal_edges:
        lines.extend([
            "## Causal Composition Hypotheses",
            "",
            "Weak same-entrypoint path-to-sink hypotheses. These rows are proof-first and not causal proof.",
            "",
            "| Edge | Impact Family | Source | Relation Sink | Strength |",
            "|---|---|---|---|---|",
        ])
        for edge in causal_edges[:200]:
            lines.append(
                "| `{edge_id}` | {family} | `{source}` | `{sink}` | `{strength}` |".format(
                    edge_id=edge.get("edge_id", ""),
                    family=edge.get("impact_family", ""),
                    source=edge.get("source_component", ""),
                    sink=edge.get("relation_sink_component", ""),
                    strength=edge.get("hypothesis_strength", ""),
                )
            )
        lines.append("")
    cross_domain_edges = (
        graph.get("cross_domain_edges")
        if isinstance(graph.get("cross_domain_edges"), list)
        else []
    )
    if cross_domain_edges:
        lines.extend([
            "## Cross-Domain Edges",
            "",
            "Pattern-matched domain-boundary crossings (source-shape only; NOT causal proof).",
            "",
            "| Edge | Kind | Source Domain | Target Domain | Source | Evidence |",
            "|---|---|---|---|---|---|",
        ])
        for edge in cross_domain_edges[:200]:
            lines.append(
                "| `{edge_id}` | {kind} | {src_dom} | {tgt_dom} | `{source}` | `{evidence}` |".format(
                    edge_id=edge.get("edge_id", ""),
                    kind=edge.get("edge_kind", ""),
                    src_dom=edge.get("source_domain", ""),
                    tgt_dom=edge.get("target_domain", ""),
                    source=f"{edge.get('source_contract', '')}.{edge.get('source_function', '')}",
                    evidence=edge.get("evidence", "-"),
                )
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--root", action="append", default=[], type=Path, help="Limit fresh scanning to this workspace-relative file/dir. Repeatable.")
    parser.add_argument("--from-graph", type=Path, help="Select a scoped graph from an existing semantic graph sidecar instead of rescanning.")
    parser.add_argument("--scoped", action="store_true", help="Write a bounded semantic/live-depth graph selection.")
    parser.add_argument("--target-items", type=int, default=DEFAULT_SCOPED_TARGET)
    parser.add_argument("--min-items", type=int, default=DEFAULT_SCOPED_MIN)
    parser.add_argument("--max-items", type=int, default=DEFAULT_SCOPED_MAX)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[semantic-graph] ERR workspace not found: {ws}", file=sys.stderr, flush=True)
        return 2
    if args.scoped:
        graph = build_or_select_scoped_graph(
            ws,
            roots=args.root,
            from_graph=args.from_graph,
            target_items=args.target_items,
            min_items=args.min_items,
            max_items=args.max_items,
        )
    elif args.from_graph:
        graph = load_graph(args.from_graph.expanduser().resolve())
    else:
        graph = build_graph(ws, roots=args.root)
    out_json = args.out_json or (ws / ".auditooor" / ("semantic_graph.scoped.json" if args.scoped else "semantic_graph.json"))
    out_md = args.out_md or (ws / ".auditooor" / ("semantic_graph.scoped.md" if args.scoped else "semantic_graph.md"))
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(graph), encoding="utf-8")
    if args.print_json:
        print(json.dumps(graph, indent=2, sort_keys=True))
    print(
        f"[semantic-graph] OK contracts={graph['contract_count']} "
        f"entrypoints={graph['entrypoint_count']} "
        f"relation_edges={graph.get('relation_edge_count', 0)} "
        f"multi_hop_paths={graph.get('multi_hop_path_count', 0)} "
        f"causal_composition_edges={graph.get('causal_composition_edge_count', 0)} "
        f"cross_domain_edges={graph.get('cross_domain_edge_count', 0)} "
        f"selection_mode={graph.get('selection_mode', 'full')} json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
