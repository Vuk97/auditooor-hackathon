"""Candidate-level production-path dossier helpers.

The dossier is the bridge between source/deep candidates and PoC work. It is
deliberately conservative: missing evidence stays `needs_poc`, and privileged,
mock-only, project-inaction, or contradicted paths become `unsafe_to_submit`.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.production_path_dossier.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]

RISK_RE = re.compile(
    r"\b(admin|guardian|owner|governance|multisig|privileged|blacklist|retire|"
    r"compromised|invalid\s+TEE|invalid\s+ZK|forged?\s+proof|mock|mockverifier|"
    r"project\s+inaction|will\s+not\s+blacklist|base\s+does\s+not|operator\s+does\s+not)\b",
    re.IGNORECASE,
)
NATURAL_RE = re.compile(r"\b(time|price|market|liquidity|deposit|withdraw|settle|oracle|auction)\b", re.IGNORECASE)
FUNDS_RE = re.compile(r"\b(steal|theft|drain|fund|token|balance|transfer|withdraw|redeem|claim|bond|reward)\b", re.IGNORECASE)
FREEZE_RE = re.compile(r"\b(freeze|brick|stuck|lock|halt|dos|denial|cannot\s+withdraw)\b", re.IGNORECASE)
ACCOUNTING_RE = re.compile(r"\b(accounting|shares?|rounding|solvency|debt|collateral|invariant)\b", re.IGNORECASE)
CHALLENGE_RE = re.compile(r"\b(challenge|dispute|proof|verifier|finali[sz]e|blacklist|guardian|game)\b", re.IGNORECASE)
SOURCE_ONLY_RE = re.compile(r"\b(source[-\s]?only|pre[-\s]?deployment|no\s+live\s+deployment)\b", re.IGNORECASE)
GO_FUNC_RE = re.compile(
    r"(?m)^func\s+(?:\((?P<receiver>[^)]*)\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
GO_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*\(")
GO_WRITE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*(?:=|:=|\+=|-=|\*=|/=|\+\+|--)")
GO_DEFAULT_EXCLUDES = {
    ".git",
    ".auditooor",
    "build",
    "dist",
    "mock",
    "mocks",
    "node_modules",
    "out",
    "poc-tests",
    "test",
    "testdata",
    "tests",
    "third_party",
    "third-party",
    "vendor",
}
GO_GENERATED_SUFFIXES = (".pb.go", ".pb.gw.go", ".mock.go", "_mock.go", ".gen.go", "_generated.go")
GO_ABCI_ENTRYPOINTS = {
    "BeginBlock",
    "BeginBlocker",
    "CheckTx",
    "DeliverTx",
    "EndBlock",
    "EndBlocker",
    "FinalizeBlock",
    "PrepareProposal",
    "ProcessProposal",
}
GO_VOTE_EXTENSION_ENTRYPOINTS = {"ExtendVote", "VerifyVoteExtension"}


def _is_go_excluded_rel(rel: str) -> bool:
    path = Path(rel)
    parts = set(path.parts[:-1])
    if parts & GO_DEFAULT_EXCLUDES:
        return True
    name = path.name
    if name.startswith("zz_generated") or name.endswith("_test.go") or name.endswith(GO_GENERATED_SUFFIXES):
        return True
    return False


def _rust_graph_signal(graph: dict[str, Any]) -> tuple[int, int, int, int]:
    runtime_calls = 0
    rpc_routes = 0
    route_runtime_calls = 0
    entrypoints = 0
    crate_count = 0
    for crate_name, body in graph.items():
        if crate_name == "_meta" or not isinstance(body, dict):
            continue
        crate_count += 1
        entrypoints += len(body.get("entrypoints", []) or [])
        runtime_calls += len(body.get("runtime_calls", []) or [])
        runtime_calls += len(body.get("trait_impl_methods", []) or [])
        runtime_calls += len(body.get("enum_dispatches", []) or [])
        routes = body.get("rpc_routes", []) or []
        rpc_routes += len(routes)
        for route in routes:
            if isinstance(route, dict):
                route_runtime_calls += len(route.get("runtime_calls", []) or [])
    return runtime_calls + route_runtime_calls, rpc_routes, entrypoints, crate_count


def _load_best_rust_source_graph(workspace: Path) -> tuple[Path | None, dict[str, Any]]:
    auditooor = workspace / ".auditooor"
    default_path = auditooor / "rust_source_graph.json"
    paths: list[Path] = []
    if default_path.is_file():
        paths.append(default_path)
    if auditooor.is_dir():
        for path in sorted(auditooor.glob("rust_source_graph.*.json")):
            if path not in paths:
                paths.append(path)

    best_path: Path | None = None
    best_data: dict[str, Any] = {}
    best_signal = (-1, -1, -1, -1)
    for path in paths:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(raw, dict):
            continue
        signal = _rust_graph_signal(raw)
        if signal > best_signal:
            best_path = path
            best_data = raw
            best_signal = signal
    return best_path, best_data


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    in_string = ""
    escaped = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = ""
            continue
        if ch in {'"', "'", "`"}:
            in_string = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text) - 1


def _iter_go_files(workspace: Path) -> list[Path]:
    out: list[Path] = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = sorted(
            d for d in dirs
            if d not in GO_DEFAULT_EXCLUDES
        )
        for name in sorted(files):
            if not name.endswith(".go"):
                continue
            path = Path(root) / name
            try:
                rel = path.relative_to(workspace)
            except ValueError:
                continue
            if _is_go_excluded_rel(rel.as_posix()):
                continue
            out.append(path)
    return out


def _go_signature_from_source(raw: str, start: int, brace: int) -> str:
    if brace >= start:
        return raw[start:brace]
    line_end = raw.find("\n", start)
    if line_end < 0:
        return raw[start:]
    return raw[start:line_end]


def _is_go_msg_server_handler(
    rel: str,
    receiver: str,
    name: str,
    signature: str = "",
    params: list[Any] | None = None,
    return_types: list[Any] | None = None,
) -> bool:
    rel_l = rel.lower()
    base = Path(rel_l).name
    receiver_l = _go_receiver_family(receiver).lower()
    if not (base.startswith("msg_server") or receiver_l == "msgserver"):
        return False
    if not name or name.startswith("_") or not name[0].isupper():
        return False
    if name == "NewMsgServerImpl" or name.startswith("New"):
        return False
    sig_text = " ".join(
        [
            signature,
            " ".join(str((p or {}).get("type") or "") for p in (params or []) if isinstance(p, dict)),
            " ".join(str(r) for r in (return_types or [])),
        ]
    )
    return (
        "context.Context" in sig_text
        and re.search(r"\*types\.Msg[A-Za-z0-9_]+", sig_text)
        and "Response" in sig_text
        and re.search(r"\berror\b", sig_text)
    )


def _is_go_abci_handler_name(name: str) -> bool:
    if name in GO_ABCI_ENTRYPOINTS:
        return True
    if name.endswith("Handler"):
        return any(entry in name for entry in {"PrepareProposal", "ProcessProposal"})
    return False


def _is_go_vote_extension_handler_name(name: str) -> bool:
    if name in GO_VOTE_EXTENSION_ENTRYPOINTS:
        return True
    if name.endswith("Handler"):
        return any(entry in name for entry in GO_VOTE_EXTENSION_ENTRYPOINTS)
    return False


def _is_go_ante_handler(rel: str, receiver: str, name: str) -> bool:
    rel_l = rel.lower()
    receiver_l = _go_receiver_family(receiver).lower()
    return name == "AnteHandle" and (
        "/ante/" in rel_l or rel_l.endswith("/ante.go") or "decorator" in receiver_l or "ante" in receiver_l
    )


def _go_production_kind(
    rel: str,
    receiver: str,
    name: str,
    signature: str = "",
    params: list[Any] | None = None,
    return_types: list[Any] | None = None,
) -> str:
    rel_l = rel.lower()
    receiver_l = _go_receiver_family(receiver).lower()
    if _is_go_abci_handler_name(name):
        return "cosmos_abci_entrypoint"
    if _is_go_vote_extension_handler_name(name):
        return "cosmos_vote_extension_entrypoint"
    if _is_go_msg_server_handler(rel, receiver, name, signature, params, return_types):
        return "cosmos_msg_server"
    if _is_go_ante_handler(rel, receiver, name):
        return "cosmos_ante_handler"
    if "/keeper/" in rel_l or receiver_l.endswith("keeper"):
        return "cosmos_keeper_method"
    if "iavl" in rel_l:
        return "iavl_storage_method"
    if "cometbft" in rel_l or "comet" in rel_l:
        return "cometbft_consensus_method"
    return ""


def _go_call_edges_from_body(
    *,
    body: str,
    body_offset: int,
    source_text: str,
    rel: str,
    receiver: str,
    name: str,
    kind: str,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    role = _go_role_for_kind(kind)
    for match in GO_CALL_RE.finditer(body):
        call = match.group(1)
        if call in seen:
            continue
        seen.add(call)
        edges.append(
            {
                "kind": "go_call",
                "source_contract": _go_receiver_family(receiver) or "package",
                "source_function": name,
                "target": call,
                "method": call,
                "file": rel,
                "line": _line_for_offset(source_text, body_offset + match.start()),
                "role": role,
                "evidence": "go-cosmos-source-call",
                "confidence": "source-shape",
                "lang": "go",
            }
        )
        if len(edges) >= 20:
            break
    return edges


def _call_name_segments(value: str) -> set[str]:
    return {
        part
        for part in re.split(r"[^a-z0-9_]+", value.lower())
        if part
    }


def _structured_call_match(structured: str, source_function: str, target: str, method: str) -> bool:
    if not structured:
        return False
    if structured in {source_function, target}:
        return True
    if len(structured) < 4:
        return False
    return structured in (_call_name_segments(target) | _call_name_segments(method))


def _go_receiver_family(receiver: str) -> str:
    text = re.sub(r"[*\[\]]", " ", str(receiver or ""))
    parts = [part for part in re.split(r"\s+", text.strip()) if part]
    return parts[-1] if parts else ""


def _go_role_for_kind(kind: str) -> str:
    if kind in {
        "cosmos_abci_entrypoint",
        "cosmos_vote_extension_entrypoint",
        "cosmos_msg_server",
        "cosmos_ante_handler",
    }:
        return "permissionless"
    if kind in {"cosmos_keeper_method", "iavl_storage_method", "cometbft_consensus_method"}:
        return "cosmos-internal"
    return ""


def _sig_extract_paths(workspace: Path) -> list[Path]:
    paths = [
        workspace / ".auditooor" / "go_sig_extracts.jsonl",
        workspace / ".auditooor" / "sig_extracts.jsonl",
    ]
    workspace_l = str(workspace).lower()
    if workspace.name.lower() == "dydx" or "/dydx" in workspace_l:
        paths.append(REPO_ROOT / "audit" / "sig_extracts" / "dydx-v4-chain.jsonl")
    out: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        if path.is_file():
            out.append(path)
    return out


def _sig_extract_rows(workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    sources: list[str] = []
    for path in _sig_extract_paths(workspace):
        sources.append(str(path))
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and str(row.get("language") or "").lower() in {"", "go"}:
                rows.append(row)
    return rows, sources


def _sig_extract_entrypoints(workspace: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    entries: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    rows, sources = _sig_extract_rows(workspace)
    seen_entries: set[tuple[str, str, int]] = set()
    for row in rows:
        rel = str(row.get("file_path") or "").replace("\\", "/")
        if not rel:
            continue
        if _is_go_excluded_rel(rel):
            continue
        name = str(row.get("function_name") or "")
        receiver = str(row.get("receiver_type") or "")
        kind = _go_production_kind(
            rel,
            receiver,
            name,
            str(row.get("function_signature") or ""),
            row.get("params") if isinstance(row.get("params"), list) else [],
            row.get("return_types") if isinstance(row.get("return_types"), list) else [],
        )
        if not kind:
            continue
        line = int(row.get("line_start") or 0)
        key = (rel, name, line)
        if key in seen_entries:
            continue
        seen_entries.add(key)
        calls = [
            str(call)
            for call in row.get("calls_made", [])
            if isinstance(call, str) and call.strip()
        ]
        entries.append(
            {
                "contract": receiver or "package",
                "function": name,
                "file": rel,
                "line": line,
                "role": _go_role_for_kind(kind),
                "privileged": False,
                "state_writes": [],
                "value_movement": bool(re.search(r"\b(bank|SendCoins|Transfer|withdraw|deposit|fund|collateral)\b", " ".join(calls), re.IGNORECASE)),
                "external_calls": [],
                "relation_edges": [],
                "lang": "go",
                "kind": kind,
                "receiver": receiver,
                "function_signature": row.get("function_signature", ""),
                "guards_detected": row.get("guards_detected", []),
                "evidence": "go-sig-extract",
            }
        )
        for call in calls[:20]:
            edges.append(
                {
                    "kind": "go_call",
                    "source_contract": receiver or "package",
                    "source_function": name,
                    "target": call,
                    "method": call,
                    "file": rel,
                    "line": line,
                    "role": _go_role_for_kind(kind),
                    "evidence": "go-sig-extract-calls_made",
                    "confidence": "source-shape",
                    "lang": "go",
                }
            )
    return entries, edges, sources


def _load_go_cosmos_source_graph(workspace: Path) -> dict[str, Any]:
    sig_entries, sig_edges, sig_sources = _sig_extract_entrypoints(workspace)
    entries: list[dict[str, Any]] = list(sig_entries)
    relation_edges: list[dict[str, Any]] = list(sig_edges)
    seen_entries = {
        (str(entry.get("file") or ""), str(entry.get("function") or ""), int(entry.get("line") or 0))
        for entry in entries
    }
    files_scanned = 0
    for path in _iter_go_files(workspace):
        files_scanned += 1
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            rel = path.relative_to(workspace).as_posix()
        except ValueError:
            rel = str(path)
        for match in GO_FUNC_RE.finditer(raw):
            name = match.group("name") or ""
            receiver = match.group("receiver") or ""
            brace = raw.find("{", match.end())
            next_func = raw.find("\nfunc ", match.end())
            signature = _go_signature_from_source(raw, match.start(), brace)
            kind = _go_production_kind(rel, receiver, name, signature)
            if not kind:
                continue
            if brace < 0 or (next_func >= 0 and next_func < brace):
                body = ""
            else:
                end = _find_matching_brace(raw, brace)
                body = raw[brace : end + 1]
            relation_edges.extend(
                _go_call_edges_from_body(
                    body=body,
                    body_offset=brace if brace >= 0 else match.end(),
                    source_text=raw,
                    rel=rel,
                    receiver=receiver,
                    name=name,
                    kind=kind,
                )
            )
            state_writes = sorted({m.group(1) for m in GO_WRITE_RE.finditer(body)})[:20]
            key = (rel, name, _line_for_offset(raw, match.start()))
            if key in seen_entries:
                continue
            seen_entries.add(key)
            entries.append(
                {
                    "contract": _go_receiver_family(receiver) or "package",
                    "function": name,
                    "file": rel,
                    "line": _line_for_offset(raw, match.start()),
                    "role": _go_role_for_kind(kind),
                    "privileged": False,
                    "state_writes": state_writes,
                    "value_movement": bool(re.search(r"\b(bank|SendCoins|Transfer|withdraw|deposit|fund|collateral)\b", body, re.IGNORECASE)),
                    "external_calls": [],
                    "relation_edges": [],
                    "lang": "go",
                    "kind": kind,
                    "receiver": _go_receiver_family(receiver),
                    "evidence": "go-cosmos-source-shape",
                }
            )
    return {
        "_meta": {
            "schema_version": "auditooor.go_cosmos_source_graph.v1",
            "files_scanned": files_scanned,
            "entrypoint_count": len(entries),
            "relation_edge_count": len(relation_edges),
            "sig_extract_sources": sig_sources,
            "sig_extract_entrypoint_count": len(sig_entries),
            "heuristic": "regex source-shape over Go/Cosmos production entrypoint names and keeper/msg_server/ante/iavl paths",
        },
        "entrypoints": entries,
        "relation_edges": relation_edges,
    }


def load_graph(workspace: Path) -> dict[str, Any]:
    path = workspace / ".auditooor" / "semantic_graph.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        graph: dict[str, Any] = data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        graph = {}
    go_graph = _load_go_cosmos_source_graph(workspace)
    go_entries = go_graph.get("entrypoints") if isinstance(go_graph, dict) else []
    if isinstance(go_entries, list) and go_entries:
        graph["_go_cosmos_source_graph"] = go_graph.get("_meta", {})
        graph["entrypoints"] = list(graph.get("entrypoints") or []) + go_entries
        graph["relation_edges"] = list(graph.get("relation_edges") or []) + list(go_graph.get("relation_edges") or [])
    # P1-2 burn-down: if a Rust source graph exists, merge its
    # per-crate entrypoints into the same `entrypoints` list the
    # Solidity dossier already consumes. Each rust crate.entrypoint is
    # promoted into the same shape as a Solidity entrypoint
    # (file/function/contract/role/...) so `_entrypoint_matches` works
    # without language-specific branches. Rust crates expose no
    # Slither role/visibility info; we mark `role: permissionless`
    # since the rust-source-graph entrypoint heuristic only fires on
    # `pub fn` under a contract attribute or at lib.rs top-level —
    # i.e. an externally-callable surface. Privileged-ness is
    # rediscovered by the existing precondition classifier from the
    # candidate text (RISK_RE etc.).
    rust_path, rust_data = _load_best_rust_source_graph(workspace)
    if rust_data:
        graph["_rust_source_graph_path"] = str(rust_path) if rust_path else ""
        merged_entries = list(graph.get("entrypoints") or [])
        merged_edges = list(graph.get("relation_edges") or [])
        for crate_name, body in rust_data.items():
            if crate_name == "_meta" or not isinstance(body, dict):
                continue
            for entry in body.get("entrypoints", []) or []:
                if not isinstance(entry, dict):
                    continue
                merged_entries.append({
                    "contract": crate_name,
                    "function": entry.get("fn", ""),
                    "file": entry.get("file", ""),
                    "line": entry.get("line", 0),
                    "role": "permissionless",
                    "privileged": False,
                    "state_writes": [],
                    "value_movement": False,
                    "external_calls": [],
                    "relation_edges": [],
                    "lang": "rust",
                    "kind": entry.get("kind", ""),
                    "rpc_method": entry.get("rpc_method", ""),
                    "cfg_attrs": entry.get("cfg_attrs", []),
                    "rpc_trait_cfg_attrs": entry.get("rpc_trait_cfg_attrs", []),
                })
            for call in body.get("runtime_calls", []) or []:
                if not isinstance(call, dict):
                    continue
                merged_edges.append({
                    "kind": "rust_runtime_call",
                    "source_contract": crate_name,
                    "source_function": "",
                    "target": call.get("call", ""),
                    "method": call.get("snippet", ""),
                    "file": call.get("file", ""),
                    "line": call.get("line", 0),
                    "role": "permissionless",
                    "evidence": "rust-runtime-call",
                    "confidence": "source-shape",
                    "lang": "rust",
                })
            for route in body.get("rpc_routes", []) or []:
                if not isinstance(route, dict):
                    continue
                merged_edges.append({
                    "kind": "rust_rpc_route",
                    "source_contract": crate_name,
                    "source_function": route.get("fn", ""),
                    "target": route.get("rpc_method", ""),
                    "method": f"{route.get('impl_file', '')}:{route.get('impl_line', '')}",
                    "file": route.get("file", ""),
                    "line": route.get("line", 0),
                    "role": "permissionless",
                    "evidence": "rust-rpc-route",
                    "confidence": "source-shape",
                    "lang": "rust",
                    "cfg_attrs": route.get("cfg_attrs", []),
                    "rpc_trait_cfg_attrs": route.get("rpc_trait_cfg_attrs", []),
                    "impl_cfg_attrs": route.get("impl_cfg_attrs", []),
                    "impl_method_cfg_attrs": route.get("impl_method_cfg_attrs", []),
                })
                for call in route.get("runtime_calls", []) or []:
                    if not isinstance(call, dict):
                        continue
                    merged_edges.append({
                        "kind": "rust_rpc_runtime_call",
                        "source_contract": crate_name,
                        "source_function": route.get("fn", ""),
                        "target": call.get("call", ""),
                        "method": call.get("snippet", ""),
                        "file": call.get("file", ""),
                        "line": call.get("line", 0),
                        "role": "permissionless",
                        "evidence": "rust-rpc-route-runtime-call",
                        "confidence": "source-shape",
                        "lang": "rust",
                        "rpc_method": route.get("rpc_method", ""),
                        "route_file": route.get("file", ""),
                        "route_line": route.get("line", 0),
                    })
            for method in body.get("trait_impl_methods", []) or []:
                if not isinstance(method, dict):
                    continue
                merged_edges.append({
                    "kind": "rust_trait_impl_method",
                    "source_contract": crate_name,
                    "source_function": method.get("fn", ""),
                    "target": method.get("trait", ""),
                    "method": f"{method.get('struct', '')}::{method.get('fn', '')}",
                    "file": method.get("file", ""),
                    "line": method.get("line", 0),
                    "role": "permissionless",
                    "evidence": "rust-trait-impl-method",
                    "confidence": method.get("confidence", "source-shape"),
                    "lang": "rust",
                    "trait_decl_file": method.get("trait_decl_file", ""),
                    "trait_decl_line": method.get("trait_decl_line", 0),
                    "impl_trait": method.get("impl_trait", ""),
                    "impl_cfg_attrs": method.get("impl_cfg_attrs", []),
                    "cfg_attrs": method.get("cfg_attrs", []),
                })
                for call in method.get("runtime_calls", []) or []:
                    if not isinstance(call, dict):
                        continue
                    merged_edges.append({
                        "kind": "rust_trait_impl_runtime_call",
                        "source_contract": crate_name,
                        "source_function": method.get("fn", ""),
                        "target": call.get("call", ""),
                        "method": call.get("snippet", ""),
                        "file": call.get("file", ""),
                        "line": call.get("line", 0),
                        "role": "permissionless",
                        "evidence": "rust-trait-impl-runtime-call",
                        "confidence": "source-shape",
                        "lang": "rust",
                        "trait": method.get("trait", ""),
                        "impl_struct": method.get("struct", ""),
                    })
            for dispatch in body.get("enum_dispatches", []) or []:
                if not isinstance(dispatch, dict):
                    continue
                merged_edges.append({
                    "kind": "rust_enum_dispatch",
                    "source_contract": crate_name,
                    "source_function": "",
                    "target": dispatch.get("target", ""),
                    "method": f"{dispatch.get('enum', '')}::{dispatch.get('variant', '')}",
                    "file": dispatch.get("file", ""),
                    "line": dispatch.get("line", 0),
                    "role": "permissionless",
                    "evidence": dispatch.get("dispatch_kind", "rust-enum-dispatch"),
                    "confidence": dispatch.get("confidence", "source-shape"),
                    "lang": "rust",
                    "enum": dispatch.get("enum", ""),
                    "variant": dispatch.get("variant", ""),
                    "snippet": dispatch.get("snippet", ""),
                })
        graph["entrypoints"] = merged_entries
        graph["relation_edges"] = merged_edges
    # Wave 2: cross-crate import graph. When a finding spans two
    # in-workspace Rust crates, every `use other_crate::...` edge in
    # the cross-crate graph becomes a `cross_crate_call` relation edge
    # in the same shape the Solidity dossier already consumes (so the
    # `_relation_edge_matches` and dossier reporting paths get a Rust
    # signal without a language-specific branch). Heuristic limit:
    # a `use` does not prove a runtime call; it proves the symbol is
    # imported. The dossier surfaces it as `confidence: source-shape`
    # so the consumer can downgrade if the actual call site is needed.
    cross_path = workspace / ".auditooor" / "rust_cross_crate_graph.json"
    try:
        cross_raw = json.loads(cross_path.read_text(encoding="utf-8"))
        cross_data = cross_raw if isinstance(cross_raw, dict) else {}
    except (OSError, ValueError):
        cross_data = {}
    if cross_data:
        merged_edges = list(graph.get("relation_edges") or [])
        for edge in cross_data.get("edges", []) or []:
            if not isinstance(edge, dict):
                continue
            merged_edges.append({
                "kind": "cross_crate_call",
                "source_contract": edge.get("from_crate", ""),
                "source_function": "",
                "target": edge.get("to_crate", ""),
                "method": edge.get("to_path", ""),
                "file": edge.get("from_file", ""),
                "line": 0,
                "role": "permissionless",
                "evidence": "rust-use-import",
                "confidence": "source-shape",
                "lang": "rust",
            })
        graph["relation_edges"] = merged_edges
    # P0-2 Wave C-2B: load cross-crate dispatch edges (with concrete/abstract
    # confidence annotations) and surface them as typed relation edges so the
    # dossier can cite concrete dispatch hops in the production_path chain.
    if cross_data:
        merged_edges = list(graph.get("relation_edges") or [])
        for edge in cross_data.get("cross_crate_dispatch", []) or []:
            if not isinstance(edge, dict):
                continue
            merged_edges.append({
                "kind": "rust_cross_crate_dispatch",
                "source_contract": edge.get("impl_crate", ""),
                "source_function": edge.get("target_method", ""),
                "target": edge.get("trait_decl_crate", ""),
                "method": f"{edge.get('struct_name', '')}::{edge.get('target_method', '')}",
                "file": edge.get("site_file", ""),
                "line": edge.get("site_line", 0),
                "role": "permissionless",
                "evidence": "rust-cross-crate-dispatch",
                "confidence": edge.get("confidence", "source-shape"),
                "lang": "rust",
                "trait_name": edge.get("trait_name", ""),
                "struct_name": edge.get("struct_name", ""),
                "inferred_from": edge.get("inferred_from", ""),
            })
        graph["relation_edges"] = merged_edges
    # P0-2 Wave C-2B: load constant registry. Constants are surfaced in
    # graph["rust_constants"] as a list keyed by name. Dossier callers can
    # look up a constant's literal value to resolve implementation-pointer
    # addresses cited in candidates.
    const_path = workspace / ".auditooor" / "rust_constant_registry.json"
    try:
        const_raw = json.loads(const_path.read_text(encoding="utf-8"))
        const_rows = const_raw.get("constants") if isinstance(const_raw, dict) else None
    except (OSError, ValueError):
        const_rows = None
    if isinstance(const_rows, list):
        const_index: dict[str, Any] = {}
        for row in const_rows:
            if isinstance(row, dict) and row.get("name"):
                const_index.setdefault(row["name"], []).append(row)
        graph["rust_constants"] = const_index
        graph["_rust_constant_registry_path"] = str(const_path)
    return graph


def _resolve_rust_production_path(
    candidate: dict[str, Any],
    graph: dict[str, Any],
    relation_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Traverse caller->callee->final-implementation for Rust candidates.

    Returns a dict:
      {
        "verdict": "PROVEN" | "EXTERNAL_REACHABLE" | "OPAQUE_GENERIC",
        "hops": [...],   # list of resolved hop dicts
        "reason": str,
      }

    Algorithm (heuristic / source-shape):
      1. Collect all dispatch edges from relation_edges that are Rust.
      2. For each hop, classify:
         - confidence==concrete -> PROVEN hop
         - confidence==source-shape + crosses public API (lib_rs_pub / jsonrpsee)
           -> EXTERNAL_REACHABLE hop
         - confidence==abstract -> OPAQUE_GENERIC hop
         - cross_crate_call (use-import) -> EXTERNAL_REACHABLE (import proves
           the symbol is accessible, not that it is called)
      3. Overall verdict:
         - All hops concrete -> PROVEN
         - At least one hop crosses public API (external_actor_path proven in
           outer dossier) -> EXTERNAL_REACHABLE
         - Any hop is opaque/abstract -> OPAQUE_GENERIC
         - No rust edges -> NOT_RUST (caller is Solidity; skip this path)
    """
    rust_edges = [
        e for e in relation_edges
        if str(e.get("lang", "")).lower() == "rust"
    ]
    if not rust_edges:
        return {"verdict": "NOT_RUST", "hops": [], "reason": "no rust relation edges matched"}

    hops = []
    all_concrete = True
    any_external = False
    any_opaque = False

    for e in rust_edges:
        confidence = str(e.get("confidence", "source-shape"))
        kind = str(e.get("kind", ""))
        hop: dict[str, Any] = {
            "kind": kind,
            "source_contract": e.get("source_contract", ""),
            "source_function": e.get("source_function", ""),
            "target": e.get("target", ""),
            "method": e.get("method", ""),
            "file": e.get("file", ""),
            "line": e.get("line", 0),
            "confidence": confidence,
        }
        if confidence == "concrete":
            hop["resolution"] = "PROVEN_HOP"
        elif kind in {"cross_crate_call", "rust_rpc_route", "rust_rpc_runtime_call"}:
            hop["resolution"] = "EXTERNAL_REACHABLE_HOP"
            any_external = True
            all_concrete = False
        elif confidence == "abstract":
            hop["resolution"] = "OPAQUE_GENERIC_HOP"
            any_opaque = True
            all_concrete = False
        else:
            hop["resolution"] = "SOURCE_SHAPE_HOP"
            all_concrete = False
        hops.append(hop)

    if all_concrete:
        verdict = "PROVEN"
        reason = f"all {len(hops)} rust hop(s) resolved to concrete dispatch"
    elif any_opaque:
        verdict = "OPAQUE_GENERIC"
        reason = "at least one hop is an unresolved generic type parameter"
    elif any_external:
        verdict = "EXTERNAL_REACHABLE"
        reason = "at least one hop crosses a public API or crate boundary"
    else:
        verdict = "EXTERNAL_REACHABLE"
        reason = "source-shape edges span multiple crates (import/trait boundary)"

    return {"verdict": verdict, "hops": hops[:20], "reason": reason}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_strings(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_strings(item))
        return out
    return []


def _candidate_text(candidate: dict[str, Any]) -> str:
    fields = [
        candidate.get("claim"),
        candidate.get("trigger"),
        candidate.get("impact"),
        candidate.get("reproduction"),
        candidate.get("lane_payload"),
    ]
    return "\n".join(s for field in fields for s in _strings(field))


def _norm_file(value: str) -> str:
    return re.sub(r":\d+(?:-\d+)?$", "", value).lstrip("./")


def _entrypoint_matches(candidate: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    files = {_norm_file(str(f)) for f in candidate.get("files", []) if isinstance(f, str)}
    text = _candidate_text(candidate).lower()
    payload = candidate.get("lane_payload") if isinstance(candidate.get("lane_payload"), dict) else {}
    structured_functions = {
        str(value).lower()
        for key, value in payload.items()
        if isinstance(value, str) and key in {"function", "target_function", "rpc_method"}
    }
    structured_names = {
        str(value).lower()
        for key, value in payload.items()
        if isinstance(value, str) and key in {"contract", "function", "target_contract", "target_function"}
    }
    out = []
    for entry in graph.get("entrypoints", []) if isinstance(graph.get("entrypoints"), list) else []:
        if not isinstance(entry, dict):
            continue
        file_match = entry.get("file") in files
        fn = str(entry.get("function", "")).lower()
        rpc_method = str(entry.get("rpc_method", "")).lower()
        contract = str(entry.get("contract", "")).lower()
        if structured_functions:
            name_match = any(
                name and (name in text or name in structured_functions)
                for name in (fn, rpc_method)
            )
        else:
            name_match = bool(fn and (fn in text or fn in structured_names))
        contract_match = bool(contract and (contract in text or contract in structured_names))
        if file_match and (name_match or (contract_match and not structured_functions)):
            out.append(entry)
    return out


def _relation_edge_matches(candidate: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    files = {_norm_file(str(f)) for f in candidate.get("files", []) if isinstance(f, str)}
    text = _candidate_text(candidate).lower()
    payload = candidate.get("lane_payload") if isinstance(candidate.get("lane_payload"), dict) else {}
    structured_functions = {
        str(value).lower()
        for key, value in payload.items()
        if isinstance(value, str) and key in {"function", "target_function", "rpc_method"}
    }
    structured_names = {
        str(value).lower()
        for key, value in payload.items()
        if isinstance(value, str) and key in {"contract", "function", "target_contract", "target_function"}
    }
    out: list[dict[str, Any]] = []
    for edge in graph.get("relation_edges", []) if isinstance(graph.get("relation_edges"), list) else []:
        if not isinstance(edge, dict):
            continue
        file_match = edge.get("file") in files
        names = {
            str(edge.get("source_contract") or "").lower(),
            str(edge.get("source_function") or "").lower(),
            str(edge.get("target") or "").lower(),
            str(edge.get("method") or "").lower(),
        }
        if structured_functions:
            source_function = str(edge.get("source_function") or "").lower()
            target = str(edge.get("target") or "").lower()
            method = str(edge.get("method") or "").lower()
            name_match = any(
                _structured_call_match(structured, source_function, target, method)
                or (structured in text and structured in {source_function, target})
                for structured in structured_functions
            )
        else:
            name_match = any(name and (name in text or name in structured_names) for name in names)
        if file_match and name_match:
            out.append(edge)
    return out[:20]


_CLONE_EDGE_KINDS = frozenset({"clone-deploy", "proxy-deploy"})


def _clone_factory_reachability(
    candidate: dict[str, Any], graph: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return permissionless factory clone/proxy-deploy edges that reach the
    candidate's implementation contract.

    The candidate must explicitly opt in via ``lane_payload.implementation_var``
    (the state-variable name that holds the implementation address, e.g.
    ``childImplementation``). This keeps the heuristic conservative: we never
    auto-promote candidates that did not declare the link, so existing
    ``missing``/``privileged-only`` dossiers stay blocked unless the lane
    payload explicitly cites the implementation pointer.

    Returns the matching edges (sorted by file/line), or an empty list when:

      * no ``implementation_var`` is declared on the candidate;
      * no clone/proxy-deploy edge in the graph names that variable; or
      * every matching edge originates from a privileged source function (the
        factory itself is gated, so reachability is still privileged-only).
    """
    payload = candidate.get("lane_payload") if isinstance(candidate.get("lane_payload"), dict) else {}
    impl_var = str(payload.get("implementation_var") or "").strip()
    if not impl_var:
        return []
    impl_var_lower = impl_var.lower()
    matches: list[dict[str, Any]] = []
    for edge in graph.get("relation_edges", []) if isinstance(graph.get("relation_edges"), list) else []:
        if not isinstance(edge, dict):
            continue
        if edge.get("kind") not in _CLONE_EDGE_KINDS:
            continue
        target_var = str(edge.get("target_var") or edge.get("target") or "").strip().lower()
        if not target_var or target_var != impl_var_lower:
            continue
        if str(edge.get("role") or "").lower() != "permissionless":
            continue
        matches.append(edge)
    matches.sort(key=lambda e: (str(e.get("file") or ""), int(e.get("line") or 0)))
    return matches[:20]


def explicit_production_path(candidate: dict[str, Any]) -> str:
    payload = candidate.get("lane_payload")
    if not isinstance(payload, dict):
        return ""
    raw: Any = payload.get("production_path_verdict") or payload.get("production_path_status")
    prod = payload.get("production_path")
    if isinstance(prod, dict):
        raw = raw or prod.get("verdict") or prod.get("status")
    elif isinstance(prod, str):
        raw = raw or prod
    if not isinstance(raw, str):
        return ""
    return re.sub(r"[^A-Za-z0-9]+", "_", raw.strip().upper()).strip("_")


def classify_preconditions(text: str) -> list[str]:
    cats: list[str] = []
    if RISK_RE.search(text):
        cats.append("privileged")
    if re.search(r"\b(mock|mockverifier|mockoracle|returns\s+true)\b", text, re.IGNORECASE):
        cats.append("mock-only")
    if re.search(r"\b(project\s+inaction|will\s+not|does\s+not\s+act)\b", text, re.IGNORECASE):
        cats.append("project-inaction")
    if NATURAL_RE.search(text):
        cats.append("natural")
    if re.search(r"\b(attacker|anyone|permissionless|external|user-controlled)\b", text, re.IGNORECASE):
        cats.append("attacker-controlled")
    return sorted(set(cats)) or ["missing"]


def classify_impact(text: str) -> str:
    if FUNDS_RE.search(text):
        return "funds"
    if FREEZE_RE.search(text):
        return "freeze"
    if ACCOUNTING_RE.search(text):
        return "accounting"
    if CHALLENGE_RE.search(text):
        return "challenge-system"
    return "none"


def classify_proof_plan(candidate: dict[str, Any], text: str) -> str:
    reproduction = str(candidate.get("reproduction", ""))
    if re.search(r"\bgo\s+test\b", reproduction):
        return "go test PoC"
    if re.search(r"\bforge\s+test\b|\.t\.sol\b", reproduction):
        return "forge PoC"
    if re.search(r"\bfork\b|cast\s+run|fork_replay", reproduction, re.IGNORECASE):
        return "fork replay"
    if re.search(r"\binvariant|counterexample|halmos|medusa|echidna\b", reproduction, re.IGNORECASE):
        return "invariant counterexample"
    if SOURCE_ONLY_RE.search(text):
        return "source-only"
    return "cannot prove"


def build_dossier(candidate: dict[str, Any], *, workspace: Path, graph: dict[str, Any] | None = None) -> dict[str, Any]:
    graph = graph if graph is not None else load_graph(workspace)
    text = _candidate_text(candidate)
    explicit = explicit_production_path(candidate)
    entries = _entrypoint_matches(candidate, graph)
    relation_edges = _relation_edge_matches(candidate, graph)
    clone_factory_edges = _clone_factory_reachability(candidate, graph)
    permissionless_entries = [
        e for e in entries
        if e.get("role") == "permissionless" and not e.get("privileged")
    ]
    privileged_entries = [e for e in entries if e.get("privileged")]
    preconditions = classify_preconditions(text)
    impact = classify_impact(text)
    proof_plan = classify_proof_plan(candidate, text)

    if explicit in {"CONTRADICTED", "OOS", "OOS_ONLY", "OUT_OF_SCOPE"}:
        external_actor_path = "contradicted"
    elif explicit in {"PRE_DEPLOYMENT_SOURCE_ONLY", "SOURCE_ONLY_PREDEPLOYMENT"}:
        external_actor_path = "source-only"
    elif {"privileged", "mock-only", "project-inaction"} & set(preconditions):
        external_actor_path = "privileged-only"
    elif explicit in {"PROVEN", "EXTERNAL_REACHABLE", "IN_SCOPE_REACHABLE"}:
        external_actor_path = "proven"
    elif permissionless_entries:
        external_actor_path = "proven"
    elif privileged_entries:
        external_actor_path = "privileged-only"
    elif clone_factory_edges:
        # P0-2 burn-down: the candidate explicitly cites an
        # ``implementation_var`` and the graph contains a permissionless
        # factory function that clones / proxy-deploys against that pointer.
        # Direct entrypoint matching missed it (the candidate file is the
        # cloned implementation, not the factory), so without this branch
        # the dossier would block on ``external_actor_path_missing`` even
        # though an external actor can demonstrably reach the cloned
        # contract via the factory hop. Privileged factories are filtered
        # out inside ``_clone_factory_reachability`` so the privileged-only
        # blocker still trips for those.
        external_actor_path = "proven_via_clone_factory"
        # Surface the matched factory edges so the dossier reader can audit
        # which clone/proxy hop unblocked the path.
        relation_edges = list(relation_edges)
        for edge in clone_factory_edges:
            if edge not in relation_edges:
                relation_edges.append(edge)
        relation_edges = relation_edges[:20]
    else:
        external_actor_path = "missing"

    if external_actor_path in {"contradicted", "privileged-only"}:
        submit_verdict = "unsafe_to_submit"
    elif impact == "none":
        submit_verdict = "rejected"
    elif external_actor_path in {"proven", "proven_via_clone_factory", "source-only"} and proof_plan != "cannot prove":
        submit_verdict = "poc_ready"
    else:
        submit_verdict = "needs_poc"

    # P0-2 Wave C-2B: traverse caller->callee->final-implementation chain
    # for Rust candidates and emit a production_path_resolution block.
    # This is additive and never changes external_actor_path or submit_verdict;
    # it gives the reviewer a structured view of the dispatch chain.
    rust_pp_resolution = _resolve_rust_production_path(candidate, graph, relation_edges)

    # Resolve constant values cited in the candidate text from the registry.
    const_index = graph.get("rust_constants") or {}
    cited_constants: list[dict[str, Any]] = []
    if const_index:
        cand_text_lower = text.lower()
        for const_name, rows in const_index.items():
            if const_name.lower() in cand_text_lower:
                for row in rows[:3]:  # cap to 3 matches per name
                    cited_constants.append({
                        "name": const_name,
                        "crate": row.get("crate", ""),
                        "file": row.get("file", ""),
                        "line": row.get("line", 0),
                        "kind": row.get("kind", ""),
                        "type": row.get("type", ""),
                        "literal_value_or_expr": row.get("literal_value_or_expr", ""),
                        "resolution_confidence": row.get("resolution_confidence", "opaque"),
                    })

    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": str(candidate.get("candidate_id", "")),
        "candidate_path": str(candidate.get("_path", "")),
        "external_actor_path": external_actor_path,
        "in_scope_asset": "uncertain",
        "preconditions": preconditions,
        "state_transition": {
            "matched_entrypoints": [
                {
                    "contract": e.get("contract"),
                    "function": e.get("function"),
                    "file": e.get("file"),
                    "line": e.get("line"),
                    "role": e.get("role"),
                    "lang": e.get("lang", ""),
                    "kind": e.get("kind", ""),
                    "evidence": e.get("evidence", ""),
                    "state_writes": e.get("state_writes", []),
                }
                for e in entries
            ],
            "matched_relation_edges": [
                {
                    "kind": e.get("kind"),
                    "source_contract": e.get("source_contract"),
                    "source_function": e.get("source_function"),
                    "target": e.get("target"),
                    "target_var": e.get("target_var", ""),
                    "method": e.get("method"),
                    "file": e.get("file"),
                    "line": e.get("line"),
                    "role": e.get("role"),
                    "evidence": e.get("evidence"),
                    "confidence": e.get("confidence"),
                    "lang": e.get("lang", ""),
                }
                for e in relation_edges
            ],
        },
        "production_path_resolution": rust_pp_resolution,
        "cited_constants": cited_constants[:20],
        "blocker_explanation": blocker_explanation(external_actor_path, relation_edges),
        "victim_impact": impact,
        "proof_plan": proof_plan,
        "submit_verdict": submit_verdict,
        "blockers": blockers_for(external_actor_path, preconditions, impact, proof_plan),
    }


def blocker_explanation(external_actor_path: str, relation_edges: list[dict[str, Any]]) -> str:
    if external_actor_path == "missing" and relation_edges:
        kinds = ", ".join(sorted({str(edge.get("kind") or "") for edge in relation_edges if edge.get("kind")}))
        return (
            "cross-contract source-shape edges were detected "
            f"({kinds or 'relation edge'}), but no matching permissionless/public actor path was found"
        )
    if external_actor_path == "privileged-only" and relation_edges:
        return "matched cross-contract edges are gated by privileged or unsafe preconditions"
    if external_actor_path == "proven_via_clone_factory":
        clone_edges = [
            e for e in relation_edges
            if e.get("kind") in {"clone-deploy", "proxy-deploy"}
        ]
        targets = sorted({
            str(e.get("target_var") or e.get("target") or "")
            for e in clone_edges
            if (e.get("target_var") or e.get("target"))
        })
        if targets:
            return (
                "permissionless factory clone/proxy-deploy edges link the "
                f"declared implementation pointer ({', '.join(targets)}) to "
                "the cloned implementation; reachability is proven via the "
                "factory hop, not direct entrypoint match"
            )
        return (
            "permissionless factory clone/proxy-deploy edges reach the cloned "
            "implementation; reachability is proven via the factory hop"
        )
    return ""


def blockers_for(external_actor_path: str, preconditions: list[str], impact: str, proof_plan: str) -> list[str]:
    blockers: list[str] = []
    if external_actor_path == "missing":
        blockers.append("external_actor_path_missing")
    if external_actor_path == "privileged-only":
        blockers.append("external_actor_path_privileged_only")
    if external_actor_path == "contradicted":
        blockers.append("external_actor_path_contradicted")
    if external_actor_path == "source-only":
        return sorted(set(blockers))
    # ``proven_via_clone_factory`` clears the reachability blocker but still
    # falls through to the precondition / impact / proof-plan checks below.
    for value in ("privileged", "mock-only", "project-inaction"):
        if value in preconditions:
            blockers.append(f"precondition_{value.replace('-', '_')}")
    if impact == "none":
        blockers.append("victim_impact_missing")
    if proof_plan == "cannot prove":
        blockers.append("proof_plan_missing")
    return sorted(set(blockers))
