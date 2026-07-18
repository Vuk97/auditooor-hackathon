#!/usr/bin/env python3
"""rust-source-graph.py — syntactic Rust source-graph inventory.

P1-2 burn-down (2026-04-29): Slither's Solidity callgraph has no Rust
analog, and `tools/semantic-graph.py` only consumes `.sol`. This tool is
the Rust syntactic counterpart — a stdlib-only, regex-driven extractor
that surfaces the per-crate inventory the production-path-dossier needs
to gate Rust candidates the same way Solidity ones get gated.

Scope and discipline:
  - Stdlib-only. No `cargo`, no `rustc`, no `syn`/`tree-sitter`. The goal
    is a *syntactic* graph at the Slither-callgraph altitude, not a full
    Rust frontend. Macros are NOT expanded; `#[contractimpl]` etc. is
    matched as a literal attribute, not resolved. Trait-method bodies
    are not unified with trait declarations. `use` aliasing is not
    resolved.
  - Conservative: every heuristic is regex/text and is documented in a
    HEURISTIC comment near the regex. False positives are acceptable;
    false negatives that block production-path proof are surfaced as
    `external_actor_path: missing` downstream (the dossier already does
    this for Solidity).
  - Confidence ceiling: `source-shape` (mirrors semantic-graph.py).
  - Output: `<workspace>/.auditooor/rust_source_graph.json`.

Layout discovery:
  1. Any `Cargo.toml` under `<workspace>` whose parent has a `src/`
     subtree becomes one crate. Heavy/generated dirs (`target/`,
     `node_modules/`, `.git/`, `.auditooor/`, `build/`, `out/`) are
     pruned. This covers real engagement roots where source lives under
     `external/<project>/crates/**` rather than directly at workspace root.
  2. Fallback: `<workspace>/src/**.rs` — the workspace itself is a
     single crate even if it lacks a Cargo manifest.

Per-crate JSON shape:
  {
    "<crate_name>": {
      "crate_root": "<rel path to crate dir>",
      "files_scanned": <int>,
      "entrypoints":           [ {file, line, fn, kind, attrs} ],
      "trait_impls":           [ {file, line, trait, struct} ],
      "trait_impl_methods":    [ {file, line, trait, struct, fn, trait_decl_file, trait_decl_line} ],
      "enum_dispatches":       [ {file, line, enum, variant, dispatch_kind, target} ],
      "external_calls":        [ {file, line, call, snippet} ],
      "runtime_calls":         [ {file, line, call, snippet} ],
      "rpc_routes":            [ {file, line, fn, rpc_method, impl_file, impl_line, runtime_calls} ],
      "unsafe_blocks":         [ {file, line} ],
      "value_movement_calls":  [ {file, line, call, snippet} ]
    },
    ...
  }

A top-level `_meta` key carries schema version + workspace path.

CLI:
  tools/rust-source-graph.py --workspace <path> [--out <path>]
  tools/rust-source-graph.py --validate <path>

Exit codes:
  0  scan/validate succeeded
  2  invalid CLI arguments / missing workspace
  3  --validate failed schema integrity
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA_VERSION = "auditooor.rust_source_graph.v1"
SKIP_DIR_PARTS = {
    "target",
    "node_modules",
    ".git",
    "build",
    "out",
    ".auditooor",
    "scanners",
}
_CARGO_PACKAGE_NAME_RE = re.compile(
    r'^\s*name\s*=\s*"([A-Za-z0-9_\-]+)"\s*$', re.MULTILINE
)


# ---------------------------------------------------------------------------
# Heuristic regexes — each documented inline.
# ---------------------------------------------------------------------------

# HEURISTIC: Soroban / Anchor / ink! contract attributes. Literal text match.
# We capture the attribute name on the line preceding a `pub fn` to mark
# every public fn inside that impl/mod as an entrypoint candidate.
_CONTRACT_ATTR_RE = re.compile(
    r"#\[\s*(contractimpl|program|ink::contract|near_bindgen|pallet::call)\b"
)

# HEURISTIC: CosmWasm contract entrypoint attribute. CosmWasm marks the
# externally-callable surface of a contract with `#[entry_point]` (older
# `#[cosmwasm_std::entry_point]`) or, in the canonical generated layout,
# `#[cfg_attr(not(feature = "library"), entry_point)]` — the latter compiles
# the wasm exports only when the crate is NOT being consumed as a library.
# These attributes sit directly above a FREE `pub fn` (NOT inside an impl):
# instantiate / execute / query / migrate / reply / sudo / ibc_* etc.
# Unlike the Soroban/Anchor shape (attribute on the impl, pub fns inside),
# CosmWasm puts the attribute one line above each standalone entrypoint fn,
# so `entry_point` can appear bare (`#[entry_point]`) or nested inside a
# `cfg_attr(...)` wrapper. We match `entry_point` anywhere inside a `#[...]`
# attribute body, while still requiring the `#[` so a plain `use
# cosmwasm_std::{entry_point, ...}` import line is never matched.
_COSMWASM_ENTRY_POINT_ATTR_RE = re.compile(
    r"#\[[^\]]*\bentry_point\b[^\]]*\]"
)

# HEURISTIC: pub fn declaration. We require `pub` so module-internal
# helpers are not surfaced; `pub(crate)` and `pub(super)` are excluded
# (they are still in-crate, not exported).
_PUB_FN_RE = re.compile(
    r"^\s*pub\s+(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)

# HEURISTIC: trait or impl method declaration. Used only when a nearby
# jsonrpsee `#[method]` / `#[subscription]` attribute proves the method is
# externally exposed by a macro-generated RPC server trait.
_METHOD_FN_RE = re.compile(
    r"^\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)

# Generic fn declaration alias: same pattern as _METHOD_FN_RE but used by the
# trait-impl method extractor at line ~936 where the surrounding context (an
# `impl Trait for Struct { ... }` body) already proves the method belongs to
# a trait implementation.
_FN_RE = _METHOD_FN_RE

# HEURISTIC: jsonrpsee RPC method/subscription attributes. These attributes
# sit directly above trait methods inside a `#[rpc(...)]` trait. The macro
# expansion generates the real `*Server` trait, so recording the source trait
# method gives production-path gates a stable external RPC surface without
# needing a Rust macro expander.
_RPC_METHOD_ATTR_RE = re.compile(
    r"#\[\s*(method|subscription)\s*\(\s*name\s*=\s*\"([^\"]+)\""
)

# HEURISTIC: cfg/cfg_attr annotations. We do not evaluate Cargo feature truth;
# we preserve nearby conditional compilation text so mining/dossier code can
# distinguish unconditional routes from feature-gated source-shape evidence.
_CFG_ATTR_RE = re.compile(r"#\[\s*(cfg|cfg_attr)\s*\((?P<body>.*)\)\s*\]\s*$")

# HEURISTIC: crate-level cfg_attr scan. Used to extract a structured flat list
# of all cfg/cfg_attr items across each file for the per-crate inventory.
# We capture optional `feature = "..."`, `test`, `target_os = "..."` etc.
_CFG_FEATURE_RE = re.compile(r'feature\s*=\s*"([^"]+)"')
_CFG_TARGET_RE = re.compile(r'target_(?:os|arch|env|family|pointer_width)\s*=\s*"([^"]+)"')

# HEURISTIC: macro invocations. Two shapes:
#   1. Function-like: `name!(...)` or `name![...]` or `name!{...}`
#   2. Derive attributes: `#[derive(Foo, Bar)]`
# We deliberately do NOT expand macros; we record only the call-site.
_MACRO_INVOCATION_RE = re.compile(
    r"\b(?P<macro>[a-z_][a-z0-9_]*)!\s*[(\[{]"
)
_DERIVE_RE = re.compile(
    r"#\[\s*derive\s*\((?P<traits>[^)]+)\)"
)

# HEURISTIC: lib.rs export — `pub fn` at the top level of `src/lib.rs`
# is treated as an entrypoint regardless of attribute (Rust crate
# external surface).
_LIB_RS_NAME = "lib.rs"

# HEURISTIC: trait impl. Captures `impl <Trait> for <Struct>` in the
# common, single-line form. Generics on the impl (`impl<T> Trait for Foo<T>`)
# are tolerated by skipping a leading angle-bracket group. Multi-line
# impl signatures wrapped over many lines are NOT matched (acceptable
# false negative — the body still gets scanned for everything else).
_TRAIT_IMPL_RE = re.compile(
    r"^\s*impl\s*(?:<[^>]*>\s*)?"
    r"(?P<trait>[A-Za-z_][A-Za-z0-9_:<>,\s]*?)"
    r"\s+for\s+"
    r"(?P<struct>[A-Za-z_][A-Za-z0-9_:<>,\s]*?)"
    r"\s*(?:where\b|\{)",
    re.MULTILINE,
)

# HEURISTIC: trait declaration header and enum declaration header. These are
# paired with `_matching_brace_pos` so method/variant extraction can stay
# local to the item body without a Rust parser.
_TRAIT_DECL_RE = re.compile(
    r"\b(?:pub\s+)?trait\s+(?P<trait>[A-Za-z_][A-Za-z0-9_:]*(?:<[^{}]*>)?)"
    r"(?:\s*:[^{]+)?\s*\{",
    re.MULTILINE | re.DOTALL,
)
_ENUM_DECL_RE = re.compile(
    r"\b(?:pub\s+)?enum\s+(?P<enum>[A-Za-z_][A-Za-z0-9_:]*(?:<[^{}]*>)?)"
    r"(?:\s+where\b[^{}]*)?\s*\{",
    re.MULTILINE | re.DOTALL,
)
_ENUM_VARIANT_RE = re.compile(r"^\s*(?P<variant>[A-Z][A-Za-z0-9_]*)\s*(?:[,({]|$)")

# HEURISTIC: impl block header with a trait target. Used by the jsonrpsee
# route linker to find methods in `impl SomeRpcServer for ConcreteRpc { ... }`.
# It is intentionally source-shape only: it tolerates multiline `where`
# clauses, but it does not expand macros or resolve type aliases.
_IMPL_BLOCK_RE = re.compile(
    r"\bimpl\s*(?:<[^{}]*>\s*)?"
    r"(?P<trait>[A-Za-z_][A-Za-z0-9_:]*(?:<[^{}]*>)?)"
    r"\s+for\s+"
    r"(?P<struct>[A-Za-z_][A-Za-z0-9_:]*(?:<[^{}]*>)?)"
    r"\s*(?:where\b[^{}]*)?\{",
    re.MULTILINE | re.DOTALL,
)

# HEURISTIC: external / cross-contract calls. Each call is the canonical
# Rust-on-chain analog of a Solidity `.call()` / `delegatecall`:
#   - Soroban:  `env.invoke_contract(...)` / `Env::invoke_contract(...)`
#   - Anchor:   `CpiContext::new(...)` / `invoke(` / `invoke_signed(`
#   - Substrate `pallet::Call::<...>`-style call and `T::Currency::transfer`
#   - ink!:     `CrossContractCall::new(` / `build_call`
#   - CosmWasm: `WasmMsg::Execute` / `WasmMsg::Instantiate` cross-contract
#               sends, and `SubMsg`/`add_message`/`add_submessage` dispatch.
#               On Injective/cw-plus contracts the chain-module call surface
#               also runs through generated `create_*_msg(...)` builders
#               (e.g. `create_spot_market_order_msg(...)`) wrapped in a
#               `SubMsg`. These are the cross-contract/module analog of a
#               Solidity `.call()` — the dossier only needs to know "this fn
#               dispatches an outbound message".
# We DO NOT try to resolve who the receiver is — the dossier only needs
# to know "this fn does cross-contract work".
_EXTERNAL_CALL_RES: List[Tuple[str, re.Pattern[str]]] = [
    ("invoke_contract",   re.compile(r"\binvoke_contract\s*\(")),
    ("Env::invoke_contract", re.compile(r"\bEnv::invoke_contract\b")),
    ("CrossContractCall", re.compile(r"\bCrossContractCall::new\s*\(")),
    ("CpiContext",        re.compile(r"\bCpiContext::new(?:_with_signer)?\s*\(")),
    ("invoke_signed",     re.compile(r"\binvoke_signed\s*\(")),
    ("solana_invoke",     re.compile(r"\b(?:solana_program::program::)?invoke\s*\(")),
    ("pallet_call",       re.compile(r"\bpallet::Call::<[^>]+>")),
    ("build_call",        re.compile(r"\bbuild_call\s*\(")),
    ("WasmMsg::Execute",  re.compile(r"\bWasmMsg::Execute\b")),
    ("WasmMsg::Instantiate", re.compile(r"\bWasmMsg::Instantiate\b")),
    ("cosmwasm_msg_builder", re.compile(r"\bcreate_[A-Za-z0-9_]*_msg\s*\(")),
    ("SubMsg",            re.compile(r"\bSubMsg::(?:new|reply_on_success|reply_on_error|reply_always)\s*\(")),
    ("add_submessage",    re.compile(r"\.\s*add_submessage(?:s)?\s*\(")),
]

# HEURISTIC: unsafe block opening. We match `unsafe {` (block) and
# deliberately do NOT count `unsafe fn` declarations (the body of the
# fn is itself an unsafe context but flagging the declaration line
# would double-report when an `unsafe { ... }` block lives inside).
_UNSAFE_BLOCK_RE = re.compile(r"\bunsafe\s*\{")

# HEURISTIC: value-movement call sites. Pure name-match against the
# canonical token-flow vocabulary. Like Solidity's VALUE_RE in
# semantic-graph.py, we accept that these are imprecise and that real
# proof comes from the dossier + PoC. Names checked:
#   transfer / transfer_from / safe_transfer / safe_transfer_from
#   mint / burn / withdraw / deposit / claim / redeem / sweep
#   token::transfer / token::mint / token::burn (Anchor pattern)
#   CosmWasm: `BankMsg::Send` moves native funds out of the contract and
#   `BankMsg::Burn` destroys them — the CosmWasm analog of a token transfer.
#   These appear as struct-variant constructions (`BankMsg::Send { ... }`),
#   not method calls, so they need a dedicated pattern.
_VALUE_MOVEMENT_RES: List[Tuple[str, re.Pattern[str]]] = [
    ("transfer",          re.compile(r"\.\s*transfer\s*\(")),
    ("transfer_from",     re.compile(r"\.\s*transfer_from\s*\(")),
    ("safe_transfer",     re.compile(r"\bsafe_transfer(?:_from)?\s*\(")),
    ("mint",              re.compile(r"\.\s*mint\s*\(")),
    ("burn",              re.compile(r"\.\s*burn\s*\(")),
    ("withdraw",          re.compile(r"\.\s*withdraw\s*\(")),
    ("deposit",           re.compile(r"\.\s*deposit\s*\(")),
    ("claim",             re.compile(r"\.\s*claim\s*\(")),
    ("redeem",            re.compile(r"\.\s*redeem\s*\(")),
    ("token::transfer",   re.compile(r"\btoken::transfer\s*\(")),
    ("token::mint_to",    re.compile(r"\btoken::mint_to\s*\(")),
    ("token::burn",       re.compile(r"\btoken::burn\s*\(")),
    ("BankMsg::Send",     re.compile(r"\bBankMsg::Send\b")),
    ("BankMsg::Burn",     re.compile(r"\bBankMsg::Burn\b")),
]

# HEURISTIC: Base/reth-style runtime production-path calls. These are not
# cross-contract/value movement, but they are the calls that connect Engine
# API, payload validation, derivation, and proof-service code paths. The
# labels are intentionally coarse so downstream dossiers can cite a real
# source line without pretending we resolved Rust dynamic dispatch.
_RUNTIME_CALL_RES: List[Tuple[str, re.Pattern[str]]] = [
    ("engine_new_payload", re.compile(r"\.\s*new_payload_v\d+(?:_metered)?\s*\(")),
    ("engine_get_payload", re.compile(r"\.\s*get_payload_v\d+(?:_metered)?\s*\(")),
    ("engine_forkchoice", re.compile(r"\.\s*fork_?choice_updated_v\d*(?:_metered)?\s*\(")),
    ("unsafe_payload_insert", re.compile(r"\.\s*insert_unsafe_payload\s*\(")),
    ("engine_task_insert", re.compile(r"\bEngineTask::Insert\s*\(")),
    ("engine_task_insert_execute", re.compile(r"\bSelf::Insert\s*\([^)]*\)\s*=>.*\.\s*execute\s*\(")),
    ("engine_enqueue", re.compile(r"\.\s*enqueue\s*\(")),
    ("engine_task_execute", re.compile(r"\.\s*execute\s*\(")),
    ("actor_send", re.compile(r"\.\s*send\s*\(")),
    ("derivation_pipeline_step", re.compile(r"\.\s*step\s*\(")),
    ("derivation_pipeline_next", re.compile(r"\.\s*next\s*\(")),
    ("payload_attributes_check", re.compile(r"\bAttributesMatch::check\s*\(")),
    ("bundle_validation", re.compile(r"\bvalidate_bundle\s*\(")),
    ("proof_service", re.compile(r"\b(proof|prove|verify)[A-Za-z0-9_]*\s*\(")),
]

# HEURISTIC: enum dispatch and construction lines. This closes the Base/reth
# gap where real production paths move through enum variants such as
# `EngineTask::Insert(...)` and later dispatch via `Self::Insert(task) =>
# task.execute(...)`. We preserve the source-shape edge instead of resolving
# the callee type.
_ENUM_MATCH_ARM_RE = re.compile(
    r"\b(?:(?P<enum>[A-Za-z_][A-Za-z0-9_:]*)::|Self::)"
    r"(?P<variant>[A-Z][A-Za-z0-9_]*)"
    r"\s*(?:\((?P<binder>[A-Za-z_][A-Za-z0-9_]*)?[^)]*\)|\{(?P<named>[^}]*)\}|)"
    r"\s*=>\s*(?P<body>.*)"
)
_ENUM_CONSTRUCT_RE = re.compile(
    r"\b(?P<enum>[A-Za-z_][A-Za-z0-9_:]*)::(?P<variant>[A-Z][A-Za-z0-9_]*)\s*(?:\(|\{)"
)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _skip_path(path: Path) -> bool:
    return any(part in SKIP_DIR_PARTS for part in path.parts)


def _rs_files_in(root: Path) -> List[Path]:
    if not root.exists() or not root.is_dir():
        return []
    out: List[Path] = []
    for p in root.rglob("*.rs"):
        if not p.is_file():
            continue
        if _skip_path(p):
            continue
        out.append(p)
    return sorted(out)


def _crate_name_from_cargo(root: Path, fallback: str) -> str:
    cargo = root / "Cargo.toml"
    if not cargo.is_file():
        return fallback
    try:
        text = cargo.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fallback
    match = _CARGO_PACKAGE_NAME_RE.search(text)
    if match:
        return match.group(1)
    return fallback


def discover_crates(workspace: Path) -> List[Tuple[str, Path]]:
    """Return ordered list of `(crate_name, crate_root_dir)` to scan.

    Layout discovery rules (documented in module docstring). The returned
    crate_root is an absolute path. crate_name comes from Cargo.toml
    `[package].name` when present, otherwise the directory basename. For
    the workspace-as-single-crate fallback the crate_name is the workspace
    dir name.
    """
    crates: List[Tuple[str, Path]] = []
    seen: set[Path] = set()

    def _add(name: str, root: Path) -> None:
        root = root.resolve()
        if root in seen:
            return
        if not (root / "src").is_dir():
            return
        seen.add(root)
        crates.append((_crate_name_from_cargo(root, name), root))

    # Real engagements often wrap source in `external/<project>/...`. Walk
    # Cargo roots from the engagement root instead of requiring operators to
    # point WS at the nested Rust checkout.
    if workspace.is_dir():
        for cargo in sorted(workspace.rglob("Cargo.toml")):
            if _skip_path(cargo):
                continue
            root = cargo.parent
            if (root / "src").is_dir():
                _add(root.name, root)

    # Fallback: workspace itself is a single crate.
    if not crates and (workspace / "src").is_dir():
        _add(workspace.name or "crate", workspace)

    return crates


# ---------------------------------------------------------------------------
# Per-file extraction
# ---------------------------------------------------------------------------

def _strip_line_comments(line: str) -> str:
    """Strip `//` line comments while preserving in-string `//`.

    Conservative: if the line contains a `"` we leave it alone (a real
    parser would track string state; we do not). This is fine for our
    text-grep heuristics.
    """
    if '"' in line:
        return line
    idx = line.find("//")
    return line if idx < 0 else line[:idx]


def _rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _snippet(line: str, cap: int = 200) -> str:
    s = line.strip()
    return s if len(s) <= cap else s[: cap - 1] + "..."


def _is_inside_contract_attr(prev_lines: List[str]) -> Optional[str]:
    """Decide if a `pub fn` is inside a contract-attributed item.

    Returns the matched attribute name (e.g. `contractimpl`,
    `entry_point`) or None. Three rules:

      1. Attribute directly above the fn (within 8 lines, no other item
         declaration in between). This covers both the Soroban/Anchor/ink!
         attributes and the CosmWasm `#[entry_point]` /
         `#[cfg_attr(not(feature = "library"), entry_point)]` shape, where
         the attribute sits one line above a FREE `pub fn` (execute / query
         / instantiate / migrate / reply / sudo / ibc_*). CosmWasm does NOT
         wrap entrypoints in an impl, so this directly-above match is the
         only one that fires for it — and it must fire before the
         `impl`-anchored Rule 2 below.
      2. Attribute above the most recent enclosing `impl ... {` block —
         this is the dominant Soroban / Anchor / ink! shape, where
         `#[contractimpl]` sits on the impl, and pub fns inside the
         impl body are the entrypoints. We do not track brace depth (a
         full Rust parser would); we just walk back to the nearest
         `impl` line and check the line(s) immediately above it.
    """
    window = prev_lines[-200:]  # generous; attribute must be near impl
    # Rule 1: directly above the fn.
    for line in reversed(window[-8:]):
        m = _CONTRACT_ATTR_RE.search(line)
        if m:
            return m.group(1)
        # CosmWasm entrypoint: `entry_point` bare or inside a cfg_attr(...).
        # Canonicalize the kind to `entry_point` regardless of the wrapper.
        if _COSMWASM_ENTRY_POINT_ATTR_RE.search(line):
            return "entry_point"
        stripped = line.strip()
        if stripped.startswith("pub ") or stripped.startswith("fn "):
            break
        if stripped.startswith("impl "):
            # Hand off to rule 2 — re-anchor on this impl line.
            break
    # Rule 2: nearest enclosing impl, attribute above it.
    impl_idx: Optional[int] = None
    for i in range(len(window) - 1, -1, -1):
        s = window[i].strip()
        if s.startswith("impl ") or s.startswith("impl<"):
            impl_idx = i
            break
        # `}` at column 0 is a strong signal we left the impl body —
        # stop hunting (avoid binding to a sibling impl above us).
        if s == "}":
            return None
    if impl_idx is None:
        return None
    for line in reversed(window[max(0, impl_idx - 8):impl_idx]):
        m = _CONTRACT_ATTR_RE.search(line)
        if m:
            return m.group(1)
        stripped = line.strip()
        # An item between the attribute and the impl breaks the binding.
        if stripped.startswith("pub ") or stripped.startswith("fn ") or stripped.startswith("impl "):
            return None
    return None


def _rpc_attr(prev_lines: List[str]) -> Optional[Tuple[str, str]]:
    """Return `(kind, wire_name)` for a nearby jsonrpsee RPC attribute."""
    for line in reversed(prev_lines[-8:]):
        m = _RPC_METHOD_ATTR_RE.search(line)
        if m:
            return m.group(1), m.group(2)
        stripped = line.strip()
        if stripped.startswith("fn ") or stripped.startswith("async fn ") or stripped == "}":
            break
    return None


def _nearby_cfg_attrs(prev_lines: List[str], max_lines: int = 12) -> List[str]:
    """Return contiguous cfg/cfg_attr annotations immediately above an item."""
    attrs: List[str] = []
    saw_attr = False
    for line in reversed(prev_lines[-max_lines:]):
        stripped = line.strip()
        m = _CFG_ATTR_RE.match(stripped)
        if m:
            attrs.append(stripped)
            saw_attr = True
            continue
        if stripped.startswith("#["):
            # Other attributes can sit in the same item attribute block.
            continue
        if stripped == "" or stripped.startswith("//"):
            if saw_attr:
                continue
            break
        break
    return list(reversed(attrs))


def _nearest_trait_context(prev_lines: List[str]) -> Tuple[Optional[str], List[str]]:
    """Return the nearest enclosing trait name plus cfg attrs on that trait."""
    for idx in range(len(prev_lines) - 1, max(-1, len(prev_lines) - 120), -1):
        line = prev_lines[idx]
        m = re.match(r"^\s*(?:pub\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)", line)
        if m:
            return m.group(1), _nearby_cfg_attrs(prev_lines[:idx])
        if line.strip() == "}":
            return None, []
    return None, []


def _line_for_pos(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _matching_brace_pos(text: str, open_pos: int) -> Optional[int]:
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _method_body_end(lines: List[str], start_idx: int) -> Optional[int]:
    """Return the inclusive end line for a method body starting at start_idx."""
    depth = 0
    saw_body = False
    for i in range(start_idx, len(lines)):
        line = _strip_line_comments(lines[i])
        if not saw_body and ";" in line and "{" not in line:
            return None
        for ch in line:
            if ch == "{":
                depth += 1
                saw_body = True
            elif ch == "}" and saw_body:
                depth -= 1
                if depth == 0:
                    return i
    return None


def _runtime_calls_for_lines(
    workspace: Path,
    path: Path,
    lines: List[str],
    start: int,
    end: int,
) -> List[Dict[str, Any]]:
    rel = _rel(workspace, path)
    calls: List[Dict[str, Any]] = []
    for idx in range(start, end + 1):
        raw_line = lines[idx]
        line = _strip_line_comments(raw_line)
        for label, rx in _RUNTIME_CALL_RES:
            if rx.search(line):
                calls.append({
                    "file": rel,
                    "line": idx + 1,
                    "call": label,
                    "snippet": _snippet(raw_line),
                })
                break
    return calls


def _collect_impl_methods(workspace: Path, path: Path, text: str) -> List[Dict[str, Any]]:
    """Collect same-crate impl methods with their body-local runtime calls."""
    lines = text.splitlines()
    rel = _rel(workspace, path)
    out: List[Dict[str, Any]] = []
    for impl in _IMPL_BLOCK_RE.finditer(text):
        open_pos = impl.end() - 1
        close_pos = _matching_brace_pos(text, open_pos)
        if close_pos is None:
            continue
        start_line = _line_for_pos(text, open_pos) - 1
        end_line = _line_for_pos(text, close_pos) - 1
        impl_cfg_attrs = _nearby_cfg_attrs(lines[:start_line])
        block_lines = lines[start_line:end_line + 1]
        for offset, line in enumerate(block_lines):
            m = _METHOD_FN_RE.match(_strip_line_comments(line))
            if not m:
                continue
            method_idx = start_line + offset
            body_end = _method_body_end(lines, method_idx)
            if body_end is None or body_end > end_line:
                continue
            method_cfg_attrs = _nearby_cfg_attrs(lines[start_line:method_idx])
            out.append({
                "file": rel,
                "line": method_idx + 1,
                "fn": m.group(1),
                "impl_trait": impl.group("trait").strip(),
                "impl_struct": impl.group("struct").strip(),
                "impl_cfg_attrs": impl_cfg_attrs,
                "cfg_attrs": method_cfg_attrs,
                "runtime_calls": _runtime_calls_for_lines(workspace, path, lines, method_idx, body_end),
            })
    return out


def _normalize_trait_name(name: str) -> str:
    """Reduce a source-shape trait name to its local identifier."""
    name = re.sub(r"<.*", "", name.strip())
    name = name.rsplit("::", 1)[-1]
    return name.strip()


def _collect_trait_methods(workspace: Path, path: Path, text: str) -> List[Dict[str, Any]]:
    """Collect declared trait methods for later impl-method binding."""
    lines = text.splitlines()
    rel = _rel(workspace, path)
    out: List[Dict[str, Any]] = []
    for trait in _TRAIT_DECL_RE.finditer(text):
        open_pos = trait.end() - 1
        close_pos = _matching_brace_pos(text, open_pos)
        if close_pos is None:
            continue
        start_line = _line_for_pos(text, open_pos) - 1
        end_line = _line_for_pos(text, close_pos) - 1
        trait_name = _normalize_trait_name(trait.group("trait"))
        block_lines = lines[start_line:end_line + 1]
        for offset, line in enumerate(block_lines):
            m = _METHOD_FN_RE.match(_strip_line_comments(line))
            if not m:
                continue
            method_idx = start_line + offset
            out.append({
                "file": rel,
                "line": method_idx + 1,
                "trait": trait_name,
                "fn": m.group(1),
                "cfg_attrs": _nearby_cfg_attrs(lines[start_line:method_idx]),
                "trait_cfg_attrs": _nearby_cfg_attrs(lines[:start_line]),
            })
    return out


def _trait_binding_keys(trait_name: str) -> set[str]:
    """Return trait names that can plausibly bind to a declaration.

    jsonrpsee expands `FooApi` into `FooApiServer`; recording that suffix
    relationship lets RPC impl methods bind back to the source trait without
    pretending we performed macro expansion.
    """
    norm = _normalize_trait_name(trait_name)
    keys = {norm}
    if norm.endswith("Server"):
        keys.add(norm[:-6])
    return {k for k in keys if k}


def _bind_trait_impl_methods(
    trait_methods: List[Dict[str, Any]],
    impl_methods: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Bind local trait declarations to impl method bodies by trait + fn."""
    decls: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for method in trait_methods:
        decls.setdefault((str(method.get("trait", "")), str(method.get("fn", ""))), []).append(method)

    out: List[Dict[str, Any]] = []
    seen: set[Tuple[str, int, str, str]] = set()
    for method in impl_methods:
        fn = str(method.get("fn", ""))
        candidates: List[Dict[str, Any]] = []
        for trait_key in _trait_binding_keys(str(method.get("impl_trait", ""))):
            candidates.extend(decls.get((trait_key, fn), []))
        if not candidates:
            # Still emit impl methods for trait-shaped impls. This catches
            # cross-crate traits (common in Base/reth) while marking the
            # declaration side as unresolved.
            candidates = [{
                "file": "",
                "line": 0,
                "trait": _normalize_trait_name(str(method.get("impl_trait", ""))),
                "fn": fn,
                "cfg_attrs": [],
                "trait_cfg_attrs": [],
            }]
        for decl in candidates:
            key = (str(method.get("file", "")), int(method.get("line", 0)), fn, str(decl.get("trait", "")))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "file": method.get("file", ""),
                "line": method.get("line", 0),
                "trait": decl.get("trait") or _normalize_trait_name(str(method.get("impl_trait", ""))),
                "struct": method.get("impl_struct", ""),
                "fn": fn,
                "method": fn,  # alias so downstream and tests can use either key
                "trait_decl_file": decl.get("file", ""),
                "trait_decl_line": decl.get("line", 0),
                "impl_trait": method.get("impl_trait", ""),
                "impl_cfg_attrs": method.get("impl_cfg_attrs", []),
                "cfg_attrs": method.get("cfg_attrs", []),
                "trait_cfg_attrs": decl.get("trait_cfg_attrs", []),
                "trait_method_cfg_attrs": decl.get("cfg_attrs", []),
                "runtime_calls": method.get("runtime_calls", []),
                "confidence": "source-shape",
            })
    return out


def _enum_variants_by_name(text: str) -> Dict[str, List[str]]:
    variants: Dict[str, List[str]] = {}
    lines = text.splitlines()
    for enum in _ENUM_DECL_RE.finditer(text):
        open_pos = enum.end() - 1
        close_pos = _matching_brace_pos(text, open_pos)
        if close_pos is None:
            continue
        enum_name = _normalize_trait_name(enum.group("enum"))
        start_line = _line_for_pos(text, open_pos) - 1
        end_line = _line_for_pos(text, close_pos) - 1
        for line in lines[start_line:end_line + 1]:
            stripped = _strip_line_comments(line).strip()
            if not stripped or stripped.startswith("#[") or stripped.startswith("///"):
                continue
            m = _ENUM_VARIANT_RE.match(stripped)
            if m:
                bucket = variants.setdefault(m.group("variant"), [])
                if enum_name not in bucket:
                    bucket.append(enum_name)
    return variants


def _nearest_impl_type(prev_lines: List[str]) -> Optional[str]:
    """Best-effort enclosing inherent impl type for resolving `Self::Variant`."""
    for line in reversed(prev_lines[-160:]):
        stripped = _strip_line_comments(line).strip()
        m = re.match(
            r"^impl\s*(?:<[^>]*>\s*)?"
            r"(?P<type>[A-Za-z_][A-Za-z0-9_:]*(?:<[^{}]*>)?)"
            r"(?:\s+where\b.*)?\s*\{",
            stripped,
        )
        if m and " for " not in stripped:
            return _normalize_trait_name(m.group("type"))
        if stripped == "}":
            return None
    return None


def _dispatch_kind_and_target(body: str, binder: str) -> Optional[Tuple[str, str]]:
    if binder and re.search(rf"\b{re.escape(binder)}\s*\.\s*execute\s*\(", body):
        return "variant_method_call", f"{binder}.execute"
    if re.search(r"\.\s*execute\s*\(", body):
        return "variant_method_call", "execute"
    if re.search(r"\.\s*send\s*\(", body):
        return "variant_send", "send"
    if re.search(r"\.\s*enqueue\s*\(", body):
        return "variant_enqueue", "enqueue"
    return None


def _collect_enum_dispatches(workspace: Path, path: Path, text: str) -> List[Dict[str, Any]]:
    """Collect conservative enum construction and match-arm dispatch edges."""
    rel = _rel(workspace, path)
    lines = text.splitlines()
    variants = _enum_variants_by_name(text)
    out: List[Dict[str, Any]] = []
    for idx, raw_line in enumerate(lines):
        line = _strip_line_comments(raw_line)

        arm = _ENUM_MATCH_ARM_RE.search(line)
        if arm:
            binder = arm.group("binder") or ""
            if not binder and arm.group("named"):
                named = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", arm.group("named") or "")
                binder = named.group(1) if named else ""
            dispatch = _dispatch_kind_and_target(arm.group("body") or "", binder)
            if dispatch:
                enum_name = arm.group("enum")
                if enum_name == "Self":
                    enum_name = None
                if not enum_name:
                    enum_name = _nearest_impl_type(lines[:idx])
                if not enum_name:
                    possible = variants.get(arm.group("variant"), [])
                    enum_name = possible[0] if len(possible) == 1 else "Self"
                kind, target = dispatch
                out.append({
                    "file": rel,
                    "line": idx + 1,
                    "enum": _normalize_trait_name(enum_name),
                    "variant": arm.group("variant"),
                    "dispatch_kind": kind,
                    "target": target,
                    "snippet": _snippet(raw_line),
                    "confidence": "source-shape",
                })
                continue

        construct = _ENUM_CONSTRUCT_RE.search(line)
        if construct:
            enum_name = _normalize_trait_name(construct.group("enum"))
            variant = construct.group("variant")
            if enum_name in {"Ok", "Err", "Some", "None", "Self"}:
                continue
            out.append({
                "file": rel,
                "line": idx + 1,
                "enum": enum_name,
                "variant": variant,
                "dispatch_kind": "variant_construct",
                "target": f"{enum_name}::{variant}",
                "snippet": _snippet(raw_line),
                "confidence": "source-shape",
            })
    return out


def _route_rpc_methods(
    rpc_entries: List[Dict[str, Any]],
    impl_methods: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Best-effort jsonrpsee declaration -> impl method/runtime-call routes."""
    routes: List[Dict[str, Any]] = []
    by_fn: Dict[str, List[Dict[str, Any]]] = {}
    for method in impl_methods:
        by_fn.setdefault(str(method.get("fn", "")), []).append(method)
    for entry in rpc_entries:
        fn = str(entry.get("fn", ""))
        for method in by_fn.get(fn, []):
            route = {
                "file": entry["file"],
                "line": entry["line"],
                "fn": fn,
                "rpc_method": entry.get("rpc_method"),
                "rpc_trait": entry.get("rpc_trait"),
                "impl_file": method["file"],
                "impl_line": method["line"],
                "impl_trait": method.get("impl_trait"),
                "impl_struct": method.get("impl_struct"),
                "runtime_calls": method.get("runtime_calls", []),
                "cfg_attrs": entry.get("cfg_attrs", []),
                "rpc_trait_cfg_attrs": entry.get("rpc_trait_cfg_attrs", []),
                "impl_cfg_attrs": method.get("impl_cfg_attrs", []),
                "impl_method_cfg_attrs": method.get("cfg_attrs", []),
                "confidence": "source-shape",
            }
            routes.append(route)
    return routes


def _cfg_kind_and_feature(body: str) -> Tuple[str, Optional[str]]:
    """Parse the body of a cfg/cfg_attr(...) expression into (kind, feature).

    kind is 'cfg_attr' when the outer keyword was cfg_attr, otherwise 'cfg'.
    feature is the value of `feature = "..."` if present; None otherwise.
    We also surface target_os / target_arch as a secondary label but still
    return kind='cfg' for those — consumers can inspect the raw expr.
    """
    m_feat = _CFG_FEATURE_RE.search(body)
    if m_feat:
        return "cfg", m_feat.group(1)
    return "cfg", None


def _collect_file_cfg_attrs(
    workspace: Path,
    path: Path,
    text: str,
) -> List[Dict[str, Any]]:
    """Return a structured list of every cfg/cfg_attr annotation in a file.

    Shape: {file, line, cfg_expr, kind, feature}

    kind is 'cfg' or 'cfg_attr'. feature is the first `feature = "..."` value
    in the body or None. cfg_expr is the full raw annotation string.
    """
    rel = _rel(workspace, path)
    out: List[Dict[str, Any]] = []
    for idx, raw_line in enumerate(text.splitlines()):
        stripped = raw_line.strip()
        m = _CFG_ATTR_RE.match(stripped)
        if not m:
            continue
        outer_kw = m.group(1)   # 'cfg' or 'cfg_attr'
        body = m.group("body")
        kind, feature = _cfg_kind_and_feature(body)
        kind = outer_kw  # use exact keyword for fidelity
        out.append({
            "file": rel,
            "line": idx + 1,
            "cfg_expr": stripped,
            "kind": kind,
            "feature": feature,
        })
    return out


def _collect_file_macro_invocations(
    workspace: Path,
    path: Path,
    text: str,
) -> List[Dict[str, Any]]:
    """Return a structured list of macro invocations in a file.

    Shapes:
      - function-like: `name!(...)` → kind='function_call'
      - derive attrs:  `#[derive(Foo, Bar)]` → kind='derive', one entry per trait
      - Other `#[...]` attribute macros are not captured here; they appear in
        the cfg_attrs list above when they are cfg/cfg_attr.

    Shape: {file, line, macro_name, kind, expansion_known}
    expansion_known is always False (we are a syntax-only tool).
    """
    rel = _rel(workspace, path)
    lines = text.splitlines()
    out: List[Dict[str, Any]] = []
    seen_lines: set = set()  # deduplicate multiple matches on same line

    for idx, raw_line in enumerate(lines):
        line = _strip_line_comments(raw_line)
        # derive attributes
        m_derive = _DERIVE_RE.search(line)
        if m_derive:
            for trait_name in re.split(r"\s*,\s*", m_derive.group("traits")):
                trait_name = trait_name.strip()
                if trait_name:
                    out.append({
                        "file": rel,
                        "line": idx + 1,
                        "macro": trait_name,      # key matches test expectation
                        "macro_name": trait_name,  # alias for consumers using either key
                        "kind": "derive",
                        "expansion_known": False,
                    })
            seen_lines.add(idx)
            continue

        # function-like macros — one entry per invocation site per line
        for m in _MACRO_INVOCATION_RE.finditer(line):
            name = m.group("macro")
            # Skip common non-macro false-positives that are always function calls.
            # In Rust syntax `name!` is always a macro; the regex already filters
            # by lowercase which avoids type names. We still skip very generic
            # single-letter names.
            if len(name) < 2:
                continue
            out.append({
                "file": rel,
                "line": idx + 1,
                "macro": name,      # key matches test expectation
                "macro_name": name,  # alias for consumers using either key
                "kind": "function_call",
                "expansion_known": False,
            })

    return out


def extract_file(
    workspace: Path,
    crate_root: Path,
    path: Path,
) -> Dict[str, List[Dict[str, Any]]]:
    """Pull all five inventory categories from one .rs file."""
    out: Dict[str, List[Dict[str, Any]]] = {
        "entrypoints": [],
        "trait_impls": [],
        "trait_method_impls": [],
        "trait_impl_methods": [],
        "enum_dispatches": [],
        "external_calls": [],
        "runtime_calls": [],
        "rpc_routes": [],
        "unsafe_blocks": [],
        "value_movement_calls": [],
    }
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    rel = _rel(workspace, path)
    lines = text.splitlines()
    is_lib_rs = path.name == _LIB_RS_NAME

    # entrypoints + value_movement + external + unsafe — line-level scan
    for idx, raw_line in enumerate(lines):
        line = _strip_line_comments(raw_line)

        # entrypoints: pub fn under a contract attribute, or pub fn at
        # top of lib.rs. Contract attribute takes precedence over the
        # lib.rs heuristic so the `kind` field surfaces the more
        # specific signal when both apply.
        m_fn = _PUB_FN_RE.match(line)
        if m_fn:
            attr = _is_inside_contract_attr(lines[:idx])
            cfg_attrs = _nearby_cfg_attrs(lines[:idx])
            if attr:
                out["entrypoints"].append({
                    "file": rel,
                    "line": idx + 1,
                    "fn": m_fn.group(1),
                    "kind": attr,
                    "attrs": [attr],
                    "cfg_attrs": cfg_attrs,
                })
            elif is_lib_rs:
                out["entrypoints"].append({
                    "file": rel,
                    "line": idx + 1,
                    "fn": m_fn.group(1),
                    "kind": "lib_rs_pub",
                    "attrs": [],
                    "cfg_attrs": cfg_attrs,
                })

        m_method = _METHOD_FN_RE.match(line)
        if m_method:
            rpc_attr = _rpc_attr(lines[:idx])
            if rpc_attr:
                rpc_kind, wire_name = rpc_attr
                trait_name, trait_cfg_attrs = _nearest_trait_context(lines[:idx])
                out["entrypoints"].append({
                    "file": rel,
                    "line": idx + 1,
                    "fn": m_method.group(1),
                    "kind": f"jsonrpsee_{rpc_kind}",
                    "attrs": [rpc_kind, f"rpc:{wire_name}"],
                    "rpc_method": wire_name,
                    "rpc_trait": trait_name,
                    "cfg_attrs": _nearby_cfg_attrs(lines[:idx]),
                    "rpc_trait_cfg_attrs": trait_cfg_attrs,
                })

        # external_calls
        for label, rx in _EXTERNAL_CALL_RES:
            if rx.search(line):
                out["external_calls"].append({
                    "file": rel,
                    "line": idx + 1,
                    "call": label,
                    "snippet": _snippet(raw_line),
                })
                break  # one tag per line is enough

        # runtime_calls
        for label, rx in _RUNTIME_CALL_RES:
            if rx.search(line):
                out["runtime_calls"].append({
                    "file": rel,
                    "line": idx + 1,
                    "call": label,
                    "snippet": _snippet(raw_line),
                })
                break

        # unsafe blocks
        if _UNSAFE_BLOCK_RE.search(line):
            out["unsafe_blocks"].append({
                "file": rel,
                "line": idx + 1,
            })

        # value_movement_calls
        for label, rx in _VALUE_MOVEMENT_RES:
            if rx.search(line):
                out["value_movement_calls"].append({
                    "file": rel,
                    "line": idx + 1,
                    "call": label,
                    "snippet": _snippet(raw_line),
                })
                break

    # trait_impls — multi-line aware via the file-level regex. We also collect
    # method names inside each matched impl block as a bounded dispatch target
    # inventory. This is not trait resolution; it just replaces "unknown trait
    # dispatch" with exact method slots for runtime review.
    for m in _TRAIT_IMPL_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        trait = m.group("trait").strip()
        struct = m.group("struct").strip()
        # filter false-positives where 'trait' captured something like
        # the body of an inherent impl (e.g. `impl Foo` with no `for`).
        # The regex requires `for`, so this is mostly safe; we still
        # drop overly long matches that span braces.
        if "{" in trait or "{" in struct:
            continue
        methods: List[str] = []
        brace_depth = 0
        seen_open = False
        for body_idx in range(line_no - 1, len(lines)):
            body_line = _strip_line_comments(lines[body_idx])
            brace_depth += body_line.count("{")
            if "{" in body_line:
                seen_open = True
            m_method = _FN_RE.match(body_line)
            if m_method and seen_open:
                method = m_method.group(1)
                methods.append(method)
                out["trait_method_impls"].append({
                    "file": rel,
                    "line": body_idx + 1,
                    "trait": trait,
                    "struct": struct,
                    "method": method,
                })
            brace_depth -= body_line.count("}")
            if seen_open and brace_depth <= 0:
                break
        out["trait_impls"].append({
            "file": rel,
            "line": line_no,
            "trait": trait,
            "struct": struct,
            "methods": methods,
            "cfg_attrs": _nearby_cfg_attrs(lines[:line_no - 1]),
        })

    out["enum_dispatches"] = _collect_enum_dispatches(workspace, path, text)

    return out


# ---------------------------------------------------------------------------
# Crate-level aggregation
# ---------------------------------------------------------------------------

def scan_crate(workspace: Path, crate_name: str, crate_root: Path) -> Dict[str, Any]:
    src = crate_root / "src"
    files = _rs_files_in(src)
    inventory: Dict[str, List[Dict[str, Any]]] = {
        "entrypoints": [],
        "trait_impls": [],
        "trait_impl_methods": [],
        "enum_dispatches": [],
        "external_calls": [],
        "runtime_calls": [],
        "rpc_routes": [],
        "unsafe_blocks": [],
        "value_movement_calls": [],
    }
    impl_methods: List[Dict[str, Any]] = []
    trait_methods: List[Dict[str, Any]] = []
    cfg_attrs_all: List[Dict[str, Any]] = []
    macro_invocations_all: List[Dict[str, Any]] = []
    for f in files:
        extracted = extract_file(workspace, crate_root, f)
        for k in inventory:
            inventory[k].extend(extracted[k])
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        impl_methods.extend(_collect_impl_methods(workspace, f, text))
        trait_methods.extend(_collect_trait_methods(workspace, f, text))
        cfg_attrs_all.extend(_collect_file_cfg_attrs(workspace, f, text))
        macro_invocations_all.extend(_collect_file_macro_invocations(workspace, f, text))
    rpc_entries = [
        e for e in inventory["entrypoints"]
        if str(e.get("kind", "")).startswith("jsonrpsee_") and e.get("rpc_method")
    ]
    inventory["rpc_routes"] = _route_rpc_methods(rpc_entries, impl_methods)
    inventory["trait_impl_methods"] = _bind_trait_impl_methods(trait_methods, impl_methods)
    # Schema (REQUIRED_CRATE_KEYS at line 1038) expects ``trait_method_impls``
    # at the crate level too — keep both names as aliases of the bound view so
    # downstream consumers and the schema validator both stay green.
    inventory.setdefault("trait_method_impls", inventory["trait_impl_methods"])
    # P1-2: Populate cfg_attrs and macro_invocations from per-file extraction.
    # cfg_attrs: flat list of every cfg/cfg_attr annotation in the crate.
    # macro_invocations: flat list of every macro call site (function-like + derive).
    inventory["cfg_attrs"] = cfg_attrs_all
    inventory["macro_invocations"] = macro_invocations_all
    return {
        "crate_root": _rel(workspace, crate_root),
        "files_scanned": len(files),
        **inventory,
    }


def build_graph(workspace: Path) -> Dict[str, Any]:
    workspace = workspace.resolve()
    crates = discover_crates(workspace)
    graph: Dict[str, Any] = {
        "_meta": {
            "schema_version": SCHEMA_VERSION,
            "workspace": str(workspace),
            "crate_count": len(crates),
        },
    }
    for name, root in crates:
        # If two crates share a name (rare; e.g. workspace + child) we
        # disambiguate with the relative path to keep the JSON valid.
        key = name
        if key in graph:
            key = f"{name}@{_rel(workspace, root)}"
        graph[key] = scan_crate(workspace, name, root)
    return graph


# ---------------------------------------------------------------------------
# Validation mode (--validate)
# ---------------------------------------------------------------------------

REQUIRED_CRATE_KEYS = {
    "crate_root", "files_scanned",
    "entrypoints", "trait_impls", "trait_method_impls",
    "cfg_attrs", "macro_invocations", "external_calls",
    "unsafe_blocks", "value_movement_calls",
}
ENTRY_KEYS = {"file", "line", "fn", "kind", "attrs"}
TRAIT_KEYS = {"file", "line", "trait", "struct"}
TRAIT_METHOD_KEYS = {"file", "line", "trait", "struct", "fn", "trait_decl_file", "trait_decl_line"}
ENUM_DISPATCH_KEYS = {"file", "line", "enum", "variant", "dispatch_kind", "target"}
CALL_KEYS = {"file", "line", "call", "snippet"}
ROUTE_KEYS = {
    "file", "line", "fn", "rpc_method", "impl_file", "impl_line", "runtime_calls",
}
UNSAFE_KEYS = {"file", "line"}
VALUE_KEYS = {"file", "line", "call", "snippet"}


def _check_list(items: Any, required: set, where: str) -> List[str]:
    errors: List[str] = []
    if not isinstance(items, list):
        errors.append(f"{where}: expected list, got {type(items).__name__}")
        return errors
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"{where}[{i}]: expected dict")
            continue
        missing = required - set(item.keys())
        if missing:
            errors.append(f"{where}[{i}]: missing keys {sorted(missing)}")
    return errors


def validate_graph(graph: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(graph, dict):
        return ["top-level: expected dict"]
    meta = graph.get("_meta")
    if not isinstance(meta, dict):
        errors.append("_meta: missing or not a dict")
    else:
        if meta.get("schema_version") != SCHEMA_VERSION:
            errors.append(
                f"_meta.schema_version: expected {SCHEMA_VERSION}, "
                f"got {meta.get('schema_version')!r}"
            )
        if not isinstance(meta.get("crate_count"), int):
            errors.append("_meta.crate_count: expected int")
    for key, val in graph.items():
        if key == "_meta":
            continue
        if not isinstance(val, dict):
            errors.append(f"{key}: expected dict crate body")
            continue
        missing = REQUIRED_CRATE_KEYS - set(val.keys())
        if missing:
            errors.append(f"{key}: missing crate keys {sorted(missing)}")
            continue
        errors.extend(_check_list(val["entrypoints"],          ENTRY_KEYS,  f"{key}.entrypoints"))
        errors.extend(_check_list(val["trait_impls"],          TRAIT_KEYS,  f"{key}.trait_impls"))
        if "trait_impl_methods" in val:
            errors.extend(_check_list(val["trait_impl_methods"], TRAIT_METHOD_KEYS, f"{key}.trait_impl_methods"))
        if "enum_dispatches" in val:
            errors.extend(_check_list(val["enum_dispatches"], ENUM_DISPATCH_KEYS, f"{key}.enum_dispatches"))
        errors.extend(_check_list(val["external_calls"],       CALL_KEYS,   f"{key}.external_calls"))
        if "runtime_calls" in val:
            errors.extend(_check_list(val["runtime_calls"],    CALL_KEYS,   f"{key}.runtime_calls"))
        if "rpc_routes" in val:
            errors.extend(_check_list(val["rpc_routes"],       ROUTE_KEYS,  f"{key}.rpc_routes"))
        errors.extend(_check_list(val["unsafe_blocks"],        UNSAFE_KEYS, f"{key}.unsafe_blocks"))
        errors.extend(_check_list(val["value_movement_calls"], VALUE_KEYS,  f"{key}.value_movement_calls"))
    return errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _default_out(workspace: Path) -> Path:
    return workspace / ".auditooor" / "rust_source_graph.json"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="rust-source-graph",
        description=(
            "Build a syntactic Rust source-graph inventory "
            "(entrypoints / trait impls / external calls / unsafe / value movement). "
            "stdlib-only; not a full Rust frontend."
        ),
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace", type=Path,
                   help="Build graph for this workspace.")
    g.add_argument("--validate", type=Path,
                   help="Re-read this graph JSON and assert schema integrity.")
    p.add_argument("--out", type=Path, default=None,
                   help="Path to write graph JSON (default: <workspace>/.auditooor/rust_source_graph.json).")
    p.add_argument("--print-json", action="store_true",
                   help="Also print the graph JSON to stdout (build mode).")
    args = p.parse_args(argv)

    if args.validate is not None:
        path = args.validate.expanduser().resolve()
        if not path.is_file():
            print(f"[rust-source-graph] ERR not found: {path}", file=sys.stderr)
            return 2
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"[rust-source-graph] ERR cannot parse {path}: {exc}", file=sys.stderr)
            return 3
        errors = validate_graph(data)
        if errors:
            for e in errors:
                print(f"[rust-source-graph] schema-error {e}", file=sys.stderr)
            return 3
        print(f"[rust-source-graph] OK {path} schema={SCHEMA_VERSION}", file=sys.stderr)
        return 0

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-source-graph] ERR workspace not found: {workspace}", file=sys.stderr)
        return 2
    graph = build_graph(workspace)
    out = args.out.expanduser().resolve() if args.out else _default_out(workspace)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    crate_count = graph["_meta"]["crate_count"]
    total_entries = sum(len(v["entrypoints"]) for k, v in graph.items() if k != "_meta")
    if args.print_json:
        sys.stdout.write(json.dumps(graph, indent=2, sort_keys=True) + "\n")
    print(
        f"[rust-source-graph] OK crates={crate_count} entrypoints={total_entries} "
        f"json={out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
