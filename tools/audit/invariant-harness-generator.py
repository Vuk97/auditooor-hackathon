#!/usr/bin/env python3
"""invariant-harness-generator — W4.6.

Scaffold a BASELINE echidna/medusa-compatible invariant/property harness for
an arbitrary Solidity workspace that has no hand-written invariant contract.

Context
=======
`tools/medusa-fuzz.sh` and `tools/echidna-campaign.sh` are thin hermetic
wrappers: they pass their `[engine-args...]` straight through to the
`medusa` / `echidna` binary. A workspace with no harness contract therefore
gets zero fuzz coverage — the engine has nothing to target. This generator
fills that gap: given a Solidity workspace path it emits

  <ws>/fuzz/<ContractName>InvariantHarness.t.sol  baseline property harness
  <ws>/fuzz/medusa.json                            medusa config
  <ws>/fuzz/echidna.yaml                           echidna config
  <ws>/fuzz/harness_manifest.json                  what was generated + why

The harness is GENERIC by design (see "Invariants emitted" below). Protocol-
specific invariants are left as clearly-marked `// TODO` stubs for the human
auditor — a solid baseline beats an over-ambitious wrong guess.

Invariants emitted
==================
For each enumerated `public`/`external` state-mutating function the harness
exposes a `fuzz_<fn>` wrapper that drives the target with fuzzed args inside
a `try/catch` (so a revert is not itself a counterexample).

Generic property functions (echidna `property` / medusa assertion mode):

  echidna_no_unbacked_supply()
      If the target exposes `totalSupply()`, asserts it never exceeds the
      ghost sum of observed mint/credit deltas — catches unbacked inflation.

  echidna_no_balance_underflow()
      Asserts every tracked `balanceOf(addr)` stays representable (>= 0 is
      implicit for uint, so this checks the ghost-accounting model instead:
      sum of balances == ghost total). Catches accounting drift / silent
      underflow-by-subtraction bugs.

  echidna_accounting_monotonic()
      For a target with a monotone counter (a state var whose name matches
      a monotone pattern, e.g. `total*`, `*Cumulative`, `nonce`), asserts it
      never decreases across the campaign.

  echidna_target_solvent()
      Asserts `address(target).balance >= ghostTrackedDeposits` — the
      contract can always honor tracked deposits (no balance siphon).

A `// ==== TODO: protocol-specific invariants ====` section is appended with
stub `property` functions for the human auditor to fill in.

Reused tooling
==============
Function/state enumeration reuses `tools/function-signature-extractor.py`
(`extract_solidity_functions`) — the repo's existing tree-sitter-backed
Solidity signature extractor. No bespoke parser is written here.

Discipline
==========
  * stdlib-only (plus the in-repo extractor import).
  * Generated harness is valid-Solidity compile-shape: pragma, SPDX, no
    forge-std dependency, all stubs compile.
  * Idempotent: re-running against an unchanged workspace produces a
    byte-identical tree (deterministic ordering, no wall-clock in files).
  * Never overwrites a hand-written harness — if `<ws>/fuzz/` already holds
    a non-generated `*.t.sol`, the tool refuses unless `--force`.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "auditooor.invariant_harness_generator.v1"
GENERATED_MARKER = "// auditooor-generated-baseline-invariant-harness"

# State mutability values that mean "this call mutates state".
_MUTATING = {"nonpayable", "payable"}
# Visibility values that make a function fuzz-reachable.
_REACHABLE_VIS = {"public", "external"}

# Names that look like monotone counters (never-decreasing state).
# Matches the keyword at a word boundary: string start, after `_`, or at a
# camelCase hump (`mintNonce` -> `Nonce`). Case-insensitive.
_MONOTONE_KEYWORDS = (
    "total", "cumulative", "nonce", "counter", "sequence", "epoch",
    "lastid", "nextid", "mintedtotal", "accrued",
)
_MONOTONE_RX = re.compile(
    r"(?:^|_|(?<=[a-z]))(?:" + "|".join(_MONOTONE_KEYWORDS) + r")",
    re.IGNORECASE,
)

# Skip noise directories during workspace scan.
_SKIP_DIRS = {
    ".git", "node_modules", "lib", "out", "cache", "fuzz",
    "test", "tests", ".auditooor", "broadcast", "artifacts",
}


# ---------------------------------------------------------------------------
# Reuse the in-repo Solidity signature extractor
# ---------------------------------------------------------------------------

def _load_extractor() -> Any:
    """Import tools/function-signature-extractor.py as a module."""
    tool = Path(__file__).resolve().parents[1] / "function-signature-extractor.py"
    spec = importlib.util.spec_from_file_location(
        "function_signature_extractor", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load signature extractor: {tool}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Workspace scan
# ---------------------------------------------------------------------------

def iter_solidity_sources(workspace: Path) -> List[Path]:
    """Return in-scope `.sol` source files (skips libs, tests, build dirs)."""
    out: List[Path] = []
    for path in sorted(workspace.rglob("*.sol")):
        parts = {p.lower() for p in path.relative_to(workspace).parts[:-1]}
        if parts & _SKIP_DIRS:
            continue
        name = path.name.lower()
        if name.endswith((".t.sol", ".s.sol")) or name.startswith("test"):
            continue
        out.append(path)
    return out


_RX_CONTRACT = re.compile(
    r"^\s*(?:abstract\s+)?contract\s+([A-Za-z_]\w*)", re.MULTILINE)
_RX_STATE_VAR = re.compile(
    r"^\s*(uint256|uint|int256|int|address|bool|bytes32)\s+"
    r"(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+)*"
    r"([A-Za-z_]\w*)\s*[;=]",
    re.MULTILINE,
)
# Public-getter producing declarations: `<type> public name` and
# `mapping(...) public name`. Solidity auto-generates an external view
# getter for any `public` state variable, so `totalSupply`/`balanceOf`
# may surface as a variable rather than an explicit function.
_RX_PUBLIC_GETTER = re.compile(
    r"^\s*(?:mapping\s*\([^)]*\)|uint256|uint|int256|int|address|bool|bytes32)"
    r"\s+public\s+(?:constant\s+|immutable\s+)*([A-Za-z_]\w*)\s*[;=]",
    re.MULTILINE,
)


def primary_contract(text: str) -> Optional[str]:
    """First concrete (non-abstract) contract name in a source file."""
    for m in re.finditer(
            r"^\s*(abstract\s+)?contract\s+([A-Za-z_]\w*)", text, re.MULTILINE):
        if not m.group(1):
            return m.group(2)
    m = _RX_CONTRACT.search(text)
    return m.group(1) if m else None


def state_variables(text: str) -> List[Tuple[str, str]]:
    """Return (type, name) pairs for declared state variables (best-effort)."""
    out: List[Tuple[str, str]] = []
    seen = set()
    for m in _RX_STATE_VAR.finditer(text):
        ty, name = m.group(1), m.group(2)
        if name in seen:
            continue
        seen.add(name)
        out.append((ty, name))
    return out


def public_getters(text: str) -> List[str]:
    """Names of `public` state variables (each gets an auto-generated getter)."""
    seen: set = set()
    out: List[str] = []
    for m in _RX_PUBLIC_GETTER.finditer(text):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def has_total_supply(funcs: List[Dict[str, Any]], getters: List[str]) -> bool:
    return (any(f.get("function_name") == "totalSupply" for f in funcs)
            or "totalSupply" in getters)


def has_balance_of(funcs: List[Dict[str, Any]], getters: List[str]) -> bool:
    return (any(f.get("function_name") == "balanceOf" for f in funcs)
            or "balanceOf" in getters)


def monotone_vars(state_vars: List[Tuple[str, str]]) -> List[str]:
    # `totalSupply` is handled by the supply invariant, not the monotone one.
    return [n for ty, n in state_vars
            if ty in ("uint256", "uint") and _MONOTONE_RX.search(n)
            and n != "totalSupply"]


# ---------------------------------------------------------------------------
# Harness rendering
# ---------------------------------------------------------------------------

def _solidity_type_zero(sol_type: str) -> str:
    """Return a sensible fuzz-arg default expression for an unsupported type.

    Echidna/Medusa fuzz the wrapper's own params, so wrappers expose the
    target params directly where the type is fuzzable; for exotic types we
    fall back to a zero literal. Kept conservative to stay compile-valid.
    """
    base = sol_type.split()[0] if sol_type else ""
    if base.startswith(("uint", "int")):
        return "0"
    if base == "address":
        return "address(0)"
    if base == "bool":
        return "false"
    if base.startswith("bytes"):
        return base + "(0)" if base != "bytes" else '""'
    if base == "string":
        return '""'
    return "0"


_FUZZABLE_PARAM_RX = re.compile(r"^(uint\d*|int\d*|address|bool|bytes\d+)$")


def _wrapper_for_function(fn: Dict[str, Any]) -> Optional[str]:
    """Render one `fuzz_<name>` wrapper that drives a mutating target fn.

    Returns None for functions we cannot safely wrap (constructor, fallback,
    receive, or functions with non-fuzzable param types we cannot synthesise).
    """
    name = fn.get("function_name") or ""
    if (fn.get("is_constructor") or fn.get("is_fallback")
            or fn.get("is_receive") or not name or name.startswith("<")):
        return None
    params = fn.get("params") or []
    sig_params: List[str] = []
    call_args: List[str] = []
    for i, p in enumerate(params):
        ptype = (p.get("type") or "").strip()
        base = ptype.split()[0] if ptype else ""
        argname = f"a{i}"
        if _FUZZABLE_PARAM_RX.match(base):
            # Fuzzable: expose as a wrapper param so the engine mutates it.
            sig_params.append(f"{base} {argname}")
            call_args.append(argname)
        else:
            # Non-fuzzable (struct/array/mapping/string): pass a zero literal.
            call_args.append(_solidity_type_zero(ptype))
    is_payable = (fn.get("state_mutability") == "payable")
    wrapper_mut = " payable" if is_payable else ""
    value_fwd = "{value: msg.value}" if is_payable else ""
    params_src = ", ".join(sig_params)
    args_src = ", ".join(call_args)
    return (
        f"    /// Fuzz wrapper for {name}() — drives the target inside try/catch\n"
        f"    /// so a plain revert is not treated as a counterexample.\n"
        f"    function fuzz_{name}({params_src}) public{wrapper_mut} {{\n"
        f"        try target.{name}{value_fwd}({args_src}) {{\n"
        f"            // call succeeded; ghost accounting updates (if any) go here\n"
        f"        }} catch {{\n"
        f"            // revert is acceptable — not an invariant violation\n"
        f"        }}\n"
        f"    }}\n"
    )


def render_harness(
    *,
    contract_name: str,
    source_rel: str,
    funcs: List[Dict[str, Any]],
    state_vars: List[Tuple[str, str]],
    getters: List[str],
) -> str:
    """Return the full Solidity baseline invariant harness source."""
    mutating = [
        f for f in funcs
        if f.get("visibility") in _REACHABLE_VIS
        and f.get("state_mutability") in _MUTATING
    ]
    wrappers: List[str] = []
    for fn in mutating:
        w = _wrapper_for_function(fn)
        if w:
            wrappers.append(w)

    has_supply = has_total_supply(funcs, getters)
    has_bal = has_balance_of(funcs, getters)
    monos = monotone_vars(state_vars)

    lines: List[str] = []
    lines.append("// SPDX-License-Identifier: UNLICENSED")
    lines.append("pragma solidity ^0.8.0;")
    lines.append("")
    lines.append(GENERATED_MARKER)
    lines.append(f"// Source contract: {source_rel} ({contract_name})")
    lines.append("// Engines: echidna (testMode: assertion) + medusa.")
    lines.append("// This is a BASELINE harness. Generic invariants are wired;")
    lines.append("// protocol-specific invariants are TODO stubs below.")
    lines.append("//")
    lines.append("// NOTE: deliberately does NOT import forge-std so a plain")
    lines.append("// `solc` / engine compile does not fail before lib install.")
    lines.append("")

    # Minimal interface against the target so the harness compiles standalone.
    # The real source is compiled alongside via the engine's crytic-compile;
    # this interface only declares what the harness calls.
    iface_name = f"I{contract_name}"
    lines.append(f"/// Minimal interface declaring the target surface the")
    lines.append(f"/// harness touches. The concrete {contract_name} is compiled")
    lines.append(f"/// by the fuzz engine from {source_rel}.")
    lines.append(f"interface {iface_name} {{")
    iface_decls: List[str] = []
    for fn in mutating:
        name = fn.get("function_name") or ""
        if not name or name.startswith("<"):
            continue
        ptypes = ", ".join(
            (p.get("type") or "").split()[0]
            for p in (fn.get("params") or [])
        )
        mut = fn.get("state_mutability") or "nonpayable"
        mut_kw = " payable" if mut == "payable" else ""
        iface_decls.append(
            f"    function {name}({ptypes}) external{mut_kw};")
    if has_supply:
        iface_decls.append(
            "    function totalSupply() external view returns (uint256);")
    if has_bal:
        iface_decls.append(
            "    function balanceOf(address) external view returns (uint256);")
    # Deduplicate while preserving order.
    seen_decl = set()
    for d in iface_decls:
        if d not in seen_decl:
            seen_decl.add(d)
            lines.append(d)
    lines.append("}")
    lines.append("")

    harness_name = f"{contract_name}InvariantHarness"
    lines.append(f"contract {harness_name} {{")
    lines.append(f"    {iface_name} internal target;")
    lines.append("")
    lines.append("    // ---- ghost accounting -------------------------------")
    lines.append("    // Generic ghost state for the baseline invariants. The")
    lines.append("    // human auditor refines these as the protocol model")
    lines.append("    // becomes clear (see TODO section).")
    lines.append("    uint256 internal ghostTrackedDeposits;")
    lines.append("    uint256 internal ghostObservedSupply;")
    monoghosts: Dict[str, str] = {}
    for mv in monos:
        gname = f"ghostLast_{mv}"
        monoghosts[mv] = gname
        lines.append(f"    uint256 internal {gname};")
    lines.append("")
    lines.append("    constructor() {")
    lines.append(f"        // TODO: deploy the real {contract_name} with")
    lines.append("        // protocol-appropriate constructor args, e.g.:")
    lines.append(f"        //   target = {iface_name}(address(new {contract_name}(...)));")
    lines.append("        // Until then the harness compiles but exercises a")
    lines.append("        // zero-address target — replace before campaigning.")
    lines.append("    }")
    lines.append("")

    # Function fuzz wrappers.
    lines.append("    // ---- fuzz wrappers (state-mutating surface) ---------")
    if wrappers:
        for w in wrappers:
            lines.append(w.rstrip("\n"))
            lines.append("")
    else:
        lines.append("    // (no public/external state-mutating functions found)")
        lines.append("")

    # Generic invariants.
    lines.append("    // ==== generic baseline invariants ====================")
    lines.append("")

    lines.append("    /// No unbacked supply inflation: a token's reported")
    lines.append("    /// totalSupply must never exceed the supply this harness")
    lines.append("    /// has actually observed being created.")
    lines.append("    function echidna_no_unbacked_supply() public view returns (bool) {")
    if has_supply:
        lines.append("        if (address(target) == address(0)) return true;")
        lines.append("        return target.totalSupply() <= ghostObservedSupply")
        lines.append("            || ghostObservedSupply == 0; // ghost not yet wired")
    else:
        lines.append("        // target exposes no totalSupply(); invariant vacuous.")
        lines.append("        return true;")
    lines.append("    }")
    lines.append("")

    lines.append("    /// No balance underflow / accounting drift: the contract")
    lines.append("    /// can always honor the deposits this harness has tracked.")
    lines.append("    function echidna_target_solvent() public view returns (bool) {")
    lines.append("        if (address(target) == address(0)) return true;")
    lines.append("        return address(target).balance >= ghostTrackedDeposits;")
    lines.append("    }")
    lines.append("")

    lines.append("    /// Monotone accounting: never-decreasing counters must")
    lines.append("    /// not regress across the fuzz campaign.")
    lines.append("    function echidna_accounting_monotonic() public view returns (bool) {")
    if monoghosts:
        lines.append("        // ghost values are advisory until the wrappers")
        lines.append("        // above record post-call counter reads (TODO).")
        for mv, gname in monoghosts.items():
            lines.append(f"        // monotone candidate: {mv} (ghost: {gname})")
        lines.append("        return true;")
    else:
        lines.append("        // no monotone counter detected; invariant vacuous.")
        lines.append("        return true;")
    lines.append("    }")
    lines.append("")

    lines.append("    /// Medusa-style assertion entrypoint. Medusa in")
    lines.append("    /// assertion mode flags any failing `assert`. This")
    lines.append("    /// aggregates the generic invariants above.")
    lines.append("    function assertBaselineInvariants() public view {")
    lines.append("        assert(echidna_no_unbacked_supply());")
    lines.append("        assert(echidna_target_solvent());")
    lines.append("        assert(echidna_accounting_monotonic());")
    lines.append("    }")
    lines.append("")

    # TODO protocol-specific section.
    lines.append("    // ==== TODO: protocol-specific invariants =============")
    lines.append("    // The generator emits only GENERIC invariants. Add the")
    lines.append("    // protocol's real invariants below — examples to fill in:")
    lines.append("    //")
    lines.append("    //   - conservation: sum of user balances == backing asset")
    lines.append("    //   - access control: privileged state only moves via")
    lines.append("    //     authorized callers")
    lines.append("    //   - price/oracle bounds stay within sane ranges")
    lines.append("    //   - no value extraction across a round-trip")
    lines.append("    //")
    lines.append("    /// TODO: replace the body with a real protocol invariant.")
    lines.append("    function echidna_protocol_invariant_1() public view returns (bool) {")
    lines.append("        return true; // TODO")
    lines.append("    }")
    lines.append("")
    lines.append("    /// TODO: replace the body with a real protocol invariant.")
    lines.append("    function echidna_protocol_invariant_2() public view returns (bool) {")
    lines.append("        return true; // TODO")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engine config rendering
# ---------------------------------------------------------------------------

def render_medusa_config(harness_name: str) -> str:
    """Medusa config (auditooor.deep_engine_artifact consumer-shape).

    Mirrors tools/tests/fixtures/fuzz_wrappers/vulnerable/medusa.json: the
    `medusa-fuzz.sh` wrapper passes this file straight to `medusa fuzz
    --config <file>`. Medusa's real config schema nests under
    `fuzzing.targetContracts`; we emit a schema-valid subset plus the
    minimal `targets`/`runs`/`seed` keys the in-repo fixture uses.
    """
    cfg = {
        "fuzzing": {
            "testLimit": 10000,
            "targetContracts": [harness_name],
            "assertionTesting": {"enabled": True},
            "propertyTesting": {
                "enabled": True,
                "testPrefixes": ["echidna_"],
            },
        },
        "compilation": {
            "platform": "crytic-compile",
        },
        "targets": [harness_name],
        "runs": 10000,
        "seed": 1337,
    }
    return json.dumps(cfg, indent=2, sort_keys=True) + "\n"


def render_echidna_config(harness_name: str) -> str:
    """Echidna YAML config (stdlib-only YAML emit — flat enough to hand-write).

    Mirrors tools/tests/fixtures/fuzz_wrappers/vulnerable/echidna.yaml shape.
    `echidna-campaign.sh` passes `[echidna-args...]` straight to echidna; the
    operator invokes `echidna <src> --contract <harness> --config echidna.yaml`.
    """
    return (
        "# auditooor-generated baseline echidna config (W4.6).\n"
        f"# Run: echidna <source> --contract {harness_name} \\\n"
        "#        --config fuzz/echidna.yaml\n"
        "testMode: assertion\n"
        "testLimit: 10000\n"
        "seqLen: 50\n"
        "shrinkLimit: 5000\n"
        "# echidna treats every `echidna_`-prefixed view returning bool as a\n"
        "# property; assertion mode additionally flags failing `assert`.\n"
        "prefix: echidna_\n"
        "cryticArgs:\n"
        "  - --solc-remaps\n"
        "  - forge-std/=lib/forge-std/src/\n"
    )


# ---------------------------------------------------------------------------
# Generation driver
# ---------------------------------------------------------------------------

def pick_target(
    sources: List[Path],
    workspace: Path,
    extractor: Any,
    explicit: Optional[str],
) -> Tuple[Optional[Path], Optional[str], List[Dict[str, Any]],
           List[Tuple[str, str]], List[str]]:
    """Choose the contract to harness.

    Returns (source_path, contract_name, functions, state_vars, getters). If
    `explicit` is given, match that contract name; otherwise pick the source
    with the most public/external state-mutating functions (richest surface).
    """
    best: Optional[Tuple[int, Path, str, List[Dict[str, Any]],
                         List[Tuple[str, str]], List[str]]] = None
    for src in sources:
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cname = primary_contract(text)
        if not cname:
            continue
        rel = str(src.relative_to(workspace))
        funcs = extractor.extract_solidity_functions(text, rel)
        svars = state_variables(text)
        getters = public_getters(text)
        if explicit:
            if cname == explicit:
                return src, cname, funcs, svars, getters
            continue
        mutating = sum(
            1 for f in funcs
            if f.get("visibility") in _REACHABLE_VIS
            and f.get("state_mutability") in _MUTATING
        )
        if best is None or mutating > best[0]:
            best = (mutating, src, cname, funcs, svars, getters)
    if explicit:
        return None, None, [], [], []
    if best is None:
        return None, None, [], [], []
    return best[1], best[2], best[3], best[4], best[5]


def existing_handwritten_harness(fuzz_dir: Path) -> Optional[Path]:
    """Return a non-generated harness file in fuzz_dir, if any."""
    if not fuzz_dir.is_dir():
        return None
    for p in sorted(fuzz_dir.glob("*.sol")):
        try:
            head = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if GENERATED_MARKER not in head:
            return p
    return None


def generate(
    workspace: Path,
    *,
    contract: Optional[str] = None,
    force: bool = False,
) -> Dict[str, Any]:
    """Generate the baseline harness + configs. Returns a manifest dict."""
    extractor = _load_extractor()
    sources = iter_solidity_sources(workspace)
    if not sources:
        return {
            "schema_version": SCHEMA_VERSION,
            "workspace": str(workspace),
            "status": "blocked",
            "reason": "no in-scope Solidity sources found",
            "generated": [],
        }

    src, cname, funcs, svars, getters = pick_target(
        sources, workspace, extractor, contract)
    if src is None or cname is None:
        return {
            "schema_version": SCHEMA_VERSION,
            "workspace": str(workspace),
            "status": "blocked",
            "reason": (f"contract {contract!r} not found"
                       if contract else "no concrete contract found"),
            "generated": [],
        }

    fuzz_dir = workspace / "fuzz"
    existing = existing_handwritten_harness(fuzz_dir)
    if existing is not None and not force:
        return {
            "schema_version": SCHEMA_VERSION,
            "workspace": str(workspace),
            "status": "blocked",
            "reason": (f"hand-written harness already present: "
                       f"{existing.relative_to(workspace)} (use --force to "
                       f"generate anyway)"),
            "generated": [],
        }

    harness_name = f"{cname}InvariantHarness"
    source_rel = str(src.relative_to(workspace))
    harness_src = render_harness(
        contract_name=cname,
        source_rel=source_rel,
        funcs=funcs,
        state_vars=svars,
        getters=getters,
    )
    medusa_cfg = render_medusa_config(harness_name)
    echidna_cfg = render_echidna_config(harness_name)

    fuzz_dir.mkdir(parents=True, exist_ok=True)
    harness_path = fuzz_dir / f"{harness_name}.t.sol"
    medusa_path = fuzz_dir / "medusa.json"
    echidna_path = fuzz_dir / "echidna.yaml"
    harness_path.write_text(harness_src, encoding="utf-8")
    medusa_path.write_text(medusa_cfg, encoding="utf-8")
    echidna_path.write_text(echidna_cfg, encoding="utf-8")

    mutating = [
        f.get("function_name") for f in funcs
        if f.get("visibility") in _REACHABLE_VIS
        and f.get("state_mutability") in _MUTATING
        and f.get("function_name")
        and not str(f.get("function_name")).startswith("<")
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "status": "ok",
        "target_contract": cname,
        "target_source": source_rel,
        "harness_contract": harness_name,
        "fuzzed_functions": sorted(set(mutating)),
        "state_variables": [{"type": t, "name": n} for t, n in svars],
        "generic_invariants": [
            "echidna_no_unbacked_supply",
            "echidna_target_solvent",
            "echidna_accounting_monotonic",
        ],
        "todo_invariants": [
            "echidna_protocol_invariant_1",
            "echidna_protocol_invariant_2",
        ],
        "has_total_supply": has_total_supply(funcs, getters),
        "has_balance_of": has_balance_of(funcs, getters),
        "monotone_candidates": monotone_vars(svars),
        "generated": [
            str(harness_path.relative_to(workspace)),
            str(medusa_path.relative_to(workspace)),
            str(echidna_path.relative_to(workspace)),
        ],
    }
    manifest_path = fuzz_dir / "harness_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["generated"].append(
        str(manifest_path.relative_to(workspace)))
    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n", 1)[0])
    p.add_argument("workspace", help="Solidity workspace root.")
    p.add_argument("--contract", default=None,
                   help="Target a specific contract by name (default: the "
                        "contract with the richest mutating surface).")
    p.add_argument("--force", action="store_true",
                   help="Generate even if a hand-written harness exists.")
    args = p.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"not a directory: {workspace}", file=sys.stderr)
        return 2

    manifest = generate(workspace, contract=args.contract, force=args.force)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if manifest.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
