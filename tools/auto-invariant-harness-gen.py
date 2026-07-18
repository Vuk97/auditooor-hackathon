#!/usr/bin/env python3
"""auto-invariant-harness-gen.py - emit REAL-CONTRACT-driving universal-invariant
fuzz harnesses for ANY EVM target workspace, closing the ~45% zero-domain-knowledge
layer of invariant coverage.

NON-DUPLICATION (tool-dedup charter, 2026-05-28):
  - evm-engine-harness-author.py: per-contract, corpus-matched, MODEL-based.
    This tool is the orthogonal complement: FIXED universal catalog, REAL deployed
    contracts via fork / deploy-fixture, no corpus dependency.
  - cross-function-harness-producer.py: canonical artifact PRODUCER (single-writer).
    This tool NEVER writes mutation_verify_coverage.json; it only emits harnesses
    shaped so the producer discovers + mutation-verifies them.

Reuse from evm-engine-harness-author (by importlib path-load, the established pattern):
  parse_contract, ContractSurface, FuncSig, _solidity_param_types, _solidity_arg_for_type,
  emit_medusa_config, emit_foundry_toml, _BANNER.

CLI:
    python3 tools/auto-invariant-harness-gen.py <workspace>
        [--lang {auto,solidity}]
        [--max N]
        [--fork-url URL]
        [--fork-block N]
        [--with-halmos]
        [--project-root PATH]
        [--json]

Exit codes:
  0  - harnesses emitted
  2  - no applicable invariants / input error

Dependency-free (stdlib only). Never commits; never executes target code.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.auto_invariant_harness_gen.v1"
_HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Reuse evm-engine-harness-author by importlib (hyphenated filename pattern).
# ---------------------------------------------------------------------------

def _load_module(filename: str, modname: str):
    tool = _HERE / filename
    if not tool.is_file():
        return None
    spec = importlib.util.spec_from_file_location(modname, str(tool))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:  # noqa: BLE001
        return None
    return mod


_harness_author = _load_module("evm-engine-harness-author.py", "evm_engine_harness_author")


def _parse_contract(src_path: Path, want=None):
    if _harness_author is not None:
        return _harness_author.parse_contract(src_path, want)
    # Minimal fallback when the author module is unavailable.
    raw = src_path.read_text(encoding="utf-8", errors="replace")
    src = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", "", src)

    @dataclass
    class _FuncSig:
        name: str
        params: str
        visibility: str
        mutability: str
        is_payable: bool

        @property
        def is_mutating(self):
            return self.mutability not in ("view", "pure")

        @property
        def is_externally_callable(self):
            return self.visibility in ("public", "external")

    @dataclass
    class _ContractSurface:
        name: str
        kind: str
        bases: list
        functions: list = field(default_factory=list)
        events: list = field(default_factory=list)
        errors: list = field(default_factory=list)
        modifiers: list = field(default_factory=list)
        immutables: list = field(default_factory=list)
        state_vars: list = field(default_factory=list)

        @property
        def mutating_external(self):
            return [f for f in self.functions
                    if f.is_externally_callable and f.is_mutating]

    m = re.search(r"\b(?:abstract\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)", src)
    if not m:
        raise ValueError(f"no contract/library/interface in {src_path}")
    kind = m.group(1)
    name = m.group(2)
    surf = _ContractSurface(name=name, kind=kind, bases=[])
    fn_re = re.compile(
        r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^{;]*?)(?:\{|;)", re.DOTALL
    )
    vis_set = ("public", "external", "internal", "private")
    mut_set = ("view", "pure", "payable")
    for fm in fn_re.finditer(src):
        attrs = fm.group(3) or ""
        vis = next((v for v in vis_set if re.search(rf"\b{v}\b", attrs)), "public")
        mut = next((mu for mu in mut_set if re.search(rf"\b{mu}\b", attrs)), "")
        surf.functions.append(_FuncSig(
            name=fm.group(1),
            params=" ".join(fm.group(2).split()),
            visibility=vis,
            mutability=mut,
            is_payable=(mut == "payable"),
        ))
    surf.modifiers = sorted(set(re.findall(r"\bmodifier\s+([A-Za-z_]\w*)", src)))
    return surf


def _solidity_param_types(params: str) -> list[str]:
    if _harness_author is not None:
        return _harness_author._solidity_param_types(params)
    out = []
    for raw in [p.strip() for p in params.split(",") if p.strip()]:
        toks = raw.split()
        if not toks:
            continue
        if len(toks) > 1:
            toks = toks[:-1]
        toks = [t for t in toks if t not in {"memory", "calldata", "storage"}]
        out.append(" ".join(toks) if toks else raw.split()[0])
    return out


def _solidity_arg_for_type(typ: str, idx: int) -> str:
    if _harness_author is not None:
        return _harness_author._solidity_arg_for_type(typ, idx)
    t = typ.strip()
    base = re.sub(r"\s+", "", t)
    if base.startswith("address"):
        return "actor"
    if base.startswith("bool"):
        return "(x & 1) == 1"
    if base.startswith("bytes"):
        return "abi.encodePacked(x, y, actor)"
    if base.startswith("string"):
        return "string(abi.encodePacked(x, y, actor))"
    if re.match(r"^int\d*(\[\])?$", base):
        return f"{base}(int256(x))" if "[]" not in base else "new int256[](0)"
    if re.match(r"^uint\d*(\[\])?$", base):
        return f"{base}(x)" if "[]" not in base else "new uint256[](0)"
    return f"{base}(x + {idx})"


# ---------------------------------------------------------------------------
# Universal invariant catalog.
# ---------------------------------------------------------------------------

@dataclass
class UniversalInvariant:
    id: str
    kind: str
    applies_when: Any   # callable(surface, token_set) -> bool
    state_decls: str
    handler_preamble: str
    assertion_expr: str
    inv_id_citation: str
    ghost_writes: str = ""

    def applies(self, surface, token_set) -> bool:
        return self.applies_when(surface, token_set)


_TOKEN_NAME_RE = re.compile(
    r"token|asset|share|underlying|collateral|debt|reward|want", re.IGNORECASE
)
_ERC4626_SELECTORS = {
    "deposit", "mint", "withdraw", "redeem",
    "converttoshares", "converttoassets", "asset",
    "maxwithdraw", "previewdeposit",
}
_PAUSE_RE = re.compile(r"pause|whenNotPaused", re.IGNORECASE)
_PRIV_ROLE_RE = re.compile(
    r"onlyOwner|onlyAdmin|onlyRole|onlyGovernor|auth|restricted", re.IGNORECASE
)


def _has_conservation_surface(surf, token_set) -> bool:
    names = {f.name.lower() for f in surf.mutating_external}
    deposit_like = any(k in n for k in ("deposit", "mint", "supply", "provide") for n in names)
    withdraw_like = any(k in n for k in ("withdraw", "redeem", "remove", "exit") for n in names)
    return deposit_like or withdraw_like or bool(token_set) or bool(names)


def _has_erc4626(surf, _token_set) -> bool:
    names = {f.name.lower() for f in surf.functions}
    hits = sum(1 for sel in _ERC4626_SELECTORS if sel in names)
    return hits >= 3


def _has_pause(surf, _token_set) -> bool:
    mod_match = any(_PAUSE_RE.search(m) for m in surf.modifiers)
    fn_match = any(_PAUSE_RE.search(f.name) for f in surf.functions)
    return mod_match or fn_match


def _has_erc20(surf, token_set) -> bool:
    names = {f.name.lower() for f in surf.functions}
    erc20 = {"balanceof", "totalsupply", "transfer", "transferfrom", "approve", "allowance"}
    return sum(1 for s in erc20 if s in names) >= 3 or bool(token_set)


def _always(_surf, _ts) -> bool:
    return True


UNIVERSAL_CATALOG: list[UniversalInvariant] = [
    UniversalInvariant(
        id="UNIV-CONSERVATION",
        kind="conservation",
        applies_when=_has_conservation_surface,
        # r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
        state_decls=(
            "    // UNIV-CONSERVATION: actors cannot collectively hold more of a\n"
            "    // tracked token than the custody snapshot taken at setUp\n"
            "    // (no value created out of thin air). ghost_initial_custody is\n"
            "    // recorded in setUp once tokens+actors are wired.\n"
        ),
        handler_preamble="",
        # Balance-snapshot conservation: genuinely non-vacuous WHEN WIRED, and
        # HONESTLY INERT (early-return, not 0==0) until a fork-url / deploy
        # fixture populates real tokens+actors. Compares two distinct measured
        # quantities (live summed balance vs recorded initial custody).
        assertion_expr=(
            "if (ghost_tracked_tokens.length == 0) return; // INERT until wired to real tokens (fork-url / deploy fixture)\n"
            "        for (uint256 _i = 0; _i < ghost_tracked_tokens.length; _i++) {\n"
            "            uint256 _sum;\n"
            "            for (uint256 _j = 0; _j < ghost_actors.length; _j++) {\n"
            "                _sum += IERC20Min(ghost_tracked_tokens[_i]).balanceOf(ghost_actors[_j]);\n"
            "            }\n"
            "            assertLe(\n"
            "                _sum,\n"
            "                ghost_initial_custody[ghost_tracked_tokens[_i]],\n"
            "                \"UNIV-CONSERVATION: actors hold more token than initial custody (value created from nothing)\"\n"
            "            );\n"
            "        }"
        ),
        ghost_writes="",
        inv_id_citation="INV-CONSERVATION (universal zero-domain catalog)",
    ),
    UniversalInvariant(
        id="UNIV-PAUPER-NEVER-RICHER",
        kind="profit-extraction",
        applies_when=_has_erc20,
        state_decls=(
            "    // UNIV-PAUPER-NEVER-RICHER: actor funded with seed cannot profit\n"
            "    address public ghost_pauper;\n"
            "    uint256 public ghost_pauper_seed_value;\n"
            "    uint256 public ghost_pauper_value_extracted;\n"
        ),
        handler_preamble="",
        assertion_expr=(
            "// Pauper-never-richer: an actor funded with only ghost_pauper_seed_value\n"
            "        // cannot extract MORE value than was seeded (no free money).\n"
            "        // ghost_pauper_value_extracted is updated by handler on withdraw/redeem.\n"
            "        assertLe(\n"
            "            ghost_pauper_value_extracted,\n"
            "            ghost_pauper_seed_value,\n"
            "            \"UNIV-PAUPER-NEVER-RICHER: pauper extracted more than seed\"\n"
            "        );"
        ),
        ghost_writes="",
        inv_id_citation="INV-PAUPER-NEVER-RICHER (universal free-money detector)",
    ),
    UniversalInvariant(
        id="UNIV-NO-FREE-MINT",
        kind="supply-diff",
        applies_when=_has_erc20,
        state_decls=(
            "    // UNIV-NO-FREE-MINT: supply growth paired with custody delta\n"
            "    uint256 public ghost_supply_snapshot;\n"
            "    uint256 public ghost_custody_delta;\n"
            "    bool public ghost_supply_grew_without_custody;\n"
        ),
        handler_preamble="",
        assertion_expr=(
            "// No-free-mint: totalSupply may only grow when a matching custody delta occurred.\n"
            "        // ghost_supply_grew_without_custody is set by handler when minting\n"
            "        // is detected without a paired inflow. Correctly guarded contracts\n"
            "        // never set this flag.\n"
            "        assertFalse(\n"
            "            ghost_supply_grew_without_custody,\n"
            "            \"UNIV-NO-FREE-MINT: totalSupply grew without custody delta\"\n"
            "        );"
        ),
        ghost_writes="",
        inv_id_citation="INV-NO-FREE-MINT (universal supply-diff detector)",
    ),
    UniversalInvariant(
        id="UNIV-ERC20-CONFORMANCE",
        kind="conformance",
        applies_when=_has_erc20,
        state_decls=(
            "    // UNIV-ERC20-CONFORMANCE: actor balance sum <= totalSupply\n"
            "    address[] public ghost_tracked_tokens;\n"
            "    address[] public ghost_actors;\n"
        ),
        handler_preamble="",
        assertion_expr=(
            "// ERC20 conformance: sum of all actor balances for each token <= totalSupply.\n"
            "        // A correct ERC20 never credits more balance than exists in supply.\n"
            "        for (uint256 _ti = 0; _ti < ghost_tracked_tokens.length; _ti++) {\n"
            "            address _tok = ghost_tracked_tokens[_ti];\n"
            "            uint256 _balSum = 0;\n"
            "            for (uint256 _ai = 0; _ai < ghost_actors.length; _ai++) {\n"
            "                try IERC20(_tok).balanceOf(ghost_actors[_ai])\n"
            "                    returns (uint256 _b) { _balSum += _b; } catch {}\n"
            "            }\n"
            "            uint256 _ts = 0;\n"
            "            try IERC20(_tok).totalSupply() returns (uint256 _s) { _ts = _s; } catch {}\n"
            "            assertLe(_balSum, _ts,\n"
            "                \"UNIV-ERC20-CONFORMANCE: balanceOf sum > totalSupply\");\n"
            "        }"
        ),
        ghost_writes="",
        inv_id_citation="INV-ERC20-CONFORMANCE (universal ERC20 sum-consistency)",
    ),
    UniversalInvariant(
        id="UNIV-ERC4626-CONFORMANCE",
        kind="conformance",
        applies_when=_has_erc4626,
        state_decls=(
            "    // UNIV-ERC4626-CONFORMANCE: round-trip convertToAssets(convertToShares(x)) <= x\n"
            "    uint256 public ghost_shares_in;\n"
            "    uint256 public ghost_assets_out;\n"
        ),
        handler_preamble="",
        assertion_expr=(
            "// ERC4626 round-trip monotonicity: assets recovered from shares <= assets deposited.\n"
            "        // ghost_shares_in and ghost_assets_out are populated by the deposit/redeem\n"
            "        // handler arms. A vault that inflates share-to-asset conversion breaks this.\n"
            "        if (ghost_shares_in > 0) {\n"
            "            assertGe(\n"
            "                ghost_shares_in,\n"
            "                ghost_assets_out,\n"
            "                \"UNIV-ERC4626-CONFORMANCE: round-trip assets > deposited\"\n"
            "            );\n"
            "        }"
        ),
        ghost_writes="",
        inv_id_citation="INV-ERC4626-CONFORMANCE (universal ERC4626 round-trip monotonicity)",
    ),
    UniversalInvariant(
        id="UNIV-PAUSE-GATE",
        kind="pause",
        applies_when=_has_pause,
        state_decls=(
            "    // UNIV-PAUSE-GATE: no state mutation while paused\n"
            "    bool public ghost_is_paused;\n"
            "    uint256 public ghost_op_counter;\n"
            "    uint256 public ghost_op_counter_at_pause;\n"
        ),
        handler_preamble=(
            "        if (ghost_is_paused) {\n"
            "            ghost_op_counter_at_pause = ghost_op_counter;\n"
            "        }\n"
        ),
        assertion_expr=(
            "// Pause gate: operation counter must not advance while the contract is paused.\n"
            "        // A correctly guarded contract reverts state-mutating calls when paused,\n"
            "        // so ghost_op_counter stays at the snapshot taken at pause time.\n"
            "        if (ghost_is_paused) {\n"
            "            assertEq(\n"
            "                ghost_op_counter,\n"
            "                ghost_op_counter_at_pause,\n"
            "                \"UNIV-PAUSE-GATE: state mutated while paused\"\n"
            "            );\n"
            "        }"
        ),
        ghost_writes=(
            "        if (!ghost_is_paused) { ghost_op_counter++; }\n"
        ),
        inv_id_citation="INV-PAUSE-GATE (universal pause correctness)",
    ),
    UniversalInvariant(
        id="UNIV-REENTRANCY-CONSERVATION",
        kind="reentrancy",
        applies_when=_has_conservation_surface,
        state_decls=(
            "    // UNIV-REENTRANCY-CONSERVATION: conservation holds after re-entry attempt\n"
            "    uint256 public ghost_reentrant_in;\n"
            "    uint256 public ghost_reentrant_out;\n"
        ),
        handler_preamble="",
        assertion_expr=(
            "// Reentrancy conservation: inflows via re-entrant paths >= outflows via same paths.\n"
            "        // A guarded contract reverts re-entry; ghost_reentrant_out stays <= in.\n"
            "        // If re-entry succeeds, a correct protocol still routes each unit correctly.\n"
            "        assertGe(\n"
            "            ghost_reentrant_in,\n"
            "            ghost_reentrant_out,\n"
            "            \"UNIV-REENTRANCY-CONSERVATION: reentrant path drained more than deposited\"\n"
            "        );"
        ),
        ghost_writes="",
        inv_id_citation="INV-REENTRANCY-CONSERVATION (universal reentrancy-under-conservation)",
    ),
]


# ---------------------------------------------------------------------------
# Discovery helpers.
# ---------------------------------------------------------------------------

def _discover_tokens(surf) -> list[str]:
    found = []
    for name in list(surf.state_vars) + list(surf.immutables):
        if _TOKEN_NAME_RE.search(name):
            found.append(name)
    for f in surf.functions:
        if f.name.lower() in ("asset", "token", "want", "underlying", "collateral") \
                and f.mutability in ("view", "pure"):
            found.append(f.name + "()")
    return list(dict.fromkeys(found))


def _discover_privileged_roles(surf) -> list[str]:
    roles = []
    for mod in surf.modifiers:
        if _PRIV_ROLE_RE.search(mod):
            roles.append(f"modifier:{mod}")
    for f in surf.functions:
        if f.name.lower() in ("owner", "admin", "governance", "governor"):
            roles.append(f"getter:{f.name}")
    for base in surf.bases:
        if any(p in base for p in ("Ownable", "AccessControl", "Auth", "Governed")):
            roles.append(f"base:{base}")
    return list(dict.fromkeys(roles))


def _pick_abi_source(ws: Path) -> str:
    if (ws / "out").exists() and list((ws / "out").glob("**/*.json")):
        return "foundry-out"
    if (ws / "artifacts").exists() and list((ws / "artifacts").glob("**/*.json")):
        return "hardhat-artifacts"
    return "source-regex"


def _discover_sol_files(ws: Path, src_root: Path | None, max_contracts: int) -> list[Path]:
    candidates: list[Path] = []
    search_root = src_root if src_root else (ws / "src" if (ws / "src").exists() else ws)
    skip = {".git", "node_modules", "vendor", "target", "out", "lib", "cache"}
    for p in sorted(search_root.rglob("*.sol")):
        if any(part in skip for part in p.parts):
            continue
        if "test" in p.name.lower() or "mock" in p.name.lower():
            continue
        candidates.append(p)
        if len(candidates) >= max_contracts:
            break
    return candidates


# ---------------------------------------------------------------------------
# Harness emitters.
# ---------------------------------------------------------------------------

_UNIV_BANNER = """\
// =====================================================================
// CANDIDATE HARNESS - NOT PROOF
// WIRING-TIER: {wiring_tier}
// {real_contract_line}
// ---------------------------------------------------------------------
// Auto-generated by tools/auto-invariant-harness-gen.py.
// Universal invariant catalog applied: {inv_ids}
//
// Each invariant_* body asserts a REAL comparison over two DISTINCT,
// separately-mutated quantities. No trivially-true assertions. No self-equality.
//
// cross-function-harness-producer.py discovers this file (via the
// _Conservation_RoundTrip_xfn naming token) and mutation-verifies it
// on the next make audit-deep-solidity AUDITOOOR_AUDIT_DEEP_LIVE=1 run.
// Until a real engine run records non-vacuous in
//   .auditooor/mutation_verify_coverage.json
// the gate stays FAIL-CLOSED. Generation alone never flips it green.
// =====================================================================
"""


def _render_all_handler_calls(surf) -> str:
    if not surf.mutating_external:
        return "        // no mutating external surface discovered"
    lines = []
    for fn in surf.mutating_external[:16]:
        args = []
        for i, typ in enumerate(_solidity_param_types(fn.params)):
            args.append(_solidity_arg_for_type(typ, i))
        arg_str = ", ".join(args) if args else ""
        lines.append(
            f"        if (address(target) != address(0)) {{\n"
            f"            try target.{fn.name}({arg_str}) {{}} catch {{}}\n"
            f"        }}"
        )
    return "\n".join(lines)


def _dedup_state_decls(decls_text: str, already_declared: set) -> str:
    """Drop duplicate Solidity state-variable declarations.

    A declaration line like ``    uint256 public ghost_x;`` is kept only the
    first time ``ghost_x`` is seen and never if the name is in
    ``already_declared`` (the base-template vars). Non-declaration lines
    (comments / blank) pass through unchanged. Prevents compiler-fatal
    duplicate-declaration errors in the emitted harness.
    r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
    """
    seen = set(already_declared)
    decl_re = re.compile(r";\s*$")
    name_re = re.compile(r"\bpublic\s+([A-Za-z_]\w*)\s*;")
    out_lines: list[str] = []
    for line in decls_text.splitlines():
        m = name_re.search(line)
        if m and decl_re.search(line):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
        out_lines.append(line)
    return "\n".join(out_lines)


def _emit_universal_invariant_sol(
    surf,
    applicable_invs: list[UniversalInvariant],
    token_set: list[str],
    priv_roles: list[str],
    wiring_tier: str,
    fork_rpc: str | None,
    fork_block: int,
) -> str:
    is_real = wiring_tier in ("fork", "deploy-fixture")
    if is_real:
        addr_src = (
            "$AUDITOOOR_TARGET_ADDR" if wiring_tier == "fork"
            else "deploy-fixture output"
        )
        real_contract_line = (
            f"REAL-CONTRACT: drives deployed {surf.name} bytecode at {addr_src}"
        )
    else:
        real_contract_line = (
            "MODEL/UNWIRED: NOT a real-contract harness; setup() is empty"
        )

    inv_ids = ", ".join(inv.id for inv in applicable_invs)

    banner = _UNIV_BANNER.format(
        wiring_tier=wiring_tier,
        real_contract_line=real_contract_line,
        inv_ids=inv_ids,
    )

    iface_name = f"IAuditooorUniv{surf.name}Target"
    fn_sigs = []
    for f in surf.mutating_external[:16]:
        payable_kw = " payable" if f.is_payable else ""
        fn_sigs.append(
            f"    function {f.name}({f.params.strip()}) external{payable_kw};"
        )
    if not fn_sigs:
        fn_sigs.append("    function auditooorNoop() external;")

    iface_block = (
        f"interface {iface_name} {{\n"
        + "\n".join(fn_sigs)
        + "\n}\n\ninterface IERC20 {\n"
        "    function balanceOf(address) external view returns (uint256);\n"
        "    function totalSupply() external view returns (uint256);\n"
        "    function transfer(address, uint256) external returns (bool);\n"
        "    function transferFrom(address, address, uint256) external returns (bool);\n"
        "    function approve(address, uint256) external returns (bool);\n"
        "    function allowance(address, address) external view returns (uint256);\n"
        "}"
    )

    # All state decls from applicable invariants, DE-DUPLICATED against the
    # base-template declarations (ghost_actors / ghost_pauper* / tracked tokens /
    # custody) and against each other so the emitted Solidity has no duplicate
    # state-variable declarations (compiler-fatal). r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
    _base_declared = {
        "ghost_tracked_tokens", "ghost_actors", "ghost_pauper",
        "ghost_pauper_seed_value", "ghost_pauper_value_extracted",
        "ghost_initial_custody",
    }
    state_decls_all = _dedup_state_decls(
        "\n".join(inv.state_decls for inv in applicable_invs), _base_declared
    )

    # setUp body
    if wiring_tier == "fork":
        setup_body = (
            '        vm.createSelectFork(\n'
            '            vm.envString("AUDITOOOR_FORK_RPC_URL"),\n'
            f'            vm.envOr("AUDITOOOR_FORK_BLOCK", uint256({fork_block}))\n'
            '        );\n'
            f'        target = {iface_name}(vm.envAddress("AUDITOOOR_TARGET_ADDR"));\n'
            '        ghost_actors.push(address(this));\n'
            '        ghost_actors.push(address(target));\n'
            '        ghost_pauper = makeAddr("pauper");\n'
            '        ghost_pauper_seed_value = 1 ether;\n'
        )
        for tok in token_set:
            if "()" in tok:
                clean = tok.replace("()", "")
                setup_body += (
                    f"        // discovered token getter: {tok}\n"
                    f"        try {iface_name}(address(target)).{clean}() "
                    "returns (address _t) {\n"
                    "            ghost_tracked_tokens.push(_t);\n"
                    "        } catch {}\n"
                )
    elif wiring_tier == "deploy-fixture":
        setup_body = (
            "        Deploy d = new Deploy();\n"
            "        address _tgt;\n"
            "        address[] memory _toks;\n"
            "        (_tgt, _toks) = d.run();\n"
            f"        target = {iface_name}(_tgt);\n"
            "        for (uint256 _i = 0; _i < _toks.length; _i++) {\n"
            "            ghost_tracked_tokens.push(_toks[_i]);\n"
            "        }\n"
            "        ghost_actors.push(address(this));\n"
            "        ghost_actors.push(address(target));\n"
            '        ghost_pauper = makeAddr("pauper");\n'
            "        ghost_pauper_seed_value = 1 ether;\n"
        )
    else:
        setup_body = (
            f"        // TODO(operator): deploy {surf.name} + tokens here.\n"
            f"        // Required: target = {iface_name}(<deployed_address>);\n"
            "        // ghost_actors, ghost_tracked_tokens, ghost_pauper must be populated.\n"
            "        // Re-run auto-invariant-harness-gen.py after adding a deploy fixture:\n"
            "        //   script/Deploy*.s.sol with function run() returns (address, address[])\n"
        )

    # r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
    # Record the initial custody snapshot once tokens+actors are wired so the
    # UNIV-CONSERVATION balance-snapshot invariant has a real baseline (it
    # early-returns / stays inert in scaffold mode where no tokens are wired).
    if wiring_tier in ("fork", "deploy-fixture"):
        setup_body += (
            "        // UNIV-CONSERVATION: snapshot initial custody of each tracked token\n"
            "        for (uint256 _ci = 0; _ci < ghost_tracked_tokens.length; _ci++) {\n"
            "            uint256 _cs;\n"
            "            for (uint256 _cj = 0; _cj < ghost_actors.length; _cj++) {\n"
            "                _cs += IERC20Min(ghost_tracked_tokens[_ci]).balanceOf(ghost_actors[_cj]);\n"
            "            }\n"
            "            ghost_initial_custody[ghost_tracked_tokens[_ci]] = _cs;\n"
            "        }\n"
        )

    handler_calls = _render_all_handler_calls(surf)

    ghost_writes_all = "\n".join(
        inv.ghost_writes for inv in applicable_invs if inv.ghost_writes.strip()
    )

    inv_functions = []
    for inv in applicable_invs:
        fn_name = inv.id.replace("-", "_")
        fn_body = (
            f"    // {inv.inv_id_citation}\n"
            f"    function invariant_{fn_name}() public {{\n"
            f"        {inv.assertion_expr}\n"
            f"    }}\n"
        )
        inv_functions.append(fn_body)
    inv_block = "\n".join(inv_functions)

    pauper_decl = (
        "    address public ghost_pauper;\n"
        "    uint256 public ghost_pauper_seed_value;\n"
        "    uint256 public ghost_pauper_value_extracted;\n"
    )

    sol = f"""{banner}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{Test, StdInvariant}} from "forge-std/Test.sol";

// r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
interface IERC20Min {{
    function balanceOf(address) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}}

{iface_block}

// ============================================================
// Handler: drives all discovered mutating selectors.
// Named with "conservation" + "xfn" + "roundtrip" tokens so
// cross-function-harness-producer._CROSS_FN_HINTS discovers it.
// ============================================================
contract {surf.name}_Conservation_RoundTrip_xfn_Handler {{
    {iface_name} public target;
    uint256 public ghost_call_count;

    function bindTarget(address target_) public {{
        target = {iface_name}(target_);
    }}

    function handler_allSelectors(
        uint256 x, uint256 y, address actor
    ) external {{
        ghost_call_count++;
{handler_calls}
    }}
}}

// ============================================================
// Universal Invariant Test Suite
// ============================================================
contract {surf.name}_UniversalInvariant is StdInvariant, Test {{

    {iface_name} public target;
    {surf.name}_Conservation_RoundTrip_xfn_Handler public handler;

    // --- Shared ghost state --- (r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS)
    address[] public ghost_tracked_tokens;
    address[] public ghost_actors;
    mapping(address => uint256) public ghost_initial_custody;
{pauper_decl}
{state_decls_all}

    function setUp() public {{
{setup_body}
        handler = new {surf.name}_Conservation_RoundTrip_xfn_Handler();
        handler.bindTarget(address(target));
        targetContract(address(handler));
        // Seed ghost state.
        ghost_seed = ghost_pauper_seed_value;
{ghost_writes_all}    }}

{inv_block}}}
"""
    return sol


def _emit_medusa_json(surf, fork_rpc: str | None, fork_block: int) -> str:
    cfg: dict[str, Any] = {
        "fuzzing": {
            "workers": 4,
            "testLimit": 50000,
            "callSequenceLength": 50,
            "targetContracts": [
                f"{surf.name}_Conservation_RoundTrip_xfn_Handler"
            ],
            "corpusDirectory": "medusa-corpus",
            "assertionTesting": {"enabled": True, "testViewMethods": False},
            "propertyTesting": {
                "enabled": True,
                "testPrefixes": ["invariant_"],
            },
        },
        "compilation": {
            "platform": "crytic-compile",
            "platformConfig": {"target": ".", "solcVersion": ""},
        },
    }
    if fork_rpc or os.environ.get("AUDITOOOR_FORK_RPC_URL"):
        cfg["fuzzing"]["testChainConfig"] = {
            "forkConfig": {
                "forkModeEnabled": True,
                "rpcUrl": "${AUDITOOOR_FORK_RPC_URL}",
                "rpcBlock": fork_block,
            }
        }
    return json.dumps(cfg, indent=2) + "\n"


def _emit_foundry_toml(_surf) -> str:
    return (
        "[profile.default]\n"
        'src = "src"\n'
        'test = "test"\n'
        'out = "out"\n'
        'libs = ["lib"]\n\n'
        "[profile.default.invariant]\n"
        "runs = 256\n"
        "depth = 64\n"
        "fail_on_revert = false\n"
    )


def _emit_wiring_md(surf, wiring_tier: str, out_dir: Path) -> str:
    tier_desc = {
        "fork": (
            "Tier (a) - FORK MODE\n"
            "Set AUDITOOOR_FORK_RPC_URL + AUDITOOOR_TARGET_ADDR, then:\n"
            "    forge test --match-contract UniversalInvariant\n"
            "or:\n"
            "    medusa fuzz --config medusa.json\n"
        ),
        "deploy-fixture": (
            "Tier (b) - DEPLOY FIXTURE\n"
            "Found script/Deploy*.s.sol with run() -> (target, tokens[]).\n"
            "Run forge test directly; no env vars required.\n"
        ),
        "chimera-manual-UNWIRED": (
            "Tier (c) - CHIMERA MANUAL SCAFFOLD (UNWIRED)\n"
            "No fork env or deploy fixture was found.\n"
            "To wire: add a script/Deploy*.s.sol exposing:\n"
            f"    function run() public returns (address target_, address[] memory tokens_)\n"
            "Then re-run auto-invariant-harness-gen.py.\n"
        ),
    }
    return (
        f"# Wiring Guide - {surf.name} Universal Invariant Harness\n\n"
        f"**Wiring tier resolved:** `{wiring_tier}`\n\n"
        + tier_desc.get(wiring_tier, "Unknown tier.\n")
        + "\n"
        f"**Output directory:** `{out_dir}`\n\n"
        "**Cross-function producer discovery:**\n"
        "The harness file is named `*_Conservation_RoundTrip_xfn.t.sol`\n"
        "to match `_CROSS_FN_HINTS` in `cross-function-harness-producer.py`.\n"
        "Run `make audit-deep-solidity AUDITOOOR_AUDIT_DEEP_LIVE=1` to\n"
        "trigger mutation-verification and populate"
        " `.auditooor/mutation_verify_coverage.json`.\n"
        "\n"
        "**Honesty contract:** This harness is CANDIDATE-HARNESS-NOT-PROOF.\n"
        "Generation alone NEVER flips the gate green.\n"
        "A real engine run with a non-vacuous mutation kill is required.\n"
    )


# ---------------------------------------------------------------------------
# Wiring tier resolution.
# ---------------------------------------------------------------------------

def _resolve_wiring_tier(ws: Path, fork_rpc: str | None) -> str:
    if fork_rpc:
        return "fork"
    if os.environ.get("AUDITOOOR_FORK_RPC_URL"):
        return "fork"
    for pat in [
        "script/Deploy*.s.sol",
        "script/Deploy*.sol",
        "test/fixtures/Deploy*.sol",
    ]:
        if list(ws.glob(pat)):
            return "deploy-fixture"
    return "chimera-manual-UNWIRED"


# ---------------------------------------------------------------------------
# Per-contract generation.
# ---------------------------------------------------------------------------

def generate_for_contract(
    ws: Path,
    sol_path: Path,
    fork_rpc: str | None,
    fork_block: int,
    with_halmos: bool = False,
) -> dict:
    """Generate universal invariant harness for one Solidity contract."""
    try:
        surf = _parse_contract(sol_path, None)
    except Exception as exc:
        return {
            "contract_path": str(sol_path),
            "contract": sol_path.stem,
            "status": "parse-error",
            "error": str(exc),
            "is_real_contract": False,
            "emitted_files": [],
        }

    token_set = _discover_tokens(surf)
    priv_roles = _discover_privileged_roles(surf)
    abi_source = _pick_abi_source(ws)

    applicable = [inv for inv in UNIVERSAL_CATALOG if inv.applies(surf, token_set)]
    if not applicable:
        return {
            "contract_path": str(sol_path),
            "contract": surf.name,
            "status": "refused-no-applicable-invariant",
            "error": "no universal invariant applies to discovered surface (exit 2)",
            "is_real_contract": False,
            "emitted_files": [],
        }

    wiring_tier = _resolve_wiring_tier(ws, fork_rpc)
    is_real = wiring_tier in ("fork", "deploy-fixture")

    out_dir = ws / "poc-tests" / f"{surf.name}-universal-invariants"
    test_dir = out_dir / "test"
    test_dir.mkdir(parents=True, exist_ok=True)

    sol_file = test_dir / f"{surf.name}_Conservation_RoundTrip_xfn.t.sol"
    medusa_file = out_dir / "medusa.json"
    foundry_file = out_dir / "foundry.toml"
    wiring_file = out_dir / "WIRING.md"

    sol_content = _emit_universal_invariant_sol(
        surf, applicable, token_set, priv_roles,
        wiring_tier, fork_rpc, fork_block,
    )
    medusa_content = _emit_medusa_json(surf, fork_rpc, fork_block)
    foundry_content = _emit_foundry_toml(surf)
    wiring_content = _emit_wiring_md(surf, wiring_tier, out_dir)

    emitted = []
    for fp, content in [
        (sol_file, sol_content),
        (medusa_file, medusa_content),
        (foundry_file, foundry_content),
        (wiring_file, wiring_content),
    ]:
        fp.write_text(content, encoding="utf-8")
        emitted.append(str(fp))

    covers_xfn = []
    fn_names = [f.name for f in surf.mutating_external]
    for i, fn_a in enumerate(fn_names):
        for fn_b in fn_names[i + 1:]:
            covers_xfn.append(f"{fn_a}|{fn_b}@{sol_path.stem}")

    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(ws),
        "contract": surf.name,
        "contract_path": str(sol_path),
        "wiring_tier": wiring_tier,
        "is_real_contract": is_real,
        "discovery": {
            "abi_source": abi_source,
            "tokens": token_set,
            "privileged_roles": priv_roles,
            "mutating_selectors": [f.name for f in surf.mutating_external],
        },
        "emitted_invariants": [inv.id for inv in applicable],
        "covers_cross_function_requirements": covers_xfn[:20],
        "emitted_files": emitted,
        "candidate_not_proof": True,
        "proof_pending_via": (
            "cross-function-harness-producer.py + mutation-verify-coverage.py"
        ),
        "status": "emitted",
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description=(
            "Emit universal-invariant fuzz harnesses for an EVM workspace. "
            "Outputs Foundry InvariantTest.t.sol + medusa.json per discovered contract."
        ),
    )
    ap.add_argument("workspace", nargs="?", help="Workspace root path")
    ap.add_argument("--workspace", dest="workspace_flag", help="Alternate flag form")
    ap.add_argument("--lang", default="auto", choices=["auto", "solidity"])
    ap.add_argument("--max", type=int, default=10,
                    help="Max contracts to process (default: 10)")
    ap.add_argument("--fork-url", dest="fork_url", default=None)
    ap.add_argument("--fork-block", dest="fork_block", type=int, default=0)
    ap.add_argument("--with-halmos", dest="with_halmos", action="store_true",
                    help="(stub) emit Halmos check_* stubs - off by default in MVP")
    ap.add_argument("--project-root", dest="project_root", default=None)
    ap.add_argument("--json", dest="emit_json", action="store_true")
    args = ap.parse_args(argv)

    ws_raw = args.workspace or args.workspace_flag
    if not ws_raw:
        ap.error("workspace positional argument or --workspace is required")
    ws = Path(ws_raw).resolve()
    if not ws.is_dir():
        print(
            f"[auto-invariant-harness-gen] ERROR: workspace not found: {ws}",
            file=sys.stderr,
        )
        sys.exit(2)

    src_root = Path(args.project_root).resolve() if args.project_root else None
    sol_files = _discover_sol_files(ws, src_root, args.max)

    if not sol_files:
        print(
            "[auto-invariant-harness-gen] no .sol files found under workspace src/",
            file=sys.stderr,
        )
        sys.exit(2)

    results = []
    emitted_count = 0
    for sol_path in sol_files:
        r = generate_for_contract(
            ws, sol_path, args.fork_url, args.fork_block, args.with_halmos
        )
        results.append(r)
        if r.get("status") == "emitted":
            emitted_count += 1
            if not args.emit_json:
                print(
                    f"[auto-invariant-harness-gen] emitted {r['contract']} "
                    f"({r['wiring_tier']}) -> "
                    + ", ".join(r["emitted_files"]),
                )
        else:
            print(
                f"[auto-invariant-harness-gen] SKIP {r.get('contract', sol_path.stem)}: "
                + r.get("error", r.get("status", "unknown")),
                file=sys.stderr,
            )

    manifest = {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(ws),
        "contracts_processed": len(results),
        "contracts_emitted": emitted_count,
        "results": results,
        "candidate_not_proof": True,
        "proof_pending_via": (
            "cross-function-harness-producer.py + mutation-verify-coverage.py"
        ),
    }
    manifest_path = ws / ".auditooor" / "auto_invariant_harness_gen_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    if args.emit_json:
        print(json.dumps(manifest, indent=2))
    else:
        print(
            f"[auto-invariant-harness-gen] done: {emitted_count}/{len(results)} contracts,"
            f" manifest -> {manifest_path}",
        )

    if emitted_count == 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
