#!/usr/bin/env python3
"""Phase 1 Solidity arm of the native offline EVM data-flow slice.

Wraps slither.analyses.data_dependency over an OFFLINE Slither load and reconstructs,
for each in-scope value-moving SINK (transfer/transferFrom/call/send/mint/burn/
state-write), the backward DefUsePath from a tainted SOURCE (function param / msg.*)
to that sink, crossing inter-procedural call hops via arg<->param mapping.

It emits one DefUsePath record per slice (schema = tools/dataflow_schema.py) to
<ws>/.auditooor/dataflow_paths.jsonl.

Slither APIs reused (real file:line citations):
  - is_tainted / is_dependent / get_dependencies:
      slither/analyses/data_dependency/data_dependency.py:137 / :56 / :203
  - GENERIC_TAINT (msg.sender/value/data, tx.origin/gasprice):
      slither/analyses/data_dependency/data_dependency.py:128
  - data_dependency is auto-computed at parse time:
      slither/solc_parsing/slither_compilation_unit_solc.py:588-589 (compute_dependency)
  - SlithIR ops (HighLevelCall/InternalCall/LibraryCall/LowLevelCall/Transfer/Send/
      Binary/Condition/SolidityCall): slither/slithir/operations/__init__.py
  - OperationWithLValue.read / .lvalue: slither/slithir/operations/operation.py

Loader (3-tier OFFLINE) reused from:
  - tools/auditor-backtest.py:488-554 (_slither_compile: plain -> solc_remaps -> tree)
  - tools/irdump.py:142-159 (Slither(target) + compilation_units[0] access)

R80 degrade contract: on compile failure -> write a single degrade record
(engine="unsupported-or-compile-fail-degrade", degraded=True) and exit 0 (advisory).
Never claim a semantic-ssa path on a heuristic / failed compile.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# local schema helper
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dataflow_schema as dfs  # noqa: E402

# Value-moving sink callee names (high-level / library / low-level)
VALUE_MOVING_CALLEES = {
    "transfer", "transferFrom", "send", "call", "safeTransfer", "safeTransferFrom",
    "mint", "burn", "_mint", "_burn", "delegatecall", "sendValue",
}
# SolidityFunction low-level value movers
LOWLEVEL_NAMES = {"call", "delegatecall", "transfer", "send"}

# ----------------------------------------------------------------------------
# ECONOMIC STORAGE-WRITE value-mover heuristic (sink-taxonomy extension, P1).
#
# The call-based classifier above (VALUE_MOVING_CALLEES) only sees CALL value
# movers (transfer/mint/burn/...). It is BLIND to the axis where accounting risk
# actually lives on share/units/balance protocols (SSV operatorEthVUnits[id] +=/
# delete @ SSVClusters.sol:510 / SSVOperators.sol:93; daoTotalEthVUnits; debt /
# earnings mappings). A direct STORAGE WRITE (`+=`, `-=`, `delete`, `[k]=`) to an
# economic state var moves protocol value just as a token transfer does, yet today
# such a write only ever appears as a state_var_READ in storage-mediated mode, so
# the engine cannot surface it as a SINK at all.
#
# `_is_economic_value_name` is a NAME heuristic; `_is_economic_value_type` is the
# TYPE heuristic (a mapping(... => uintN) or a uintN scalar). A var is an economic
# value-mover when its NAME matches an accounting token AND (its type is a value
# type OR the type is unknown — name match alone is enough to surface, type only
# strengthens). This is additive: a NEW `storage-value` sink kind, every existing
# call-based sink classification is byte-for-byte unchanged.
# ----------------------------------------------------------------------------
# accounting / value nouns (substring, case-insensitive) that mark a state var as
# an economic value-mover. Deliberately conservative: only nouns that denote a
# unit of protocol value, not arbitrary config (no "id", "index", "count", "flag").
_ECONOMIC_VALUE_NAME_RX = re.compile(
    r"balance|amount|units?|shares?|debt|earnings?|deposit|owed|credit|fee|"
    r"reward|stake|collateral|liquidity|principal|accrued|payout|owed|"
    r"vunits|ethv|totaleth|funds?|escrow",
    re.IGNORECASE,
)
# names that LOOK economic by substring but are NOT a unit of value -> excluded so
# we do not over-tag (e.g. `feeRecipient` is an address, `creditScore` is not value).
_ECONOMIC_VALUE_NAME_DENY_RX = re.compile(
    r"recipient|receiver|address|owner|admin|manager|score|enabled|paused|"
    r"timestamp|deadline|count\b|length|index|^id$|nonce",
    re.IGNORECASE,
)


def _is_economic_value_name(name: str) -> bool:
    if not name:
        return False
    if _ECONOMIC_VALUE_NAME_DENY_RX.search(name):
        return False
    return bool(_ECONOMIC_VALUE_NAME_RX.search(name))


def _is_economic_value_type(type_str: str) -> Optional[bool]:
    """True when the type denotes a value quantity (mapping(... => uintN) or a
    bare uintN). False when clearly NOT a value type (address/bool/string/bytes
    scalar). None when the type is unknown (caller treats None as 'do not veto')."""
    if not type_str:
        return None
    t = str(type_str)
    # mapping with a numeric value-leg is a strong value signal.
    if "mapping" in t:
        # value leg is the text after the LAST '=>'
        leg = t.rsplit("=>", 1)[-1]
        if re.search(r"\buint\d*\b|\bint\d*\b", leg):
            return True
        # mapping to a struct: unknown (could hold value members) -> do not veto
        if "address" in leg or "bool" in leg or "string" in leg:
            return False
        return None
    if re.search(r"\buint\d*\b|\bint\d*\b", t):
        return True
    if re.search(r"\baddress\b|\bbool\b|\bstring\b|\bbytes\d*\b", t):
        return False
    return None


def _is_economic_value_var(name: str, type_str: str = "") -> bool:
    """A state var is an economic value-mover when its NAME is an accounting noun
    AND its TYPE is not vetoed as a non-value type. Name-only (unknown type) still
    qualifies; type only strengthens or vetoes."""
    if not _is_economic_value_name(name):
        return False
    tv = _is_economic_value_type(type_str)
    if tv is False:
        return False
    return True

# B-hops: depth is UNBOUNDED by design (operator: "no limit to hops"). The real
# terminator is the visited-(function,var) set (mirrors slither_predicates.callee_closure's
# `seen` cycle-guard at tools/slither_predicates.py:547-562). MAX_HOPS_DEFAULT is now only a
# HIGH runaway-safety ceiling, NOT a small semantic cap. When the ceiling is actually hit, the
# emitted record carries dataflow_truncated=True + a "param-depth-bound" source (honesty).
# Overridable via AUDITOOOR_DATAFLOW_MAX_HOPS (an even higher ceiling for huge call graphs).
def _safety_ceiling(default: int = 512) -> int:
    import os as _os
    raw = _os.environ.get("AUDITOOOR_DATAFLOW_MAX_HOPS")
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return default


MAX_HOPS_DEFAULT = _safety_ceiling()


# ----------------------------------------------------------------------------
# OFFLINE loader (3-tier), adapted from tools/auditor-backtest.py:488-554
# ----------------------------------------------------------------------------
def _select_solc_for_pragma(sol_text: str) -> None:
    """Best-effort: pick a solc-select version matching a `pragma solidity X` line."""
    m = re.search(r"pragma\s+solidity\s+[\^>=<~ ]*([0-9]+\.[0-9]+\.[0-9]+)", sol_text or "")
    if not m:
        m2 = re.search(r"pragma\s+solidity\s+[\^>=<~ ]*([0-9]+\.[0-9]+)", sol_text or "")
        if not m2:
            return
        ver = m2.group(1) + ".0"
    else:
        ver = m.group(1)
    try:
        import subprocess
        subprocess.run(["solc-select", "use", ver], capture_output=True, timeout=30)
    except Exception:
        pass


def _find_project_root(start: Path) -> Optional[Path]:
    base = start
    for _ in range(12):
        if any((base / m).exists() for m in (
            "foundry.toml", "hardhat.config.js", "hardhat.config.ts",
            "remappings.txt", "package.json", ".git",
        )):
            return base
        if base.parent == base:
            break
        base = base.parent
    return None


def _node_modules_remaps(start: Path) -> List[str]:
    remaps: List[str] = []
    base = start
    for _ in range(10):
        nm = base / "node_modules"
        if nm.is_dir():
            for scope in sorted(p.name for p in nm.iterdir()
                                if p.is_dir() and p.name.startswith("@")):
                remaps.append(f"{scope}/={nm}/{scope}/")
            for pkg in sorted(p.name for p in nm.iterdir()
                              if p.is_dir() and not p.name.startswith("@")):
                remaps.append(f"{pkg}/={nm}/{pkg}/")
            break
        if base.parent == base:
            break
        base = base.parent
    return remaps


def load_slither_offline(target: Path) -> Tuple[Any, Optional[str]]:
    """3-tier offline Slither load. Returns (slither_obj|None, error|None).

    Tier 1: Slither(file)               (auditor-backtest.py:509-512)
    Tier 2: Slither(file, solc_remaps)  (auditor-backtest.py:530-534)
    Tier 3: Slither(project_root)       (auditor-backtest.py:548-553 / irdump.py:149)
    """
    try:
        from slither import Slither
    except ImportError as e:
        return None, f"slither-import-error: {e}"

    attempts: List[str] = []
    is_file = target.is_file()

    if is_file:
        try:
            _select_solc_for_pragma(target.read_text(errors="ignore"))
        except Exception:
            pass
        # Tier 1
        try:
            return Slither(str(target)), None
        except Exception as e:
            attempts.append(f"plain:{type(e).__name__}")
        # Tier 2
        remaps = _node_modules_remaps(target.parent)
        if remaps:
            try:
                return Slither(str(target), solc_remaps=" ".join(remaps)), None
            except Exception as e:
                attempts.append(f"remap:{type(e).__name__}")

    # Tier 3: whole project tree
    root = target if target.is_dir() else _find_project_root(target.parent)
    if root is not None:
        # Prefer the FOUNDRY framework on a hybrid project (strata 2026-06-30 R1b):
        # src/contracts had foundry.toml + hardhat.config.js + node_modules, and
        # crytic-compile's auto-detection picked HARDHAT - the slow path that hung the
        # slice 28min+ and produced 0 output (the capability went dark). `forge build`
        # compiles the same 122 contracts in ~60s. Force foundry first when a
        # foundry.toml is present, then fall back to plain auto-detect.
        #
        # axelar-sc 2026-07-12: forcing foundry is NOT universally safe. axelar-cgp-solidity
        # ships BOTH foundry.toml (solc 0.8.9, via_ir=true) and hardhat.config.js, but
        # `forge build` on that exact package hits a solc 0.8.9 via-IR codegen limitation
        # ("Yul exception: Variable param_N is N slot(s) too deep inside the stack") and
        # crytic-compile surfaces it as "'forge' returned non-zero exit code 1" -
        # ERROR:CryticCompile, hard stop, 0 dataflow rows. The SAME contracts compile fine
        # under the repo's hardhat.config.js (its optimizer uses yulDetails-only codegen,
        # not full via-IR, so it never hits the same stack-depth path). So: try foundry
        # first (fast path for the common case), but on ANY foundry compile failure, if a
        # hardhat.config.* is ALSO present, retry with compile_force_framework="hardhat"
        # before falling through to plain auto-detect. This keeps the strata fast-path
        # while fixing Hardhat-primary / Hardhat-only repos and foundry+hardhat hybrids
        # whose forge profile does not actually compile.
        hardhat_cfg = any((root / name).is_file() for name in
                           ("hardhat.config.js", "hardhat.config.ts",
                            "hardhat.config.cjs", "hardhat.config.mjs"))
        if (root / "foundry.toml").is_file():
            try:
                return Slither(str(root), compile_force_framework="foundry"), None
            except Exception as e:
                attempts.append(f"foundry:{type(e).__name__}:{str(e)[:80]}")
        if hardhat_cfg:
            try:
                return Slither(str(root), compile_force_framework="hardhat"), None
            except Exception as e:
                attempts.append(f"hardhat:{type(e).__name__}:{str(e)[:80]}")
        try:
            return Slither(str(root)), None
        except Exception as e:
            attempts.append(f"tree:{type(e).__name__}:{str(e)[:120]}")

    return None, f"compile-error: tried [{', '.join(attempts) or 'none'}]"


# ----------------------------------------------------------------------------
# IR helpers
# ----------------------------------------------------------------------------
def _ir_classes():
    from slither.slithir.operations import (  # noqa
        HighLevelCall, InternalCall, LibraryCall, LowLevelCall,
        Transfer, Send, Binary, Condition, SolidityCall, OperationWithLValue,
    )
    return dict(
        HighLevelCall=HighLevelCall, InternalCall=InternalCall, LibraryCall=LibraryCall,
        LowLevelCall=LowLevelCall, Transfer=Transfer, Send=Send,
        Binary=Binary, Condition=Condition, SolidityCall=SolidityCall,
        OperationWithLValue=OperationWithLValue,
    )


def _lines(obj) -> List[int]:
    sm = getattr(obj, "source_mapping", None)
    return list(getattr(sm, "lines", []) or []) if sm else []


def _first_line(obj) -> Optional[int]:
    ls = _lines(obj)
    return ls[0] if ls else None


def _file_of(obj) -> Optional[str]:
    sm = getattr(obj, "source_mapping", None)
    if not sm:
        return None
    fn = getattr(sm, "filename", None)
    if fn is None:
        return None
    return getattr(fn, "absolute", None) or getattr(fn, "relative", None) or str(fn)


# --- accumulation base-delta parse (co-accumulation Sigma-conservation overlay) ---
# An accumulation write `<lhs> += rhs` / `<lhs> -= rhs` / `<lhs> = <lhs> <op> rhs` carries a
# BASE delta identifier in rhs (`shares`, `shares.toUint128()`, `uint128(shares)`,
# `SafeCast.toUint128(shares)`). state-coupling-graph promotes an aggregate<->member
# co-accumulation edge to semantic-ssa ONLY when the slice witnesses the SAME base delta
# flowing into BOTH cells; that join needs a distinct-flow hop {from_var:<delta>, to_var:
# <cell>}. This parses the delta so storage_mediated_paths can emit that extra hop.
_ACCUM_WEXPR_RE = re.compile(r"^\s*(.+?)\s*([+\-])=\s*(.+?)\s*;?\s*$")


def _accum_rhs_of(expr: Optional[str]) -> Optional[str]:
    """Return the rhs of an accumulation write, else None. Handles `x += r` / `x -= r`
    and the desugared `x = x <op> r` self-accumulation form."""
    s = (expr or "").strip()
    if not s:
        return None
    m = _ACCUM_WEXPR_RE.match(s)
    if m:
        return m.group(3)
    # desugared self-accumulation: `<lhs> = <lhs> <op> <rest>`
    m = re.match(r"^\s*(.+?)\s*=\s*(.+?)\s*;?\s*$", s)
    if m:
        lhs, rhs = m.group(1).strip(), m.group(2).strip()
        lhs_id = re.match(r"[A-Za-z_][\w.\[\]]*", lhs)
        rhs_after = re.match(r"([A-Za-z_][\w.\[\]]*)\s*[+\-]\s*(.+)$", rhs)
        if lhs_id and rhs_after and rhs_after.group(1) == lhs_id.group(0):
            return rhs_after.group(2)
    return None


def _base_delta_of(rhs: Optional[str]) -> Optional[str]:
    """Leading base-delta identifier of an accumulation rhs, stripping cast wrappers
    (`.toUint128()` trailing method-cast, `uint128(...)`/`SafeCast.toX(...)` prefix-cast).
    `shares.toUint128()` -> `shares`; `uint128(assets)` -> `assets`; `shares` -> `shares`."""
    s = (rhs or "").strip().rstrip(";").strip()
    if not s:
        return None
    # strip trailing EMPTY-arg `.toXxx()` method-cast suffixes (repeatedly). Only empty
    # parens: `shares.toUint128()` casts the receiver `shares`; a NON-empty-arg static call
    # like `SafeCast.toUint128(delta)` carries the delta as an ARGUMENT and is unwrapped by
    # the prefix-cast rule below, so it must NOT be stripped here.
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r"\.\s*to[A-Za-z0-9]+\s*\(\s*\)\s*$", "", s).strip()
    # unwrap a single prefix cast wrapper: uint128( inner ) / SafeCast.toX( inner )
    m = re.match(r"^(?:SafeCast\s*\.\s*\w+|u?int\d*)\s*\(\s*(.*)\)\s*$", s)
    if m:
        s = m.group(1).strip()
    m = re.match(r"\s*([A-Za-z_]\w*)", s)
    return m.group(1) if m else None


def _accum_cell_is(expr: Optional[str], var: str) -> bool:
    """True when the accumulation lvalue's CELL is exactly `var`.

    The cell is the trailing struct `.field` if present, else the base identifier after
    stripping `[...]` index brackets:
      `totalSupply += d`                -> cell `totalSupply`
      `balanceOf[to] += d`              -> cell `balanceOf`
      `total = total + d`               -> cell `total`   (desugared self-accum)
      `market[id].totalSupplyShares+=d` -> cell `totalSupplyShares`  (NOT `market`)
    This gates the distinct-flow accum-delta hop so a contract-level accumulation fires
    only under its DIRECTLY-accumulated cell name. Slither also reports the base mapping
    (`market`) as written for a struct-member accumulation; the guard keeps that base out
    (cell != var) so the hop is emitted once under the field name by the Track-2 path and
    is NOT double-emitted as `to_var=market`."""
    s = (expr or "").strip()
    if not s:
        return False
    m = _ACCUM_WEXPR_RE.match(s)
    if m:
        lv = m.group(1)
    else:
        # desugared self-accumulation `<lhs> = <lhs> <op> r` (mirror of _accum_rhs_of)
        m = re.match(r"^\s*(.+?)\s*=\s*(.+?)\s*;?\s*$", s)
        if not m:
            return False
        lhs, rhs = m.group(1).strip(), m.group(2).strip()
        lhs_id = re.match(r"[A-Za-z_][\w.\[\]]*", lhs)
        rhs_after = re.match(r"([A-Za-z_][\w.\[\]]*)\s*[+\-]\s*(.+)$", rhs)
        if not (lhs_id and rhs_after and rhs_after.group(1) == lhs_id.group(0)):
            return False
        lv = lhs
    stripped = re.sub(r"\[[^\]]*\]", "", lv)  # drop index brackets
    dotted = re.findall(r"\.\s*([A-Za-z_]\w*)", stripped)
    if dotted:
        cell = dotted[-1]
    else:
        bm = re.match(r"\s*([A-Za-z_]\w*)", stripped)
        cell = bm.group(1) if bm else None
    return cell == var


def _callee_name(ir, C) -> Optional[str]:
    fn = getattr(ir, "function", None)
    if fn is not None:
        nm = getattr(fn, "name", None)
        if nm:
            return nm
    return getattr(ir, "function_name", None)


def _is_value_moving(ir, C) -> bool:
    if isinstance(ir, (C["Transfer"], C["Send"])):
        return True
    if isinstance(ir, C["LowLevelCall"]):
        return True
    if isinstance(ir, (C["HighLevelCall"], C["LibraryCall"])):
        nm = _callee_name(ir, C)
        return nm in VALUE_MOVING_CALLEES
    return False


def _sink_kind(ir, C) -> str:
    if isinstance(ir, C["Transfer"]):
        return "transfer"
    if isinstance(ir, C["Send"]):
        return "send"
    if isinstance(ir, C["LowLevelCall"]):
        return "low_level_call"
    nm = _callee_name(ir, C) or "call"
    return nm


# ----------------------------------------------------------------------------
# Core wrapper: backward / forward def-use over data_dependency + call hops
# ----------------------------------------------------------------------------
class DataFlowEngine:
    def __init__(self, slither, max_hops: int = MAX_HOPS_DEFAULT):
        self.sl = slither
        self.max_hops = max_hops
        self.C = _ir_classes()
        from slither.analyses.data_dependency.data_dependency import (
            is_tainted, is_dependent, get_dependencies,
        )
        self._is_tainted = is_tainted
        self._is_dependent = is_dependent
        self._get_dependencies = get_dependencies
        # caller index: callee Function -> list of (caller_fn, internalcall_ir, node)
        self._callers: Dict[Any, List[Tuple[Any, Any, Any]]] = {}
        self._build_caller_index()

    def _build_caller_index(self):
        C = self.C
        for cu in self.sl.compilation_units:
            for c in cu.contracts:
                if getattr(c, "is_interface", False):
                    continue
                for f in c.functions + list(getattr(c, "modifiers", []) or []):
                    for n in getattr(f, "nodes", []) or []:
                        for ir in getattr(n, "irs", []) or []:
                            if isinstance(ir, (C["InternalCall"], C["LibraryCall"], C["HighLevelCall"])):
                                callee = getattr(ir, "function", None)
                                if callee is not None and hasattr(callee, "parameters"):
                                    self._callers.setdefault(callee, []).append((f, ir, n))

    # --- guard detection within a function context for a set of tracked vars ---
    def _guards_for_vars(self, fn, var_names: set) -> List[Dict[str, Any]]:
        C = self.C
        guards: List[Dict[str, Any]] = []
        for n in getattr(fn, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            is_cond = getattr(n, "type", None) and "IF" in str(n.type)
            has_require = False
            for ir in getattr(n, "irs", []) or []:
                if isinstance(ir, C["SolidityCall"]):
                    snm = _callee_name(ir, C) or str(getattr(ir, "function", "")) or ""
                    if "require" in snm or "assert" in snm:
                        has_require = True
                if isinstance(ir, C["Condition"]):
                    is_cond = True
                if isinstance(ir, C["Binary"]):
                    # comparison binaries: <, <=, >, >=, ==, !=
                    btype = str(getattr(ir, "type", "") or "")
                    if any(s in btype for s in ("Less", "Greater", "Equal", "<", ">", "=")):
                        is_cond = is_cond or False  # only counts if it feeds a require/condition
            reads_tracked = any(v and v in expr for v in var_names)
            if reads_tracked and (has_require or is_cond):
                guards.append({
                    "file": _file_of(n),
                    "line": _first_line(n),
                    "expr": expr[:200],
                })
        return guards

    # --- map a callee param to the matching caller arg in an InternalCall IR ---
    @staticmethod
    def _caller_arg_for_param(callee, param, call_ir):
        try:
            idx = list(callee.parameters).index(param)
        except (ValueError, AttributeError):
            return None
        args = getattr(call_ir, "arguments", None) or []
        if idx < len(args):
            return args[idx]
        return None

    def backward_df_recursive(self, sink_fn, sink_var, sink_ir, sink_node, ctx=None) -> Optional[Dict[str, Any]]:
        """Walk backward from (sink_fn, sink_var) to a tainted source, crossing call hops.

        Returns a DefUsePath dict (schema) or None if sink_var is not a function param
        (cannot cross a hop) and is not directly tainted.
        """
        C = self.C
        hops: List[Dict[str, Any]] = []
        guard_nodes: List[Dict[str, Any]] = []
        visited = set()
        source_units = set()
        sink_units = set()

        cur_fn = sink_fn
        cur_var = sink_var
        cur_call_ir = sink_ir
        cur_node = sink_node

        # record sink
        sink_callee = _callee_name(sink_ir, C)
        try:
            arg_pos = list(getattr(sink_ir, "arguments", []) or []).index(sink_var)
        except ValueError:
            arg_pos = None
        sink_rec = {
            "kind": _sink_kind(sink_ir, C),
            "callee": sink_callee,
            "arg_pos": arg_pos,
            "fn": getattr(cur_fn, "canonical_name", getattr(cur_fn, "name", None)),
            "file": _file_of(sink_node),
            "line": _first_line(sink_node),
        }
        sink_units.add(self._unit_id(sink_node))

        depth = 0
        source_rec = None
        while depth <= self.max_hops:
            key = (id(cur_fn), getattr(cur_var, "name", str(cur_var)))
            if key in visited:
                break
            visited.add(key)

            # collect guards in this function over the current tracked var
            track_names = {getattr(cur_var, "name", None)}
            track_names.discard(None)
            for g in self._guards_for_vars(cur_fn, track_names):
                if g not in guard_nodes:
                    guard_nodes.append(g)

            # Is cur_var tainted directly within this function (param / msg.*)?
            tainted_here = False
            try:
                tainted_here = self._is_tainted(cur_var, cur_fn, ignore_generic_taint=False)
            except Exception:
                tainted_here = False

            is_param = cur_var in (getattr(cur_fn, "parameters", []) or [])

            if tainted_here and not is_param:
                # cur_var depends on msg.*/tx.* inside this fn -> source is this fn
                source_rec = {
                    "kind": "tainted-local",
                    "fn": getattr(cur_fn, "canonical_name", cur_fn.name),
                    "var": getattr(cur_var, "name", str(cur_var)),
                    "file": _file_of(cur_fn),
                    "line": _first_line(cur_fn),
                }
                source_units.add(self._unit_id(cur_fn))
                break

            if is_param:
                # cross a call hop: find a caller and the arg it passed for this param
                callers = self._callers.get(cur_fn, [])
                advanced = False
                for caller_fn, call_ir, call_node in callers:
                    caller_arg = self._caller_arg_for_param(cur_fn, cur_var, call_ir)
                    if caller_arg is None or not hasattr(caller_arg, "name"):
                        continue
                    via = "internal_call" if isinstance(call_ir, C["InternalCall"]) else "high_level"
                    hop = {
                        "from_var": getattr(caller_arg, "name", str(caller_arg)),
                        "to_var": getattr(cur_var, "name", str(cur_var)),
                        "fn": getattr(caller_fn, "canonical_name", caller_fn.name),
                        "via": via,
                        "file": _file_of(call_node),
                        "line": _first_line(call_node),
                        "ir": str(call_ir)[:160],
                        "guarded": False,  # set below
                    }
                    # guard in the *caller* over the caller_arg dominating this call
                    cguards = self._guards_for_vars(caller_fn, {getattr(caller_arg, "name", None)})
                    if cguards:
                        hop["guarded"] = True
                        for g in cguards:
                            if g not in guard_nodes:
                                guard_nodes.append(g)
                    hops.append(hop)
                    source_units.add(self._unit_id(caller_fn))
                    cur_fn = caller_fn
                    cur_var = caller_arg
                    cur_node = call_node
                    advanced = True
                    depth += 1
                    break
                if not advanced:
                    # param with no in-tree caller -> external/public entrypoint = source
                    source_rec = {
                        "kind": "param-entrypoint",
                        "fn": getattr(cur_fn, "canonical_name", cur_fn.name),
                        "var": getattr(cur_var, "name", str(cur_var)),
                        "file": _file_of(cur_fn),
                        "line": _first_line(cur_fn),
                    }
                    source_units.add(self._unit_id(cur_fn))
                    break
            else:
                # not a param, not tainted -> try local def-use back to a tainted dep
                deps = set()
                try:
                    deps = self._get_dependencies(cur_var, cur_fn)
                except Exception:
                    deps = set()
                tainted_dep = None
                for d in deps:
                    try:
                        if self._is_tainted(d, cur_fn):
                            tainted_dep = d
                            break
                    except Exception:
                        continue
                if tainted_dep is not None and hasattr(tainted_dep, "name"):
                    hops.append({
                        "from_var": getattr(tainted_dep, "name", str(tainted_dep)),
                        "to_var": getattr(cur_var, "name", str(cur_var)),
                        "fn": getattr(cur_fn, "canonical_name", cur_fn.name),
                        "via": "intra",
                        "file": _file_of(cur_fn),
                        "line": _first_line(cur_fn),
                        "ir": "data_dependency.get_dependencies",
                        "guarded": False,
                    })
                    cur_var = tainted_dep
                    depth += 1
                    continue
                # dead end - cannot establish a tainted source
                break

        if source_rec is None:
            return None

        rec = dfs.new_path(
            path_id="",  # filled by caller
            language="solidity",
            direction="backward",
            engine="slither.analyses.data_dependency",
            source=source_rec,
            sink=sink_rec,
            hops=list(reversed(hops)),  # source -> ... -> sink order
            guard_nodes=guard_nodes,
            source_unit_ids=sorted(source_units),
            sink_unit_ids=sorted(sink_units),
            confidence="semantic-ssa",
            degraded=False,
        )
        return rec

    # ------------------------------------------------------------------
    # MULTI-HOP fan-out: follow ALL distinct caller frames per param.
    # backward_df_recursive above walks the FIRST caller per hop (single chain,
    # kept for backward-compat with detectors/_predicate_engine.py). This method
    # FANS OUT: at each param hop it recurses into EVERY in-tree caller whose i-th
    # arg feeds the param, yielding one DefUsePath per distinct caller chain so a
    # value is traced across N hops over the real call graph (target depth>=2..6).
    # Termination: visited-(function,var) set + max_hops bound; external-boundary
    # honesty (a param with no in-tree caller = param-entrypoint source).
    # ------------------------------------------------------------------
    def backward_df_all(self, sink_fn, sink_var, sink_ir, sink_node) -> List[Dict[str, Any]]:
        C = self.C
        # sink record (shared by every chain to this sink/arg)
        sink_callee = _callee_name(sink_ir, C)
        try:
            arg_pos = list(getattr(sink_ir, "arguments", []) or []).index(sink_var)
        except ValueError:
            arg_pos = None
        sink_rec = {
            "kind": _sink_kind(sink_ir, C),
            "callee": sink_callee,
            "arg_pos": arg_pos,
            "fn": getattr(sink_fn, "canonical_name", getattr(sink_fn, "name", None)),
            "file": _file_of(sink_node),
            "line": _first_line(sink_node),
        }
        sink_unit = self._unit_id(sink_node)

        results: List[Dict[str, Any]] = []

        def _emit(source_rec, hops, guard_nodes, source_units):
            rec = dfs.new_path(
                path_id="",
                language="solidity",
                direction="backward",
                engine="slither.analyses.data_dependency",
                source=source_rec,
                sink=sink_rec,
                hops=list(reversed(hops)),  # source -> ... -> sink order
                guard_nodes=list(guard_nodes),
                source_unit_ids=sorted(set(source_units)),
                sink_unit_ids=[sink_unit],
                confidence="semantic-ssa",
                degraded=False,
            )
            # B-hops honesty: a "param-depth-bound" source means the safety ceiling
            # cut the walk short - the slice may be incomplete. Flag it so consumers
            # never treat a ceiling-truncated chain as a complete source->sink proof.
            if source_rec.get("kind") == "param-depth-bound":
                rec["dataflow_truncated"] = True
            results.append(rec)

        def _walk(cur_fn, cur_var, hops, guard_nodes, source_units, visited, depth):
            key = (id(cur_fn), getattr(cur_var, "name", str(cur_var)))
            if key in visited:
                return
            visited = visited | {key}

            # guards in this fn over the tracked var
            track_names = {getattr(cur_var, "name", None)}
            track_names.discard(None)
            local_guards = list(guard_nodes)
            for g in self._guards_for_vars(cur_fn, track_names):
                if g not in local_guards:
                    local_guards.append(g)

            # tainted directly here (msg.*/tx.* local) -> source is this fn
            tainted_here = False
            try:
                tainted_here = self._is_tainted(cur_var, cur_fn, ignore_generic_taint=False)
            except Exception:
                tainted_here = False
            is_param = cur_var in (getattr(cur_fn, "parameters", []) or [])

            if tainted_here and not is_param:
                src = {
                    "kind": "tainted-local",
                    "fn": getattr(cur_fn, "canonical_name", cur_fn.name),
                    "var": getattr(cur_var, "name", str(cur_var)),
                    "file": _file_of(cur_fn),
                    "line": _first_line(cur_fn),
                }
                _emit(src, hops, local_guards, source_units | {self._unit_id(cur_fn)})
                return

            if is_param:
                callers = self._callers.get(cur_fn, [])
                matched = []
                for caller_fn, call_ir, call_node in callers:
                    caller_arg = self._caller_arg_for_param(cur_fn, cur_var, call_ir)
                    if caller_arg is None or not hasattr(caller_arg, "name"):
                        continue
                    matched.append((caller_fn, call_ir, call_node, caller_arg))

                if not matched or depth >= self.max_hops:
                    # external entrypoint OR depth bound reached -> honest source
                    src = {
                        "kind": "param-entrypoint" if not matched else "param-depth-bound",
                        "fn": getattr(cur_fn, "canonical_name", cur_fn.name),
                        "var": getattr(cur_var, "name", str(cur_var)),
                        "file": _file_of(cur_fn),
                        "line": _first_line(cur_fn),
                    }
                    _emit(src, hops, local_guards, source_units | {self._unit_id(cur_fn)})
                    return

                # FAN OUT: recurse into EVERY distinct caller frame
                for caller_fn, call_ir, call_node, caller_arg in matched:
                    via = "internal_call" if isinstance(call_ir, C["InternalCall"]) else "high_level"
                    hop = {
                        "from_var": getattr(caller_arg, "name", str(caller_arg)),
                        "to_var": getattr(cur_var, "name", str(cur_var)),
                        "fn": getattr(caller_fn, "canonical_name", caller_fn.name),
                        "via": via,
                        "file": _file_of(call_node),
                        "line": _first_line(call_node),
                        "ir": str(call_ir)[:160],
                        "guarded": False,
                    }
                    chain_guards = list(local_guards)
                    cguards = self._guards_for_vars(caller_fn, {getattr(caller_arg, "name", None)})
                    if cguards:
                        hop["guarded"] = True
                        for g in cguards:
                            if g not in chain_guards:
                                chain_guards.append(g)
                    _walk(
                        caller_fn, caller_arg,
                        hops + [hop], chain_guards,
                        source_units | {self._unit_id(caller_fn)},
                        visited, depth + 1,
                    )
                return

            # not param, not tainted: intra def-use to a tainted dep
            deps = set()
            try:
                deps = self._get_dependencies(cur_var, cur_fn)
            except Exception:
                deps = set()
            tainted_dep = None
            for d in deps:
                try:
                    if self._is_tainted(d, cur_fn):
                        tainted_dep = d
                        break
                except Exception:
                    continue
            if tainted_dep is not None and hasattr(tainted_dep, "name"):
                hop = {
                    "from_var": getattr(tainted_dep, "name", str(tainted_dep)),
                    "to_var": getattr(cur_var, "name", str(cur_var)),
                    "fn": getattr(cur_fn, "canonical_name", cur_fn.name),
                    "via": "intra",
                    "file": _file_of(cur_fn),
                    "line": _first_line(cur_fn),
                    "ir": "data_dependency.get_dependencies",
                    "guarded": False,
                }
                _walk(cur_fn, tainted_dep, hops + [hop], local_guards,
                      source_units, visited, depth)
            # else dead-end: no honest source -> drop this chain

        _walk(sink_fn, sink_var, [], [], {sink_unit}, frozenset(), 0)
        return results

    def forward_df_recursive(self, source_fn, source_var, ctx=None) -> List[Dict[str, Any]]:
        """Forward: from a tainted source var, find value-moving sinks it reaches.

        Implemented as the dual of backward: enumerate sinks whose backward slice
        reaches (source_fn, source_var). Provided for API symmetry per brief.
        """
        out: List[Dict[str, Any]] = []
        for sink_fn, sink_var, sink_ir, sink_node in self._enumerate_sinks():
            rec = self.backward_df_recursive(sink_fn, sink_var, sink_ir, sink_node)
            if rec and rec["source"].get("fn") == getattr(source_fn, "canonical_name", getattr(source_fn, "name", None)):
                out.append(rec)
        return out

    # ------------------------------------------------------------------
    # STORAGE-MEDIATED def-use bridge (cross-function conservation class).
    #
    # Surfaces: write-site of state var X in fn A  ->  read-site of X in fn B,
    # where B's use is value-dependent on A's write THROUGH STORAGE.
    #
    # Two tracks, tagged honestly per R80:
    #   (1) confidence="semantic-ssa": Slither tracks X as a contract-level state
    #       variable (function.state_variables_written / .state_variables_read),
    #       so the producer/consumer relationship is IR-backed.
    #   (2) confidence="syntactic": X is a STRUCT MEMBER reached through a
    #       diamond-storage pointer (e.g. SSVStorageEB.load().operatorEthVUnits[..]).
    #       Slither does NOT model that as a contract-level state var, so we fall
    #       back to a source-anchored syntactic def-USE bridge: per-fn write-set
    #       INTERSECT read-set on the struct-member identifier, classified by
    #       expression shape (LHS assign / compound-assign / `delete` = WRITE).
    #       We NEVER label this semantic-ssa.
    #
    # A consumer/reverser read of X that no guard dominates is marked unguarded.
    # ------------------------------------------------------------------

    # struct-member storage write detector (syntactic): is `<ptr>.<member>[..]`
    # the LHS of an assignment / compound-assign, or the target of `delete`?
    @staticmethod
    def _classify_member_access(expr: str, member: str) -> Optional[str]:
        """Return 'write' | 'read' | None for a node-expression touching `.member`."""
        if not expr or member not in expr:
            return None
        # delete <ptr>.member[..]
        if re.search(r"\bdelete\b[^=;]*\." + re.escape(member) + r"\b", expr):
            return "write"
        # find each `.member[ ... ]` occurrence and test if it sits on an LHS
        # (followed by an = / += / -= / *= ... that is NOT == / >= / <= / !=).
        for m in re.finditer(r"\." + re.escape(member) + r"\b(\s*\[[^\]]*\])?", expr):
            tail = expr[m.end():].lstrip()
            am = re.match(r"([+\-*/%&|^]|<<|>>)?=(?!=)", tail)
            if am:
                return "write"
        return "read"

    def _struct_member_sites(self):
        """Yield (member, fn, contract, node, kind, file, line) for struct-member
        storage accesses (the diamond-storage / library-storage-pointer class).

        Heuristic-but-source-anchored: a `.<identifier>[..]` or `.<identifier>`
        access whose identifier is NOT a known contract state-var name and whose
        base is a `storage` local (the SSVStorageEB.load() pattern). We detect the
        member set by scanning node expressions; each is anchored to file:line.
        """
        # collect all struct member names declared in struct definitions, so we
        # only treat genuine struct-member storage accesses (not arbitrary fields).
        struct_members: set = set()
        for cu in self.sl.compilation_units:
            for st in getattr(cu, "structures_top_level", []) or []:
                for e in getattr(st, "elems_ordered", []) or []:
                    if getattr(e, "name", None):
                        struct_members.add(e.name)
            for c in cu.contracts:
                for st in getattr(c, "structures", []) or []:
                    for e in getattr(st, "elems_ordered", []) or []:
                        if getattr(e, "name", None):
                            struct_members.add(e.name)
        for cu in self.sl.compilation_units:
            for c in cu.contracts:
                if getattr(c, "is_interface", False):
                    continue
                for f in c.functions:
                    if getattr(f, "contract_declarer", None) is not c:
                        continue
                    for n in getattr(f, "nodes", []) or []:
                        expr = str(getattr(n, "expression", "") or "")
                        if "." not in expr:
                            continue
                        for member in struct_members:
                            if ("." + member) not in expr:
                                continue
                            kind = self._classify_member_access(expr, member)
                            if kind is None:
                                continue
                            yield (
                                member, f, c, n, kind,
                                _file_of(n), _first_line(n), expr[:160],
                            )

    def _contract_statevar_sites(self):
        """Yield (var_name, fn, contract, kind) for Slither-tracked contract-level
        state-var writes/reads (the semantic-ssa track)."""
        for cu in self.sl.compilation_units:
            for c in cu.contracts:
                if getattr(c, "is_interface", False):
                    continue
                for f in c.functions:
                    if getattr(f, "contract_declarer", None) is not c:
                        continue
                    for v in (getattr(f, "state_variables_written", []) or []):
                        if getattr(v, "name", None):
                            yield (v.name, f, c, "write")
                    for v in (getattr(f, "state_variables_read", []) or []):
                        if getattr(v, "name", None):
                            yield (v.name, f, c, "read")

    # ------------------------------------------------------------------
    # ECONOMIC STORAGE-VALUE SINKS (sink-taxonomy extension, P1).
    #
    # A direct WRITE (`+=`, `-=`, `delete`, `[k]=`) to an ECONOMIC state var (a
    # balance / share / units / debt / earnings / accounting mapping or scalar)
    # is a first-class value-mover, analogous to a token transfer. The existing
    # value-flow mode (VALUE_MOVING_CALLEES) is call-based and CANNOT see this
    # axis, so SSV's operatorEthVUnits[id] +=/delete economic risk is invisible.
    #
    # This emits one `storage-value` sink record PER economic storage write site,
    # honestly: source = the enclosing function (the write happens inside it),
    # guard analysis on that function over the written var. With Part-1 D-connect
    # the unguarded flag is then closure-corrected (a role gate in a modifier / up
    # the call graph flips unguarded -> false).
    #
    # ADDITIVE: a brand-new sink.kind == "storage-value"; no existing sink kind,
    # no existing value-flow record, is altered. Only runs in storage / both mode
    # AND only when --emit-storage-value (or AUDITOOOR_DATAFLOW_STORAGE_VALUE) is
    # set, so default value-flow output is byte-identical.
    # ------------------------------------------------------------------
    def _statevar_type_index(self) -> Dict[str, str]:
        """name -> declared-type-string for every contract-level state var and
        struct member (best-effort; used by the economic-value heuristic)."""
        idx: Dict[str, str] = {}
        for cu in self.sl.compilation_units:
            for c in cu.contracts:
                for v in (getattr(c, "state_variables", []) or []):
                    nm = getattr(v, "name", None)
                    if nm and nm not in idx:
                        idx[nm] = str(getattr(v, "type", "") or "")
                for st in getattr(c, "structures", []) or []:
                    for e in getattr(st, "elems_ordered", []) or []:
                        nm = getattr(e, "name", None)
                        if nm and nm not in idx:
                            idx[nm] = str(getattr(e, "type", "") or "")
            for st in getattr(cu, "structures_top_level", []) or []:
                for e in getattr(st, "elems_ordered", []) or []:
                    nm = getattr(e, "name", None)
                    if nm and nm not in idx:
                        idx[nm] = str(getattr(e, "type", "") or "")
        return idx

    def economic_storage_value_paths(self, var_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Emit one `storage-value` sink DefUsePath per economic storage WRITE site.

        A write to an economic state var (balance/units/shares/debt/earnings/...)
        via `+=` / `-=` / `delete` / `[k]=` is treated as a value-moving sink. Both
        tracks are covered:
          - contract-level state vars (Slither state_variables_written): semantic-ssa
          - struct-member diamond-storage writes (syntactic, source-anchored).
        """
        out: List[Dict[str, Any]] = []
        rx = re.compile(var_filter, re.IGNORECASE) if var_filter else None
        type_idx = self._statevar_type_index()
        seen = set()
        idx = 0

        def _accept(var: str) -> bool:
            if rx and not rx.search(var):
                return False
            return _is_economic_value_var(var, type_idx.get(var, ""))

        def _is_synthetic_slither_fn(fn) -> bool:
            # Slither synthesizes `slitherConstructorConstantVariables` /
            # `slitherConstructorVariables` pseudo-functions for constant/state-var
            # INITIALIZERS. Their "writes" are declaration-time constant assignments,
            # not an attacker-reachable runtime write site -> exclude from storage-value
            # sinks (capability noise surfaced on Polygon sPOL/StakeManagerStorage).
            nm = str(getattr(fn, "name", "") or "")
            return nm.lower().startswith("slitherconstructor")

        # --- Track 1: contract-level state-var writes (semantic-ssa) ---
        for var, f, c, kind in self._contract_statevar_sites():
            if kind != "write" or not _accept(var):
                continue
            if _is_synthetic_slither_fn(f):
                continue
            fid = getattr(f, "canonical_name", getattr(f, "name", None))
            # find the write node(s) inside f that touch this var, for file:line
            wnode, wexpr = self._first_write_node_for(f, var)
            line = _first_line(wnode) if wnode is not None else _first_line(f)
            file = _file_of(wnode) if wnode is not None else _file_of(f)
            key = (var, fid, line, "semantic-ssa")
            if key in seen:
                continue
            seen.add(key)
            rec = self._make_storage_value_record(
                var, f, c, file, line, wexpr, "semantic-ssa", idx)
            out.append(rec)
            idx += 1

        # --- Track 2: struct-member diamond-storage writes (syntactic) ---
        for var, f, c, n, kind, file, line, expr in self._struct_member_sites():
            if kind != "write" or not _accept(var):
                continue
            if _is_synthetic_slither_fn(f):
                continue
            fid = getattr(f, "canonical_name", getattr(f, "name", None))
            key = (var, fid, line, "syntactic")
            if key in seen:
                continue
            seen.add(key)
            rec = self._make_storage_value_record(
                var, f, c, file, line, expr, "syntactic", idx)
            out.append(rec)
            idx += 1
        return out

    def _first_write_node_for(self, fn, var: str):
        """Return (node, expr) for the first node in fn whose expression writes
        `var` (compound-assign / delete / [k]=), else (None, '')."""
        for n in getattr(fn, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if not expr or var not in expr:
                continue
            k = self._classify_member_access(expr, var)
            if k == "write":
                return n, expr[:160]
        # fall back: any node touching the var
        for n in getattr(fn, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if expr and var in expr:
                return n, expr[:160]
        return None, ""

    def _first_accum_write_expr_for(self, fn, var: str) -> str:
        """Return the expression of the first node in fn that ACCUMULATES the cell `var`
        (`_accum_rhs_of` truthy AND `_accum_cell_is(expr, var)`), else ''. Preferred over
        _first_write_node_for for the accum-delta hop so an earlier plain write does not
        shadow the accumulation site (`X = 0; ... X += d;` would otherwise miss its hop)."""
        for n in getattr(fn, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if not expr or var not in expr:
                continue
            e = expr[:160]
            if _accum_rhs_of(e) and _accum_cell_is(e, var):
                return e
        return ""

    def _make_storage_value_record(self, var, f, c, file, line, expr, track, idx):
        fid = getattr(f, "canonical_name", getattr(f, "name", None))
        guards = self._guards_for_vars(f, {var})
        guarded = bool(guards)
        source_rec = {
            "kind": "param-entrypoint",
            "fn": fid,
            "var": var,
            "file": _file_of(f),
            "line": _first_line(f),
        }
        sink_rec = {
            "kind": "storage-value",
            "callee": var,
            "arg_pos": None,
            "fn": fid,
            "file": file or _file_of(f),
            "line": line if line is not None else _first_line(f),
        }
        hop = {
            "from_var": var,
            "to_var": var,
            "fn": fid,
            "via": "intra",
            "file": file or _file_of(f),
            "line": line if line is not None else _first_line(f),
            "ir": ("storage-write:" + (expr or ""))[:160],
            "guarded": guarded,
        }
        rec = dfs.new_path(
            path_id=f"svp-{idx:04d}",
            language="solidity",
            direction="backward",
            engine="slither.economic-storage-value-sink",
            source=source_rec,
            sink=sink_rec,
            hops=[hop],
            guard_nodes=list(guards),
            source_unit_ids=[self._unit_id(f)],
            sink_unit_ids=[f"{Path(file).name if file else '?'}:{line}"],
            confidence=track,
            degraded=False,
        )
        rec["mode"] = "storage-value"
        return rec

    def storage_mediated_paths(self, var_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Emit cross-function DefUsePath records via:'storage' hops.

        write@fnA(state var X) -> read@fnB(X) for every distinct (A,B) pair where
        A != B and both touch the same storage var X. The consumer's read is marked
        unguarded when NO require/assert/condition in B dominates the read of X.

        Track 1 (semantic-ssa): contract-level state vars (Slither-tracked).
        Track 2 (syntactic):    struct-member diamond-storage vars (source-anchored).
        """
        out: List[Dict[str, Any]] = []
        rx = re.compile(var_filter, re.IGNORECASE) if var_filter else None

        # ---- gather writers and readers per var, per track ----
        # writers[var] = list of (fn, contract, file, line, expr, track)
        writers: Dict[str, List[tuple]] = {}
        readers: Dict[str, List[tuple]] = {}

        # Track 1: semantic contract-level state vars
        for var, f, c, kind in self._contract_statevar_sites():
            if rx and not rx.search(var):
                continue
            rec = (f, c, _file_of(f), _first_line(f), None, "semantic-ssa")
            (writers if kind == "write" else readers).setdefault(var, []).append(rec)

        # Track 2: syntactic struct-member (diamond-storage) sites
        seen_member = set()  # (var, fnid, line, kind) de-dup
        for var, f, c, n, kind, file, line, expr in self._struct_member_sites():
            if rx and not rx.search(var):
                continue
            fid = getattr(f, "canonical_name", getattr(f, "name", None))
            key = (var, fid, line, kind)
            if key in seen_member:
                continue
            seen_member.add(key)
            rec = (f, c, file, line, expr, "syntactic")
            (writers if kind == "write" else readers).setdefault(var, []).append(rec)

        # ---- build write->read pairs ----
        idx = 0
        aidx = 0
        seen_pair = set()
        seen_accum = set()
        for var in sorted(set(writers) | set(readers)):
            ws = writers.get(var, [])
            rs = readers.get(var, [])
            for (wf, wc, wfile, wline, wexpr, wtrack) in ws:
                wfid = getattr(wf, "canonical_name", getattr(wf, "name", None))
                # ACCUM DELTA HOP (co-accumulation Sigma-conservation overlay). When the
                # writer site is an accumulation (`<var> += rhs`), emit ONE extra path whose
                # single hop is the distinct storage flow {from_var:<base delta>, to_var:
                # <var>}. ADDITIVE: identity-hop pair records below are byte-unchanged; only
                # state-coupling-graph._slice_delta_links (from_var!=to_var) reads this hop.
                # Track 1 (contract-level Slither state vars) carries wexpr=None; resolve the
                # accumulation write expression on demand so plain `totalSupply += amount` /
                # `balanceOf[to] += amount` (canonical sum(balances)==totalSupply) also emit the
                # distinct-flow delta hop. `_accum_cell_is` gates on the DIRECTLY-accumulated
                # cell so a struct-member write's Slither base mapping is not double-emitted.
                _wx = wexpr if wexpr is not None else self._first_accum_write_expr_for(wf, var)
                _delta = _base_delta_of(_accum_rhs_of(_wx))
                if _delta and _delta != var and _accum_cell_is(_wx, var):
                    _akey = (var, wfid, wline, _delta)
                    if _akey not in seen_accum:
                        seen_accum.add(_akey)
                        _af = wfile or _file_of(wf)
                        _al = wline if wline is not None else _first_line(wf)
                        ahop = {
                            "from_var": _delta,
                            "to_var": var,
                            "fn": wfid,
                            "via": "storage",
                            "file": _af,
                            "line": _al,
                            "ir": ("accum:" + (_wx or ""))[:160],
                            "guarded": False,
                        }
                        arec = dfs.new_path(
                            path_id=f"sda-{aidx:04d}",
                            language="solidity",
                            direction="forward",
                            engine="slither.statevar-accum-delta",
                            source={"kind": "delta_var", "fn": wfid, "var": _delta,
                                    "file": _af, "line": _al},
                            sink={"kind": "state_var_accum", "callee": var, "arg_pos": None,
                                  "fn": wfid, "file": _af, "line": _al},
                            hops=[ahop],
                            guard_nodes=[],
                            source_unit_ids=[f"{Path(_af).name if _af else '?'}:{_al}"],
                            sink_unit_ids=[f"{Path(_af).name if _af else '?'}:{_al}"],
                            confidence="syntactic",
                            degraded=False,
                        )
                        arec["mode"] = "storage-accum-delta"
                        out.append(arec)
                        aidx += 1
                for (rf, rc, rfile, rline, rexpr, rtrack) in rs:
                    rfid = getattr(rf, "canonical_name", getattr(rf, "name", None))
                    if wfid == rfid:
                        continue  # producer == consumer, not a cross-fn flow
                    pair_key = (var, wfid, wline, rfid, rline)
                    if pair_key in seen_pair:
                        continue
                    seen_pair.add(pair_key)
                    # honesty: a pair is semantic-ssa ONLY if BOTH ends are semantic.
                    track = "semantic-ssa" if (wtrack == "semantic-ssa" and rtrack == "semantic-ssa") else "syntactic"

                    # guard analysis on the CONSUMER fn over the storage var name
                    rguards = self._guards_for_vars(rf, {var})
                    guarded = bool(rguards)

                    source_rec = {
                        "kind": "state_var",
                        "fn": wfid,
                        "var": var,
                        "file": wfile or _file_of(wf),
                        "line": wline if wline is not None else _first_line(wf),
                    }
                    sink_rec = {
                        "kind": "state_var_read",
                        "callee": var,
                        "arg_pos": None,
                        "fn": rfid,
                        "file": rfile or _file_of(rf),
                        "line": rline if rline is not None else _first_line(rf),
                    }
                    hop = {
                        "from_var": var,
                        "to_var": var,
                        "fn": rfid,
                        "via": "storage",
                        "file": rfile or _file_of(rf),
                        "line": rline if rline is not None else _first_line(rf),
                        "ir": (("write:" + (wexpr or "")) + " -> read:" + (rexpr or ""))[:160],
                        "guarded": guarded,
                    }
                    guard_nodes = list(rguards)
                    rec = dfs.new_path(
                        path_id=f"sdp-{idx:04d}",
                        language="solidity",
                        direction="forward",
                        engine="slither.statevar-defuse-bridge",
                        source=source_rec,
                        sink=sink_rec,
                        hops=[hop],
                        guard_nodes=guard_nodes,
                        source_unit_ids=[f"{Path(source_rec['file']).name if source_rec['file'] else '?'}:{source_rec['line']}"],
                        sink_unit_ids=[f"{Path(sink_rec['file']).name if sink_rec['file'] else '?'}:{sink_rec['line']}"],
                        confidence=track,
                        degraded=False,
                    )
                    rec["mode"] = "storage-mediated"
                    out.append(rec)
                    idx += 1
        return out

    def _unit_id(self, obj) -> str:
        f = _file_of(obj) or "?"
        ln = _first_line(obj) or 0
        return f"{Path(f).name}:{ln}"

    def _enumerate_sinks(self):
        """Yield (fn, tainted_arg_var, ir, node) for value-moving sinks with var args."""
        C = self.C
        for cu in self.sl.compilation_units:
            for c in cu.contracts:
                if getattr(c, "is_interface", False):
                    continue
                for f in c.functions:
                    if getattr(f, "contract_declarer", None) is not c:
                        continue
                    for n in getattr(f, "nodes", []) or []:
                        for ir in getattr(n, "irs", []) or []:
                            if not _is_value_moving(ir, C):
                                continue
                            args = list(getattr(ir, "arguments", []) or [])
                            for a in args:
                                if hasattr(a, "name") and getattr(a, "name", None):
                                    yield (f, a, ir, n)

    def emit_all(self, fanout: bool = True) -> List[Dict[str, Any]]:
        """Backward value-flow slices to value-moving sinks.

        fanout=True (default): use backward_df_all (multi-hop fan-out across ALL
        distinct caller frames per param) so a sink reachable from >1 caller chain
        yields >1 DefUsePath. fanout=False keeps the legacy single-chain walk.
        """
        records: List[Dict[str, Any]] = []
        seen = set()
        idx = 0
        for sink_fn, sink_var, sink_ir, sink_node in self._enumerate_sinks():
            if fanout:
                recs = self.backward_df_all(sink_fn, sink_var, sink_ir, sink_node)
            else:
                one = self.backward_df_recursive(sink_fn, sink_var, sink_ir, sink_node)
                recs = [one] if one is not None else []
            for rec in recs:
                if rec is None:
                    continue
                # dedup identical (source,sink,depth) slices
                sig = (
                    rec["source"].get("fn"), rec["source"].get("var"),
                    rec["sink"].get("fn"), rec["sink"].get("callee"),
                    rec["sink"].get("line"), rec["sink"].get("arg_pos"),
                    rec.get("call_depth"),
                )
                if sig in seen:
                    continue
                seen.add(sig)
                rec["path_id"] = f"dfp-{idx:04d}"
                records.append(rec)
                idx += 1
        return records

    # ------------------------------------------------------------------
    # D-CONNECT (KEYSTONE, P0): closure-aware `unguarded` correction.
    #
    # The per-record `unguarded` computed by dataflow_schema.new_path is
    # SLICE-LOCAL: it is true unless a guard sits on the slice's OWN hops /
    # guard_nodes. A guard that lives UP the call graph (a different function, a
    # modifier BODY, a base contract) is invisible -> the slice OVER-REPORTS
    # `unguarded=true` on role-gated codebases (SSV cluster/operator gating).
    #
    # This post-pass consults the WHOLE inter-procedural closure
    # (slither_predicates.has_guard_in_closure, which folds modifier bodies and
    # the transitive callee closure) for the sink function. When the closure
    # finds a caller-identity guard dominating the sink that the slice-local
    # computation missed, it flips `unguarded` true -> false and records WHY.
    # It NEVER flips false -> true (a slice-local guard already proves guarded).
    #
    # resolve_concrete_impl is used to follow virtual / interface / override
    # dispatch so a sink that crosses an interface call does not dead-end (and so
    # a base guard DROPPED by a child override is correctly seen as unguarded).
    #
    # R80 honesty: if Slither degrades (the predicates module is unimportable, or
    # the sink fn is not navigable / not found), we LEAVE the slice-local
    # `unguarded` untouched and stamp `closure_degraded`. We never silently claim
    # closure-backed when it did not run.
    #
    # ADDITIVE / default-off: only runs when called (gated by --closure-unguarded
    # in main()); it only ADDS keys (`closure_consulted`, `closure_guarded`,
    # `closure_degraded`, `closure_note`) and may flip `unguarded` true->false.
    # When the flag is off the records are byte-identical to before.
    # ------------------------------------------------------------------
    def _load_predicates(self):
        try:
            import importlib.util as _ilu
            import os as _os
            here = _os.path.dirname(_os.path.abspath(__file__))
            sp_path = _os.path.join(here, "slither_predicates.py")
            if not _os.path.exists(sp_path):
                return None
            spec = _ilu.spec_from_file_location("_sp_for_dataflow", sp_path)
            mod = _ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        except Exception:
            return None

    def _build_fn_index(self):
        """canonical_name -> Slither Function (concrete, non-interface)."""
        idx: Dict[str, Any] = {}
        for cu in self.sl.compilation_units:
            for c in cu.contracts:
                if getattr(c, "is_interface", False):
                    continue
                for f in c.functions:
                    cn = getattr(f, "canonical_name", getattr(f, "name", None))
                    if cn and cn not in idx:
                        idx[cn] = f
                    nm = getattr(f, "name", None)
                    if nm and nm not in idx:
                        idx[nm] = f
        return idx

    def _resolve_fn(self, sp, fid, fn_index):
        """Resolve a recorded canonical_name `fid` to a concrete Function,
        following override/interface dispatch via resolve_concrete_impl when the
        resolved fn is virtual / has a more-derived override (so a base-guard
        dropped by a child override lands on the child, and an interface call lands
        on its impl). Returns (fn_or_None, note)."""
        fn = fn_index.get(fid)
        note = ""
        if fn is None:
            return None, "fn-not-found"
        try:
            contract = getattr(fn, "contract", None) or getattr(fn, "contract_declarer", None)
            sel = (getattr(fn, "solidity_signature", None)
                   or getattr(fn, "full_name", None)
                   or getattr(fn, "name", None))
            if contract is not None and sel:
                impl = sp.resolve_concrete_impl(contract, sel)
                if impl is not None and not sp.is_degraded(impl) and impl is not fn:
                    fn = impl
                    note = "dispatch-resolved"
        except Exception:
            pass
        return fn, note

    def apply_closure_unguarded(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Closure-correct each record's `unguarded` in place. Returns a stats dict.

        For every record currently `unguarded == True`, consult the inter-procedural
        guard closure of its sink function. If a caller-identity guard dominates the
        sink across the call graph / modifiers (that the slice-local pass missed),
        flip `unguarded -> False`. Records already guarded are left alone.

        BACKWARD-ENTRYPOINT pass (additive, conservative): the FORWARD closure above
        misses a guard that lives on the CALLER when the slice's SOURCE fn is an
        INTERNAL/private value-mover (the modifier sits on the public entrypoint, up
        the call graph, not in the internal fn's own forward closure). For each path
        that is STILL `unguarded == True` after the forward pass AND whose source fn
        is internal/private, we enumerate the public/external ENTRYPOINTS that reach
        the internal source (backward caller closure). If there is >=1 such entrypoint
        AND EVERY one of them is guarded, the internal sink is unreachable without
        passing a guard -> flip `unguarded -> False` (closure_note=
        "guarded-via-all-entrypoints"). If ANY reaching entrypoint is unguarded, OR
        zero entrypoints are found (cannot prove), we KEEP `unguarded == True`
        (never over-flip a genuinely-reachable unguarded path). Slither-degrade on the
        backward check leaves `unguarded` untouched (R80).
        """
        stats = {"consulted": 0, "flipped_to_guarded": 0, "degraded": 0,
                 "kept_unguarded": 0, "flipped_via_entrypoints": 0,
                 "backward_consulted": 0, "backward_kept_unguarded": 0,
                 "backward_degraded": 0, "boundary_suspect": 0,
                 "downcast_suspect": 0, "asm_suspect": 0,
                 "intra_cei_suspect": 0, "unbounded_loop_suspect": 0,
                 "override_dropped_guard_suspect": 0,
                 "div_before_mul_suspect": 0,
                 "oracle_swallow_suspect": 0,
                 "enumset_remove_in_loop_suspect": 0,
                 "unchecked_return_value_suspect": 0,
                 "logic_tautology_suspect": 0,
                 "memory_copy_no_writeback_suspect": 0,
                 "two_step_accept_wrong_guard_suspect": 0,
                 "signature_replay_suspect": 0}
        sp = self._load_predicates()
        if sp is None:
            # R80: closure layer unavailable -> mark every record degraded, do not
            # touch unguarded. Output stays slice-local + honest.
            for rec in records:
                rec["closure_consulted"] = False
                rec["closure_degraded"] = True
                rec["closure_note"] = "predicates-module-unimportable"
                stats["degraded"] += 1
            return stats
        fn_index = self._build_fn_index()
        # Candidate universe for the BACKWARD caller-closure pass (built once, lazily).
        # Every concrete (non-interface) function across the compilation - the same
        # `scope` unguarded_paths_to_sink expects.
        _scope_cache: List[Any] = []
        _scope_built = [False]

        def _entrypoint_scope() -> List[Any]:
            if not _scope_built[0]:
                seen_ids = set()
                for cu in self.sl.compilation_units:
                    for c in cu.contracts:
                        if getattr(c, "is_interface", False):
                            continue
                        for f in c.functions:
                            if id(f) in seen_ids:
                                continue
                            seen_ids.add(id(f))
                            _scope_cache.append(f)
                _scope_built[0] = True
            return _scope_cache

        for rec in records:
            rec["closure_consulted"] = True
            rec["closure_degraded"] = False
            if rec.get("degraded"):
                rec["closure_consulted"] = False
                rec["closure_degraded"] = True
                rec["closure_note"] = "record-degraded"
                stats["degraded"] += 1
                continue

            # The guard that protects an over-reported slice usually sits on the
            # ENTRYPOINT (the slice's source fn): its forward closure includes the
            # whole path down to the sink PLUS the entrypoint's own modifiers
            # (onlyOwner / role gates). We also consult the SINK fn's own closure
            # (a guard inside / below the sink). resolve_concrete_impl follows
            # virtual/override/interface dispatch on BOTH so neither dead-ends.
            src_fid = (rec.get("source") or {}).get("fn")
            sink_fid = (rec.get("sink") or {}).get("fn")
            src_fn, src_note = self._resolve_fn(sp, src_fid, fn_index)
            sink_fn, sink_note = self._resolve_fn(sp, sink_fid, fn_index)

            if src_fn is None and sink_fn is None:
                rec["closure_degraded"] = True
                rec["closure_consulted"] = False
                rec["closure_note"] = "no-resolvable-fn"
                stats["degraded"] += 1
                continue

            stats["consulted"] += 1
            guarded = False
            degraded_any = False
            notes = []
            for label, fn, n in (("source", src_fn, src_note), ("sink", sink_fn, sink_note)):
                if fn is None:
                    continue
                g = sp.has_guard_in_closure(fn)
                if sp.is_degraded(g):
                    degraded_any = True
                    notes.append(f"{label}-degraded")
                    continue
                if n:
                    notes.append(f"{label}-{n}")
                if g is True:
                    guarded = True
                    notes.append(f"guard@{label}-closure")
                    break  # a single dominating guard is enough

            if not guarded and degraded_any:
                # Could not confirm guarded AND at least one closure degraded ->
                # do NOT flip; report honestly so consumers know it is slice-local.
                rec["closure_degraded"] = True
                rec["closure_note"] = ";".join(notes) or "closure-degraded"
                stats["degraded"] += 1
                continue

            rec["closure_guarded"] = bool(guarded)
            rec["closure_note"] = ";".join(notes) or "closure-consulted"

            # ----------------------------------------------------------------
            # GUARD-CORRECTNESS / BOUNDARY-SUSPECT annotation (additive LEAD).
            # The closure pass above answers "is there a guard"; this answers "is
            # the guard CORRECT". For a path whose dominating guard is a comparator
            # on the tainted VALUE against a cap/const where a `<=`/`>=` could be an
            # off-by-one (`<`/`>` intended), stamp `boundary_suspect` + `guard_comparator`
            # so consumers can seed an off-by-one/boundary hunt question. This is a
            # LEAD ONLY: it NEVER flips `unguarded`, NEVER auto-claims a finding, and
            # a CORRECT strict guard yields boundary_suspect=False (never-FP). Runs
            # for guarded AND unguarded paths (a guarded path may still be exploitable
            # via a boundary bug). R80: a degrade on the comparator extraction leaves
            # no annotation (no false boundary_suspect on a non-navigable fn).
            try:
                # Scan the SOURCE fn's own body + forward closure first (the guard
                # that dominates the value flow usually lives at the entrypoint or
                # an intermediate hop, e.g. withdraw -> _route[require(amt<=cap)] ->
                # _pay -> transferFrom). Fall back to the sink fn's closure. The
                # tainted var is renamed across hops, so the closure scan uses no
                # value-name filter (the path flow already establishes the value
                # relationship) - a CONSERVATIVE LEAD, never a flip of `unguarded`.
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    bs = sp.closure_boundary_suspect(fn, value_names=None)
                    if sp.is_degraded(bs):
                        continue
                    if bs.get("boundary_suspect"):
                        rec["boundary_suspect"] = True
                        rec["guard_comparator"] = {
                            "op": bs.get("op", ""),
                            "suggested_op": bs.get("suggested_op", ""),
                            "at_fn": bs.get("at_fn") or label,
                            "at_end": label,
                            "line": bs.get("line"),
                            "reason": bs.get("reason", ""),
                        }
                        rec["closure_note"] = (
                            (rec.get("closure_note") or "")
                            + f";boundary-suspect@{bs.get('at_fn') or label}"
                              f"({bs.get('op','')})")
                        stats["boundary_suspect"] = stats.get("boundary_suspect", 0) + 1
                        break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # UNSAFE-DOWNCAST / TYPE-CONVERTIBILITY annotation (additive LEAD).
            # Glider can_convert / type-convertibility analog. Where the value-flow
            # crosses a LOSSY cast on a value-moving operand (uint256 -> uint64
            # silent truncation, or int<->uint sign-flip), stamp `downcast_suspect`
            # + `downcast{var,from,to,kind,line}` so consumers can seed a
            # truncation/sign-flip hunt question at the cast file:line. CONSERVATIVE:
            # a SafeCast.toUintN() wrap (a LibraryCall, not a TypeConversion) and a
            # widening / non-value cast are NEVER flagged (never-false-positive). It
            # is a LEAD ONLY: NEVER flips `unguarded`, NEVER auto-claims a finding.
            # Runs for guarded AND unguarded paths. R80: a degrade on the cast scan
            # leaves no annotation.
            try:
                # Scan the SOURCE fn's own body + forward closure first (the lossy
                # cast usually lives at the entrypoint or an intermediate settle/pay
                # hop), then the sink fn. The tainted var is renamed across hops, so
                # the closure scan uses no value-name filter (the path flow already
                # establishes the value relationship) - a CONSERVATIVE LEAD, never a
                # flip of `unguarded`.
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    dc = sp.closure_unsafe_value_downcasts(fn, value_names=None)
                    if sp.is_degraded(dc) or not dc:
                        continue
                    d = dc[0]
                    rec["downcast_suspect"] = True
                    rec["downcast"] = {
                        "var": d.get("var", ""),
                        "from": d.get("from", ""),
                        "to": d.get("to", ""),
                        "kind": d.get("kind", ""),
                        "at_fn": d.get("at_fn") or label,
                        "at_end": label,
                        "line": d.get("line"),
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";downcast-suspect@{d.get('at_fn') or label}"
                          f"({d.get('from','')}->{d.get('to','')})")
                    stats["downcast_suspect"] = stats.get("downcast_suspect", 0) + 1
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # DIVIDE-BEFORE-MULTIPLY precision annotation (additive LEAD, Glider
            # gap W3). The closure pass answers "is there a guard", the comparator
            # layer "is the guard CORRECT", the type-convertibility layer "is a value
            # silently CHANGED by a cast". This layer answers "is a value TRUNCATED by
            # a divide-before-multiply" - where the value-flow's source/sink fn (or an
            # intermediate hop) computes `(a / b) * c` (integer DIVISION whose result
            # feeds a MULTIPLICATION), losing precision vs the correct `(a * c) / b`.
            # Stamp `div_before_mul_suspect` + `div_before_mul{div_line, mul_line,
            # at_fn, at_end, value_moving, severity_hint}` so consumers can seed a
            # precision-loss hunt question at the div file:line. CONSERVATIVE /
            # never-false-positive: `(a * b) / c` (mul-before-div, the CORRECT order)
            # and a pure compile-time-literal fold are NEVER flagged. LEAD ONLY: NEVER
            # flips `unguarded`, NEVER auto-claims a finding. Runs for guarded AND
            # unguarded paths (a precision bug is exploitable either way). R80: a
            # degrade on the IR scan leaves no annotation.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    dbm = sp.closure_divide_before_multiply(fn, value_names=None)
                    if sp.is_degraded(dbm) or not dbm:
                        continue
                    d = dbm[0]
                    rec["div_before_mul_suspect"] = True
                    rec["div_before_mul"] = {
                        "div_line": d.get("div_line"),
                        "mul_line": d.get("mul_line"),
                        "at_fn": d.get("at_fn") or label,
                        "at_end": label,
                        "value_moving": d.get("value_moving", "unknown"),
                        "severity_hint": d.get("severity_hint", "precision-loss"),
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";div-before-mul-suspect@{d.get('at_fn') or label}"
                          f"(div@{d.get('div_line')})")
                    stats["div_before_mul_suspect"] = (
                        stats.get("div_before_mul_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # INLINE-ASSEMBLY / YUL SINK annotation (additive LEAD).
            # Glider `is_assembly` analog. Where the value-flow crosses an inline-
            # assembly (Yul) block containing a delegatecall (proxy/upgrade
            # backdoor), a LITERAL-slot sstore (storage-slot collision), or a raw
            # value-moving call, stamp `asm_suspect` + `asm{kind,slot?,line}` so
            # consumers can seed an asm-delegatecall / storage-collision hunt
            # question at the asm file:line. CONSERVATIVE: a Yul delegatecall is
            # always surfaced; an sstore is surfaced ONLY for a literal/constant
            # slot (a `.slot` declared-var sstore and plain memory-only asm are
            # NEVER flagged - never-false-positive). It is a LEAD ONLY: NEVER flips
            # `unguarded`, NEVER auto-claims a finding. Runs for guarded AND
            # unguarded paths (a proxy/storage-collision bug is exploitable either
            # way). R80: a degrade on the asm scan leaves no annotation.
            try:
                # Scan the SOURCE fn's own body + forward closure first (the Yul
                # delegatecall / literal-slot sstore usually lives at the
                # entrypoint or an intermediate set-impl / delegate hop), then the
                # sink fn.
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    az = sp.closure_asm_suspect_sinks(fn)
                    if sp.is_degraded(az) or not az:
                        continue
                    a = az[0]
                    rec["asm_suspect"] = True
                    rec["asm"] = {
                        "kind": a.get("kind", ""),
                        "slot": a.get("slot"),
                        "at_fn": a.get("at_fn") or label,
                        "at_end": label,
                        "line": a.get("line"),
                        "snippet": a.get("snippet", ""),
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";asm-suspect@{a.get('at_fn') or label}"
                          f"({a.get('kind','')})")
                    stats["asm_suspect"] = stats.get("asm_suspect", 0) + 1
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # SAME-FN CEI / INTRA-PROC reentrancy annotation (additive LEAD).
            # Glider gap #5 intra-procedural CFG navigation. The closure pass above
            # answers "is there an access-control guard"; the cross-fn closure
            # reentrancy reasoning sees A->B call EDGES. NEITHER sees a state-write
            # that occurs AFTER an external call WITHIN ONE function (the same-fn
            # CEI violation). Where the value-flow's source/sink fn (or an
            # intermediate hop) contains an ext-call-then-state-write with NO
            # reentrancy guard, stamp `intra_cei_suspect` + `intra_cei{ext_line,
            # write_line,var,at_fn}` so consumers can seed a same-fn-reentrancy hunt
            # question at the ext-call/write file:line. CONSERVATIVE: a write-BEFORE
            # the call (CEI-correct) and a nonReentrant-guarded fn are NEVER flagged
            # (never-false-positive). LEAD ONLY: NEVER flips `unguarded`, NEVER
            # auto-claims a finding. Runs for guarded AND unguarded paths (a
            # reentrancy bug is exploitable regardless of access-control). R80: a
            # degrade on the CFG scan leaves no annotation. COMPLEMENTS (does not
            # duplicate) the cross-fn closure reentrancy oracle.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    ce = sp.closure_intra_fn_cei(fn)
                    if sp.is_degraded(ce) or not ce:
                        continue
                    c0 = ce[0]
                    rec["intra_cei_suspect"] = True
                    rec["intra_cei"] = {
                        "ext_call_line": c0.get("ext_call_line"),
                        "state_write_line": c0.get("state_write_line"),
                        "var": c0.get("var", ""),
                        "at_fn": c0.get("at_fn") or label,
                        "at_end": label,
                    }
                    # ADDITIVE (Glider gap W4): when the ext marker came TRANSITIVELY
                    # via an internal helper, forward the provenance so the same-fn
                    # reentrancy question can NAME the helper. question_class /
                    # attack_class stay UNCHANGED; a direct-ext lead omits these keys.
                    if c0.get("transitive") is True:
                        rec["intra_cei"]["transitive"] = True
                        rec["intra_cei"]["via"] = c0.get("via")
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";intra-cei-suspect@{c0.get('at_fn') or label}"
                          f"(write@{c0.get('state_write_line')})")
                    stats["intra_cei_suspect"] = stats.get("intra_cei_suspect", 0) + 1
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # UNBOUNDED-LOOP gas-griefing annotation (additive LEAD).
            # Glider gap #5 loop oracle. Where the value-flow's source/sink fn (or
            # an intermediate hop) contains a loop bounded by an attacker-growable
            # `<state-collection>.length` with an effect inside, stamp
            # `unbounded_loop_suspect` + `unbounded_loop{loop_line,bound_var,at_fn}`
            # so consumers can seed an unbounded-loop-gas hunt question at the loop
            # file:line. CONSERVATIVE: a constant / parameter / local-cap bound
            # (reads no state var in its condition) and a read-only / empty loop
            # body are NEVER flagged (never-false-positive). LEAD ONLY: NEVER flips
            # `unguarded`, NEVER auto-claims a finding. R80: a degrade leaves no
            # annotation.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    ul = sp.closure_unbounded_loops(fn)
                    if sp.is_degraded(ul) or not ul:
                        continue
                    u0 = ul[0]
                    rec["unbounded_loop_suspect"] = True
                    rec["unbounded_loop"] = {
                        "loop_line": u0.get("loop_line"),
                        "bound_var": u0.get("bound_var", ""),
                        "at_fn": u0.get("at_fn") or label,
                        "at_end": label,
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";unbounded-loop-suspect@{u0.get('at_fn') or label}"
                          f"({u0.get('bound_var','')}.length)")
                    stats["unbounded_loop_suspect"] = (
                        stats.get("unbounded_loop_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # ENUMERABLESET REMOVE-IN-LOOP iteration-skip annotation (additive
            # LEAD, Glider gap W5). Where the value-flow's source/sink fn (or an
            # intermediate hop) contains a FORWARD loop that reads `<coll>.at(i)`
            # AND `<coll>.remove(...)` on the SAME collection while the counter
            # advances monotonically, stamp `enumset_remove_in_loop_suspect` +
            # `enumset_remove_in_loop{loop_line,at_line,remove_line,collection,...}`
            # so consumers can seed an iteration-skip hunt question at the remove
            # file:line. CONSERVATIVE / never-FP: a BACKWARD loop (`i--`), an
            # unknown direction, a `.remove()` without an `.at(counter)` on that
            # collection (fixed-key removal), and an `.at(i)` read without a remove
            # are NEVER flagged. LEAD ONLY: NEVER flips `unguarded`, NEVER
            # auto-claims a finding. New stat key only. R80: a degrade leaves no
            # annotation. Distinct from gap #5 `unbounded_loop` (gas-exhaustion via
            # an attacker-growable `.length` bound) - this is FUNCTIONAL
            # iteration-skip (incomplete iteration / unhandled state), not griefing.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    er = sp.closure_enumerable_remove_in_loop(fn)
                    if sp.is_degraded(er) or not er:
                        continue
                    e0 = er[0]
                    rec["enumset_remove_in_loop_suspect"] = True
                    rec["enumset_remove_in_loop"] = {
                        "loop_line": e0.get("loop_line"),
                        "at_line": e0.get("at_line"),
                        "remove_line": e0.get("remove_line"),
                        "collection": e0.get("collection", ""),
                        "at_fn": e0.get("at_fn") or label,
                        "at_end": label,
                        "severity_hint": e0.get("severity_hint", "iteration-skip"),
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";enumset-remove-in-loop-suspect@{e0.get('at_fn') or label}"
                          f"({e0.get('collection','')}@{e0.get('remove_line')})")
                    stats["enumset_remove_in_loop_suspect"] = (
                        stats.get("enumset_remove_in_loop_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # UNCHECKED RETURN-VALUE annotation (additive LEAD, Glider gap W6 P1).
            # Where the value-flow's source/sink fn (or an intermediate hop in its
            # forward callee closure) makes a transfer / transferFrom / .call /
            # .send / delegatecall whose boolean success RETURN value is never
            # consumed by a require/assert/if-revert/return (or any downstream
            # read), stamp `unchecked_return_value_suspect` +
            # `unchecked_return_value{call_line,callee,kind,at_fn,...}` so consumers
            # can seed an unchecked-return-value hunt question at the call
            # file:line. CONSERVATIVE / never-FP: a consumed return, a SafeERC20
            # wrapper call, and address.transfer (reverts itself, no bool) are NEVER
            # flagged. LEAD ONLY: NEVER flips `unguarded`, NEVER auto-claims a
            # finding. New stat key only. R80: a degrade leaves no annotation.
            # Distinct from cap-3 taint-of-INPUTS-to-sinks and from cap-8 / W4
            # external-call-then-write ORDERING - this keys on RETURN-value
            # CONSUMPTION.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    ur = sp.closure_unchecked_return_values(fn)
                    if sp.is_degraded(ur) or not ur:
                        continue
                    r0 = ur[0]
                    rec["unchecked_return_value_suspect"] = True
                    rec["unchecked_return_value"] = {
                        "call_line": r0.get("call_line"),
                        "callee": r0.get("callee", ""),
                        "kind": r0.get("kind", ""),
                        "at_fn": r0.get("function") or label,
                        "at_end": label,
                        "at_file": r0.get("at_file", ""),
                        "severity_hint": r0.get("severity_hint", "unchecked-return"),
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";unchecked-return-value-suspect@{r0.get('function') or label}"
                          f"({r0.get('callee','')}@{r0.get('call_line')})")
                    stats["unchecked_return_value_suspect"] = (
                        stats.get("unchecked_return_value_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # MEMORY-COPY-OF-STORAGE-NEVER-WRITTEN-BACK annotation (additive
            # LEAD, Glider gap W6 P8). Where the value-flow's source/sink fn
            # (or its own body - no closure walk needed; this is intra-fn)
            # reads a storage state-var into a MEMORY local, mutates the local,
            # but NEVER writes the mutation back to the state var, stamp
            # `memory_copy_no_writeback_suspect` + `memory_copy_no_writeback`
            # with the copy/mutate line numbers so consumers can seed a
            # lost-state-update hunt question at the mutation file:line.
            # CONSERVATIVE / never-FP: a storage pointer (location=="storage"),
            # a read-only copy (no mutation), or a copy with any writeback in
            # the same fn are NEVER flagged. LEAD ONLY: NEVER flips `unguarded`,
            # NEVER auto-claims a finding. New stat key only. R80: a degrade
            # (non-navigable fn / Assignment IR unavailable) leaves no annotation.
            # Distinct from the intra-CEI / unchecked-return / enumset oracles.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    mc = sp.memory_copy_no_writeback(fn)
                    if sp.is_degraded(mc) or not mc:
                        continue
                    m0 = mc[0]
                    rec["memory_copy_no_writeback_suspect"] = True
                    rec["memory_copy_no_writeback"] = {
                        "state_var": m0.get("state_var", ""),
                        "local": m0.get("local", ""),
                        "copy_line": m0.get("copy_line"),
                        "mutate_line": m0.get("mutate_line"),
                        "at_fn": m0.get("function") or label,
                        "at_end": label,
                        "severity_hint": m0.get("severity_hint", "lost-state-update"),
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";memory-copy-no-writeback@{m0.get('function') or label}"
                          f"({m0.get('state_var','')}@{m0.get('copy_line')})")
                    stats["memory_copy_no_writeback_suspect"] = (
                        stats.get("memory_copy_no_writeback_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # SIGNATURE-REPLAY precondition annotation (additive LEAD, Glider
            # gap W6 P3). Where the value-flow's source/sink fn (or an
            # intermediate hop in its forward callee closure) calls ecrecover
            # (or a recover/ECDSA.recover helper) but EITHER (a) never writes a
            # per-signer/per-message nonce mapping (missing-nonce: same-chain
            # replay) OR (b) never reads block.chainid in the digest-building
            # path (missing-chainid: cross-chain replay), stamp
            # `signature_replay_suspect` + `signature_replay{kind, ecrecover_line,
            # at_line, at_fn, at_end, severity_hint}` so consumers can seed a
            # signature-replay hunt question at the ecrecover file:line.
            # CONSERVATIVE / never-FP: ecrecover absent -> no flag; nonce write
            # present -> missing-nonce suppressed; block.chainid read present ->
            # missing-chainid suppressed. LEAD ONLY: NEVER flips `unguarded`,
            # NEVER auto-claims a finding. New stat key only. R80: a degrade
            # (non-navigable fn / slither unavailable) leaves no annotation.
            # Distinct from the access-control, boundary, downcast, and CEI
            # oracles - this keys on SIGNATURE-VERIFICATION preconditions.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    sr = sp.closure_signature_replay_suspects(fn)
                    if sp.is_degraded(sr) or not sr:
                        continue
                    r0 = sr[0]
                    rec["signature_replay_suspect"] = True
                    rec["signature_replay"] = {
                        "kind": r0.get("kind", ""),
                        "ecrecover_line": r0.get("ecrecover_line"),
                        "at_fn": r0.get("at_fn") or r0.get("function") or label,
                        "at_end": label,
                        "at_line": r0.get("at_line"),
                        "severity_hint": r0.get("severity_hint", "signature-replay"),
                    }
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";signature-replay-{r0.get('kind','?')}@"
                          f"{r0.get('at_fn') or r0.get('function') or label}"
                          f"(ecrecover@{r0.get('ecrecover_line')})")
                    stats["signature_replay_suspect"] = (
                        stats.get("signature_replay_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # OVERRIDE-DROPPED-GUARD DISPATCH annotation (additive LEAD, Glider
            # gap W1). The closure pass above answers "is there a guard reachable
            # NOW"; it does NOT answer "did a child override DROP an access-control
            # guard the base version enforced". Where the slice's source/sink fn is
            # a concrete override whose base version was guarded but whose own
            # closure is not, stamp `override_dropped_guard_suspect` +
            # `override_dropped_guard{...}` so consumers can seed a dropped-guard
            # access-control hunt question at the override's file:line. CONSERVATIVE
            # / never-FP: the predicate flags ONLY a positively-guarded base + a
            # positively-unguarded override; a guard re-added under a recognized name
            # or moved into a forward callee is NOT a drop. LEAD ONLY: NEVER flips
            # `unguarded`, NEVER auto-claims a finding. New stat key only. R80: a
            # degrade leaves no annotation. Distinct from has_guard_in_closure (which
            # sees only the post-drop state) and from gap #4 callsite-selector (which
            # enumerates call SITES, not guard deltas across the override DAG).
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    contract = getattr(fn, "contract", None)
                    if contract is None:
                        continue
                    odg = sp.override_dropped_guards(contract)
                    if sp.is_degraded(odg) or not odg:
                        continue
                    # Pick the record (if any) that matches THIS fn, else the first
                    # drop on the contract (still an actionable lead on the path).
                    fn_name = str(getattr(fn, "name", "") or "")
                    pick = None
                    for r0 in odg:
                        if r0.get("function") == fn_name:
                            pick = r0
                            break
                    if pick is None:
                        pick = odg[0]
                    rec["override_dropped_guard_suspect"] = True
                    rec["override_dropped_guard"] = dict(pick)
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";override-dropped-guard@{pick.get('contract','')}"
                          f".{pick.get('function','')}"
                          f"(base={pick.get('base_contract','')})")
                    stats["override_dropped_guard_suspect"] = (
                        stats.get("override_dropped_guard_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # ORACLE TRY/CATCH-SWALLOW annotation (additive LEAD, Glider gap W2).
            # The closure pass above answers caller-identity guard questions; it does
            # NOT detect an ORACLE / price read wrapped in a try whose catch SWALLOWS
            # the failure (no revert / no re-throw / no validating require), so the
            # function proceeds on a stale/zero/default value. Where the slice's
            # source/sink fn (or an intermediate closure hop) has such a swallowing
            # oracle try/catch, stamp `oracle_swallow_suspect` + `oracle_swallow{...}`
            # so consumers can seed a stale-price / oracle-failure-ignored hunt
            # question at the catch file:line. CONSERVATIVE / never-FP: the predicate
            # flags ONLY a curated-oracle-callee try whose every catch swallows; a
            # reverting / re-throwing / validated catch is NOT flagged. LEAD ONLY:
            # NEVER flips `unguarded`, NEVER auto-claims a finding. New stat key only.
            # R80: a degrade (non-navigable fn / slither lacks try/catch modeling)
            # leaves no annotation. Distinct from the access-control / boundary /
            # downcast / asm / intra-CEI / unbounded-loop oracles.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    osw = sp.closure_oracle_swallow_suspects(fn)
                    if sp.is_degraded(osw) or not osw:
                        continue
                    # Pick the record (if any) matching THIS fn, else the first
                    # swallow on the closure (still an actionable lead on the path).
                    fn_name = str(getattr(fn, "name", "") or "")
                    pick = None
                    for r0 in osw:
                        if r0.get("function") == fn_name:
                            pick = r0
                            break
                    if pick is None:
                        pick = osw[0]
                    rec["oracle_swallow_suspect"] = True
                    rec["oracle_swallow"] = dict(pick)
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";oracle-swallow@{pick.get('contract','')}"
                          f".{pick.get('function','')}"
                          f"({pick.get('oracle_callee','')})")
                    stats["oracle_swallow_suspect"] = (
                        stats.get("oracle_swallow_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # LOGIC-TAUTOLOGY / DEAD-COMPARISON annotation (additive LEAD,
            # Glider gap W6 P2). Where the value-flow's source/sink fn (or an
            # intermediate hop in its forward callee closure) contains a guard
            # whose LOGIC is broken - either an always-true OR tautology
            # (msg.sender != A || msg.sender != B, always satisfied) or a dead
            # comparison (result of == / != discarded, guard never applied) -
            # stamp `logic_tautology_suspect` + `logic_tautology{...}` so
            # consumers can seed a broken-access-control hunt question at the
            # guard's file:line. CONSERVATIVE / never-FP: (a) requires BOTH
            # OR sides to share the SAME caller-identity name; (b) fires only
            # on EXPRESSION nodes whose lvalue is wholly unread. LEAD ONLY:
            # NEVER flips `unguarded`, NEVER auto-claims a finding. New stat
            # key only. R80: a degrade leaves no annotation. Distinct from
            # has_guard_in_closure (which answers "is a guard present", not
            # "is the guard logically correct").
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    lt = sp.closure_logic_tautology_suspects(fn)
                    if sp.is_degraded(lt) or not lt:
                        continue
                    fn_name = str(getattr(fn, "name", "") or "")
                    pick = None
                    for r0 in lt:
                        if r0.get("function") == fn_name:
                            pick = r0
                            break
                    if pick is None:
                        pick = lt[0]
                    rec["logic_tautology_suspect"] = True
                    rec["logic_tautology"] = dict(pick)
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";logic-tautology-{pick.get('kind','?')}@"
                          f"{pick.get('contract','')}.{pick.get('function','')}"
                          f"(line={pick.get('at_line')})")
                    stats["logic_tautology_suspect"] = (
                        stats.get("logic_tautology_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # ----------------------------------------------------------------
            # TWO-STEP-OWNERSHIP-ACCEPT WRONG-GUARD annotation (additive LEAD,
            # Glider gap W6 P5). Where the value-flow's source/sink fn is an
            # accept/claim-ownership function gated by onlyOwner-family (the WRONG
            # guard - the current owner) instead of checking msg.sender == pending*
            # (the CORRECT guard - the pending owner), stamp
            # `two_step_accept_wrong_guard_suspect` + `two_step_accept_wrong_guard
            # {contract, function, ownership_var, pending_var, guard_modifier,
            # at_line, severity_hint}` so consumers can seed an access-control wrong-
            # guard hunt question at the function's file:line.
            # CONSERVATIVE / never-FP: flags ONLY when (1) fn name is accept/claim
            # ownership/admin, (2) a pending* var exists in the contract, (3) the fn
            # writes an ownership var, (4) an onlyOwner-family modifier is present,
            # AND (5) no msg.sender==pending* check exists. A correct pending check
            # suppresses the annotation entirely. LEAD ONLY: NEVER flips `unguarded`,
            # NEVER auto-claims a finding. New stat key only. R80: a degrade leaves
            # no annotation. Distinct from override-dropped-guard (W1) and missing-
            # guard (cap-1): this fires on a WRONG guard, not a dropped or absent one.
            try:
                for label, fn in (("source", src_fn), ("sink", sink_fn)):
                    if fn is None:
                        continue
                    tsawg = sp.two_step_accept_wrong_guard(fn)
                    if sp.is_degraded(tsawg) or not tsawg:
                        continue
                    pick = tsawg[0]
                    rec["two_step_accept_wrong_guard_suspect"] = True
                    rec["two_step_accept_wrong_guard"] = dict(pick)
                    rec["closure_note"] = (
                        (rec.get("closure_note") or "")
                        + f";two-step-accept-wrong-guard@{pick.get('contract','')}"
                          f".{pick.get('function','')}"
                          f"(guard={pick.get('guard_modifier','')}"
                          f",pending={pick.get('pending_var','')})")
                    stats["two_step_accept_wrong_guard_suspect"] = (
                        stats.get("two_step_accept_wrong_guard_suspect", 0) + 1)
                    break  # first suspect end is enough
            except Exception:
                # Never let the additive annotation break the closure pass.
                pass

            # Only the over-report direction: flip an unguarded slice to guarded
            # when the closure finds an up-graph / modifier guard. Never flip the
            # other way (a slice-local guard already proves guarded).
            if rec.get("unguarded") is True and guarded is True:
                rec["unguarded"] = False
                rec["unguarded_closure_corrected"] = True
                stats["flipped_to_guarded"] += 1
            elif rec.get("unguarded") is True:
                stats["kept_unguarded"] += 1

            # ----------------------------------------------------------------
            # BACKWARD-ENTRYPOINT pass (additive, conservative, never over-flip).
            # The forward pass above only sees a guard in the source/sink's OWN
            # forward closure. When the slice SOURCE is an INTERNAL/private
            # value-mover, its caller-side guard (a modifier on the public
            # entrypoint) is up the call graph and INVISIBLE forward -> the path
            # stays unguarded=True (the documented under-flip; recurs for every
            # internal value-mover guarded at the entrypoint, e.g. polygon
            # StakeManager._delegationDeposit gated by onlyDelegation entrypoints).
            #
            # Only run when: (a) the path is STILL unguarded after the forward
            # pass, (b) the source fn resolved, and (c) the source fn visibility
            # is internal/private (a public/external source is already covered by
            # the forward pass on itself). Flip to guarded ONLY when >=1 reaching
            # public/external entrypoint exists AND EVERY one is guarded. If ANY
            # entrypoint is unguarded, or zero are found, KEEP unguarded.
            # ----------------------------------------------------------------
            if rec.get("unguarded") is not True or src_fn is None:
                continue
            src_vis = str(getattr(src_fn, "visibility", "") or "").lower()
            if src_vis not in ("internal", "private"):
                continue
            stats["backward_consulted"] += 1
            try:
                eps = sp.unguarded_paths_to_sink(src_fn, _entrypoint_scope())
            except Exception:
                eps = sp.DEGRADED
            if sp.is_degraded(eps):
                # R80: backward closure could not navigate -> leave unguarded,
                # stamp honestly. Never claim guarded on a degrade.
                rec["backward_closure_degraded"] = True
                rec["closure_note"] = (rec.get("closure_note") or "") + ";backward-degraded"
                stats["backward_degraded"] += 1
                continue
            rec["backward_entrypoints_total"] = len(eps)
            guarded_eps = [e for e in eps if e.get("guarded") is True]
            rec["backward_entrypoints_guarded"] = len(guarded_eps)
            # Flip ONLY when there is >=1 reaching entrypoint and ALL are guarded.
            if eps and len(guarded_eps) == len(eps):
                rec["unguarded"] = False
                rec["unguarded_closure_corrected"] = True
                rec["closure_note"] = (rec.get("closure_note") or "") + ";guarded-via-all-entrypoints"
                stats["flipped_via_entrypoints"] += 1
            else:
                # zero reaching entrypoints OR >=1 unguarded entrypoint -> keep.
                rec["closure_note"] = (rec.get("closure_note") or "") + ";backward-kept-unguarded"
                stats["backward_kept_unguarded"] += 1
        return stats


# ----------------------------------------------------------------------------
# Workspace target resolution
# ----------------------------------------------------------------------------
def _resolve_targets(ws: Path) -> List[Path]:
    """Find the Solidity project root(s) under the workspace to compile.

    Prefer the nearest dir with a foundry/hardhat config containing in-scope
    `contracts/` or `src/` Solidity (skip out/, cache/, node_modules/, test/).
    """
    candidates: List[Path] = []
    # Exclude vendored/build dirs AND audit-generated scaffolding. The latter is the
    # strata 2026-06-30 root-explosion: a real protocol ws also contains foundry roots
    # under .auditooor/fuzz_run, chimera_harnesses, and poc-tests/* (harnesses WE
    # authored), so _resolve_targets returned 11 roots and Slither compilation of all
    # of them blew past the timeout before any dataflow row was written. Those are not
    # the audit TARGET - the in-scope protocol is. Exclude them so the slice compiles
    # only the real protocol root(s) and finishes in-budget.
    _EXCLUDE_PARTS = {
        "node_modules", "out", "cache", "crytic-export", "lib",
        ".auditooor", "chimera_harnesses", "poc-tests", "poc_execution",
        "prior_audits", "medusa", "medusa-corpus", "fuzz_run", "test", "tests",
    }
    for cfg in ("foundry.toml", "hardhat.config.ts", "hardhat.config.js"):
        for p in ws.rglob(cfg):
            parts = set(p.parts)
            if parts & _EXCLUDE_PARTS:
                continue
            candidates.append(p.parent)
    # uniq, prefer shallowest
    uniq = sorted(set(candidates), key=lambda d: len(d.parts))
    return uniq


def _parse_file_line(spec: str) -> Tuple[str, int]:
    """Parse 'path/to/File.sol:46' (or File.sol#46). Returns (file_token, line).
    The file_token is matched on basename, so a bare filename or a relative/
    absolute path all work."""
    m = re.match(r"^(.*?)[:#](\d+)$", spec.strip())
    if not m:
        raise ValueError(f"--from-sink expects FILE:LINE, got {spec!r}")
    return m.group(1), int(m.group(2))


def _run_mark_explained(args) -> int:
    """Record confirmed-finding DefUsePath ids as EXPLAINED in an additive sidecar
    (<ws>/.auditooor/dataflow_explained_paths.json). Idempotent union. The next
    hunt round's seeding can consult this set to SKIP already-explained paths
    (consumer wiring is a documented follow-up). No existing file is mutated."""
    ws = Path(args.workspace).resolve()
    side = ws / ".auditooor" / "dataflow_explained_paths.json"
    side.parent.mkdir(parents=True, exist_ok=True)
    ids = [s.strip() for s in str(args.mark_explained).split(",") if s.strip()]
    data: Dict[str, Any] = {"schema": "dataflow_explained.v1", "explained": {}}
    if side.is_file():
        try:
            prev = json.loads(side.read_text())
            if isinstance(prev, dict) and isinstance(prev.get("explained"), dict):
                data = prev
                data.setdefault("schema", "dataflow_explained.v1")
        except Exception:
            pass  # corrupt -> rewrite fresh (advisory sidecar)
    finding = args.explained_finding or "unattributed"
    for pid in ids:
        entry = data["explained"].setdefault(pid, {"findings": []})
        if finding not in entry["findings"]:
            entry["findings"].append(finding)
    side.write_text(json.dumps(data, indent=2, sort_keys=True))
    result = {
        "status": "ok",
        "explained_sidecar": str(side),
        "newly_marked": ids,
        "total_explained": len(data["explained"]),
        "finding": finding,
    }
    print(json.dumps(result, indent=2) if args.json
          else f"marked {len(ids)} path id(s) explained -> {side} "
               f"(total {len(data['explained'])})")
    return 0


def _run_from_sink(args) -> int:
    """VICE-VERSA: targeted backward slice for ONE suspected sink (file:line).

    Resolves the workspace target(s), loads Slither offline, enumerates the
    value-moving sinks (same _enumerate_sinks the full run uses), keeps only the
    sink site(s) at the requested file:line, runs backward_df_all per matching
    sink, and prints the recovered DefUsePaths. R80 degrade on compile failure.
    """
    ws = Path(args.workspace).resolve()
    try:
        want_file, want_line = _parse_file_line(args.from_sink)
    except ValueError as e:
        print(json.dumps({"status": "error", "error": str(e)}) if args.json else f"ERROR: {e}")
        return 2
    want_base = os.path.basename(want_file)

    if args.target:
        targets = [Path(args.target).resolve()]
    else:
        targets = _resolve_targets(ws) or [ws]

    matched_recs: List[Dict[str, Any]] = []
    errors: List[str] = []
    loaded_any = False
    sinks_at_loc = 0
    idx = 0

    for tgt in targets:
        sl, err = load_slither_offline(tgt)
        if sl is None:
            errors.append(f"{tgt}: {err}")
            continue
        loaded_any = True
        try:
            eng = DataFlowEngine(sl, max_hops=args.max_hops)
            for sink_fn, sink_var, sink_ir, sink_node in eng._enumerate_sinks():
                sfile = _file_of(sink_node) or ""
                sline = _first_line(sink_node)
                if os.path.basename(sfile) != want_base:
                    continue
                if sline != want_line:
                    continue
                sinks_at_loc += 1
                for rec in eng.backward_df_all(sink_fn, sink_var, sink_ir, sink_node):
                    if rec is None:
                        continue
                    rec["path_id"] = f"fromsink-{idx:04d}"
                    matched_recs.append(rec)
                    idx += 1
        except Exception as e:
            errors.append(f"{tgt}: engine-error: {type(e).__name__}: {str(e)[:160]}")

    if not loaded_any:
        # R80 degrade contract: compile failure -> advisory degrade, exit 0.
        rec = dfs.degrade_record("solidity", "; ".join(errors)[:500] or "no compilable target")
        result = {
            "status": "degraded",
            "from_sink": args.from_sink,
            "records": [rec] if args.json else 1,
            "errors": errors,
        }
        print(json.dumps(result, indent=2, default=str) if args.json
              else f"DEGRADED (compile-fail) for sink {args.from_sink}: {errors}")
        return 0

    # optional: merge the targeted slices into the shared sidecar so a consumer
    # can re-read them (off by default; only when --out is given explicitly).
    if args.out:
        n = dfs.merge_write(str(Path(args.out)), matched_recs, "solidity") \
            if not args.no_merge else dfs.write_jsonl(str(Path(args.out)), matched_recs)

    result = {
        "status": "ok",
        "from_sink": args.from_sink,
        "sink_sites_at_location": sinks_at_loc,
        "backward_paths": len(matched_recs),
        "unguarded_paths": sum(1 for r in matched_recs if r.get("unguarded")),
        "records": matched_recs,
        "errors": errors,
    }
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"--from-sink {args.from_sink}: {sinks_at_loc} sink site(s), "
              f"{len(matched_recs)} backward DefUsePath(s) "
              f"(unguarded={result['unguarded_paths']})")
        for r in matched_recs[:20]:
            s = r.get("source", {})
            print(f"  {r['path_id']}: source {s.get('fn')} ({s.get('var')}) "
                  f"depth={r.get('call_depth')} unguarded={r.get('unguarded')} "
                  f"conf={r.get('confidence')}")
        if errors:
            print(f"  partial errors: {errors}")
    return 0


# ============================================================================
# UNIQUENESS-SINK class (A4 - namespace-uniqueness lane, advisory-first).
#
# Emits <ws>/.auditooor/namespace_uniqueness_hypotheses.jsonl, one needs-fuzz
# row per keyed-store uniqueness WRITE (map[k]= / .insert(k) / nonce_slot
# .replace(true) / nullifier.push) reachable with NO dominating already-present
# per-key guard (a check-and-set that consumes the sink's boolean return, or a
# require!(!contains)/!used[k] membership pre-check). Generalizes the
# signature-replay DSL beyond EVM ecrecover to Rust/Anchor/Go keyed stores; it
# does NOT re-derive that detector - a hit whose file:line the signature-replay
# sidecar already flags is marked covered_by="signature-replay" and dropped
# from the needs-fuzz count (A1 dedup boundary).
#
# NO-AUTO-CREDIT: every row carries verdict="needs-fuzz"; never flips a gate.
# The advisory axis is gated OFF by default: AUDITOOOR_NAMESPACE_UNIQUENESS_
# STRICT unset => advisory-only (recorded in accounting, never a hard gate).
#
# FP-GUARD: append-only/monotone stores whose uniqueness is STRUCTURAL are
# suppressed - the sink key is an internal monotone counter, or the sink
# statement IS itself an Anchor init-once account creation (load_init /
# #[account(init]). init-once is treated as a guard for the ACCOUNT-level sink
# ONLY (checked on the sink's own statement), NOT for a per-key sub-index write
# like a bit-slot .replace(true) on a persistent BitArray, whose uniqueness must
# come from the per-key check-and-set - so stripping that require! still fires.
# ============================================================================

UNIQ_OUT_REL = os.path.join(".auditooor", "namespace_uniqueness_hypotheses.jsonl")
UNIQ_ACC_REL = os.path.join(".auditooor", "namespace_uniqueness_accounting.json")
# The NAMED existing detector we dedup against (do NOT re-derive its signal).
_SIGREPLAY_SIDECARS = (
    "signature_replay_hypotheses.jsonl",
    "authority_blast_radius_hypotheses.jsonl",
)

# collection / receiver namespace hints - a uniqueness REGISTRY, not any store.
_UNIQ_NS = re.compile(
    r"nonce|nullifier|used|seen|spent|processed|consumed|commitment|replay|"
    r"claimed|slot|registered|executed|redeemed|dispatched", re.I)

# per-key uniqueness WRITE idioms: (kind, regex). group(1)=collection base,
# group(2) (when present)=the KEY expression written under (nullifier / index).
_UNIQ_SINKS = (
    ("bitset-replace", re.compile(r"(\w+)\s*\.replace\s*\(\s*(?:true|false)\s*\)")),
    ("set-insert",     re.compile(r"(\w+)\s*\.insert\s*\(\s*([^,\)]*)")),
    ("vec-push",       re.compile(r"(\w+)\s*\.push\s*\(\s*([^\)]*)")),
    ("indexed-store",  re.compile(r"(\w+)\s*\[([^\]]+)\]\s*=\s*(?:true|1\b)")),
)
_IDENT = re.compile(r"[A-Za-z_]\w*")
_RUST_KW = {"true", "false", "as", "usize", "u64", "u32", "u8", "self", "mut"}
# Anchor init-once account creation - a structural guard for account-level sinks.
_INIT_ONCE = re.compile(r"load_init\s*\(|init_if_needed|#\[account\(\s*init")
_GUARD_MACRO = re.compile(r"\b(require!|ensure!|assert!|require|assert|if)\b")
_MEMBERSHIP = re.compile(
    r"contains_key|contains|is_used|already|\bhas_|exists|used\s*\[", re.I)
_FN_DECL = re.compile(r"\bfn\s+(\w+)")


def _uniq_short(path, ws):
    try:
        return str(pathlib.PurePath(path).relative_to(ws))
    except Exception:
        return os.path.basename(str(path))


def _uniq_enclosing_body(lines, sink_idx):
    """(start, end, fn_name) of the fn body containing line sink_idx, by brace
    balance. Falls back to a small window when no `fn` header is found."""
    start = 0
    fn_name = "?"
    for i in range(sink_idx, -1, -1):
        m = _FN_DECL.search(lines[i])
        if m:
            start, fn_name = i, m.group(1)
            break
    depth, seen, end = 0, False, len(lines)
    for j in range(start, len(lines)):
        opens = lines[j].count("{")
        depth += opens - lines[j].count("}")
        if opens:
            seen = True
        if seen and depth <= 0 and j >= sink_idx:
            end = j
            break
    return start, end, fn_name


def _uniq_find_sinks(line):
    """Yield (kind, collection, match_start, key_tokens) for each uniqueness
    sink on a line whose collection base looks like a uniqueness namespace.
    key_tokens = identifiers of the KEY written under (the replayable index)."""
    out = []
    for kind, rx in _UNIQ_SINKS:
        for m in rx.finditer(line):
            coll = m.group(1)
            if not _UNIQ_NS.search(coll):
                continue
            key_expr = m.group(2) if rx.groups >= 2 else coll
            toks = [t for t in _IDENT.findall(key_expr or coll)
                    if t not in _RUST_KW]
            if not toks:
                toks = [coll]
            out.append((kind, coll, m.start(), toks))
    return out


def _uniq_fp_suppressed(lines, start, end, idx, stmt, key_tokens):
    """Structural-uniqueness FP-guard. init-once only when the SINK STATEMENT is
    itself an Anchor account creation; monotone only when one of the sink's own
    KEY tokens is a counter incremented in the body (structural, non-replayable
    key). A per-key sub-index write (e.g. a bit-slot .replace) whose key is an
    external param is NOT suppressed."""
    if _INIT_ONCE.search(stmt):
        return True, "anchor-init-once"
    for tok in key_tokens:
        inc = re.compile(
            r"\b" + re.escape(tok) + r"\b\s*(?:\+\+|\+=\s*1\b|=\s*\w+\s*\+\s*1\b)")
        for k in range(start, end):
            if inc.search(lines[k]):
                return True, "monotone-counter-key"
    return False, None


def _uniq_dominating_guard(lines, start, end, idx, stmt, pos):
    """A dominating per-key guard is PRESENT when: (a) the sink's boolean return
    is consumed by a negated guard macro on the same statement (check-and-set),
    or (b) the sink's assigned lhs is negated by a later guard, or (c) a
    membership pre-check on the collection precedes the sink in the body."""
    pre = stmt[:pos]
    if _GUARD_MACRO.search(pre) and "!" in pre:
        return True, "check-and-set-return"
    m = re.match(r"\s*(?:let\s+(?:mut\s+)?)?(\w+)\s*=", stmt)
    if m:
        lhs = m.group(1)
        neg = re.compile(
            r"(require!|ensure!|assert!|if)\b[^;{]*!\s*" + re.escape(lhs) + r"\b")
        for k in range(idx + 1, min(idx + 6, end)):
            if neg.search(lines[k]):
                return True, "check-and-set-lhs"
    for k in range(start, idx):
        line = lines[k]
        if _GUARD_MACRO.search(line) and "!" in line and _MEMBERSHIP.search(line):
            return True, "membership-precheck"
    return False, None


def _uniq_load_covered(ws):
    """Read the NAMED existing detector's emitted file:line set (do NOT
    re-derive it). Returns a set of "file:line" already covered."""
    covered = set()
    for name in _SIGREPLAY_SIDECARS:
        p = pathlib.Path(ws) / ".auditooor" / name
        if not p.is_file():
            continue
        try:
            for ln in p.read_text(errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                rec = json.loads(ln)
                fl = rec.get("file_line") or rec.get("loc")
                if not fl:
                    for s in (rec.get("sink_fns") or []):
                        if s.get("file_line"):
                            covered.add(s["file_line"])
                if fl:
                    covered.add(fl)
        except Exception:
            continue
    return covered


def uniqueness_scan(ws, targets=None,
                    exts=(".rs", ".sol", ".go", ".move")):
    """Scan for unguarded uniqueness-sink writes. Returns (hyps, accounting).
    Pure-syntactic + advisory; never flips a gate."""
    ws = pathlib.Path(ws)
    if targets:
        files = [pathlib.Path(t) for t in targets]
    else:
        files = []
        skip = {".git", "node_modules", "target", "lib", "out", "cache",
                "artifacts", "test", "tests", "mock", "mocks"}
        for root, dirs, fnames in os.walk(ws):
            dirs[:] = [d for d in dirs if d.lower() not in skip]
            for fn in fnames:
                if os.path.splitext(fn)[1] in exts:
                    files.append(pathlib.Path(root) / fn)
                    if len(files) >= 8000:
                        break
    covered = _uniq_load_covered(ws)
    acc = {
        "tool": "dataflow-slice::uniqueness-sinks",
        "workspace": str(ws),
        "sinks_detected": 0,
        "guarded_suppressed": 0,
        "fp_suppressed": 0,
        "covered_dedup": 0,
        "hypotheses": 0,
        "files_scanned": 0,
    }
    hyps = []
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        acc["files_scanned"] += 1
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            for (kind, coll, pos, key_tokens) in _uniq_find_sinks(line):
                acc["sinks_detected"] += 1
                start, end, fn_name = _uniq_enclosing_body(lines, idx)
                fp, fpr = _uniq_fp_suppressed(
                    lines, start, end, idx, line, key_tokens)
                if fp:
                    acc["fp_suppressed"] += 1
                    continue
                guarded, gr = _uniq_dominating_guard(
                    lines, start, end, idx, line, pos)
                if guarded:
                    acc["guarded_suppressed"] += 1
                    continue
                loc = f"{_uniq_short(f, ws)}:{idx + 1}"
                cov = loc in covered
                if cov:
                    acc["covered_dedup"] += 1
                hyps.append({
                    "flag_kind": "namespace-uniqueness-write-unguarded",
                    "file_line": loc,
                    "fn": fn_name,
                    "collection": coll,
                    "sink_kind": kind,
                    "snippet": line.strip()[:200],
                    "covered_by": "signature-replay" if cov else None,
                    "verdict": "needs-fuzz",
                    "attack_class": "namespace-uniqueness-replay",
                    "dedup_note": ("A4 keyed-store per-key uniqueness write with "
                                   "no dominating guard; generalizes signature-"
                                   "replay DSL beyond EVM ecrecover, does not "
                                   "re-derive its covered_by signal"),
                })
    acc["hypotheses"] = sum(1 for h in hyps if not h["covered_by"])
    return hyps, acc


def _run_uniqueness_sinks(args) -> int:
    ws = pathlib.Path(args.workspace).resolve()
    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    strict = bool(os.environ.get("AUDITOOOR_NAMESPACE_UNIQUENESS_STRICT"))
    targets = [args.target] if args.target else None
    hyps, acc = uniqueness_scan(ws, targets=targets)
    acc["strict_enabled"] = strict
    acc["advisory"] = True
    out_path = pathlib.Path(args.out) if args.out else (ws / UNIQ_OUT_REL)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fh:
        for h in hyps:
            fh.write(json.dumps(h) + "\n")
    with open(ws / UNIQ_ACC_REL, "w") as fh:
        json.dump(acc, fh, indent=2)
    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": hyps}, indent=2))
    else:
        print(f"[ok] A4 namespace-uniqueness: strict={strict} "
              f"detected={acc['sinks_detected']} "
              f"guarded_suppressed={acc['guarded_suppressed']} "
              f"fp_suppressed={acc['fp_suppressed']} "
              f"covered_dedup={acc['covered_dedup']} "
              f"needs-fuzz={acc['hypotheses']} -> {out_path}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Phase 1 Solidity data-flow slice")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--target", help="explicit .sol file or project dir (overrides ws scan)")
    ap.add_argument("--max-hops", type=int, default=MAX_HOPS_DEFAULT,
                    help="DEPRECATED soft default; depth is now effectively unbounded "
                         "(visited-set terminated). Use --max-hops to pin a cap, or "
                         "AUDITOOOR_DATAFLOW_MAX_HOPS to set the safety ceiling.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="override output jsonl path")
    ap.add_argument("--no-merge", action="store_true",
                    help="truncate the sidecar instead of language-scoped merge "
                         "(legacy single-language behavior; drops other arms' rows)")
    ap.add_argument("--no-fanout", action="store_true",
                    help="legacy single-chain backward walk (default fans out across all callers)")
    ap.add_argument("--mode", choices=["value-flow", "storage", "both"], default="value-flow",
                    help="value-flow=backward sink slices (default); storage=storage-mediated "
                         "cross-fn def-use; both=emit both into the same jsonl")
    ap.add_argument("--storage-var",
                    help="regex to filter storage-mediated paths to a single state var (e.g. operatorEthVUnits)")
    ap.add_argument("--closure-unguarded", action="store_true",
                    help="ADDITIVE/default-off (P0 D-connect): after building slices, consult "
                         "the inter-procedural guard closure (slither_predicates.has_guard_in_closure "
                         "+ resolve_concrete_impl) so `unguarded` reflects the WHOLE call graph "
                         "(a guard up the call graph / in a modifier counts), not just slice-local "
                         "hops. Only flips unguarded true->false; degrades honestly (R80). "
                         "Off => records byte-identical.")
    ap.add_argument("--emit-storage-value", action="store_true",
                    help="ADDITIVE/default-off (P1 sink-taxonomy): also emit `storage-value` sinks "
                         "for ECONOMIC storage WRITES (+=/-=/delete/[k]=) to balance/units/shares/"
                         "debt/earnings accounting state vars (e.g. SSV operatorEthVUnits). "
                         "Requires --mode storage|both. Off => no storage-value rows.")
    ap.add_argument("--mark-explained", metavar="PATH_IDS",
                    help="(loop-until-dry, cheap half of wiring 49d.3) record a comma-separated "
                         "list of DefUsePath ids as EXPLAINED in "
                         "<ws>/.auditooor/dataflow_explained_paths.json so a confirmed finding's "
                         "paths are skippable by the next hunt round's seeding. ADDITIVE sidecar; "
                         "no existing file is touched. (Consumer-side skip wiring in "
                         "dataflow-invariant-seed.py is a documented follow-up.)")
    ap.add_argument("--explained-finding", default="",
                    help="optional finding id/slug to attribute --mark-explained path ids to")
    ap.add_argument("--from-sink", metavar="FILE:LINE",
                    help="VICE-VERSA on-demand backward slice (wiring 49d): given a SUSPECTED "
                         "SINK as <file:line> (e.g. CoreLib.sol:46), run a TARGETED backward "
                         "slice for JUST that sink and print/merge the DefUsePaths reaching it. "
                         "Reuses the engine's backward_df_all traversal; no full-ws run needed. "
                         "Pairs with the enforcement gate so a finding/hacker-Q can PULL a slice "
                         "for one sink. R80: degrades honestly if Slither cannot load.")
    ap.add_argument("--uniqueness-sinks", action="store_true",
                    help="ADVISORY/default-off (A4 namespace-uniqueness lane): "
                         "SYNTACTIC scan for keyed-store per-key uniqueness WRITES "
                         "(map[k]= / .insert(k) / nonce_slot.replace(true) / "
                         "nullifier.push) with NO dominating per-key guard. Emits "
                         ".auditooor/namespace_uniqueness_hypotheses.jsonl "
                         "(verdict=needs-fuzz, NO-AUTO-CREDIT). Generalizes the "
                         "signature-replay DSL beyond EVM ecrecover; deduped vs it "
                         "via covered_by. Advisory axis gated off by "
                         "AUDITOOOR_NAMESPACE_UNIQUENESS_STRICT.")
    args = ap.parse_args()

    # ----------------------------------------------------------------------
    # A4 namespace-uniqueness lane (advisory-first). Distinct sink taxonomy;
    # dispatched before the Slither slice so it runs on Rust/Go/Move too.
    # ----------------------------------------------------------------------
    if args.uniqueness_sinks or os.environ.get("AUDITOOOR_NAMESPACE_UNIQUENESS"):
        return _run_uniqueness_sinks(args)

    # ----------------------------------------------------------------------
    # loop-until-dry: mark confirmed-finding paths EXPLAINED (cheap sidecar).
    # ----------------------------------------------------------------------
    if args.mark_explained:
        return _run_mark_explained(args)

    # ----------------------------------------------------------------------
    # VICE-VERSA on-demand backward slice (--from-sink). Targeted, single-sink.
    # ----------------------------------------------------------------------
    if args.from_sink:
        return _run_from_sink(args)

    # env aliases (cron/shell tools that cannot pass flags)
    if os.environ.get("AUDITOOOR_DATAFLOW_CLOSURE_UNGUARDED"):
        args.closure_unguarded = True
    if os.environ.get("AUDITOOOR_DATAFLOW_STORAGE_VALUE"):
        args.emit_storage_value = True

    ws = Path(args.workspace).resolve()
    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else (out_dir / "dataflow_paths.jsonl")

    # B-merge: default to language-scoped merge into the shared polyglot sidecar so a
    # Solidity run preserves Go/Rust/ZK rows. --no-merge OR an explicit single-file
    # --out keeps the legacy truncating write (byte-identical default-off behavior).
    _use_merge = not args.no_merge
    # A TARGETED run (--target <subdir>) re-covers only that subtree, so the merge
    # must replace ONLY this language's rows under that scope - NOT the whole
    # language (else a partial re-slice silently wipes the other in-scope projects'
    # rows from the shared sidecar). Full-ws run (no --target) -> replace-all-language.
    _merge_scope = str(Path(args.target).resolve()) if args.target else None

    def _emit_records(recs: List[Dict[str, Any]]) -> int:
        if _use_merge:
            return dfs.merge_write(str(out_path), recs, "solidity", scope_prefix=_merge_scope)
        return dfs.write_jsonl(str(out_path), recs)

    if args.target:
        targets = [Path(args.target).resolve()]
    else:
        targets = _resolve_targets(ws)
        if not targets:
            # fall back to compiling the ws dir directly (Tier 3)
            targets = [ws]

    all_records: List[Dict[str, Any]] = []
    errors: List[str] = []
    loaded_any = False
    closure_stats_total = {"consulted": 0, "flipped_to_guarded": 0, "degraded": 0, "kept_unguarded": 0}

    for tgt in targets:
        sl, err = load_slither_offline(tgt)
        if sl is None:
            errors.append(f"{tgt}: {err}")
            continue
        loaded_any = True
        try:
            eng = DataFlowEngine(sl, max_hops=args.max_hops)
            tgt_records: List[Dict[str, Any]] = []
            if args.mode in ("value-flow", "both"):
                tgt_records.extend(eng.emit_all(fanout=not args.no_fanout))
            if args.mode in ("storage", "both"):
                tgt_records.extend(eng.storage_mediated_paths(var_filter=args.storage_var))
                if args.emit_storage_value:
                    tgt_records.extend(eng.economic_storage_value_paths(var_filter=args.storage_var))
            # D-connect (P0): closure-correct `unguarded` over the WHOLE call graph.
            # Default-off: only when --closure-unguarded is set, so default output
            # is byte-identical. Degrades honestly per R80.
            if args.closure_unguarded:
                cstats = eng.apply_closure_unguarded(tgt_records)
                for k in closure_stats_total:
                    closure_stats_total[k] += cstats.get(k, 0)
            all_records.extend(tgt_records)
        except Exception as e:  # engine error on a loaded CU is still advisory-degrade for THIS target
            errors.append(f"{tgt}: engine-error: {type(e).__name__}: {str(e)[:160]}")

    if not loaded_any:
        # R80 degrade contract: compile failure -> degrade record, exit 0
        rec = dfs.degrade_record("solidity", "; ".join(errors)[:500] or "no compilable target")
        _emit_records([rec])
        result = {
            "status": "degraded",
            "out": str(out_path),
            "records": 1,
            "semantic_ssa_paths": 0,
            "errors": errors,
        }
        print(json.dumps(result, indent=2) if args.json else
              f"DEGRADED (compile-fail): {out_path}\n  errors: {errors}")
        return 0

    # validate every record before write (keep producers honest)
    valid = []
    invalid = 0
    for r in all_records:
        ok, verrs = dfs.validate(r)
        if ok:
            valid.append(r)
        else:
            invalid += 1
    n = _emit_records(valid)
    sem = sum(1 for r in valid if r.get("confidence") == "semantic-ssa" and not r.get("degraded"))
    syn = sum(1 for r in valid if r.get("confidence") == "syntactic" and not r.get("degraded"))
    truncated = sum(1 for r in valid if r.get("dataflow_truncated"))
    unguarded = sum(1 for r in valid if r.get("unguarded"))
    multi_hop = sum(1 for r in valid if r.get("call_depth", 0) >= 2)
    max_depth = max([r.get("call_depth", 0) for r in valid], default=0)
    storage_paths = [r for r in valid if r.get("mode") == "storage-mediated"]
    storage_unguarded = sum(1 for r in storage_paths if r.get("unguarded"))
    storage_value_paths = [r for r in valid if r.get("mode") == "storage-value"]
    storage_value_unguarded = sum(1 for r in storage_value_paths if r.get("unguarded"))

    result = {
        "status": "ok",
        "out": str(out_path),
        "targets_loaded": loaded_any,
        "records": n,
        "invalid_dropped": invalid,
        "semantic_ssa_paths": sem,
        "syntactic_paths": syn,
        "unguarded_paths": unguarded,
        "multi_hop_paths_ge2": multi_hop,
        "max_call_depth": max_depth,
        "storage_mediated_paths": len(storage_paths),
        "storage_mediated_unguarded": storage_unguarded,
        "storage_value_paths": len(storage_value_paths),
        "storage_value_unguarded": storage_value_unguarded,
        "dataflow_truncated_paths": truncated,
        "merged": _use_merge,
        "errors": errors,
    }
    if args.closure_unguarded:
        result["closure_unguarded"] = closure_stats_total
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"OK: wrote {n} DefUsePath records to {out_path}")
        print(f"  semantic-ssa={sem} syntactic={syn} unguarded={unguarded} "
              f"multi-hop(>=2)={multi_hop} max_depth={max_depth}")
        print(f"  storage-mediated={len(storage_paths)} (unguarded={storage_unguarded})")
        if args.emit_storage_value:
            print(f"  storage-value={len(storage_value_paths)} (unguarded={storage_value_unguarded})")
        if args.closure_unguarded:
            print(f"  closure-unguarded: consulted={closure_stats_total['consulted']} "
                  f"flipped_to_guarded={closure_stats_total['flipped_to_guarded']} "
                  f"degraded={closure_stats_total['degraded']}")
        if errors:
            print(f"  partial errors: {errors}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
