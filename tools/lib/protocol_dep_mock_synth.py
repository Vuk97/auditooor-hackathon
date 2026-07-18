"""protocol_dep_mock_synth -- PROTOCOL-COUPLED DEPENDENCY-MOCK SYNTHESIZER.

The +1 tail obl7 explicitly deferred. After solmate/OZ vendoring resolves the
ERC20/ERC4626 token/vault dependency surface, real V3-grade-PoC targets STILL
block because the converter (`tools/evm-0day-proof-pipeline.py`, owned by obl8)
cannot synthesize a deployable mock for an APPLICATION-LEVEL protocol dependency
interface -- a dep the target both IMPORTS and CALLS INTO that is neither an
ERC20 token nor an ERC4626 vault. Existing paths in the pipeline either:

  - `return None`  (block honestly: asset/arg type not synthesizable-castable),
    e.g. line ~2465, ~2917, ~4216 of evm-0day-proof-pipeline.py; or
  - cast a dummy `IFoo(address(0xBEEF))` whose `.code` is EMPTY so any call the
    REAL constructor / entrypoint makes on the dep REVERTS (line ~2914,
    `_synthesize_ctor_args_factory`: "factory only STORES it" -- which is FALSE
    for targets that call into the dep).

This module turns "target needs IFoo (and calls bar(), totalAssets(), ...)" into
a minimal CONCRETE, DEPLOYABLE Solidity mock implementing EXACTLY those members
ONLY when the method surface, return expressions, and negative-control behavior
are source-backed or test-provided. Unknown protocol state emits obligations
instead of fake defaults. Settable getters get storage + setters for values the
exploit must drive (a price, a cap, a totalAssets, an allow-flag).

DOCSTRING ANCHORS (NOT in logic -- the logic is 100% target-agnostic):
  - Pods options vault needs `IConfigurationManager.getParameter(bytes32)` plus
    a `configure(...)`/cap wiring -> a config-manager getter shape.
  - Maple pool needs `PoolManager.totalAssets()` and `.canCall(...)` -> a
    pool-manager getter + permission-gate shape.
  - Punk lending needs a Compound `cToken`/`comptroller` -> an oracle/registry
    lookup shape.
None of those literal names appear in any decision branch below; they are
illustrative only. The synthesizer keys on member SHAPES (return arity/type,
mutability, exploit-controllability heuristics), never on a protocol/target name.

Design mirrors the existing pipeline conventions so obl9 can wire with minimal
glue:
  - emits a no-arg-ctor contract named `_SynthProtoDep<idx>` (cf.
    `_SynthConstDep{idx}` from `_synth_const_dep_mock_contract`);
  - pragma is parameterizable (cf. `_derive_test_pragma` / `_pick_solc`): the
    caller passes the already-derived test pragma string; this module normalizes
    it to a caret form for a float-friendly mock (matching the `"^" +
    _pick_solc(pragma)` convention in `_synthesize_dep_mock`);
  - records the called-member list in the banner for honesty (cf. every existing
    synth-mock banner).

The module is STANDALONE (no import of the busy pipeline file) and OFFLINE-
TESTABLE: the synthesized SOURCE is asserted correct WITHOUT requiring forge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple, Union

__all__ = [
    "MemberSig",
    "MockSynthesisResult",
    "UnsupportedObligation",
    "analyze_protocol_dep_mock_synthesis",
    "parse_interface",
    "parse_called_members",
    "synthesize_protocol_dep_mock",
    "normalize_pragma",
]


@dataclass(frozen=True)
class UnsupportedObligation:
    """A concrete evidence gap that blocks protocol-dependency mock synthesis."""

    code: str
    member: str
    detail: str
    required_evidence: str

    def format(self) -> str:
        return (
            f"{self.code}: {self.member}: {self.detail} "
            f"required={self.required_evidence}"
        )


@dataclass(frozen=True)
class MockSynthesisResult:
    """Structured synthesis result.

    `source` is populated only when every required method, return value, and
    negative-control behavior has evidence. Otherwise `obligations` explains
    exactly what the caller must source-back or test-provide before retrying.
    """

    source: Optional[str]
    obligations: Tuple[UnsupportedObligation, ...]
    implemented_members: Tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.source is not None and not self.obligations

    def obligation_text(self) -> str:
        return "\n".join(o.format() for o in self.obligations)

# --------------------------------------------------------------------------- #
# Pragma normalization (mirror of `"^" + _pick_solc(pragma)` convention)
# --------------------------------------------------------------------------- #

_PRAGMA_VER_RE = re.compile(r"(\d+\.\d+\.\d+|\d+\.\d+)")


def normalize_pragma(pragma: Optional[str]) -> str:
    """Normalize a caller-supplied pragma to a float-friendly `^X.Y.Z` form.

    Accepts any of: `0.8.21`, `=0.8.21`, `^0.8.0`, `pragma solidity 0.8.21;`,
    `>=0.8.0 <0.9.0`, or None. Extracts the first concrete X.Y.Z (or X.Y) and
    returns it carated, so the synthesized mock floats up to the run's pinned
    solc rather than hard-pinning a version the repo's solc set may lack -- the
    SAME reasoning `_synthesize_dep_mock` applies via `"^" + _pick_solc(pragma)`.
    A caller that NEEDS an exact pin can pass it pre-carated; we never strip an
    existing caret. Falls back to `^0.8.0` when no version is parseable.
    """
    if not pragma:
        return "^0.8.0"
    s = pragma.strip()
    m = _PRAGMA_VER_RE.search(s)
    if not m:
        return "^0.8.0"
    ver = m.group(1)
    if "." not in ver.split(".", 1)[-1]:  # only X.Y -> leave as-is, caret it
        pass
    # if the original already carried a caret directly before the version, keep
    # caret semantics; otherwise apply caret (float-friendly mock default).
    return "^" + ver


# --------------------------------------------------------------------------- #
# Solidity type -> legacy default literal + zero-init storage type
# --------------------------------------------------------------------------- #

# A "settable" member is one whose return value the exploit may need to DRIVE:
# a getter-shaped view/pure member with a single non-trivial return (a price, a
# cap, a totalAssets, a per-actor balance, an allow-flag). For those we back the
# return with mutable storage + a setter. GENERIC: keyed on shape, not on name.

_UINT_RE = re.compile(r"^uint\d*$")
_INT_RE = re.compile(r"^int\d*$")
_BYTESN_RE = re.compile(r"^bytes([1-9]|[12]\d|3[0-2])$")


def _strip_data_location(typ: str) -> str:
    """Drop `memory`/`calldata`/`storage` qualifiers and collapse whitespace."""
    typ = re.sub(r"\b(memory|calldata|storage)\b", "", typ)
    return re.sub(r"\s+", " ", typ).strip()


def _default_value(typ: str) -> Optional[str]:
    """Return a default literal for legacy helper paths.

    The strict P3 synthesizer does not use this to invent protocol state for
    required return-bearing members; callers must provide `return_values`.
    """
    t = _strip_data_location(typ)
    if t in ("bool",):
        return "false"
    if t == "address" or t == "address payable":
        return "address(0)"
    if _UINT_RE.match(t) or _INT_RE.match(t):
        return "0"
    if t in ("bytes", "string"):
        # dynamic bytes/string default: empty. `""` is valid for both.
        return '""'
    if _BYTESN_RE.match(t):
        return f"{t}(0)"
    if t == "bytes32":
        return "bytes32(0)"
    # interface return type: an interface handle defaults to the zero-address
    # cast. We recognize ONLY the `I[A-Z]\w*` interface naming convention (the
    # SAME conservative rule the pipeline's `_synthesize_ctor_args_factory` uses
    # for interface ctor args). A bare capitalized identifier (`SomeStruct`,
    # a contract type, an enum type) is NOT defaultable here -> the caller blocks
    # honestly rather than emit a non-compiling `SomeStruct(address(0))`.
    if re.fullmatch(r"I[A-Z]\w*", t):
        return f"{t}(address(0))"
    return None


def _storage_type_for(typ: str) -> Optional[str]:
    """The state-variable storage type backing a settable member's return. For
    dynamic bytes/string we store the dynamic type; for value types we store the
    value type directly. Returns None when not settable-storable."""
    t = _strip_data_location(typ)
    if t in ("bool", "address", "address payable", "bytes", "string"):
        return "address" if t == "address payable" else t
    if _UINT_RE.match(t) or _INT_RE.match(t) or _BYTESN_RE.match(t) or t == "bytes32":
        return t
    if re.fullmatch(r"I[A-Z]\w*", t):
        # interface handle -> store as address, return as an interface cast.
        return "address"
    return None


# --------------------------------------------------------------------------- #
# MemberSig -- a normalized parsed external member the target calls on the dep
# --------------------------------------------------------------------------- #

class MemberSig:
    """A single external function member the target invokes on the dependency.

    Attributes:
        name      : function name (e.g. "totalAssets").
        params    : list of (type, name) tuples (names may be "").
        returns   : list of return type strings (data-location-stripped).
        mutability: "view" / "pure" / "payable" / "nonpayable".
    """

    __slots__ = ("name", "params", "returns", "mutability")

    def __init__(self, name: str, params: List[Tuple[str, str]],
                 returns: List[str], mutability: str):
        self.name = name
        self.params = params
        self.returns = [_strip_data_location(r) for r in returns]
        self.mutability = mutability

    # --- shape predicates (GENERIC; never key on the member name literal) ---

    def is_settable(self) -> bool:
        """A member whose return value the exploit may need to DRIVE: a read-only
        (view/pure) member with EXACTLY ONE storable return and ZERO params (a
        plain getter) OR exactly one param of value type (a per-key getter, e.g.
        a per-actor balance / per-token price). Multi-return or write members
        require explicit fixed return or void-behavior evidence."""
        if self.mutability not in ("view", "pure"):
            return False
        if len(self.returns) != 1:
            return False
        if _storage_type_for(self.returns[0]) is None:
            return False
        # zero-arg getter, or single value-type-keyed getter.
        if len(self.params) == 0:
            return True
        if len(self.params) == 1:
            ptyp = _strip_data_location(self.params[0][0])
            return _storage_type_for(ptyp) is not None
        return False

    def signature(self) -> str:
        """Canonical `name(type1,type2)` signature (param names dropped)."""
        ptypes = ",".join(_strip_data_location(t) for t, _ in self.params)
        return f"{self.name}({ptypes})"

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<MemberSig {self.signature()} returns {self.returns} {self.mutability}>"


# --------------------------------------------------------------------------- #
# Parsing: interface source OR called-member signature list
# --------------------------------------------------------------------------- #

_FN_DECL_RE = re.compile(
    r"function\s+(?P<name>\w+)\s*\("
    r"(?P<params>[^)]*)\)"
    r"(?P<mods>[^;{]*?)"
    r"(?:returns\s*\((?P<rets>[^)]*)\))?"
    r"\s*[;{]",
    re.S,
)


def _split_top_level(s: str) -> List[str]:
    """Split a parameter / return list on top-level commas (ignores commas inside
    nested parens, e.g. tuple types). Trims and drops empties."""
    out: List[str] = []
    depth = 0
    cur = []
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return [x for x in out if x]


def _parse_param(p: str) -> Tuple[str, str]:
    """Parse one parameter declaration into (type, name). Name may be ''. The
    type keeps array suffixes; data-location qualifiers are stripped downstream."""
    p = _strip_data_location(p).strip()
    if not p:
        return ("", "")
    toks = p.split()
    if len(toks) == 1:
        return (toks[0], "")
    # last token is the param name ONLY if it is a bare identifier and the rest
    # forms a type; otherwise it is all type (e.g. `uint256` alone handled above).
    name = toks[-1]
    if re.fullmatch(r"[A-Za-z_]\w*", name) and not _looks_like_type_keyword(name):
        return (" ".join(toks[:-1]), name)
    return (p, "")


def _looks_like_type_keyword(tok: str) -> bool:
    """True for tokens that are clearly part of a type, not a param name."""
    if _UINT_RE.match(tok) or _INT_RE.match(tok) or _BYTESN_RE.match(tok):
        return True
    return tok in ("address", "bool", "bytes", "string", "bytes32",
                   "payable")


def _parse_returns(rets: Optional[str]) -> List[str]:
    """Parse a returns-clause body into a list of return type strings (names in
    named returns are dropped)."""
    if not rets:
        return []
    out = []
    for r in _split_top_level(rets):
        typ, _name = _parse_param(r)
        out.append(typ or r)
    return out


def _mutability_of(mods: str) -> str:
    mods = mods or ""
    if re.search(r"\bview\b", mods):
        return "view"
    if re.search(r"\bpure\b", mods):
        return "pure"
    if re.search(r"\bpayable\b", mods):
        return "payable"
    return "nonpayable"


def parse_interface(interface_src: str) -> List[MemberSig]:
    """Parse `interface IFoo { function bar(...) external ...; ... }` (or a
    contract body) into a list of MemberSig. Robust to inheritance, comments,
    and multiple interfaces in one blob -- every `function ...` declaration is
    collected. Function bodies (`{...}`) are tolerated and ignored.
    """
    src = _strip_comments(interface_src or "")
    members: List[MemberSig] = []
    seen = set()
    for m in _FN_DECL_RE.finditer(src):
        name = m.group("name")
        params = [_parse_param(p) for p in _split_top_level(m.group("params") or "")]
        params = [(t, n) for (t, n) in params if t]
        rets = _parse_returns(m.group("rets"))
        mut = _mutability_of(m.group("mods"))
        sig = (name, tuple(t for t, _ in params))
        if sig in seen:
            continue
        seen.add(sig)
        members.append(MemberSig(name, params, rets, mut))
    return members


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def parse_called_members(called: List[str]) -> List[MemberSig]:
    """Parse a list of called-member signatures the target invokes on the dep.

    Each entry may be:
      - a full declaration fragment:
        "function totalAssets() external view returns (uint256)"
      - a compact form: "totalAssets() view returns (uint256)"
      - a bare signature with no returns: "canCall(bytes32,address)" (defaults to
        a single bool return when the name shape implies a predicate? NO -- we do
        NOT guess returns; a bare signature with no `returns` clause yields a
        member with empty returns, i.e. a void external call stub).
    """
    members: List[MemberSig] = []
    seen = set()
    for entry in called:
        e = entry.strip()
        if not e:
            continue
        if not e.startswith("function"):
            e = "function " + e
        if not re.search(r"[;{]\s*$", e):
            e = e + ";"
        parsed = parse_interface(e)
        for p in parsed:
            sig = (p.name, tuple(t for t, _ in p.params))
            if sig in seen:
                continue
            seen.add(sig)
            members.append(p)
    return members


# --------------------------------------------------------------------------- #
# Mock body emission
# --------------------------------------------------------------------------- #

def _setter_name(member_name: str) -> str:
    """Derive a setter name for a settable getter: `set<Capitalized>`. GENERIC --
    derived purely from the getter's own name, never a target literal."""
    return "set" + member_name[:1].upper() + member_name[1:]


def _emit_settable_member(m: MemberSig) -> Tuple[str, List[str]]:
    """Emit a settable getter: a storage var + setter + the getter returning the
    stored value. Returns (function_block, [storage_decl_lines])."""
    ret_typ = m.returns[0]
    store_typ = _storage_type_for(ret_typ)
    assert store_typ is not None  # guarded by is_settable()
    ret_decl = _strip_data_location(ret_typ)
    # Return data-location for dynamic types in an external view returns clause.
    ret_loc = " memory" if store_typ in ("bytes", "string") else ""
    interface_handle = bool(re.fullmatch(r"I[A-Z]\w*", ret_decl)) and store_typ == "address"

    if len(m.params) == 0:
        var = f"_v_{m.name}"
        storage = [f"    {store_typ} public {var};"]
        setter = _setter_name(m.name)
        set_loc = " memory" if store_typ in ("bytes", "string") else ""
        ret_expr = f"{ret_decl}({var})" if interface_handle else var
        block = (
            f"    function {setter}({store_typ}{set_loc} v) external {{ {var} = v; }}\n"
            f"    function {m.name}() external view returns ({ret_decl}{ret_loc}) "
            f"{{ return {ret_expr}; }}"
        )
        return block, storage
    # single value-type-keyed getter: mapping(key => stored).
    key_typ = _storage_type_for(_strip_data_location(m.params[0][0]))
    assert key_typ is not None
    var = f"_m_{m.name}"
    storage = [f"    mapping({key_typ} => {store_typ}) public {var};"]
    setter = _setter_name(m.name)
    set_loc = " memory" if store_typ in ("bytes", "string") else ""
    ret_expr = f"{ret_decl}({var}[k])" if interface_handle else f"{var}[k]"
    block = (
        f"    function {setter}({key_typ} k, {store_typ}{set_loc} v) external "
        f"{{ {var}[k] = v; }}\n"
        f"    function {m.name}({key_typ} k) external view returns ({ret_decl}{ret_loc}) "
        f"{{ return {ret_expr}; }}"
    )
    return block, storage


def _emit_stub_member(m: MemberSig) -> Optional[str]:
    """Emit a legacy stub helper.

    The strict synthesizer calls this only for evidenced void members. Returning
    members are emitted by `_emit_fixed_return_member` with caller-provided
    expressions.
    """
    # Param decls: give every param a positional name so the body compiles even
    # though it is unused; suppress unused-var warnings by omitting names is fine
    # for externals (Solidity allows nameless params).
    pdecls = []
    for typ, _name in m.params:
        t = _strip_data_location(typ)
        loc = " memory" if (t in ("bytes", "string") or t.endswith("[]")) else ""
        pdecls.append(f"{t}{loc}")
    params_src = ", ".join(pdecls)

    # mutability keyword: a view/pure stub must be declared view/pure to satisfy
    # the interface; but returning a default literal is allowed in a view fn.
    mut_kw = ""
    if m.mutability == "view":
        mut_kw = " view"
    elif m.mutability == "pure":
        mut_kw = " pure"
    elif m.mutability == "payable":
        mut_kw = " payable"

    if not m.returns:
        return (f"    function {m.name}({params_src}) external{mut_kw} {{}}")

    ret_types = []
    ret_locs = []
    defaults = []
    for r in m.returns:
        d = _default_value(r)
        if d is None:
            return None  # un-defaultable return -> block honestly.
        rt = _strip_data_location(r)
        ret_types.append(rt)
        ret_locs.append(" memory" if rt in ("bytes", "string") or rt.endswith("[]") else "")
        defaults.append(d)
    rets_decl = ", ".join(f"{t}{loc}" for t, loc in zip(ret_types, ret_locs))
    rets_val = ", ".join(defaults)
    return (
        f"    function {m.name}({params_src}) external{mut_kw} "
        f"returns ({rets_decl}) {{ return ({rets_val}); }}"
        if len(defaults) > 1 else
        f"    function {m.name}({params_src}) external{mut_kw} "
        f"returns ({rets_decl}) {{ return {rets_val}; }}"
    )


def _evidence_lookup(
    evidence: Optional[Dict[str, Union[str, Sequence[str]]]],
    m: MemberSig,
) -> Optional[Union[str, Sequence[str]]]:
    """Find member-scoped evidence by canonical signature, name, or wildcard."""
    if not evidence:
        return None
    for key in (m.signature(), m.name, "*"):
        if key in evidence:
            val = evidence[key]
            if isinstance(val, str):
                return val if val.strip() else None
            return val
    return None


def _has_negative_control_evidence(
    negative_control_behavior: Optional[Dict[str, str]],
    m: MemberSig,
) -> bool:
    val = _evidence_lookup(negative_control_behavior, m)
    return isinstance(val, str) and bool(val.strip())


def _return_values_for(
    return_values: Optional[Dict[str, Union[str, Sequence[str]]]],
    m: MemberSig,
) -> Optional[List[str]]:
    val = _evidence_lookup(return_values, m)
    if val is None:
        return None
    if isinstance(val, str):
        return [val.strip()]
    return [str(v).strip() for v in val if str(v).strip()]


def _emit_fixed_return_member(m: MemberSig, values: Sequence[str]) -> str:
    """Emit a member with caller-provided Solidity return expressions."""
    pdecls = []
    for typ, _name in m.params:
        t = _strip_data_location(typ)
        loc = " memory" if (t in ("bytes", "string") or t.endswith("[]")) else ""
        pdecls.append(f"{t}{loc}")
    params_src = ", ".join(pdecls)

    mut_kw = ""
    if m.mutability == "view":
        mut_kw = " view"
    elif m.mutability == "pure":
        mut_kw = " pure"
    elif m.mutability == "payable":
        mut_kw = " payable"

    ret_types = []
    ret_locs = []
    for r in m.returns:
        rt = _strip_data_location(r)
        ret_types.append(rt)
        ret_locs.append(" memory" if rt in ("bytes", "string") or rt.endswith("[]") else "")
    rets_decl = ", ".join(f"{t}{loc}" for t, loc in zip(ret_types, ret_locs))
    rets_val = ", ".join(values)
    return (
        f"    function {m.name}({params_src}) external{mut_kw} "
        f"returns ({rets_decl}) {{ return ({rets_val}); }}"
        if len(values) > 1 else
        f"    function {m.name}({params_src}) external{mut_kw} "
        f"returns ({rets_decl}) {{ return {rets_val}; }}"
    )


def _resolve_required_members(
    interface_src_or_signature: Union[str, List[str]],
    called_members: Optional[List[str]],
) -> Tuple[List[MemberSig], List[UnsupportedObligation]]:
    """Resolve the exact required method set without falling back to extras."""
    obligations: List[UnsupportedObligation] = []
    if isinstance(interface_src_or_signature, list):
        return parse_called_members(interface_src_or_signature), obligations

    all_members = parse_interface(interface_src_or_signature)
    if not called_members:
        return all_members, obligations

    called = parse_called_members(called_members)
    by_exact = {
        (m.name, tuple(t for t, _ in m.params)): m
        for m in all_members
    }
    resolved: List[MemberSig] = []
    seen = set()
    for cm in called:
        key = (cm.name, tuple(t for t, _ in cm.params))
        found = by_exact.get(key)
        if not found:
            obligations.append(UnsupportedObligation(
                code="missing-required-method-source",
                member=cm.signature(),
                detail="called member is not declared in the provided interface source",
                required_evidence=(
                    "cite the dependency interface source containing this exact "
                    "method or pass a test-provided signature list without "
                    "conflicting interface source"
                ),
            ))
            continue
        if key not in seen:
            resolved.append(found)
            seen.add(key)
    return resolved, obligations


def _obligation(
    code: str,
    member: MemberSig,
    detail: str,
    required_evidence: str,
) -> UnsupportedObligation:
    return UnsupportedObligation(
        code=code,
        member=member.signature(),
        detail=detail,
        required_evidence=required_evidence,
    )


def analyze_protocol_dep_mock_synthesis(
    interface_src_or_signature: Union[str, List[str]],
    called_members: Optional[List[str]] = None,
    *,
    idx: int = 0,
    pragma: Optional[str] = None,
    contract_name: Optional[str] = None,
    return_values: Optional[Dict[str, Union[str, Sequence[str]]]] = None,
    negative_control_behavior: Optional[Dict[str, str]] = None,
) -> MockSynthesisResult:
    """Analyze and, only when fully evidenced, synthesize a protocol dep mock.

    This is the strict P3 path. It refuses to invent protocol state:

      - required methods must resolve from the provided interface source, or be
        provided as the direct signature-list input;
      - non-settable return stubs must have caller-provided Solidity return
        expressions in `return_values`;
      - every synthesized member must have source-backed or test-provided
        negative-control behavior in `negative_control_behavior`.

    When any condition is missing, `source` is None and `obligations` lists the
    exact evidence needed.

    Args:
        interface_src_or_signature:
            EITHER the dependency interface source
            (`interface IFoo { function bar(...) external ...; ... }`)
            OR a list of called-member signature strings the target invokes.
        called_members:
            Optional list of member signatures the target ACTUALLY calls. When
            provided AND the first arg is interface source, the mock implements
            ONLY those members (the minimal-surface case the converter needs --
            implement exactly what the target invokes). When omitted and the
            first arg is interface source, ALL interface members are implemented.
        idx: disambiguating index for the mock contract name (cf. `_SynthConstDep{idx}`).
        pragma: caller-derived pragma string (cf. `_derive_test_pragma`); normalized
            to a float-friendly caret form. Defaults to `^0.8.0`.
        contract_name: override the synthesized contract name (default
            `_SynthProtoDep<idx>`).
        return_values:
            Test-provided Solidity return expressions for non-settable members.
            Keys may be canonical signatures, member names, or `*`.
        negative_control_behavior:
            Evidence strings explaining how each member behaves in the negative
            control. Keys may be canonical signatures, member names, or `*`.

    Returns:
        A MockSynthesisResult. A populated source means there are no obligations.
    """
    members, obligations = _resolve_required_members(
        interface_src_or_signature, called_members)

    if not members:
        obligations.append(UnsupportedObligation(
            code="missing-required-methods",
            member="(dependency)",
            detail="no dependency methods were parsed or provided",
            required_evidence=(
                "provide an interface source block or a called-member signature "
                "list extracted from the real target call sites"
            ),
        ))
        return MockSynthesisResult(None, tuple(obligations), tuple())

    name = contract_name or f"_SynthProtoDep{idx}"
    pv = normalize_pragma(pragma)

    storage_lines: List[str] = []
    member_blocks: List[str] = []
    member_summary: List[str] = []
    implemented: List[str] = []

    for m in members:
        for typ, _name in m.params:
            t = _strip_data_location(typ)
            base = t[:-2] if t.endswith("[]") else t
            if base not in ("bool", "address", "address payable", "bytes", "string", "bytes32") \
                    and not _UINT_RE.match(base) and not _INT_RE.match(base) \
                    and not _BYTESN_RE.match(base):
                obligations.append(_obligation(
                    "unsupported-param-type",
                    m,
                    f"parameter type {t!r} is not self-contained in the mock source",
                    "provide a real dependency, embed the required type definitions, "
                    "or narrow the called-member list",
                ))

        if not _has_negative_control_evidence(negative_control_behavior, m):
            obligations.append(_obligation(
                "missing-negative-control-behavior",
                m,
                "member behavior in the negative control is not evidenced",
                "provide source-backed or test-provided negative-control behavior "
                "for this member",
            ))

        if m.is_settable():
            block, storage = _emit_settable_member(m)
            storage_lines.extend(storage)
            member_blocks.append(block)
            member_summary.append(f"{m.signature()}*")  # * = settable
            implemented.append(m.signature())
            continue

        if not m.returns:
            stub = _emit_stub_member(m)
            assert stub is not None
            member_blocks.append(stub)
            member_summary.append(f"{m.signature()}~")  # ~ = void behavior evidenced
            implemented.append(m.signature())
            continue

        values = _return_values_for(return_values, m)
        if values is None:
            obligations.append(_obligation(
                "missing-return-values",
                m,
                "non-settable return member has no evidenced return expressions",
                "provide test return_values for this signature or switch to a real "
                "dependency",
            ))
            continue
        if len(values) != len(m.returns):
            obligations.append(_obligation(
                "return-value-arity-mismatch",
                m,
                f"expected {len(m.returns)} return expressions, got {len(values)}",
                "provide one Solidity expression per return value",
            ))
            continue

        unsupported_ret = [
            _strip_data_location(r) for r in m.returns
            if _storage_type_for(r) is None
        ]
        if unsupported_ret:
            obligations.append(_obligation(
                "unsupported-return-type",
                m,
                "return type is not self-contained in the mock source: "
                + ", ".join(unsupported_ret),
                "provide a real dependency or embed a hand-written mock with the "
                "required type definitions",
            ))
            continue

        member_blocks.append(_emit_fixed_return_member(m, values))
        member_summary.append(f"{m.signature()}=")  # = fixed return expressions
        implemented.append(m.signature())

    if obligations:
        return MockSynthesisResult(None, tuple(obligations), tuple(implemented))

    summary = ", ".join(member_summary) if member_summary else "(none)"
    banner = (
        f"// AUTO-SYNTHESIZED protocol-coupled dependency mock (obl7 +1 tail).\n"
        f"// Backs an APPLICATION-LEVEL dep the target imports AND calls into\n"
        f"// (neither ERC20 token nor ERC4626 vault), so the REAL constructor /\n"
        f"// entrypoint's external calls on the dep succeed and the V3-grade PoC\n"
        f"// drives the real vulnerable path. Members implemented ONLY when\n"
        f"// required method, return value, and negative-control evidence is present\n"
        f"// (`*`=settable, `=`=test-provided fixed return, `~`=void behavior):\n"
        f"//   {summary}\n"
        f"// Unknown selectors revert; no fallback returns fake protocol state.\n"
        f"// NOT hand-placed, NOT target-named: synthesized from usage shape only."
    )
    body_lines = [
        f"// SPDX-License-Identifier: MIT",
        f"pragma solidity {pv};",
        "",
        banner,
        f"contract {name} {{",
    ]
    if storage_lines:
        body_lines.extend(storage_lines)
        body_lines.append("")
    body_lines.extend(member_blocks)
    body_lines.append("    fallback() external payable { revert(\"UNSUPPORTED_PROTOCOL_DEP_CALL\"); }")
    body_lines.append("    receive() external payable { revert(\"UNSUPPORTED_PROTOCOL_DEP_RECEIVE\"); }")
    body_lines.append("}")
    return MockSynthesisResult("\n".join(body_lines), tuple(), tuple(implemented))


def synthesize_protocol_dep_mock(
    interface_src_or_signature: Union[str, List[str]],
    called_members: Optional[List[str]] = None,
    *,
    idx: int = 0,
    pragma: Optional[str] = None,
    contract_name: Optional[str] = None,
    return_values: Optional[Dict[str, Union[str, Sequence[str]]]] = None,
    negative_control_behavior: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Return synthesized source, or None when obligations block synthesis.

    Call `analyze_protocol_dep_mock_synthesis` when the caller needs the explicit
    unsupported obligations for user-facing diagnostics.
    """
    return analyze_protocol_dep_mock_synthesis(
        interface_src_or_signature,
        called_members,
        idx=idx,
        pragma=pragma,
        contract_name=contract_name,
        return_values=return_values,
        negative_control_behavior=negative_control_behavior,
    ).source
