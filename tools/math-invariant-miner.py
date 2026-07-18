#!/usr/bin/env python3
"""math-invariant-miner.py — V4 P2 math-spec extractor (Tier B / advisory).

Walks Solidity sources in a workspace and emits a structured math-spec artifact:

    <output-dir>/MATH_SPEC.md      # human-readable summary
    <output-dir>/math_spec.json    # machine-readable JSON

The artifact lists, per contract:
  - state_variables (with inferred role/unit/decimals when obvious),
  - conservation_laws (heuristic: totalSupply ↔ sum(balanceOf), totalAssets ↔ sum,
    totalDebt ↔ sum, etc.),
  - monotonicity expectations (function-name + variable mutation patterns),
  - rounding direction hints (Math.mulDiv, /, OZ floor/ceil helpers),
  - regime_boundaries (require()/if () with constant comparisons),
  - user_inputs (function parameters of public/external functions),
  - oracle_config_dependencies (state vars matching oracle / config / admin shapes),
  - candidates (top-N invariants worth fuzzing),
  - violations: heuristic flag where a function only mutates one side of a
    conservation law (e.g. mint() that increments totalSupply but not
    balanceOf).

Discipline:
  - Stdlib only. Regex-based extraction. No solc / slither dependency.
  - Tier B: this is advisory. The artifact never asserts a finding —
    it lists candidate invariants for downstream fuzzers / human review.
  - Output is deterministic given the same input set (sorted contracts,
    sorted variables, stable JSON keys).

Schema: see MATH_SPEC_JSON_SCHEMA_VERSION below.

Usage:
    python3 tools/math-invariant-miner.py \\
        --workspace <ws> \\
        --output-dir <ws>/math_invariants \\
        [--contracts 'src/**/*.sol' ...]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

MATH_SPEC_JSON_SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Regex toolkit — kept conservative; we explicitly do NOT try to parse
# arbitrary Solidity. The miner emits *candidates*; downstream tooling
# (Foundry invariants, halmos) actually proves them.
# ---------------------------------------------------------------------------

# Strip line comments first, then block comments. Order matters because /*...*/
# can span newlines.
_RE_LINE_COMMENT = re.compile(r"//[^\n]*")
_RE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

_RE_CONTRACT = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+(\w+)\b[^{]*\{",
)

_RE_STATE_VAR = re.compile(
    r"^\s*(?P<type>(?:mapping\s*\([^)]*=>\s*[^)]+\)|"
    r"(?:u?int(?:\d+)?|address|bool|bytes(?:\d+)?|string)\s*(?:\[\])?))"
    r"\s+(?P<vis>public|external|internal|private)?\s*"
    r"(?P<imm>immutable|constant)?\s*"
    r"(?P<name>\w+)\s*(?:=\s*[^;]+)?;",
    re.MULTILINE,
)

_RE_FUNCTION = re.compile(
    r"\bfunction\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*"
    r"(?P<mods>[^{;]*)\s*(?P<body>\{)",
)

_RE_REQUIRE = re.compile(
    r"\brequire\s*\(\s*(?P<expr>[^,)]+)(?:,\s*[^)]+)?\)\s*;",
)

_RE_ROUND_FLOOR_HINT = re.compile(r"\bMath\.(?:mulDiv|floorDiv)\b|/\s*\w+")
_RE_ROUND_CEIL_HINT = re.compile(
    r"\bMath\.(?:mulDivCeil|ceilDiv)\b|\bMathUpgradeable\.mulDiv.*Rounding\.Up",
)

# Accounting heuristics: any state var whose name matches these substrings
# is treated as participating in conservation laws. Lower-case prefix match.
_ACCOUNTING_KEYWORDS = (
    "totalsupply",
    "totalassets",
    "totaldebt",
    "totalborrows",
    "totalshares",
    "totalcollateral",
    "totalliabilities",
    "totalreserves",
    "totalstaked",
    "totaldeposits",
    "totalidle",
    "balanceof",
    "shares",
    "debt",
    "deposits",
    "borrowed",
    "balance",
    "reserves",
)

# Oracle / config heuristics.
_ORACLE_KEYWORDS = ("oracle", "feed", "pricefeed", "chainlink", "rate")
_CONFIG_KEYWORDS = ("admin", "owner", "governance", "guardian", "factor", "ratio", "threshold")

# Monotonicity heuristics: function name -> direction expectation.
_MONOTONIC_HINTS = {
    "mint": ("totalSupply", "non-decreasing"),
    "burn": ("totalSupply", "non-increasing"),
    "deposit": ("totalAssets", "non-decreasing"),
    "withdraw": ("totalAssets", "non-increasing"),
    "redeem": ("totalAssets", "non-increasing"),
    "borrow": ("totalDebt", "non-decreasing"),
    "repay": ("totalDebt", "non-increasing"),
    "stake": ("totalStaked", "non-decreasing"),
    "unstake": ("totalStaked", "non-increasing"),
}


def _strip_comments(src: str) -> str:
    src = _RE_BLOCK_COMMENT.sub("", src)
    src = _RE_LINE_COMMENT.sub("", src)
    return src


def _split_contracts(src: str) -> List[Tuple[str, str]]:
    """Return [(contract_name, body_source)] using brace-balanced extraction.

    `body_source` is the text *inside* the contract's outermost { ... }.
    Robust enough for fixtures and most real contracts; not a full parser.
    """
    stripped = _strip_comments(src)
    out: List[Tuple[str, str]] = []
    pos = 0
    while True:
        m = _RE_CONTRACT.search(stripped, pos)
        if not m:
            break
        name = m.group(1)
        # Walk braces from the matching '{' (which is at m.end()-1).
        depth = 0
        body_start = m.end()  # one past the opening brace
        i = m.end() - 1
        while i < len(stripped):
            c = stripped[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append((name, stripped[body_start:i]))
                    pos = i + 1
                    break
            i += 1
        else:
            # Unbalanced — bail to avoid infinite loop.
            break
    return out


def _infer_role(name: str) -> Optional[str]:
    n = name.lower()
    for kw in _ACCOUNTING_KEYWORDS:
        if kw in n:
            return "accounting"
    for kw in _ORACLE_KEYWORDS:
        if kw in n:
            return "oracle"
    for kw in _CONFIG_KEYWORDS:
        if kw in n:
            return "config"
    return None


def _infer_unit_decimals(type_str: str, name: str) -> Tuple[Optional[str], Optional[int]]:
    n = name.lower()
    t = type_str.replace(" ", "")
    # Heuristic: balance / supply / asset variables are wei-denominated 18d.
    if any(kw in n for kw in ("supply", "asset", "balance", "shares", "debt", "deposits", "borrowed")):
        if "uint" in t:
            return ("wei", 18)
    if "rate" in n or "ratio" in n or "factor" in n:
        return ("bps_or_ray", None)
    return (None, None)


def _extract_state_vars(body: str) -> List[Dict]:
    out: List[Dict] = []
    seen: set[str] = set()
    for m in _RE_STATE_VAR.finditer(body):
        # Skip anything that looks like a local var declaration inside a
        # function — state vars sit at contract-body scope, but the regex
        # is line-anchored so we must reject names that appear inside
        # `function { ... }` blocks. Cheap filter: check brace depth at
        # match position.
        idx = m.start()
        depth = body.count("{", 0, idx) - body.count("}", 0, idx)
        if depth != 0:
            continue
        name = m.group("name")
        if name in seen:
            continue
        seen.add(name)
        type_str = m.group("type").strip()
        unit, decimals = _infer_unit_decimals(type_str, name)
        entry: Dict = {
            "name": name,
            "type": type_str,
            "visibility": (m.group("vis") or "internal"),
            "mutability": (m.group("imm") or "mutable"),
            "role": _infer_role(name),
        }
        if unit is not None:
            entry["unit"] = unit
        if decimals is not None:
            entry["decimals"] = decimals
        out.append(entry)
    out.sort(key=lambda e: e["name"])
    return out


def _extract_functions(body: str) -> List[Dict]:
    """Return [{name, params, modifiers, body_text, mutates}] for each function."""
    out: List[Dict] = []
    for m in _RE_FUNCTION.finditer(body):
        # Walk balanced braces from the body opener.
        start = m.end() - 1  # at '{'
        depth = 0
        i = start
        while i < len(body):
            c = body[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    fbody = body[start + 1 : i]
                    mods_raw = (m.group("mods") or "").strip()
                    out.append(
                        {
                            "name": m.group("name"),
                            "params": (m.group("params") or "").strip(),
                            "modifiers": mods_raw,
                            "body": fbody,
                            "mutates": _vars_mutated(fbody),
                        }
                    )
                    break
            i += 1
    out.sort(key=lambda f: f["name"])
    return out


def _vars_mutated(fbody: str) -> List[str]:
    """Variable names that appear on the LHS of an assignment / compound op.

    Matches `name = ...`, `name += ...`, `name -= ...`, `mapping[k] = ...`.
    """
    pattern = re.compile(
        r"\b(\w+)\s*(?:\[[^\]]+\])?\s*(?:=(?!=)|\+=|-=|\*=|/=)",
    )
    seen = []
    for m in pattern.finditer(fbody):
        v = m.group(1)
        if v in ("require", "assert", "revert", "if", "for", "while", "return", "emit"):
            continue
        if v not in seen:
            seen.append(v)
    return seen


def _extract_user_inputs(functions: List[Dict]) -> List[str]:
    out: set[str] = set()
    for fn in functions:
        if "external" not in fn["modifiers"] and "public" not in fn["modifiers"]:
            continue
        for p in fn["params"].split(","):
            p = p.strip()
            if not p:
                continue
            # last whitespace-separated token is the param name
            tokens = p.split()
            if len(tokens) >= 2:
                out.add(tokens[-1])
    return sorted(out)


def _conservation_candidates(
    state_vars: List[Dict], functions: List[Dict]
) -> Tuple[List[Dict], List[Dict]]:
    """Emit conservation-law candidates and one-sided-mutation violations.

    A "law" pairs a scalar accounting variable (e.g. totalSupply) with a
    mapping variable (e.g. balanceOf) when both are present. Any function
    that mutates exactly one side of the pair is flagged as a candidate
    violation (heuristic only; downstream fuzzers confirm).
    """
    scalars: List[str] = []
    mappings: List[str] = []
    for v in state_vars:
        if v.get("role") != "accounting":
            continue
        if v["type"].startswith("mapping"):
            mappings.append(v["name"])
        else:
            scalars.append(v["name"])

    laws: List[Dict] = []
    violations: List[Dict] = []
    cl_id = 1
    for s in scalars:
        for mp in mappings:
            laws.append(
                {
                    "id": f"CL-{cl_id:03d}",
                    "name": f"conservation-of-{s.lower()}",
                    "formula": f"{s} == sum({mp})",
                    "severity": "HIGH",
                    "tests": [],
                }
            )
            cl_id += 1
            for fn in functions:
                muts = set(fn["mutates"])
                # Conservative one-sided flag: ONLY when the scalar moves and
                # the mapping is untouched. The reverse case (mapping moves
                # but scalar does not) is the legal `transfer` shape — money
                # changes hands inside the mapping while the scalar total is
                # invariant, so we do NOT flag it.
                if s in muts and mp not in muts:
                    violations.append(
                        {
                            "function": fn["name"],
                            "mutates": sorted(muts),
                            "law": f"{s} == sum({mp})",
                            "kind": "scalar-moved-mapping-untouched",
                            "severity": "HIGH",
                        }
                    )
    return laws, violations


def _monotonicity_candidates(functions: List[Dict], state_vars: List[Dict]) -> List[Dict]:
    var_names = {v["name"] for v in state_vars}
    out: List[Dict] = []
    for fn in functions:
        for hint_name, (var, direction) in _MONOTONIC_HINTS.items():
            if fn["name"].lower() == hint_name and var in var_names:
                out.append(
                    {
                        "variable": var,
                        "direction": direction,
                        "trigger": f"{fn['name']}()",
                        "exceptions": [],
                    }
                )
    return out


def _rounding_candidates(functions: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for fn in functions:
        body = fn["body"]
        floor = bool(_RE_ROUND_FLOOR_HINT.search(body))
        ceil = bool(_RE_ROUND_CEIL_HINT.search(body))
        if floor or ceil:
            out.append(
                {
                    "function": fn["name"],
                    "direction": "ceil" if ceil else "floor",
                    "impact": (
                        "ceil-rounded — depositor may overpay"
                        if ceil
                        else "floor-rounded — depositor may receive fewer shares"
                    ),
                }
            )
    return out


def _regime_boundaries(functions: List[Dict]) -> List[Dict]:
    """Pull simple `require(x op constant)` boundaries into a list."""
    out: List[Dict] = []
    seen: set[str] = set()
    boundary_re = re.compile(r"(\w+)\s*(<=|>=|<|>|==|!=)\s*(\d+|0x[0-9a-fA-F]+)")
    for fn in functions:
        for m in _RE_REQUIRE.finditer(fn["body"]):
            for bm in boundary_re.finditer(m.group("expr")):
                key = f"{bm.group(1)}{bm.group(2)}{bm.group(3)}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "variable": bm.group(1),
                        "operator": bm.group(2),
                        "threshold": bm.group(3),
                        "context": fn["name"],
                    }
                )
    return out


def _oracle_config_deps(state_vars: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for v in state_vars:
        if v.get("role") in ("oracle", "config"):
            out.append(
                {
                    "config": v["name"],
                    "kind": v["role"],
                    "type": v["type"],
                }
            )
    return out


def _candidates(
    laws: List[Dict],
    monotonicity: List[Dict],
    rounding: List[Dict],
) -> List[Dict]:
    out: List[Dict] = []
    for law in laws:
        out.append(
            {
                "name": law["name"],
                "severity": law["severity"],
                "body": f"assert({law['formula']});",
                "source": "conservation",
            }
        )
    for mono in monotonicity:
        out.append(
            {
                "name": f"{mono['variable']}-{mono['direction']}-on-{mono['trigger']}",
                "severity": "MEDIUM",
                "body": (
                    f"assert({mono['variable']}_after >= {mono['variable']}_before);"
                    if mono["direction"] == "non-decreasing"
                    else f"assert({mono['variable']}_after <= {mono['variable']}_before);"
                ),
                "source": "monotonicity",
            }
        )
    for r in rounding:
        out.append(
            {
                "name": f"{r['function']}-rounding-{r['direction']}",
                "severity": "LOW",
                "body": f"// {r['function']} rounds {r['direction']}; verify protocol-favoring direction",
                "source": "rounding",
            }
        )
    return out


# ---------------------------------------------------------------------------
# Top-level analysis & emission
# ---------------------------------------------------------------------------


def analyze_contract(name: str, body: str) -> Dict:
    state_vars = _extract_state_vars(body)
    functions = _extract_functions(body)
    laws, violations = _conservation_candidates(state_vars, functions)
    mono = _monotonicity_candidates(functions, state_vars)
    rounding = _rounding_candidates(functions)
    regimes = _regime_boundaries(functions)
    inputs = _extract_user_inputs(functions)
    oracle_deps = _oracle_config_deps(state_vars)
    cands = _candidates(laws, mono, rounding)

    # Sanitise function records for JSON (drop raw body text).
    fn_summaries = [
        {
            "name": f["name"],
            "params": f["params"],
            "modifiers": f["modifiers"],
            "mutates": f["mutates"],
        }
        for f in functions
    ]

    return {
        "state_variables": state_vars,
        "functions": fn_summaries,
        "conservation_laws": laws,
        "monotonicity": mono,
        "rounding": rounding,
        "regime_boundaries": regimes,
        "user_inputs": inputs,
        "oracle_config_dependencies": oracle_deps,
        "candidates": cands,
        "violations": violations,
    }


def discover_contracts(workspace: Path, globs: Iterable[str]) -> List[Path]:
    out: List[Path] = []
    seen: set[Path] = set()
    for g in globs:
        for p in workspace.glob(g):
            if p.is_file() and p.suffix == ".sol":
                rp = p.resolve()
                if rp not in seen:
                    seen.add(rp)
                    out.append(p)
    out.sort()
    return out


def render_markdown(spec: Dict) -> str:
    out: List[str] = []
    out.append(f"# Math Invariant Specification — {spec['workspace']}")
    out.append("")
    out.append(f"- generated: `{spec['generated_at']}`")
    out.append(f"- schema: `{spec['schema_version']}`")
    out.append(f"- tier: B (advisory)")
    out.append("")
    out.append("## Contracts Analyzed")
    out.append("")
    for cname in sorted(spec["contracts"].keys()):
        out.append(f"- `{cname}`")
    out.append("")

    for cname in sorted(spec["contracts"].keys()):
        c = spec["contracts"][cname]
        out.append(f"## Contract: `{cname}`")
        out.append("")

        # State variables
        out.append("### State Variables & Accounting Units")
        out.append("")
        if c["state_variables"]:
            out.append("| Name | Type | Visibility | Role | Unit | Decimals |")
            out.append("|------|------|------------|------|------|----------|")
            for v in c["state_variables"]:
                out.append(
                    "| {n} | `{t}` | {v} | {r} | {u} | {d} |".format(
                        n=v["name"],
                        t=v["type"],
                        v=v.get("visibility", ""),
                        r=v.get("role") or "—",
                        u=v.get("unit") or "—",
                        d=v.get("decimals") if v.get("decimals") is not None else "—",
                    )
                )
        else:
            out.append("_(none detected)_")
        out.append("")

        # Conservation laws
        out.append("### Conservation Laws")
        out.append("")
        if c["conservation_laws"]:
            for law in c["conservation_laws"]:
                out.append(f"- **{law['id']}** `{law['name']}` — `{law['formula']}` (severity: {law['severity']})")
        else:
            out.append("_(none detected)_")
        out.append("")

        # Violations
        out.append("### Heuristic Violations (one-sided mutations)")
        out.append("")
        if c["violations"]:
            out.append("| Function | Mutates | Law | Severity |")
            out.append("|----------|---------|-----|----------|")
            for v in c["violations"]:
                out.append(
                    f"| `{v['function']}` | {', '.join(v['mutates']) or '—'} | `{v['law']}` | {v['severity']} |"
                )
        else:
            out.append("_(none flagged — all accounting writes are paired)_")
        out.append("")

        # Monotonicity
        out.append("### Monotonicity Expectations")
        out.append("")
        if c["monotonicity"]:
            out.append("| Variable | Direction | Trigger |")
            out.append("|----------|-----------|---------|")
            for m in c["monotonicity"]:
                out.append(f"| {m['variable']} | {m['direction']} | {m['trigger']} |")
        else:
            out.append("_(none detected)_")
        out.append("")

        # Rounding
        out.append("### Rounding Direction Hints")
        out.append("")
        if c["rounding"]:
            out.append("| Function | Direction | Impact |")
            out.append("|----------|-----------|--------|")
            for r in c["rounding"]:
                out.append(f"| `{r['function']}` | {r['direction']} | {r['impact']} |")
        else:
            out.append("_(no obvious rounding-direction calls — manual review still required)_")
        out.append("")

        # Regime boundaries
        out.append("### Regime Boundaries (`require(...)` constants)")
        out.append("")
        if c["regime_boundaries"]:
            out.append("| Variable | Operator | Threshold | Context |")
            out.append("|----------|----------|-----------|---------|")
            for r in c["regime_boundaries"]:
                out.append(
                    f"| {r['variable']} | `{r['operator']}` | `{r['threshold']}` | `{r['context']}` |"
                )
        else:
            out.append("_(none detected)_")
        out.append("")

        # User inputs
        out.append("### User-Controllable Inputs")
        out.append("")
        if c["user_inputs"]:
            out.append(", ".join(f"`{i}`" for i in c["user_inputs"]))
        else:
            out.append("_(none detected)_")
        out.append("")

        # Oracle/config deps
        out.append("### Oracle / Config Dependencies")
        out.append("")
        if c["oracle_config_dependencies"]:
            for d in c["oracle_config_dependencies"]:
                out.append(f"- `{d['config']}` ({d['kind']}, type `{d['type']}`)")
        else:
            out.append("_(none detected)_")
        out.append("")

        # Candidate invariants
        out.append("### Candidate Invariants (Tier B — advisory)")
        out.append("")
        if c["candidates"]:
            out.append("| Name | Severity | Source | Body |")
            out.append("|------|----------|--------|------|")
            for cand in c["candidates"]:
                out.append(
                    "| `{n}` | {s} | {src} | `{b}` |".format(
                        n=cand["name"],
                        s=cand["severity"],
                        src=cand["source"],
                        b=cand["body"].replace("|", "\\|"),
                    )
                )
        else:
            out.append("_(no candidates emitted)_")
        out.append("")

    out.append("---")
    out.append("")
    out.append("**Tier B / advisory.** This artifact lists candidate invariants")
    out.append("and heuristic violations. Downstream fuzzers (Foundry invariant,")
    out.append("Halmos) and human review are still required to confirm bugs.")
    out.append("See `docs/ROADMAP_10_OF_10_V4.md` §2 Workstream B + §4 P2.")
    out.append("")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Mine math invariants from a Solidity workspace (V4 P2, Tier B).",
    )
    p.add_argument("--workspace", required=True, help="Workspace directory")
    p.add_argument(
        "--output-dir",
        required=True,
        help="Where MATH_SPEC.md and math_spec.json are written (created if missing)",
    )
    p.add_argument(
        "--contracts",
        action="append",
        default=None,
        help="Glob (relative to workspace) to find .sol files. May be repeated. "
        "Default: src/**/*.sol, contracts/**/*.sol, *.sol.",
    )
    p.add_argument(
        "--max-bytes",
        type=int,
        default=2_000_000,
        help="Skip any single .sol file larger than this many bytes (safety cap).",
    )
    p.add_argument(
        "--emit-candidate",
        action="store_true",
        help=(
            "Opt-in V5 deep-lane emission: write deep_candidate.v1 JSON files "
            "to <workspace>/deep_candidates/ for each conservation-law violation "
            "and rounding hint. Default outputs (MATH_SPEC.md / math_spec.json) "
            "are unchanged."
        ),
    )
    args = p.parse_args(argv)

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"[math-invariant-miner] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    globs = args.contracts or ["src/**/*.sol", "contracts/**/*.sol", "*.sol"]
    paths = discover_contracts(ws, globs)

    contracts: Dict[str, Dict] = {}
    for path in paths:
        try:
            if path.stat().st_size > args.max_bytes:
                print(
                    f"[math-invariant-miner] SKIP {path} (size {path.stat().st_size}B > {args.max_bytes}B)",
                    file=sys.stderr,
                )
                continue
            src = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[math-invariant-miner] WARN unreadable {path}: {exc}", file=sys.stderr)
            continue
        for cname, cbody in _split_contracts(src):
            # Disambiguate same-named contracts across files by suffixing path.
            key = cname if cname not in contracts else f"{cname}@{path.relative_to(ws)}"
            contracts[key] = analyze_contract(cname, cbody)
            contracts[key]["source_path"] = str(path.relative_to(ws))

    spec = {
        "schema_version": MATH_SPEC_JSON_SCHEMA_VERSION,
        "workspace": str(ws),
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tier": "B",
        "tool": "math-invariant-miner.py",
        "contracts": contracts,
    }

    json_path = out_dir / "math_spec.json"
    md_path = out_dir / "MATH_SPEC.md"
    json_path.write_text(
        json.dumps(spec, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(spec), encoding="utf-8")

    if args.emit_candidate:
        try:
            emitted = _emit_deep_candidates(ws, contracts)
            print(
                f"[math-invariant-miner] EMIT deep_candidates={emitted} "
                f"dir={ws / 'deep_candidates'}"
            )
        except Exception as exc:  # pragma: no cover — emission must never block default run
            print(
                f"[math-invariant-miner] WARN deep-candidate emission failed: {exc}",
                file=sys.stderr,
            )

    print(f"[math-invariant-miner] OK contracts={len(contracts)} json={json_path} md={md_path}")
    return 0


# ---------------------------------------------------------------------------
# V5 deep-candidate emission (opt-in)
# ---------------------------------------------------------------------------


def _load_deep_candidate_lib() -> Optional[Any]:
    """Dynamically load tools/lib/deep_candidate.py without requiring tools/ to be a package."""
    spec_path = Path(__file__).resolve().parent / "lib" / "deep_candidate.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_deep_candidate_lib", spec_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib", module)
    spec.loader.exec_module(module)
    return module


def _emit_deep_candidates(ws: Path, contracts: Dict[str, Dict]) -> int:
    """Emit deep_candidate.v1 JSON files for math-spec violations + rounding hints.

    Each emission carries ``confidence='low'``, ``promotion_status='investigate'``,
    and at least one blocking question — the advisory floor required by the
    schema until a downstream fuzzer / Forge invariant promotes the candidate.
    """
    lib = _load_deep_candidate_lib()
    if lib is None:
        return 0

    count = 0
    for cname, cdata in sorted(contracts.items()):
        source_path = cdata.get("source_path", "")
        # One-sided-mutation violations are the strongest math signal.
        for v in cdata.get("violations", []):
            doc = lib.build_candidate(
                lane="math",
                candidate_id=f"math.violation.{cname}.{v.get('function', 'unknown')}.{v.get('law', 'law')}",
                files=[source_path] if source_path else [f"{cname}"],
                claim=(
                    f"Function `{v.get('function', '?')}` in {cname} mutates "
                    f"only one side of the {v.get('law', '?')} conservation "
                    "law; downstream invariants may break."
                ),
                trigger=(
                    f"Caller invokes {cname}.{v.get('function', '?')} with "
                    "any path that reaches the heuristic mutation site."
                ),
                impact=(
                    "Possible accounting drift between paired state variables. "
                    "Requires fuzzer/invariant test to confirm whether the "
                    "drift is observable or compensated elsewhere."
                ),
                reproduction=(
                    "forge test --match-contract Invariant_"
                    f"{cname} -vv "
                    "(generate Foundry invariant from math_spec.json and run)"
                ),
                blocking_questions=[
                    "Is the conservation law actually expected to hold for this contract?",
                    "Does another function compensate the mutation atomically?",
                    "What is the runnable Forge invariant that would close this?",
                ],
                tool="math-invariant-miner.py",
                workspace=ws,
                lane_payload={
                    "violation": v,
                    "source_path": source_path,
                    "contract": cname,
                },
            )
            lib.write_candidate(doc, workspace=ws)
            count += 1
        # Rounding hints — lower-signal but still worth advisory emission.
        for r in cdata.get("rounding", []):
            doc = lib.build_candidate(
                lane="math",
                candidate_id=f"math.rounding.{cname}.{r.get('function', 'unknown')}.{r.get('direction', 'dir')}",
                files=[source_path] if source_path else [f"{cname}"],
                claim=(
                    f"Function `{r.get('function', '?')}` in {cname} rounds "
                    f"{r.get('direction', '?')}; verify protocol-favoring direction."
                ),
                trigger=(
                    f"Any caller of {cname}.{r.get('function', '?')} with "
                    "edge-case denominators or near-zero numerators."
                ),
                impact=(
                    "Potential value leak / dust-accrual depending on which "
                    "actor benefits from the rounding direction."
                ),
                reproduction=(
                    "Build differential test: compare ceil vs floor outcomes "
                    f"on {cname}.{r.get('function', '?')} across the input "
                    "range surfaced in math_spec.json."
                ),
                blocking_questions=[
                    "Does the protocol expect rounding-against-user or rounding-against-protocol here?",
                    "Is there an executable test that demonstrates an exploitable rounding gap?",
                ],
                tool="math-invariant-miner.py",
                workspace=ws,
                lane_payload={
                    "rounding": r,
                    "source_path": source_path,
                    "contract": cname,
                },
            )
            lib.write_candidate(doc, workspace=ws)
            count += 1
    return count


if __name__ == "__main__":
    sys.exit(main())
