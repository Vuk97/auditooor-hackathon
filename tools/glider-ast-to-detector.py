#!/usr/bin/env python3
"""
glider-ast-to-detector.py — AST transpile of Hexens Glider queries into
auditooor DSL YAML patterns (reference/patterns.dsl/*.yaml).

Issue #51 / #114 — Round 40 wave17.

Unlike glider-ast-to-specs.py (which emits skeleton specs under detectors/_specs/),
this emits the compact DSL YAML shape consumed by tools/pattern-compile.py.

Supported Glider -> DSL predicate mapping (mappable-only chain policy):
    Contracts() / Functions() / Instructions()        → base iteration
    .with_name(str) / .with_one_of_the_names([s..])   → function.name_matches
    .with_signature("sig(a,b)") / .with_signatures     → function.name_matches
    .with_callee_names([...]) / .with_callee_name     → function.calls_function_matching
    .with_callee_signature                             → function.calls_function_matching
    .with_modifier_name(m)                             → function.has_modifier (includes)
    .without_modifier_name(m)                          → function.has_modifier (includes,negate)
    .with_modifier_name("nonReentrant") etc.           → function.has_modifier
    .with_properties([MethodProp.X])                   → function.kind/is_payable/etc
    .without_properties([MethodProp.X])                → inverse of above
    .with_arg_type("address") / .with_arg_types(...)   → function.has_param_of_type
    .with_arg_name / .with_arg_names                   → function.has_param_name_matching
    MethodProp.IS_CONSTRUCTOR                          → function.is_constructor: true
    MethodProp.IS_VIEW / IS_PURE                       → function.state_mutability
    MethodProp.EXTERNAL / PUBLIC                       → function.kind
    .with_callee_names for require/assert/revert ...   → body_contains_regex shortcut
    .source_contains / has_source_code_matching        → function.body_contains_regex

SKIPPED (needs CFG/DFG or deep traversal – tag as NEEDS-CFG):
    .forward_df / .forward_df_recursive
    .has_global_df / .has_global_df_recursive
    .previous_instructions / .next_instructions
    .caller_functions / .caller_functions_recursive (cross-function traversal)
    .callee_functions_recursive / .callee_values (deep)
    .get_components / .get_value / .get_callee_values
    .source_code() containment done dynamically
    loops containing `for`/`any(...)` over instruction iterators

Usage:
    python3 tools/glider-ast-to-detector.py --all
    python3 tools/glider-ast-to-detector.py <queryfile.py> ...
    python3 tools/glider-ast-to-detector.py --list      # report coverage only
"""
import ast
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GLIDER_DIR = REPO / "external" / "glider-query-db" / "queries"
DSL_DIR = REPO / "reference" / "patterns.dsl"
FIX_DIR = REPO / "patterns" / "fixtures"

# Method names that block mapping outright (need real CFG/DFG semantics)
NEEDS_CFG_METHODS = {
    "forward_df", "forward_df_recursive",
    "backward_df", "backward_df_recursive",
    "has_global_df", "has_global_df_recursive",
    "previous_instructions", "next_instructions",
    "placeholder_instructions", "instructions_recursive",
    "caller_functions", "caller_functions_recursive",
    "callee_functions_recursive", "callee_values",
    "get_components", "get_callee_values", "get_call_value",
    "get_call_gas", "get_call_type", "get_dests", "get_dest",
    "get_value", "get_arg", "get_args", "get_local_vars",
    "state_variables", "base_contracts", "modifiers_recursive",
    "library_calls", "low_level_external_calls", "delegate_calls",
    "events", "arguments", "with_globals", "with_operators",
}

METHOD_PROP_STATE_MUTABILITY = {
    "IS_VIEW": ("function.state_mutability", "view"),
    "IS_PURE": ("function.state_mutability", "pure"),
}
METHOD_PROP_KIND = {
    "EXTERNAL": ("function.kind", "external"),
    "PUBLIC": ("function.kind", "external_or_public"),
    "INTERNAL": ("function.kind", "internal"),
    "PRIVATE": ("function.kind", "internal"),
}
METHOD_PROP_FLAGS = {
    "IS_CONSTRUCTOR": ("function.is_constructor", True),
    "IS_PAYABLE": ("function.is_payable", True),
}

TITLE_RE = re.compile(r"@title[:\s]+(.+?)(?=\n\s*@|\n\s*\"\"\"|$)", re.DOTALL)
DESC_RE = re.compile(r"@description[:\s]+(.+?)(?=\n\s*@|\n\s*\"\"\"|$)", re.DOTALL)
TAGS_RE = re.compile(r"@tags[:\s]+(.+?)(?=\n\s*@|\n\s*\"\"\"|$)", re.DOTALL)


def _kebab(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return re.sub(r"-+", "-", s)[:70]


def _flatten_chain(expr):
    """Flatten chained attribute/method calls into a list of (method, args, kws) items.
    Base is first, tail is last."""
    parts = []
    node = expr
    while isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            parts.append(("METHOD", func.attr, node.args, node.keywords))
            node = func.value
        elif isinstance(func, ast.Name):
            parts.append(("BASE", func.id, node.args, node.keywords))
            break
        else:
            break
    parts.reverse()
    return parts


def _resolve_name_list(mod_tree, name_id):
    for stmt in mod_tree.body:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name_id:
                    if isinstance(stmt.value, ast.List):
                        vs = []
                        for e in stmt.value.elts:
                            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                                vs.append(e.value)
                        return vs or None
    return None


def _strlist_from_arg(arg, mod_tree):
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return [arg.value]
    if isinstance(arg, ast.List):
        vs = []
        for e in arg.elts:
            if isinstance(e, ast.Constant) and isinstance(e.value, str):
                vs.append(e.value)
        return vs or None
    if isinstance(arg, ast.Name):
        return _resolve_name_list(mod_tree, arg.id)
    return None


def _signature_to_name(sig):
    """`get_p(uint256)` -> `get_p`"""
    return sig.split("(", 1)[0]


def _method_prop_names(args_or_list, mod_tree):
    """Extract MethodProp.X constants from a list-of-attrs arg (often ast.List)."""
    props = []
    candidates = []
    if isinstance(args_or_list, ast.List):
        candidates = args_or_list.elts
    else:
        candidates = [args_or_list]
    for e in candidates:
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name) \
           and e.value.id in ("MethodProp", "FunctionFilters"):
            props.append(e.attr)
        elif isinstance(e, ast.Name):
            props.append(e.id)
    return props


def _find_best_chain(tree, query_fn):
    """Find the most informative Contracts()/Functions() chain anywhere in query().
    Returns (chain, source_label) or (None, None)."""
    best = None
    best_score = -1
    best_label = None
    for node in ast.walk(query_fn):
        if isinstance(node, ast.Call):
            parts = _flatten_chain(node)
            if not parts:
                continue
            # Need a Contracts()/Functions() base
            base_ok = False
            for tag, name, *_ in parts:
                if tag == "BASE" and name in ("Contracts", "Functions"):
                    base_ok = True
                    break
            if not base_ok:
                continue
            # Score = number of structural filters (with_name/with_signature/with_callee/...)
            score = 0
            for tag, name, *_ in parts:
                if tag == "METHOD" and any(
                    name.startswith(p) for p in (
                        "with_name", "with_signature", "with_signatures",
                        "with_callee", "with_modifier", "with_arg",
                        "with_properties", "with_one_property",
                        "with_all_properties", "without_properties",
                        "without_modifier", "with_one_of",
                    )
                ):
                    score += 1
            if score > best_score:
                best_score = score
                best = parts
                best_label = "walk"
    return best, best_label


def parse_query(qpath: Path):
    """Returns dict with either mappable predicates or a skip reason."""
    src = qpath.read_text(errors="ignore")
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {"skip": "syntax-error"}

    query_fn = None
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "query":
            query_fn = stmt
            break
    if not query_fn:
        return {"skip": "no-query-fn"}

    doc = ast.get_docstring(query_fn) or ""
    # If there is no docstring inside query(), try the module-level one (top of file)
    if not doc:
        mod_doc = ast.get_docstring(tree) or ""
        doc = mod_doc
    title_m = TITLE_RE.search(doc)
    desc_m = DESC_RE.search(doc)
    tags_m = TAGS_RE.search(doc)
    title = re.sub(r"\s+", " ", title_m.group(1).strip()) if title_m else qpath.stem
    desc = re.sub(r"\s+", " ", desc_m.group(1).strip()) if desc_m else ""
    tags = re.sub(r"\s+", " ", tags_m.group(1).strip()) if tags_m else ""

    # Find the best chain anywhere in the function (not just the return).
    chain, _label = _find_best_chain(tree, query_fn)
    if chain is None:
        return {"skip": "no-chain", "title": title, "desc": desc, "tags": tags}

    # If the chain itself uses a NEEDS_CFG method → skip.
    cfg_hits = [m for (tag, m, *_rest) in chain if tag == "METHOD" and m in NEEDS_CFG_METHODS]
    if cfg_hits:
        return {"skip": f"needs-cfg:{','.join(sorted(set(cfg_hits)))}",
                "title": title, "desc": desc, "tags": tags}

    # Translate each chain item into DSL predicates
    preconds = []
    matches = []
    base_kind = None
    names_re = []       # for function.name_matches
    callee_regs = []    # for function.calls_function_matching
    body_regs = []      # extra regex body terms
    needs_cfg = False

    # Track filter lambdas we saw — if any, we cannot reliably map semantics → skip
    saw_lambda_filter = False
    has_non_trivial_filter = False

    for kind_tag, method, args, kws in chain:
        if kind_tag == "BASE":
            if method == "Contracts":
                base_kind = "contracts"
            elif method == "Functions":
                base_kind = "functions"
            elif method == "Instructions":
                # Instruction-level only detectors are hard — punt
                return {"skip": "needs-cfg:Instructions-base", "title": title}
            elif method == "Modifiers":
                return {"skip": "needs-cfg:Modifiers-base", "title": title}
            continue

        # Skip purely navigational no-ops. `instructions()` and `arguments()`
        # are treated as no-ops because subsequent with_callee_*/with_name
        # gets folded into function-level predicates.
        if method in (
            "exec", "mains", "functions", "contracts",
            "instructions", "arguments", "non_interface_contracts",
            "with_all_function_names", "with_all_function_signatures",
        ):
            continue

        if method in ("with_name", "with_one_of_the_names", "with_one_of_the_function_names",
                      "with_name_regex", "with_name_prefix"):
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            if method == "with_name_regex" and len(vs) == 1:
                names_re.append(vs[0])
            elif method == "with_name_prefix" and len(vs) == 1:
                names_re.append(f"^{re.escape(vs[0])}")
            else:
                names_re.append("^(" + "|".join(re.escape(v) for v in vs) + ")$")

        elif method in ("with_signature", "with_signatures"):
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            fnames = [_signature_to_name(s) for s in vs]
            names_re.append("^(" + "|".join(re.escape(n) for n in fnames) + ")$")

        elif method in ("with_callee_name", "with_callee_names",
                        "with_one_of_callee_names", "with_one_of_the_callee_names"):
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            callee_regs.append("^(" + "|".join(re.escape(v) for v in vs) + ")$")

        elif method == "with_callee_signature":
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            fnames = [_signature_to_name(s) for s in vs]
            callee_regs.append("^(" + "|".join(re.escape(n) for n in fnames) + ")$")

        elif method == "with_modifier_name":
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            preconds.append({"function.has_modifier": {"includes": list(vs)}})

        elif method == "without_modifier_name":
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            preconds.append({"function.has_modifier": {"includes": list(vs), "negate": True}})

        elif method in ("with_properties", "with_one_property", "with_all_properties"):
            if not args:
                continue
            props = _method_prop_names(args[0], tree)
            for p in props:
                if p in METHOD_PROP_KIND:
                    k, v = METHOD_PROP_KIND[p]
                    preconds.append({k: v})
                elif p in METHOD_PROP_STATE_MUTABILITY:
                    k, v = METHOD_PROP_STATE_MUTABILITY[p]
                    preconds.append({k: v})
                elif p in METHOD_PROP_FLAGS:
                    k, v = METHOD_PROP_FLAGS[p]
                    preconds.append({k: v})

        elif method == "without_properties":
            if not args:
                continue
            props = _method_prop_names(args[0], tree)
            # INTERNAL/PRIVATE/IS_PURE/IS_VIEW being excluded commonly means
            # we want external/public, mutating functions.
            if any(p in ("INTERNAL", "PRIVATE") for p in props):
                preconds.append({"function.kind": "external_or_public"})
            if any(p in ("IS_VIEW", "IS_PURE") for p in props):
                preconds.append({"function.is_mutating": True})
            if "IS_CONSTRUCTOR" in props:
                preconds.append({"function.is_constructor": False})

        elif method in ("with_arg_type", "with_arg_types"):
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            for v in vs:
                preconds.append({"function.has_param_of_type": v})

        elif method in ("with_arg_name", "with_arg_names"):
            if not args:
                continue
            vs = _strlist_from_arg(args[0], tree)
            if not vs:
                continue
            preconds.append({"function.has_param_name_matching":
                             "|".join(re.escape(v) for v in vs)})

        elif method == "filter":
            # A filter; we don't attempt to translate its semantics. We pass through
            # and rely on the structural preconditions we've already collected.
            # The pattern will be approximate — over-match rather than under-match —
            # which is fine for wave17 surface detection.
            continue

        elif method in NEEDS_CFG_METHODS:
            needs_cfg = True
            break

        else:
            # Unknown method — bail to be safe
            return {"skip": f"unmapped-method:{method}", "title": title,
                    "desc": desc, "tags": tags}

    if needs_cfg:
        return {"skip": "needs-cfg-in-chain", "title": title, "desc": desc, "tags": tags}

    # Need at least something of substance
    if not (names_re or callee_regs or preconds or body_regs):
        return {"skip": "empty-chain", "title": title, "desc": desc, "tags": tags}

    # Materialize names_re / callee_regs as predicates.
    # If multiple names_re were stacked, AND them by building a combined regex via
    # positive lookahead — but simpler: just use the last one (Glider's chain AND-s,
    # but the YAML engine allows only one name_matches, so we pick the first).
    if names_re:
        preconds.append({"function.name_matches": names_re[0]})
    for cr in callee_regs:
        matches.append({"function.calls_function_matching": cr})
    for br in body_regs:
        matches.append({"function.body_contains_regex": br})

    # Deduplicate preconds/matches while preserving order
    def _uniq(seq):
        seen = []
        for x in seq:
            if x not in seen:
                seen.append(x)
        return seen
    preconds = _uniq(preconds)
    matches = _uniq(matches)

    # Always add the FP-guard predicates at the end of match
    matches.append({"function.not_in_skip_list": True})
    matches.append({"function.not_leaf_helper": True})

    return {
        "slug": qpath.stem,
        "title": title,
        "desc": desc,
        "tags": tags,
        "base_kind": base_kind,
        "preconditions": preconds,
        "match": matches,
        "names": names_re,
        "callee": callee_regs,
    }


def _yaml_dump(spec: dict) -> str:
    """Minimal YAML emitter that mirrors the style of existing patterns.dsl files."""
    out = []
    for k in ("pattern", "source", "severity", "confidence"):
        if k in spec:
            out.append(f"{k}: {spec[k]}")
    out.append("")
    if spec.get("preconditions"):
        out.append("preconditions:")
        for p in spec["preconditions"]:
            (key, val), = p.items()
            if isinstance(val, dict):
                out.append(f"  - {key}:")
                for sk, sv in val.items():
                    if isinstance(sv, list):
                        out.append(f"      {sk}: [{', '.join(json.dumps(x) for x in sv)}]")
                    elif isinstance(sv, bool):
                        out.append(f"      {sk}: {str(sv).lower()}")
                    else:
                        out.append(f"      {sk}: {json.dumps(sv)}")
            elif isinstance(val, bool):
                out.append(f"  - {key}: {str(val).lower()}")
            else:
                out.append(f"  - {key}: {json.dumps(val)}")
        out.append("")
    if spec.get("match"):
        out.append("match:")
        for m in spec["match"]:
            (key, val), = m.items()
            if isinstance(val, dict):
                out.append(f"  - {key}:")
                for sk, sv in val.items():
                    if isinstance(sv, list):
                        out.append(f"      {sk}: [{', '.join(json.dumps(x) for x in sv)}]")
                    elif isinstance(sv, bool):
                        out.append(f"      {sk}: {str(sv).lower()}")
                    else:
                        out.append(f"      {sk}: {json.dumps(sv)}")
            elif isinstance(val, bool):
                out.append(f"  - {key}: {str(val).lower()}")
            else:
                out.append(f"  - {key}: {json.dumps(val)}")
        out.append("")
    if "fixtures" in spec:
        out.append("fixtures:")
        for fk, fv in spec["fixtures"].items():
            out.append(f"  {fk}: {fv}")
        out.append("")
    for k in ("help", "wiki_title", "wiki_description",
              "wiki_exploit_scenario", "wiki_recommendation"):
        if k in spec:
            # Single-line string → quote to keep YAML compatible
            v = spec[k].replace('"', '\\"')
            out.append(f'{k}: "{v}"')
    return "\n".join(out) + "\n"


def render_yaml(parsed: dict, pattern_id: str) -> str:
    spec = {
        "pattern": pattern_id,
        "source": f"hexens-glider/{parsed['slug']}",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "preconditions": parsed["preconditions"],
        "match": parsed["match"],
        "fixtures": {
            "vuln": f"patterns/fixtures/{pattern_id}_vuln.sol",
            "clean": f"patterns/fixtures/{pattern_id}_clean.sol",
        },
        "help": (parsed["title"] or parsed["slug"])[:200],
        "wiki_title": (parsed["title"] or parsed["slug"])[:140],
        "wiki_description": (parsed["desc"] or parsed["title"] or parsed["slug"])[:400],
        "wiki_exploit_scenario":
            f"Transpiled from Hexens Glider query {parsed['slug']}. "
            f"Tags: {parsed['tags']}.",
        "wiki_recommendation":
            "Apply the check implied by the original Glider query — "
            "see hexens-glider source for context.",
    }
    tags_lower = (parsed["tags"] or "").lower()
    if any(t in tags_lower for t in ("access control", "drain", "theft")):
        spec["severity"] = "HIGH"
    return _yaml_dump(spec)


def _fixture_vuln(pattern_id: str, parsed: dict) -> str:
    # Pick a concrete function name that will hit name_matches if present.
    fn_name = "targetFn"
    if parsed["names"]:
        m = re.match(r"^\^?\(?([A-Za-z_][A-Za-z0-9_]*)", parsed["names"][0])
        if m:
            fn_name = m.group(1)
    callee_stub = ""
    callee_line = ""
    if parsed["callee"]:
        m = re.match(r"^\^?\(?([A-Za-z_][A-Za-z0-9_]*)", parsed["callee"][0])
        callee = m.group(1) if m else "someCallee"
        callee_stub = f"    function {callee}(address) internal {{}}\n"
        callee_line = f"        {callee}(msg.sender);\n"
    params = ""
    for p in parsed["preconditions"]:
        if "function.has_param_of_type" in p:
            t = p["function.has_param_of_type"]
            if t == "address":
                params = "address to"
            elif "bytes" in t:
                params = "bytes calldata data"
            else:
                params = f"{t} x"
            break
    cname = "".join(p.capitalize() for p in pattern_id.split("-"))
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        f"contract {cname}Vuln {{\n"
        f"{callee_stub}"
        f"    function {fn_name}({params}) external {{\n"
        f"{callee_line}"
        f"    }}\n"
        f"}}\n"
    )


def _fixture_clean(pattern_id: str, parsed: dict) -> str:
    # Clean version simply omits the callee / has modifier etc. Make a different fn name.
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        f"contract {''.join(p.capitalize() for p in pattern_id.split('-'))}Clean {{\n"
        f"    function safeFn() external pure returns (uint256) {{ return 0; }}\n"
        f"}}\n"
    )


def main(argv):
    mode_list_only = "--list" in argv
    argv = [a for a in argv if a != "--list"]
    limit = None
    for a in list(argv):
        if a.startswith("--limit="):
            limit = int(a.split("=", 1)[1])
            argv.remove(a)
    if not argv or argv[0] == "--all":
        queries = sorted(GLIDER_DIR.glob("*.py"))
    else:
        queries = [Path(a) if "/" in a else (GLIDER_DIR / a) for a in argv]
    _limit = limit  # noqa

    emitted = []
    skipped = []
    for q in queries:
        if not q.exists():
            skipped.append((q.name, "missing"))
            continue
        parsed = parse_query(q)
        if "skip" in parsed:
            skipped.append((q.name, parsed["skip"]))
            continue

        pattern_id = f"glider-{_kebab(parsed['slug'])}"[:70]
        yaml_text = render_yaml(parsed, pattern_id)
        emitted.append((q.name, pattern_id, parsed, yaml_text))
        if _limit is not None and len(emitted) >= _limit:
            break

    if mode_list_only:
        print(f"would emit: {len(emitted)}  skip: {len(skipped)}")
        for n, r in skipped:
            print(f"  SKIP {n:60s} {r}")
        for n, pid, _p, _y in emitted:
            print(f"  OK   {n:60s} -> {pid}")
        return

    written = []
    for q_name, pattern_id, parsed, yaml_text in emitted:
        out_yaml = DSL_DIR / f"{pattern_id}.yaml"
        out_yaml.write_text(yaml_text)
        # Minimal fixture pair
        vuln_f = FIX_DIR / f"{pattern_id}_vuln.sol"
        clean_f = FIX_DIR / f"{pattern_id}_clean.sol"
        vuln_f.write_text(_fixture_vuln(pattern_id, parsed))
        clean_f.write_text(_fixture_clean(pattern_id, parsed))
        written.append((q_name, pattern_id))

    print(f"EMITTED: {len(written)}  SKIPPED: {len(skipped)}")
    for n, r in skipped:
        print(f"  SKIP {n:60s} {r}")
    for n, pid in written:
        print(f"  OK   {n:60s} -> {pid}")


if __name__ == "__main__":
    main(sys.argv[1:])
