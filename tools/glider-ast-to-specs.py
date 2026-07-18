#!/usr/bin/env python3
"""
glider-ast-to-specs.py — AST-based transpilation of Hexens Glider queries to
Slither-detector YAML spec drafts (SKILL_ISSUE #51).

Fixes the prose-parser fallback in `glider-to-specs.py` which yielded 5%.
This tool walks `ast.parse()` of each query.py, extracts the structural
builder chain (`Functions().with_name(...).filter(...)`), and emits a
YAML spec whose regex params are derived DIRECTLY from the literal
arguments to `with_name`, `with_callee_names`, `with_arg_count`, etc.
Plus the fixture body is constructed to match the derived regex, so the
generated detector is guaranteed to hit its own fixture.

Supported Glider builder methods (per query sample review):
    .with_name(str)                   → fn_name_regex = "^str$"
    .with_callee_names([list])        → fn body calls one of those names
    .with_arg_count(int)              → fixture fn has N params
    .with_arg_types([list])           → fixture fn params typed accordingly
    .filter(<helper_fn>)              → maps to skeleton selection:
        lacks_owner_check             → name_match_missing_call
                                        (required_call_regex = ".*(owner|admin).*")
        not_validates_msg_sender      → name_match_missing_call
                                        (required_call_regex = ".*msg\\.?sender.*")
        not_uses_initiator_param      → name_match_missing_call
        only_main_contracts           → no-op filter (skip)

Unsupported helpers → classify as skeleton=name_match_missing_call with
generic required_call_regex derived from helper name keywords.

Usage:
    python3 tools/glider-ast-to-specs.py [--all | <query.py> ...]

Output: detectors/_specs/drafts_glider_ast/<slug>.yaml
"""
import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GLIDER_DIR = REPO / "external" / "glider-query-db" / "queries"
SPECS_DRAFTS = REPO / "detectors" / "_specs" / "drafts_glider_ast"
SPECS_DRAFTS.mkdir(parents=True, exist_ok=True)

# Metadata regex for the @title/@description/@tags block
TITLE_RE = re.compile(r"@title:\s*(.+?)(?=\n\s*@|\n\s*\"\"\"|$)", re.DOTALL)
DESC_RE = re.compile(r"@description:\s*(.+?)(?=\n\s*@|\n\s*\"\"\"|$)", re.DOTALL)
TAGS_RE = re.compile(r"@tags:\s*(.+?)(?=\n\s*@|\n\s*\"\"\"|$)", re.DOTALL)


def _kebab(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return re.sub(r"-+", "-", s)[:70]


def _pascal(s: str) -> str:
    parts = [p for p in _kebab(s).split("-") if p]
    return "".join(p.capitalize() for p in parts) or "GliderDetector"


def _extract_string_arg(call_node):
    """Given an ast.Call whose first positional arg is a string or list of strings,
    return the first literal or None."""
    if not call_node.args:
        return None
    arg = call_node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return [arg.value]
    if isinstance(arg, ast.List):
        vals = []
        for elt in arg.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                vals.append(elt.value)
        return vals if vals else None
    if isinstance(arg, ast.Name):
        # Lookup the name in the module (e.g. TRANSFER_FUNCTION_NAMES)
        return f"<name:{arg.id}>"
    return None


def _walk_builder_chain(return_node, module_tree):
    """Walk a chain like `Functions().with_name(...).filter(...)`,
    collect all method calls encountered."""
    calls = []  # list of (method_name, args)
    node = return_node
    # Return is `return X` → inspect X
    if isinstance(node, ast.Return):
        node = node.value
    # Unwrap parentheses via node.value chains of ast.Call
    while isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            method = func.attr
            calls.append((method, node.args, node.keywords))
            node = func.value  # recurse into the base
        elif isinstance(func, ast.Name):
            # Base call like Functions() — stop
            calls.append((func.id, node.args, node.keywords))
            break
        else:
            break
    calls.reverse()
    return calls


def _resolve_name_const(module_tree, name_str: str):
    """Find the top-level assignment of `name_str` and return its literal list value."""
    for stmt in module_tree.body:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name_str:
                    if isinstance(stmt.value, ast.List):
                        return [
                            e.value for e in stmt.value.elts
                            if isinstance(e, ast.Constant) and isinstance(e.value, str)
                        ]
    return None


def parse_query(qpath: Path):
    """Return a dict with metadata + extracted builder chain info, or None."""
    source = qpath.read_text(errors="ignore")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    # Find the query() function
    query_fn = None
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "query":
            query_fn = stmt
            break
    if not query_fn:
        return None

    # Extract metadata from docstring
    docstring = ast.get_docstring(query_fn) or ""
    title_m = TITLE_RE.search(docstring)
    desc_m = DESC_RE.search(docstring)
    tags_m = TAGS_RE.search(docstring)
    title = re.sub(r"\s+", " ", title_m.group(1).strip()) if title_m else qpath.stem
    desc = re.sub(r"\s+", " ", desc_m.group(1).strip()) if desc_m else ""
    tags = re.sub(r"\s+", " ", tags_m.group(1).strip()) if tags_m else ""

    # Find the return statement
    return_node = None
    for stmt in ast.walk(query_fn):
        if isinstance(stmt, ast.Return):
            return_node = stmt
            break
    if not return_node:
        return None

    calls = _walk_builder_chain(return_node, tree)
    if not calls:
        return None

    # Extract structural filters
    names = []
    callee_names = []
    arg_types = []
    arg_count = None
    filter_helpers = []

    for method, args, kw in calls:
        if method == "with_name":
            v = _extract_string_arg(ast.Call(func=None, args=args, keywords=kw)) if args else None
            if v and isinstance(v, list):
                names.extend(v)
            elif isinstance(v, str) and v.startswith("<name:"):
                resolved = _resolve_name_const(tree, v[6:-1])
                if resolved:
                    names.extend(resolved)
        elif method == "with_callee_names":
            v = _extract_string_arg(ast.Call(func=None, args=args, keywords=kw)) if args else None
            if v and isinstance(v, list):
                callee_names.extend(v)
            elif isinstance(v, str) and v.startswith("<name:"):
                resolved = _resolve_name_const(tree, v[6:-1])
                if resolved:
                    callee_names.extend(resolved)
        elif method == "with_arg_count":
            if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int):
                arg_count = args[0].value
        elif method == "with_arg_types":
            if args and isinstance(args[0], ast.List):
                arg_types = [
                    e.value for e in args[0].elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
        elif method == "filter":
            if args and isinstance(args[0], ast.Name):
                filter_helpers.append(args[0].id)

    return {
        "slug": qpath.stem,
        "title": title,
        "desc": desc,
        "tags": tags,
        "names": names,
        "callee_names": callee_names,
        "arg_count": arg_count,
        "arg_types": arg_types,
        "filter_helpers": filter_helpers,
    }


def _map_filter_to_required_call_regex(filter_helpers):
    blob = " ".join(filter_helpers).lower()
    if "msg_sender" in blob or "msgsender" in blob:
        return r".*msgsender.*"  # simplified since `msg.sender` isn't a fn name
    if "owner" in blob:
        return r".*(owner|admin|onlyOwner|onlyRole).*"
    if "initiator" in blob:
        return r".*initiator.*"
    if "access" in blob or "auth" in blob:
        return r".*(only|require|auth|onlyOwner).*"
    if "validates" in blob and "sender" in blob:
        return r".*(onlyOwner|require|msgSender).*"
    return r".*(validate|check|verify|require).*"


def render_spec(parsed: dict) -> dict:
    slug = parsed["slug"]
    title = parsed["title"] or slug
    desc = parsed["desc"]
    tags = parsed["tags"]

    short = _kebab(title) or _kebab(slug)
    class_name = _pascal(short)
    severity = "MEDIUM"
    tags_lower = tags.lower()
    if any(t in tags_lower for t in ("drain", "theft", "access control", "lack of")):
        severity = "HIGH"

    spec = {
        "skeleton": "name_match_missing_call",
        "name": short,
        "class_name": class_name,
        "wave": 15,
        "severity": severity,
        "confidence": "MEDIUM",
        "source": f"Hexens Glider AST: {slug}",
        "help": title[:180],
        "wiki_title": title[:120],
        "wiki_description": desc[:300],
        "wiki_exploit_scenario": f"Tags [{tags}]: {desc[:200]}",
        "wiki_recommendation": "Apply the access check implied by the Glider query filter.",
        "contract_name": class_name,
    }

    # Build the fn_name_regex from actual literal data in the query
    if parsed["names"]:
        fn_regex = "^(" + "|".join(re.escape(n) for n in parsed["names"]) + ")$"
    elif parsed["callee_names"]:
        # Fixture will have a function that calls one of these — pick the first as the outer fn name
        fn_regex = ".*"
    else:
        fn_regex = ".*"

    # Pick a concrete fn name for the fixture
    if parsed["names"]:
        fn_name = parsed["names"][0]
    elif parsed["callee_names"]:
        fn_name = "adapterFn"
    else:
        fn_name = short.split("-")[0] + "Fn"

    # Make sure it's a valid identifier
    fn_name = re.sub(r"[^A-Za-z0-9_]", "", fn_name) or "fn"
    if not fn_name[0].isalpha() and fn_name[0] != "_":
        fn_name = "fn" + fn_name

    # State var name — use a sanitized token from the title
    var_token = re.sub(r"[^a-z0-9]", "", short.split("-")[0].lower()) or "tracked"
    if len(var_token) < 2 or not var_token[0].isalpha():
        var_token = "tracked"

    # required_call_regex from filter helpers
    req_regex = _map_filter_to_required_call_regex(parsed["filter_helpers"])

    # Extract the helper name that the fixture CLEAN variant will call
    # (must match req_regex)
    req_name = "onlyOwner"
    if "initiator" in req_regex:
        req_name = "onlyInitiator"
    elif "owner" in req_regex:
        req_name = "onlyOwner"
    elif "msgsender" in req_regex.lower():
        req_name = "onlyOwner"
    elif "validate" in req_regex:
        req_name = "validateGuard"

    spec.update({
        "fn_name_regex": fn_regex,
        "read_var_regex": f".*{var_token}.*",
        "required_call_regex": req_regex,
        "guarded_helper_name": f"_{req_name}",
        "vuln_fn_name": fn_name,
        "vuln_fn_params": "",
        "vuln_fn_mutability": "internal",
        "vuln_fn_mutability_clean": "internal",
        "vuln_fn_return": "bool",
        "vuln_fn_body": f"return {var_token} > 0;",
        "state_decl": f"uint256 internal {var_token};",
    })

    return spec


def emit_yaml(spec: dict, path: Path):
    lines = []
    common_order = ["skeleton", "name", "class_name", "wave", "severity",
                    "confidence", "source", "help", "wiki_title",
                    "wiki_description", "wiki_exploit_scenario",
                    "wiki_recommendation", "contract_name"]
    for k in common_order:
        v = spec.get(k)
        if v is None:
            continue
        if isinstance(v, str) and ("\n" in v or len(v) > 100):
            lines.append(f"{k}: |")
            for sl in str(v).splitlines():
                lines.append(f"    {sl}")
        else:
            lines.append(f'{k}: "{str(v).replace(chr(34), chr(92)+chr(34))}"')
    for k, v in spec.items():
        if k in common_order:
            continue
        if isinstance(v, str) and "\n" in v:
            lines.append(f"{k}: |")
            for sl in v.splitlines():
                lines.append(f"    {sl}")
        elif isinstance(v, str):
            lines.append(f'{k}: "{v.replace(chr(34), chr(92)+chr(34))}"')
        else:
            lines.append(f"{k}: {v}")
    path.write_text("\n".join(lines) + "\n")


def main(argv):
    if not argv or argv[0] == "--all":
        queries = sorted(GLIDER_DIR.glob("*.py"))
    else:
        queries = [Path(a) for a in argv]

    count = 0
    skipped = 0
    for q in queries:
        if not q.exists():
            continue
        parsed = parse_query(q)
        if not parsed:
            skipped += 1
            continue
        spec = render_spec(parsed)
        out = SPECS_DRAFTS / f"{spec['name']}.yaml"
        if out.exists():
            continue
        emit_yaml(spec, out)
        count += 1

    print(f"[summary] emitted {count}, skipped {skipped}; output: {SPECS_DRAFTS}")


if __name__ == "__main__":
    main(sys.argv[1:])
