#!/usr/bin/env python3
"""
glider-to-specs.py — extract Hexens Glider query metadata into draft YAML
specs for mechanical detector generation.

Walks `external/glider-query-db/queries/*.py`, parses each file's
`@title` / `@description` / `@tags` docstring metadata, classifies the
query to one of the 5 skeletons via keyword matching on the description,
and emits a draft YAML spec under `detectors/_specs/drafts_glider/`.

Usage:
    python3 tools/glider-to-specs.py [--all | <query.py> ...]

Zero agent tokens.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GLIDER_DIR = REPO / "external" / "glider-query-db" / "queries"
SPECS_DRAFTS = REPO / "detectors" / "_specs" / "drafts_glider"
SPECS_DRAFTS.mkdir(parents=True, exist_ok=True)

# Regex to extract docstring metadata from glider queries
DOCSTRING_RE = re.compile(r'"""\s*(.*?)\s*"""', re.DOTALL)
TITLE_RE = re.compile(r"@title:\s*(.+?)(?:\n|@|$)", re.DOTALL)
DESC_RE = re.compile(r"@description:\s*(.+?)(?:\n\s*@|$)", re.DOTALL)
TAGS_RE = re.compile(r"@tags:\s*(.+?)(?:\n|@|$)", re.DOTALL)


def _kebabize(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    s = re.sub(r"-+", "-", s)
    return s[:70]


def _pascal(name: str) -> str:
    parts = [p for p in _kebabize(name).split("-") if p]
    return "".join(p.capitalize() for p in parts) or "Query"


def _classify_skeleton(title: str, desc: str, tags: str) -> str:
    blob = f"{title} {desc} {tags}".lower()
    if (
        "paired" in blob or "inverse" in blob
        or ("add" in blob and "remove" in blob and "symmetry" in blob)
    ):
        return "paired_function_divergence"
    if (
        "calls" in blob and ("without" in blob or "missing" in blob)
        and ("function" in blob or "call" in blob)
    ) or "sibling" in blob:
        return "highlevelcall_missing_sibling"
    if (
        "require" in blob or "assert" in blob or "cap" in blob
        or "bound" in blob or "lacks" in blob or "missing-check" in blob
        or "unchecked" in blob or "does not validate" in blob
    ):
        return "name_match_missing_require"
    if ("not reset" in blob or "not cleared" in blob or "stale" in blob
            or "paired" in blob or "flag" in blob):
        return "state_write_without_paired_write"
    return "name_match_missing_call"


def _guess_severity(title: str, desc: str, tags: str) -> str:
    blob = f"{title} {desc} {tags}".lower()
    if "drain" in blob or "theft" in blob or "steal" in blob or "insolv" in blob:
        return "HIGH"
    if "dos" in blob or "denial" in blob or "block" in blob or "brick" in blob:
        return "HIGH"
    if "bypass" in blob or "missing access" in blob or "lacks" in blob:
        return "HIGH"
    if "rounding" in blob or "precision" in blob or "dust" in blob:
        return "MEDIUM"
    return "MEDIUM"


def _extract_fn_name(title: str, desc: str) -> str:
    """Pull a plausible function name from a glider query title/desc."""
    # Look for `functionName` or backticks
    m = re.search(r"`([a-zA-Z_][a-zA-Z0-9_]*)`", f"{title} {desc}")
    if m:
        return m.group(1)
    # Look for lowercase camelCase tokens that look like function names
    m = re.search(r"\b([a-z][a-zA-Z0-9]+(?:[A-Z][a-zA-Z0-9]+)+)\b", f"{title} {desc}")
    if m:
        return m.group(1)
    return ""


def parse_query_file(qpath: Path) -> dict:
    text = qpath.read_text(errors="ignore")
    ds_match = DOCSTRING_RE.search(text)
    if not ds_match:
        return None
    ds = ds_match.group(1)
    title_m = TITLE_RE.search(ds)
    desc_m = DESC_RE.search(ds)
    tags_m = TAGS_RE.search(ds)
    title = title_m.group(1).strip() if title_m else qpath.stem
    desc = desc_m.group(1).strip() if desc_m else ""
    tags = tags_m.group(1).strip() if tags_m else ""
    # Normalize whitespace in description
    desc = re.sub(r"\s+", " ", desc)
    return {"title": title, "desc": desc, "tags": tags, "slug": qpath.stem}


def render_spec(parsed: dict) -> dict:
    title = parsed["title"]
    desc = parsed["desc"]
    tags = parsed["tags"]
    slug = parsed["slug"]

    short = _kebabize(title)
    if not short or len(short) < 4:
        short = _kebabize(slug)
    class_name = _pascal(short)
    severity = _guess_severity(title, desc, tags)
    skeleton = _classify_skeleton(title, desc, tags)

    spec = {
        "skeleton": skeleton,
        "name": short,
        "class_name": class_name,
        "wave": 13,
        "severity": severity,
        "confidence": "MEDIUM",
        "source": f"Hexens Glider query: {slug}",
        "help": title[:180],
        "wiki_title": title,
        "wiki_description": desc[:300],
        "wiki_exploit_scenario": f"Per Glider query tags [{tags}]: {desc[:200]}",
        "wiki_recommendation": "Apply the guard described by the Glider query; cross-reference the canonical Hexens doc.",
        "contract_name": class_name,
    }

    # Extract heuristic identifiers from title/desc
    fn_hint = _extract_fn_name(title, desc)
    fn_regex_core = re.escape(fn_hint) if fn_hint else short.split("-")[0]
    fn_regex = f".*({fn_regex_core}).*"

    # Skeleton-specific fill-ins
    if skeleton == "name_match_missing_call":
        spec.update({
            "fn_name_regex": fn_regex,
            "read_var_regex": f".*({fn_regex_core[:10].lower() or 'tracked'}).*",
            "required_call_regex": r".*(accrue|update|sync|validate|check).*",
            "guarded_helper_name": "_guard",
            "vuln_fn_name": fn_hint or (short.split("-")[0] + "Fn"),
            "vuln_fn_params": "",
            "vuln_fn_mutability": "internal",
            "vuln_fn_mutability_clean": "internal",
            "vuln_fn_return": "bool",
            "vuln_fn_body": f"return {fn_regex_core[:10].lower() or 'tracked'} > 0;",
            "state_decl": f"uint256 internal {fn_regex_core[:10].lower() or 'tracked'};",
        })
    elif skeleton == "name_match_missing_require":
        spec.update({
            "fn_name_regex": fn_regex,
            "write_var_regex": f".*({fn_regex_core[:10].lower() or 'tracked'}).*",
            "guard_var_regex": f".*({fn_regex_core[:10].lower() or 'tracked'}).*",
            "vuln_fn_name": fn_hint or "setParam",
            "vuln_fn_params": "uint256 newVal",
            "vuln_fn_body_no_require": f"{fn_regex_core[:10].lower() or 'tracked'} = newVal;",
            "guard_require_line": "require(newVal <= 10000);",
            "state_decl": f"uint256 internal {fn_regex_core[:10].lower() or 'tracked'};",
        })
    elif skeleton == "paired_function_divergence":
        spec.update({
            "forward_verb": r"add",
            "inverse_verb": r"remove",
            "tracking_var_regex": ".*(counter|total|tracked).*",
            "forward_fn_name": "addThing",
            "inverse_fn_name": "removeThing",
            "fn_params": "address account",
            "forward_body": "balances[account] += 1; counter++;",
            "inverse_body_no_tracker": "balances[account] -= 1;",
            "inverse_body_with_tracker": "balances[account] -= 1; counter--;",
            "state_decl": "mapping(address => uint256) internal balances;\n    uint256 internal counter;",
        })
    elif skeleton == "highlevelcall_missing_sibling":
        spec.update({
            "trigger_sig_regex": f".*({fn_regex_core}).*",
            "required_sibling_regex": r".*(validate|check|verify|assert).*",
            "target_interface_decl": "interface IT { function trigger(uint256) external; function sibling(uint256) external; }",
            "target_iface_name": "IT",
            "vuln_fn_name": fn_hint or "doStuff",
            "vuln_fn_params": "uint256 x",
            "trigger_call": "target.trigger(x)",
            "sibling_call": "target.sibling(x)",
            "post_trigger_body": "balances[msg.sender] = x;",
            "state_decl": "mapping(address => uint256) internal balances;",
        })
    elif skeleton == "state_write_without_paired_write":
        spec.update({
            "fn_name_regex": fn_regex,
            "primary_var_regex": r".*(balance|amount|position|stake).*",
            "paired_var_regex": r".*(flag|status|cleared|isLong|reset).*",
            "vuln_fn_name": fn_hint or "liquidate",
            "vuln_fn_params": "address user",
            "primary_write_line": "balances[user] = 0;",
            "paired_write_line": "flags[user] = false;",
            "state_decl": "mapping(address => uint256) internal balances;\n    mapping(address => bool) internal flags;",
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
            escaped = str(v).replace('"', '\\"')
            lines.append(f'{k}: "{escaped}"')
    for k, v in spec.items():
        if k in common_order:
            continue
        if isinstance(v, str) and "\n" in v:
            lines.append(f"{k}: |")
            for sl in v.splitlines():
                lines.append(f"    {sl}")
        elif isinstance(v, str):
            escaped = v.replace('"', '\\"')
            lines.append(f'{k}: "{escaped}"')
        else:
            lines.append(f"{k}: {v}")
    path.write_text("\n".join(lines) + "\n")


def main(argv):
    if not argv or argv[0] == "--all":
        queries = sorted(GLIDER_DIR.glob("*.py"))
    else:
        queries = [Path(a) for a in argv]

    count = 0
    for q in queries:
        if not q.exists():
            continue
        parsed = parse_query_file(q)
        if not parsed or not parsed["desc"]:
            continue
        spec = render_spec(parsed)
        out = SPECS_DRAFTS / f"{spec['name']}.yaml"
        if out.exists():
            continue
        emit_yaml(spec, out)
        count += 1

    print(f"[summary] {count} glider draft specs written to {SPECS_DRAFTS}")


if __name__ == "__main__":
    main(sys.argv[1:])
