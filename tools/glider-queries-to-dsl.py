#!/usr/bin/env python3
"""
glider-queries-to-dsl.py — R76 F: bridge Glider's 150+ query library into
our DSL by translating query intent into pattern YAMLs.

Glider (ChainSecurity) expresses queries in Python with a fluent API
(`Functions().with_name(...).filter(...)`). The semantics are richer
than our regex DSL (real AST-level filters), but the INTENT of every
query maps to a bug class we can express.

This tool:
  1. Walks `external/glider-query-db/queries/*.py`.
  2. Extracts each query's @title, @description, @tags, and the filter chain.
  3. Writes a DSL YAML stub under `reference/patterns.dsl.r76_glider/`
     with a best-effort regex approximation of the query's intent.
  4. Flags high-confidence translations (simple name match + filter) vs
     low-confidence ones (complex inter-procedural) that need manual review.

Usage:
  python3 tools/glider-queries-to-dsl.py                # dry-run, count
  python3 tools/glider-queries-to-dsl.py --write        # generate YAMLs

Once generated, operators review + promote YAMLs to
`reference/patterns.dsl/` via the standard promotion pipeline.
"""

import argparse, pathlib, re, sys

AUDITOOOR = pathlib.Path(__file__).resolve().parent.parent
QUERIES_DIR = AUDITOOOR / "external" / "glider-query-db" / "queries"
OUT_DIR = AUDITOOOR / "reference" / "patterns.dsl.r76_glider"


def parse_query(path):
    """Extract @title / @description / @tags / filter chain hints from a
    Glider query file."""
    txt = path.read_text()
    title = ""
    desc = ""
    tags = ""
    author = ""
    m = re.search(r"@title:\s*(.+)", txt)
    if m: title = m.group(1).strip()
    m = re.search(r"@description:\s*(.+?)(?=@|\"\"\")", txt, flags=re.S)
    if m: desc = m.group(1).strip()[:1200]
    m = re.search(r"@tags:\s*(.+)", txt)
    if m: tags = m.group(1).strip()
    m = re.search(r"@author:\s*(.+)", txt)
    if m: author = m.group(1).strip()

    # Heuristic filters → DSL regex shapes
    name_filter = None
    nm = re.search(r'\.with_name\(\s*"([^"]+)"', txt)
    if nm: name_filter = nm.group(1)
    visibility = []
    if ".is_public()" in txt: visibility.append("public")
    if ".is_external()" in txt: visibility.append("external")

    return {
        "title": title, "desc": desc, "tags": tags,
        "author": author, "name": name_filter, "vis": visibility,
        "body": txt,
    }


def slugify(s):
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s.lower()).strip("-")
    return s[:80]


def emit_yaml(q, name):
    slug = slugify(name) or "glider-" + slugify(q.get("title", "query"))
    kind = "external_or_public" if q["vis"] else "external_or_public"
    name_rx = q["name"] or ".*"
    tags = q["tags"] or ""

    # Convert tags to precondition hints (mostly keywords)
    source_kw = "|".join(re.findall(r"[a-zA-Z][a-zA-Z0-9]+", tags))
    preconds = []
    if source_kw:
        preconds.append({"contract.source_matches_regex": f"(?i){source_kw}"})

    match = [
        {"function.kind": kind},
        {"function.name_matches": f"(?i){name_rx}"},
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
    ]

    yaml_txt = f"""# Auto-translated from Glider query: {q['title']}
# Source: {name}
# Original author: {q.get('author', 'unknown')}
# Review before promoting to reference/patterns.dsl/
pattern: glider-{slug}
source: auditooor-R76-glider-{name.replace('.py', '')}
severity: MEDIUM
confidence: LOW

preconditions:
"""
    for p in preconds:
        for k, v in p.items():
            yaml_txt += f"  - {k}: '{v}'\n"
    yaml_txt += "\nmatch:\n"
    for p in match:
        for k, v in p.items():
            if isinstance(v, bool):
                yaml_txt += f"  - {k}: {str(v).lower()}\n"
            else:
                yaml_txt += f"  - {k}: '{v}'\n"
    desc_single_line = q['desc'].replace('\n', ' ').replace("'", "\\'")
    yaml_txt += f"""
help: "{q['title']}"
wiki_title: "{q['title']}"
wiki_description: "{desc_single_line[:500]}"
wiki_exploit_scenario: "TODO: review Glider query {name} and fill in the exploit scenario."
wiki_recommendation: "TODO: review and fill in mitigation."
"""
    return slug, yaml_txt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    if not QUERIES_DIR.exists():
        print(f"[err] {QUERIES_DIR} not found — is external/glider-query-db populated?", file=sys.stderr)
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(QUERIES_DIR.glob("*.py"))[:args.limit]
    written = 0
    low_conf = 0
    for qf in files:
        q = parse_query(qf)
        if not q["title"]:
            continue
        slug, yaml_txt = emit_yaml(q, qf.name)
        out = OUT_DIR / f"glider-{slug}.yaml"
        if args.write:
            if out.exists(): continue
            out.write_text(yaml_txt)
        written += 1
        low_conf += 1  # all start LOW confidence

    print(f"[ok] translated {written} queries (dry-run)" if not args.write else
          f"[ok] wrote {written} YAMLs → {OUT_DIR}")
    print(f"     All emitted with confidence: LOW. Operator must review "
          f"and either promote to reference/patterns.dsl/ OR tighten the "
          f"regex filters before promoting.")


if __name__ == "__main__":
    main()
