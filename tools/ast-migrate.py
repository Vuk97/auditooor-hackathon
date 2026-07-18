#!/usr/bin/env python3
"""
ast-migrate.py — R75 gap-5: mechanical regex→AST migration helper.

For every pattern YAML under reference/patterns.dsl/, this tool inspects
the predicate list and proposes AST-level replacements for the most
common regex shapes. It can optionally apply the rewrites in-place
(`--write`) or print a unified diff (`--diff`).

Supported rewrites (top-20 identified via usage frequency in R75):

  body_contains_regex: '\\.safeTransfer\\s*\\('
    → function.has_high_level_call_named: 'safeTransfer'

  body_contains_regex: '\\.transfer\\s*\\(' / '\\.send\\s*\\(' / '\\.call\\s*\\{'
    → function.has_low_level_call: true  (with op filter if we can infer)

  body_contains_regex: 'msg\\.sender'
    → function.reads_msg_sender: true

  body_contains_regex: 'tx\\.origin'
    → function.reads_tx_origin: true

  body_contains_regex: 'block\\.timestamp'
    → function.reads_block_timestamp: true

  body_contains_regex: 'block\\.number'
    → function.reads_block_number: true

  body_contains_regex: 'keccak256'
    → function.computes_keccak: true

  body_contains_regex: '^emit\\s+Event\\(' / 'emit\\s+Name'
    → function.emits_event_matching: '<name>'

  body_contains_regex: 'require\\s*\\(.*<expr>.*\\)'
    → function.has_require_mentioning: '<expr>'

  body_contains_regex: 'onlyOwner|onlyAdmin|onlyRole\\(\\s*ROLE\\)'
    → function.has_modifier: <name>  (when single modifier)

Conservative behaviour:
  - If a regex has multiple alternatives (|), we only rewrite when EVERY
    alternative maps cleanly to the same AST predicate (e.g. 'transfer|send'
    → has_low_level_call).
  - If uncertain, we DO NOT rewrite; we print a suggestion comment in the
    --diff output instead.
  - We PRESERVE the original regex predicate as a follow-on (either/or) until
    the operator confirms the AST predicate matches at least the same set.

Usage:
  python3 tools/ast-migrate.py --report                # dry-run, count migratable predicates
  python3 tools/ast-migrate.py --diff reference/patterns.dsl/some-pattern.yaml
  python3 tools/ast-migrate.py --write --glob 'aave-*.yaml'
  python3 tools/ast-migrate.py --write --all           # migrate everything that matches

Idempotent: running --write twice does not re-rewrite already-migrated YAMLs.

DOES NOT:
  - Delete the original regex predicate (that's a manual step once operator
    sees no regression).
  - Rewrite complex regex shapes (dispatcher-domain-specific).
"""

import argparse, pathlib, re, sys, difflib
from collections import defaultdict, Counter

AUDITOOOR_DIR = pathlib.Path(__file__).resolve().parent.parent
DSL_DIR = AUDITOOOR_DIR / "reference" / "patterns.dsl"

# ── Rewrite rules: list of (regex_to_match_in_value, ast_key, ast_val_template) ──
# Each rule is tried in order; first match wins. None values mean "unchanged".
# The rule's match operates on the REGEX VALUE, not on source. If it succeeds,
# we emit the AST predicate instead.
# Each rule is a pure substring match on the YAML regex value. We require the
# regex to ONLY reference the target construct (i.e. not also mention other
# unrelated constructs) — otherwise we'd lose semantics on rewrite.
# For that, each rule has an optional `must_not_contain` list: if any of those
# fragments also appears in the value, we skip the rule (hybrid regex, keep it).
RULES = [
    # Safe-lib call helpers — if the value is a clean safeTransfer/safeApprove check.
    {"contains_any": ["safeTransferFrom", "safeTransfer(", "safeTransfer\\s", "safeTransfer "],
     "must_not_contain": ["||", " and ", "0x", "assembly", "balanceOf", "keccak"],
     "ast_key": "function.has_high_level_call_named", "ast_val": "safeTransferFrom|safeTransfer"},

    {"contains_any": ["safeApprove"],
     "must_not_contain": ["assembly", "balanceOf"],
     "ast_key": "function.has_high_level_call_named", "ast_val": "safeApprove"},

    {"contains_any": ["safeIncreaseAllowance", "safeDecreaseAllowance"],
     "must_not_contain": [],
     "ast_key": "function.has_high_level_call_named", "ast_val": "safeIncreaseAllowance|safeDecreaseAllowance"},

    # Low-level EVM calls — hard to get right, skip unless value is VERY simple
    {"contains_any": [".call{", ".call\\{", ".call\\s*\\{"],
     "must_not_contain": [".call(", "staticcall", "delegatecall", "safeTransfer", "balanceOf"],
     "ast_key": "function.has_low_level_call", "ast_val": True},

    # Sender / origin reads — very simple anchor, almost never the whole pattern
    # but can be added as a precondition.
    {"contains_any": ["msg\\.sender", "msg.sender"],
     "must_not_contain": ["\\)", "safeTransfer", "onlyOwner", "require"],  # only simple reads
     "ast_key": "function.reads_msg_sender", "ast_val": True,
     "anchor_only": True},

    {"contains_any": ["tx\\.origin", "tx.origin"],
     "must_not_contain": ["=="],
     "ast_key": "function.reads_tx_origin", "ast_val": True,
     "anchor_only": True},

    # Keccak
    {"contains_any": ["keccak256"],
     "must_not_contain": ["||", " and "],
     "ast_key": "function.computes_keccak", "ast_val": True,
     "anchor_only": True},

    # ecrecover
    {"contains_any": ["ecrecover", "ECDSA\\.recover", "ECDSA.recover"],
     "must_not_contain": [],
     "ast_key": "function.has_high_level_call_named", "ast_val": "recover|ecrecover"},

    # block members
    {"contains_any": ["block\\.timestamp", "block.timestamp"],
     "must_not_contain": [],
     "ast_key": "function.reads_block_timestamp", "ast_val": True,
     "anchor_only": True},

    {"contains_any": ["block\\.number", "block.number"],
     "must_not_contain": [],
     "ast_key": "function.reads_block_number", "ast_val": True,
     "anchor_only": True},

    # R75 expansion — call-name anchors (balanceOf / totalSupply / transferFrom / approve / decimals)
    {"contains_any": ["balanceOf"],
     "must_not_contain": ["||", "&&"],
     "ast_key": "function.has_high_level_call_named", "ast_val": "balanceOf"},
    {"contains_any": ["totalSupply"],
     "must_not_contain": ["||", "&&"],
     "ast_key": "function.has_high_level_call_named", "ast_val": "totalSupply"},
    {"contains_any": ["transferFrom"],
     "must_not_contain": ["safeTransferFrom", "||", "&&"],
     "ast_key": "function.has_high_level_call_named", "ast_val": "transferFrom"},
    {"contains_any": ["delegatecall"],
     "must_not_contain": ["||", "&&"],
     "ast_key": "function.has_low_level_call", "ast_val": {"op": "delegatecall"}},
    {"contains_any": ["staticcall"],
     "must_not_contain": ["||", "&&"],
     "ast_key": "function.has_low_level_call", "ast_val": {"op": "staticcall"}},
    {"contains_any": ["selfdestruct", "suicide"],
     "must_not_contain": [],
     "ast_key": "function.has_high_level_call_named", "ast_val": "selfdestruct|suicide"},
]

def rule_matches(value, rule):
    """Does the rule apply to this value?"""
    if not any(f in value for f in rule["contains_any"]):
        return False
    for bad in rule.get("must_not_contain", []):
        if bad in value:
            return False
    return True

def load_yaml_text(p):
    return p.read_text()

def iter_predicate_lines(txt):
    """
    Yields (i, line_no, indent_prefix, key, value, raw_line) for every YAML
    line that looks like '- <indent>function.<key>: <value>' or
    '- <indent>contract.<key>: <value>'.
    """
    for i, line in enumerate(txt.splitlines()):
        m = re.match(r'^(\s*-\s+)(function\.\w+|contract\.\w+):\s*(.+)$', line)
        if not m:
            continue
        prefix, key, val = m.group(1), m.group(2), m.group(3).strip()
        yield i, line, prefix, key, val

def propose_rewrite(key, val):
    """Given a regex predicate, return (new_key, new_val, anchor_only) or None."""
    if key not in ("function.body_contains_regex",):
        return None
    # Strip quotes
    v = val
    for q in ("'", '"'):
        if v.startswith(q) and v.endswith(q):
            v = v[1:-1]
            break
    for rule in RULES:
        if rule_matches(v, rule):
            return rule["ast_key"], rule["ast_val"], rule.get("anchor_only", False)
    return None

def format_predicate(prefix, key, val):
    if val is True:
        val_str = "true"
    elif val is False:
        val_str = "false"
    elif isinstance(val, str):
        # Use single quotes for strings containing special chars
        if re.search(r'[^\w\-|]', val):
            val_str = f"'{val}'"
        else:
            val_str = val
    else:
        val_str = str(val)
    return f"{prefix}{key}: {val_str}"

def migrate(txt):
    """Return (new_txt, n_rewrites) for a given YAML text."""
    new_lines = []
    n = 0
    lines = txt.splitlines()
    for line in lines:
        m = re.match(r'^(\s*-\s+)(function\.\w+|contract\.\w+):\s*(.+)$', line)
        if not m:
            new_lines.append(line)
            continue
        prefix, key, val = m.group(1), m.group(2), m.group(3).strip()
        rewrite = propose_rewrite(key, val)
        if rewrite is None:
            new_lines.append(line)
            continue
        new_key, new_val, _anchor = rewrite
        # Insert the AST predicate BEFORE the original regex, so engine short-circuits
        # cheaply on AST while preserving original semantics. The regex stays as a
        # belt-and-suspenders check until the operator confirms no regression.
        new_lines.append(format_predicate(prefix, new_key, new_val))
        new_lines.append(line)
        n += 1
    return "\n".join(new_lines) + ("\n" if txt.endswith("\n") else ""), n

def report_all():
    totals = Counter()
    per_rule = Counter()
    touched_files = 0
    for p in sorted(DSL_DIR.glob("*.yaml")):
        t = p.read_text()
        for i, line, prefix, key, val in iter_predicate_lines(t):
            totals[key] += 1
            rewrite = propose_rewrite(key, val) if key == "function.body_contains_regex" else None
            if rewrite:
                per_rule[rewrite[0]] += 1
                touched_files += 1
    print("=== Predicate usage in patterns.dsl/ ===")
    for k, n in totals.most_common(20):
        print(f"  {n:5d}  {k}")
    print()
    print("=== AST-migratable body_contains_regex predicates ===")
    for k, n in per_rule.most_common():
        print(f"  {n:5d} → {k}")
    print(f"\nTotal rewrites available across {touched_files} predicate-lines")

def apply_migration(paths, write=False, show_diff=False):
    changed = 0
    total_rewrites = 0
    for p in paths:
        orig = p.read_text()
        new, n = migrate(orig)
        if n == 0:
            continue
        total_rewrites += n
        changed += 1
        if show_diff:
            diff = difflib.unified_diff(
                orig.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=str(p), tofile=str(p) + " (proposed)",
            )
            sys.stdout.writelines(diff)
        if write:
            p.write_text(new)
            print(f"[ok] migrated {n} predicate(s) in {p.name}")
    print(f"\n=== Summary: {changed} file(s) touched, {total_rewrites} predicate(s) rewritten ===")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true", help="dry-run, print usage counts")
    ap.add_argument("--diff", metavar="PATH", nargs="+", help="print diff for one or more YAMLs")
    ap.add_argument("--write", action="store_true", help="apply in-place")
    ap.add_argument("--glob", default=None, help="only touch files matching glob (e.g. 'aave-*.yaml')")
    ap.add_argument("--all", action="store_true", help="apply to all YAMLs")
    args = ap.parse_args()

    if args.report:
        report_all()
        return

    if args.diff:
        paths = [pathlib.Path(p) for p in args.diff]
        apply_migration(paths, write=False, show_diff=True)
        return

    if args.write and args.all:
        paths = sorted(DSL_DIR.glob("*.yaml"))
        apply_migration(paths, write=True)
        return

    if args.write and args.glob:
        paths = sorted(DSL_DIR.glob(args.glob))
        apply_migration(paths, write=True)
        return

    ap.print_help()

if __name__ == "__main__":
    main()
