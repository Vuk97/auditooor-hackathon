#!/usr/bin/env python3
"""new-detector-wizard.py — scaffold all 4 artifacts for a new canonical bug
class (Phase 11 of PR #84).

Creates, in one shot:
    detectors/rust_wave1/r94_loop_<stem>.py
    detectors/rust_wave1/test_fixtures/<stem>_positive.rs
    detectors/rust_wave1/test_fixtures/<stem>_negative.rs
    reference/patterns.dsl/r94-loop-<kebab>.yaml

Also (unless --dry-run):
    appends a class entry to tools/parity-report.py::BUG_CLASSES
    appends the detector stem to detectors/rust_wave1/test_fixtures/test_detectors.sh

Usage:
    python3 tools/new-detector-wizard.py \\
        --class <kebab-name> \\
        --fn-name-regex "<pattern>" \\
        --bad-hint "<what-to-look-for>" \\
        --safe-hint "<what-should-prevent>" \\
        --source-url <postmortem-url> \\
        [--dry-run]

Idempotent: refuses to overwrite any of the 4 artifact files. Prints a next-
steps line on success. Fill in the TODOs by hand, then `make all`.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST_DIR = ROOT / "detectors" / "rust_wave1"
FIX_DIR = RUST_DIR / "test_fixtures"
YAML_DIR = ROOT / "reference" / "patterns.dsl"
PARITY_REPORT = ROOT / "tools" / "parity-report.py"
TEST_SH = FIX_DIR / "test_detectors.sh"


def kebab_to_snake(kebab: str) -> str:
    return kebab.replace("-", "_")


def kebab_to_words(kebab: str) -> list[str]:
    """Split a kebab-name into word tokens, lowercased."""
    return [w for w in kebab.split("-") if w]


def derive_keywords(kebab: str) -> list[str]:
    """Pick up to 4 non-trivial tokens to use as parity-report keywords."""
    stop = {"on", "in", "to", "of", "the", "and", "or", "a", "no", "not",
            "with", "for", "at", "by", "as", "is"}
    words = [w for w in kebab_to_words(kebab) if w not in stop and len(w) > 2]
    # dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
        if len(out) >= 4:
            break
    if not out:
        out = kebab_to_words(kebab)[:1] or [kebab]
    return out


def detector_template(kebab: str, stem: str, fn_name_regex: str,
                      bad_hint: str, safe_hint: str, source_url: str) -> str:
    return f'''"""
r94_loop_{stem}.py — auto-scaffolded stub; fill in _BAD_RE / _SAFE_RE.

Source: {source_url}.
Class: {kebab} (both).
"""
from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl,
    fn_body, fn_name, is_pub,
    line_col, snippet_of, body_text_nocomment,
    IDENT, CALL, ASSIGN, COMP,  # shared primitives
)

_FN_NAME_RE = re.compile(r"(?i)({fn_name_regex})")
# TODO: tighten — what syntactic shape is the bug?  Hint: {bad_hint}
_BAD_RE = re.compile(fr"(?i)({re.escape(bad_hint)})")
# TODO: what guard / safe pattern should suppress the hit?  Hint: {safe_hint}
_SAFE_RE = re.compile(fr"(?i)({re.escape(safe_hint)})")


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _BAD_RE.search(body_nc):
            continue
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({{
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{{name}}` TODO: describe the invariant violation "
                f"({kebab}). "
                f"See {source_url}."
            ),
        }})
    return hits
'''


def positive_fixture(stem: str, bad_hint: str, kebab: str) -> str:
    return f'''// Positive fixture for r94_loop_{stem}.
// MUST trigger the detector (matches _BAD_RE, not _SAFE_RE).
// TODO: flesh out body so the bug pattern is obviously present.
// Class: {kebab}
use soroban_sdk::{{contract, contractimpl, Env}};

#[contract]
pub struct X;

#[contractimpl]
impl X {{
    pub fn test_fn(env: Env) {{
        // TODO: add minimal code that exhibits `{bad_hint}`.
        {bad_hint}();
    }}
}}

fn {bad_hint}() {{}}
'''


def negative_fixture(stem: str, bad_hint: str, safe_hint: str,
                     kebab: str) -> str:
    return f'''// Negative fixture for r94_loop_{stem}.
// MUST NOT trigger the detector (guard present).
// TODO: add the safe guard so _SAFE_RE matches or _BAD_RE does not.
// Class: {kebab}
use soroban_sdk::{{contract, contractimpl, Env}};

#[contract]
pub struct X;

#[contractimpl]
impl X {{
    pub fn test_fn(env: Env) {{
        // TODO: insert the safe counterpart to `{bad_hint}`.
        {safe_hint}();
    }}
}}

fn {safe_hint}() {{}}
'''


def yaml_template(kebab: str, stem: str, fn_name_regex: str,
                  bad_hint: str, safe_hint: str, source_url: str) -> str:
    return f'''pattern: r94-loop-{kebab}
source: {source_url}
severity: HIGH
confidence: LOW
tier: D
preconditions:
  - contract.source_matches_regex: '(TODO_fill_contract_scope)'
match:
  - function.kind: external_or_public
  - function.name_matches: '(?i)({fn_name_regex})'
  - function.source_matches_regex: '({re.escape(bad_hint)})'
  - function.not_source_matches_regex: '({re.escape(safe_hint)})'
severity_default: HIGH
message: |
  `{{fn}}` TODO: describe the invariant violation
  ({kebab}). See {source_url}.
cross_refs: [detectors/rust_wave1/r94_loop_{stem}.py]
tags: [{kebab}]
'''


def append_to_parity_report(kebab: str, keywords: list[str]) -> None:
    """Append a new class entry inside the BUG_CLASSES dict.

    Inserts just before the comment line that starts the platform-only
    section ('# Platform-only classes'). Idempotent: skips if the class
    key already appears.
    """
    text = PARITY_REPORT.read_text()
    class_key = f'"{kebab}"'
    if class_key + ":" in text:
        print(f"  parity-report.py already contains {class_key}, skipping")
        return

    anchor = "    # Platform-only classes"
    if anchor not in text:
        raise RuntimeError(
            f"cannot find anchor '# Platform-only classes' in "
            f"{PARITY_REPORT}; refusing to edit")
    kw_list = ", ".join(f'"{k}"' for k in keywords)
    entry = (
        f'    "{kebab}": {{\n'
        f'        "keywords": [{kw_list}],\n'
        f'        "applies_to": "both",\n'
        f'        "description": "{kebab}: auto-scaffolded class, '
        f'refine description",\n'
        f'    }},\n'
    )
    new_text = text.replace(anchor, entry + anchor, 1)
    PARITY_REPORT.write_text(new_text)
    print(f"  appended class '{kebab}' to parity-report.py::BUG_CLASSES")


def append_to_test_sh(stem: str) -> None:
    """Append the detector stem to the DETECTORS=(...) array.

    Inserts on the line immediately above the closing ')'. Idempotent:
    skips if the stem already appears.
    """
    text = TEST_SH.read_text()
    detector_stem = f"r94_loop_{stem}"
    # Quick membership test — look for the stem as its own token
    if re.search(rf"(?m)^\s*{re.escape(detector_stem)}\s*$", text):
        print(f"  test_detectors.sh already contains {detector_stem}, skipping")
        return

    lines = text.splitlines(keepends=True)
    close_idx = None
    in_array = False
    for i, line in enumerate(lines):
        if re.match(r"^DETECTORS=\(\s*$", line):
            in_array = True
            continue
        if in_array and re.match(r"^\)\s*$", line):
            close_idx = i
            break
    if close_idx is None:
        raise RuntimeError(
            f"cannot find DETECTORS=(...) closing ')' in {TEST_SH}; "
            f"refusing to edit")
    lines.insert(close_idx, f"    {detector_stem}\n")
    TEST_SH.write_text("".join(lines))
    print(f"  appended '{detector_stem}' to test_detectors.sh DETECTORS")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--class", dest="klass", required=True,
                    help="canonical kebab-case class name")
    ap.add_argument("--fn-name-regex", required=True,
                    help="inner regex body for _FN_NAME_RE (no wrapping parens needed)")
    ap.add_argument("--bad-hint", required=True,
                    help="token or phrase the bug pattern contains")
    ap.add_argument("--safe-hint", required=True,
                    help="token or phrase that should suppress the hit")
    ap.add_argument("--source-url", required=True,
                    help="URL or citation for the source finding")
    ap.add_argument("--dry-run", action="store_true",
                    help="skip parity-report.py + test_detectors.sh edits")
    args = ap.parse_args()

    kebab = args.klass.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9\-]*[a-z0-9]", kebab):
        print(f"ERROR: --class must be kebab-case, got {kebab!r}",
              file=sys.stderr)
        return 2
    stem = kebab_to_snake(kebab)

    py_path = RUST_DIR / f"r94_loop_{stem}.py"
    pos_path = FIX_DIR / f"{stem}_positive.rs"
    neg_path = FIX_DIR / f"{stem}_negative.rs"
    yaml_path = YAML_DIR / f"r94-loop-{kebab}.yaml"

    existing = [p for p in (py_path, pos_path, neg_path, yaml_path) if p.exists()]
    if existing:
        print("ERROR: refusing to overwrite existing artifact(s):",
              file=sys.stderr)
        for p in existing:
            print(f"  {p}", file=sys.stderr)
        return 1

    py_path.write_text(detector_template(
        kebab, stem, args.fn_name_regex, args.bad_hint,
        args.safe_hint, args.source_url))
    print(f"  wrote {py_path}")
    pos_path.write_text(positive_fixture(stem, args.bad_hint, kebab))
    print(f"  wrote {pos_path}")
    neg_path.write_text(negative_fixture(stem, args.bad_hint, args.safe_hint, kebab))
    print(f"  wrote {neg_path}")
    yaml_path.write_text(yaml_template(
        kebab, stem, args.fn_name_regex, args.bad_hint,
        args.safe_hint, args.source_url))
    print(f"  wrote {yaml_path}")

    if not args.dry_run:
        append_to_parity_report(kebab, derive_keywords(kebab))
        append_to_test_sh(stem)
    else:
        print("  --dry-run: skipped parity-report.py + test_detectors.sh edits")

    print("Next steps: edit the 4 files to fill TODOs, then `make all` to verify.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
