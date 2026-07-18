#!/usr/bin/env python3
"""parity-gap-closer.py — generate FIRST-DRAFT sibling detectors for
BUG_CLASSES flagged `rust_only` or `sol_only` by detector-lint.

For each class that only has coverage on one language side, we:
  1. Locate the EXISTING detector/pattern (whichever side has it).
  2. Translate its regex/preconditions into a best-effort starter file
     on the OTHER side.
  3. Emit the starter with a DRAFT header and `#TODO` markers so the
     operator knows it must be reviewed before wiring up.

Drafts are IDEMPOTENT (skip if file already exists) and are NOT added
to test_detectors.sh or BUG_CLASSES. Manual promotion only.

Usage:
    python3 tools/parity-gap-closer.py         # generate drafts + report

Outputs:
    detectors/rust_wave1/DRAFT_<slug>.py       # rust starters (sol-only classes)
    reference/patterns.dsl/DRAFT-<slug>.yaml   # sol starters (rust-only classes)
    docs/archive/PARITY_GAP_DRAFTS.md                  # index + review status
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARITY_REPORT = ROOT / "tools" / "parity-report.py"
RUST_DIR = ROOT / "detectors" / "rust_wave1"
SOL_DIR = ROOT / "reference" / "patterns.dsl"
DOCS_OUT = ROOT / "docs" / "PARITY_GAP_DRAFTS.md"

# Matches `"<slug>": { ... "applies_to": "<val>" ... }` at top-level of BUG_CLASSES.
_CLASS_RE = re.compile(
    r'"([a-z][a-z0-9\-_]+)"\s*:\s*\{([^{}]*?)\}',
    re.DOTALL,
)
_APPLIES_RE = re.compile(r'"applies_to"\s*:\s*"([^"]+)"')
_KEYWORDS_RE = re.compile(r'"keywords"\s*:\s*\[([^\]]*)\]', re.DOTALL)
_DESC_RE = re.compile(r'"description"\s*:\s*"([^"]*)"')


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def extract_bug_classes() -> dict:
    """Regex-parse BUG_CLASSES out of parity-report.py."""
    text = _read(PARITY_REPORT)
    classes: dict = {}
    for m in _CLASS_RE.finditer(text):
        slug = m.group(1)
        body = m.group(2)
        am = _APPLIES_RE.search(body)
        if not am:
            continue
        applies = am.group(1)
        kw_match = _KEYWORDS_RE.search(body)
        kws: list[str] = []
        if kw_match:
            for raw in re.findall(r'"([^"]+)"', kw_match.group(1)):
                kws.append(raw)
        desc_m = _DESC_RE.search(body)
        desc = desc_m.group(1) if desc_m else ""
        classes[slug] = {"applies_to": applies, "keywords": kws, "description": desc}
    return classes


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def find_source_detector(side: str, keywords: list[str], slug: str) -> Path | None:
    """Look for an existing detector on the given side matching any keyword."""
    needles = [_norm(k) for k in keywords + [slug]]
    if side == "rust":
        candidates = [p for p in RUST_DIR.glob("*.py")
                      if not p.name.startswith("_") and p.name != "__init__.py"
                      and not p.name.startswith("DRAFT_")]
    else:
        candidates = [p for p in SOL_DIR.glob("*.yaml")
                      if not p.name.startswith("DRAFT-")]
    best: tuple[int, Path] | None = None
    for p in candidates:
        n = _norm(p.stem)
        score = sum(1 for nd in needles if nd and nd in n)
        if score == 0:
            # fall back to body-text match
            body = _read(p)
            score = sum(1 for nd in needles if nd and nd in _norm(body))
            score = min(score, 1)  # weaker signal
        if score > 0:
            if best is None or score > best[0]:
                best = (score, p)
    return best[1] if best else None


def _slug_snake(slug: str) -> str:
    return slug.replace("-", "_")


def rust_draft_body(slug: str, meta: dict, source: Path | None) -> str:
    kws = meta.get("keywords", [])
    desc = meta.get("description", "")
    src_excerpt = ""
    src_regex_hints: list[str] = []
    if source is not None:
        src_text = _read(source)
        # pull body_contains_regex / function.has_low_level_call hints from YAML
        for m in re.finditer(r"body_(?:not_)?contains_regex\s*:\s*['\"]([^'\"]+)['\"]", src_text):
            src_regex_hints.append(m.group(1))
        for m in re.finditer(r"has_low_level_call\s*:\s*\{\s*'op'\s*:\s*'([^']+)'", src_text):
            src_regex_hints.append(rf"\.{m.group(1)}\s*\(")
        src_excerpt = src_text[:400]

    # Collate an OR-ed regex from any translated hints or keywords; fall back to keywords.
    if not src_regex_hints:
        src_regex_hints = [re.escape(k) for k in kws if k]
    # Sanitize: drop duplicates and blanks, cap at 6 for readability.
    seen = set()
    hints = []
    for h in src_regex_hints:
        if h and h not in seen:
            hints.append(h)
            seen.add(h)
        if len(hints) >= 6:
            break
    combined = "|".join(hints) if hints else re.escape(slug)

    return f'''"""
DRAFT_{_slug_snake(slug)}.py

# DRAFT: auto-generated sibling for {slug} (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: {slug}
description: {desc}

Auto-translated from: {source.relative_to(ROOT) if source else "(no source detector found)"}

This is a REVIEWER PROMPT — translation is best-effort from the Solidity
DSL regex/precondition shape into a tree-sitter-rust heuristic. Human must:
  1. Confirm the bug-class actually manifests on the Rust side (Soroban /
     Solana / Move / Sway / FunC / TON / CosmWasm). If not, delete this file
     and leave the class `solidity_only`.
  2. Replace the naive regex scan below with AST-level predicates matching
     the actual Rust shape of the bug (see e.g. delegatecall_to_user_address.py
     which ports EVM delegatecall → Soroban SEP-41 transfer-from spoof).
  3. Add fixtures: test_fixtures/DRAFT_{_slug_snake(slug)}_positive.rs
     and _negative.rs, then register in test_detectors.sh.
"""
from __future__ import annotations

import re

# TODO: import the specific _util helpers your AST predicate needs
from _util import line_col  # TODO  # noqa: F401


# Translated hint tokens from source-side regex (combine / refine as needed).
_HINT_RE = re.compile(r"{combined}")  # TODO: replace with AST-shape predicate


def run(tree, source: bytes, filepath: str):
    """Best-effort text-regex port of the {slug} Solidity detector.

    TODO: upgrade from text-regex to tree-sitter-rust walk. This stub is
    intentionally over-eager to force the reviewer to think about
    positive/negative fixtures.
    """
    hits = []
    text = source.decode("utf-8", errors="replace")
    for m in _HINT_RE.finditer(text):
        line = text[:m.start()].count("\\n") + 1
        hits.append({{
            "severity": "low",  # TODO: calibrate after fixtures
            "line": line,
            "col": 0,
            "snippet": m.group(0)[:160].replace("\\n", " "),
            "message": (
                "DRAFT match for {slug}: "
                "{desc[:120]}"
            ),
        }})
    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# {src_excerpt[:300].replace(chr(10), " | ")}
'''


def sol_draft_body(slug: str, meta: dict, source: Path | None) -> str:
    kws = meta.get("keywords", [])
    desc = (meta.get("description", "") or "").replace('"', '\\"')

    # Scan the Rust-side detector for useful token hints.
    regex_hints: list[str] = []
    src_excerpt = ""
    if source is not None:
        src_text = _read(source)
        src_excerpt = src_text[:400]
        # Grab string literals from compiled regex or tuple constants.
        for m in re.finditer(r'["\']([A-Za-z_][A-Za-z0-9_\\.]{3,60})["\']', src_text):
            tok = m.group(1)
            if "." not in tok and "_" not in tok and len(tok) < 6:
                continue
            regex_hints.append(re.escape(tok))
        # Also grab compiled regex source directly.
        for m in re.finditer(r"re\.compile\(\s*r?['\"]([^'\"]+)['\"]", src_text):
            regex_hints.append(m.group(1))

    if not regex_hints:
        regex_hints = [re.escape(k) for k in kws if k]
    seen = set()
    hints: list[str] = []
    for h in regex_hints:
        if h and h not in seen:
            hints.append(h)
            seen.add(h)
        if len(hints) >= 5:
            break
    combined = "|".join(hints) if hints else re.escape(slug)
    src_rel = source.relative_to(ROOT) if source else "(no source detector found)"

    return f"""# DRAFT: auto-generated sibling for {slug} (source side: rust).
# Review required before enabling. Do NOT list in any registry yet.
# BUG_CLASS: {slug}
# Auto-translated from: {src_rel}
#
# Translation is best-effort from a tree-sitter-rust detector into the
# Solidity DSL shape. Human must:
#   1. Confirm this bug-class actually manifests in Solidity. If it is
#      Solana/Soroban/Move-specific, delete this file and leave the class
#      `rust_only`.
#   2. Replace the naive body_contains_regex below with real DSL predicates
#      (function.kind, function.has_low_level_call, etc.) — see
#      reference/patterns.dsl/delegatecall-user-supplied-target.yaml for an
#      example of the intended shape.
#   3. Add fixtures under patterns/fixtures/ and cross_refs once the
#      detector lands on a real finding.
pattern: DRAFT-{slug}
source: parity-gap-closer
severity: LOW                # TODO: raise once triaged
confidence: LOW              # TODO: raise once triaged

preconditions:
  # TODO: narrow to a real contract-shape gate (e.g. contract.inherits or
  #       contract.source_matches_regex). Catch-all placeholder below.
  - contract.source_matches_regex: '.*'

match:
  # TODO: replace this naive body-regex with AST-level predicates.
  #       The regex below was auto-derived from the Rust detector's string
  #       literals and is almost certainly too loose or too tight.
  - function.kind: external_or_public
  - function.body_contains_regex: '{combined}'
  - function.not_in_skip_list: true
  - function.not_source_matches_regex: '(?i)mock|test|fixture'

# TODO: add vuln + clean fixtures, then uncomment:
# fixtures:
#   vuln: patterns/fixtures/DRAFT-{slug}_vuln.sol
#   clean: patterns/fixtures/DRAFT-{slug}_clean.sol

help: "DRAFT sibling for {slug}: {desc[:160]}"
wiki_title: "DRAFT: {slug} (auto-generated from Rust sibling)"
wiki_description: "{desc}"
wiki_exploit_scenario: "TODO: flesh out once the reviewer confirms this class applies to Solidity."
wiki_recommendation: "TODO: write once reviewer signs off on the bug class."

# --- Source-side excerpt (reference only) ------------------------------------
# {src_excerpt[:300].replace(chr(10), ' | ')}
"""


def main() -> int:
    classes = extract_bug_classes()
    gap = [
        (slug, meta) for slug, meta in classes.items()
        if meta["applies_to"] in ("rust_only", "sol_only", "solidity_only")
    ]
    gap.sort(key=lambda x: x[0])

    drafts: list[dict] = []
    for slug, meta in gap:
        applies = meta["applies_to"]
        # rust_only → we need to GENERATE a Solidity sibling (and source is rust)
        # sol_only / solidity_only → we need to GENERATE a Rust sibling (source is solidity)
        if applies == "rust_only":
            target = SOL_DIR / f"DRAFT-{slug}.yaml"
            source_side = "rust"
            emit_kind = "solidity"
        else:
            target = RUST_DIR / f"DRAFT_{_slug_snake(slug)}.py"
            source_side = "solidity"
            emit_kind = "rust"

        status = "existing"
        if target.exists():
            drafts.append({
                "slug": slug, "applies": applies, "target": target,
                "source": None, "status": "skip-already-exists",
                "emit_kind": emit_kind,
            })
            continue

        src = find_source_detector(source_side, meta["keywords"], slug)
        if src is None:
            status = "written-no-source"
        else:
            status = "written"

        if emit_kind == "rust":
            target.write_text(rust_draft_body(slug, meta, src), encoding="utf-8")
        else:
            target.write_text(sol_draft_body(slug, meta, src), encoding="utf-8")
        drafts.append({
            "slug": slug, "applies": applies, "target": target,
            "source": src, "status": status, "emit_kind": emit_kind,
        })

    # Emit index.
    lines = [
        "# Parity Gap Drafts",
        "",
        "_Auto-generated by `tools/parity-gap-closer.py`. Each entry is a "
        "REVIEWER PROMPT, not a shipping detector. Drafts do NOT count "
        "toward parity and are NOT registered in `test_detectors.sh` or "
        "`BUG_CLASSES`. Promote manually after review._",
        "",
        f"**Total drafts on record:** {len(drafts)}",
        "",
        "| slug | gap side | sibling emitted | source used | status |",
        "|------|----------|-----------------|-------------|--------|",
    ]
    for d in drafts:
        src_rel = (
            str(d["source"].relative_to(ROOT)) if d["source"] is not None else "—"
        )
        tgt_rel = str(d["target"].relative_to(ROOT))
        lines.append(
            f"| `{d['slug']}` | {d['applies']} | `{tgt_rel}` | `{src_rel}` | "
            f"{d['status']} |"
        )
    lines.append("")
    lines.append("## Operator next-step")
    lines.append("")
    lines.append("For each draft marked `written` or `written-no-source`:")
    lines.append("1. Open the draft and confirm the bug class genuinely applies "
                 "to the missing language. If not, delete the file and leave the "
                 "class single-sided in BUG_CLASSES.")
    lines.append("2. Replace `#TODO` markers (naive regex, placeholder severity, "
                 "skeleton preconditions) with real AST / DSL predicates.")
    lines.append("3. Add `_positive` / `_negative` (rust) or `_vuln` / `_clean` "
                 "(solidity) fixtures; register the detector in "
                 "`test_detectors.sh` (rust) or compile via `make build` (DSL).")
    lines.append("4. Flip BUG_CLASSES `applies_to` to `both` once the sibling "
                 "lands green.")
    DOCS_OUT.parent.mkdir(parents=True, exist_ok=True)
    DOCS_OUT.write_text("\n".join(lines), encoding="utf-8")

    written = sum(1 for d in drafts if d["status"].startswith("written"))
    skipped = sum(1 for d in drafts if d["status"] == "skip-already-exists")
    print(f"[parity-gap-closer] gaps={len(gap)} written={written} "
          f"skipped={skipped} index={DOCS_OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
