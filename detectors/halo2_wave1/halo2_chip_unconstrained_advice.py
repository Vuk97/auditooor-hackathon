"""halo2_chip_unconstrained_advice.py

Flags Halo2 `assign_advice` calls inside a Chip's region whose target
advice column is NEVER referenced from any `meta.create_gate(...)` or
`meta.lookup(...)` constraint block in the same file. This is the
classic "Assigned but Unconstrained" zkBugs class (5 of 35 Halo2 bugs
in the curated subset — e.g. zksecurity "Equality between tag_value and
the final tag_value_acc not checked").

Detection (regex-only):
  1. The file must look like Halo2 (`use halo2_proofs::*` or
     `impl Chip<F>`).
  2. Identify every advice column let-binding name introduced via
     `meta.advice_column()` AND every advice column field accessed via
     `config.<name>` inside a `synthesize` / `assign_region` body.
  3. Identify every advice column NAME passed as the first arg to
     `region.assign_advice` (the closure tag string after `||`).
  4. For each assigned advice column, search ALL `meta.create_gate(...)`
     and `meta.lookup(...)` block bodies in the file. If the column
     identifier never appears (by name or by `<self|config>.<col>`),
     emit a finding.

Known FPs (documented):
  - Advice columns constrained by a permutation argument (enable_equality)
    only — these are "structurally constrained" by copy-equality and are
    NOT bugs. The detector flags them; reviewer should grep
    `enable_equality(<name>)` to dismiss.
  - Columns constrained by a constraint block whose closure references
    the column via an indexed expression (`config.cols[i]`). The detector
    is name-based; indexed references are a known false-negative escape.
  - Test fixtures using `Expression::Constant` in a gate that mentions the
    column textually as a comment-only — comments are stripped first, so
    this is generally safe.

Reference: zkBugs class "Assigned but Unconstrained"; canonical example
scroll-tech/zkevm-circuits bug "Equality between tag_value and the final
tag_value_acc not checked".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util  # type: ignore
except ImportError:  # pragma: no cover - allow importlib.util loading
    import importlib.util
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = importlib.util.spec_from_file_location("halo2_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "halo2_chip_unconstrained_advice"

_ASSIGN_ADVICE_RE = re.compile(
    # region.assign_advice(|| "<tag>", <col_expr>, offset, || ...)
    # or region.assign_advice(<col_expr>, offset, ...) in newer halo2 forks
    r"\bregion\s*\.\s*assign_advice\s*\(\s*(?:\|\|\s*[^,]+,\s*)?"
    r"(?P<col>[A-Za-z_][A-Za-z0-9_.<>:\s]*)\s*,",
    re.M | re.S,
)

_GATE_BLOCK_RE = re.compile(
    r"\bmeta\s*\.\s*(?:create_gate|lookup|lookup_any)\s*\(",
    re.M,
)


def _gate_bodies(source: str) -> str:
    """Return the concatenation of all create_gate / lookup body
    contents. Used as the corpus we search for column references."""
    out_parts: list[str] = []
    for m in _GATE_BLOCK_RE.finditer(source):
        # Walk forward to find the closure body `{ ... }` after the
        # opening `(`. Halo2 gate APIs typically look like:
        #   meta.create_gate("name", |meta| { ... })
        # We scan to the first `{` after the match, then balance-match.
        depth_paren = 1
        i = m.end()
        first_brace = -1
        while i < len(source) and depth_paren > 0:
            c = source[i]
            if c == "(":
                depth_paren += 1
            elif c == ")":
                depth_paren -= 1
                if depth_paren == 0:
                    break
            elif c == "{" and first_brace < 0:
                first_brace = i
            i += 1
        if first_brace >= 0:
            end = _util.block_end(source, first_brace)
            out_parts.append(source[first_brace + 1: end - 1])
    return "\n".join(out_parts)


def _last_ident(col_expr: str) -> str:
    """Reduce `self.config.tag_value` → `tag_value`; `tag_value` → `tag_value`."""
    parts = re.split(r"[.\s]+", col_expr.strip())
    parts = [p for p in parts if p]
    return parts[-1] if parts else ""


def find_unconstrained_advice(source: str) -> list[dict[str, Any]]:
    """Return list of dicts {col, offset, line} for advice columns
    assigned but never referenced from any gate/lookup body."""
    if not _util.is_halo2_file(source):
        return []
    stripped = _util.strip_comments(source)
    gate_blob = _gate_bodies(stripped)

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in _ASSIGN_ADVICE_RE.finditer(stripped):
        raw = m.group("col")
        col = _last_ident(raw)
        if not col or col in seen:
            continue
        # Skip obvious non-name expressions
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", col):
            continue
        seen.add(col)
        # Search gate_blob for the column identifier
        pat = re.compile(rf"\b{re.escape(col)}\b")
        if pat.search(gate_blob):
            continue
        findings.append(
            {
                "col": col,
                "offset": m.start(),
                "raw_expr": raw.strip(),
            }
        )
    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_unconstrained_advice(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 220].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "advice_columns": [f["col"]],
                "severity": "high",
                "message": (
                    f"Advice column `{f['col']}` is assigned via "
                    "region.assign_advice but never referenced from any "
                    "meta.create_gate / meta.lookup body in this file. "
                    "Classic zkBugs 'Assigned but Unconstrained' shape. "
                    "Verify the column is constrained or constrained by "
                    "permutation copy (enable_equality)."
                ),
                "snippet": snippet,
            }
        )
    return hits
