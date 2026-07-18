"""plonky3_air_constraint_unused_advice.py

Flags Plonky3 AIR columns accessed via `local.<field>` or `next.<field>`
in the `fn eval` body that are NEVER passed to any `builder.assert_*` /
`builder.when` call in the same body. This is the "Assigned but
Unconstrained" zkBugs shape applied to Plonky3's AIR interface.

Detection (regex-only):
  1. The file must look like Plonky3 (imports p3_air::* or impl Air<AB>).
  2. Locate the `fn eval(&self, builder: &mut AB)` body.
  3. Extract all column field names accessed as `local.<name>` or
     `next.<name>`.
  4. Collect the text of all `builder.assert_eq(...)`, `builder.assert_zero(...)`,
     `builder.when(...)`, `builder.assert_bool(...)` calls.
  5. For each accessed column name, check if it appears in any assert call.
     If not — emit a finding.

Known limitations:
  - Name-based only: indirect references (stored in a variable, then
    used) may be false-negative. Reviewer should trace manually.
  - Columns constrained via a custom constraint system extension
    (e.g. permutation or lookup argument that doesn't use `builder.assert_*`)
    are false-positives. Check `builder.send` / `builder.receive` usage.

Reference: zkBugs class "Assigned but Unconstrained"; applicable to
Plonky3 AIR layouts as established in the Plonky3 8-bug corpus subset.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util
except ImportError:
    import importlib.util as _ilu
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = _ilu.spec_from_file_location("plonky3_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "plonky3_air_constraint_unused_advice"


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_plonky3_file(source):
        return []
    stripped = _util.strip_comments(source)
    eval_range = _util.find_eval_body(stripped)
    if eval_range is None:
        return []
    body_start, body_end = eval_range
    body = stripped[body_start:body_end]
    # Strip comments from body before any pattern extraction so that
    # column names mentioned only in comments don't influence detection.
    body_no_comments = _util.strip_comments(body)

    accessed_cols = _util.extract_row_field_accesses(body_no_comments)
    if not accessed_cols:
        return []
    assert_blob = _util.extract_assert_calls(body_no_comments)
    # Also include lookup send/receive blobs — if a col appears there it IS
    # being used in a constraint (LogUp argument).
    lookup_blob_parts: list[str] = []
    for m in re.finditer(
        r"\bbuilder\s*\.\s*(?:send|receive|push_send|push_receive)\b",
        body_no_comments,
    ):
        lookup_blob_parts.append(body_no_comments[m.start() : m.start() + 300])
    lookup_blob = "\n".join(lookup_blob_parts)
    full_constraint_blob = assert_blob + "\n" + lookup_blob

    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in accessed_cols:
        if name in seen:
            continue
        seen.add(name)
        pat = re.compile(rf"\b{re.escape(name)}\b")
        if pat.search(full_constraint_blob):
            continue
        # Find offset of first access (in comment-stripped source so we
        # don't anchor on a comment mention of the column name).
        first_access = re.search(
            rf"\b(?:local|next)\s*\.\s*{re.escape(name)}\b", stripped
        )
        offset = first_access.start() if first_access else body_start
        line, col = _util.line_col(source, offset)
        snippet = source[offset : offset + 180].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "severity": "high",
                "message": (
                    f"AIR column `{name}` is accessed in `fn eval` "
                    "(via `local.{name}` / `next.{name}`) but never "
                    "referenced from any `builder.assert_eq` / "
                    "`builder.assert_zero` / `builder.when` / "
                    "`builder.send` / `builder.receive` call. "
                    "Classic 'Assigned but Unconstrained' zkBugs shape. "
                    "Verify the column is properly constrained."
                ).format(name=name),
                "snippet": snippet,
            }
        )
    return hits
