"""cairo_storage_var_aliasing.py

Flags Cairo storage_var patterns where the same storage variable is both
read (.read()) and written (.write()) within a single function body WITHOUT
an intervening serialization fence (i.e. a call to `serialize_felt` or
explicit packing of the written value), creating a potential aliasing bug.

In Cairo's storage model, a storage_var's felt-domain read value may be
cached; writing back a derived-but-not-reserialized value into the same var
can produce a silent state inconsistency if the underlying storage slot is
shared with a differently-typed interpretation (aliasing via storage key
collision or implicit felt truncation).

This also catches the simpler pattern of reading and writing the same
storage_var with no intervening computation — a no-op write that may mask
a missing update to a related variable (commonly seen in Cairo 0.x audits
as a "phantom write" pattern).

Detection (regex-only):
  1. File must look like Cairo.
  2. Within each fn/func body, find pairs of `X.read()` and `X.write(...)`.
  3. If both appear and there is no `serialize` / `pack` / `into()` call
     between the read and the write, flag it.
  4. Also flag if the written argument is syntactically identical to the
     read result (phantom no-op write).

Known FPs:
  - Read-then-write patterns that intentionally update a storage var after
    validation (the common case). Only the SAME-var read+write WITHOUT any
    transformation in between is flagged.
  - Storage vars updated from a completely different source (not derived
    from the read). The detector may flag these; annotate with
    `// cairo-storage-ok` to suppress.

Reference: Cairo storage aliasing; zkBugs "Storage Collision" class;
StarkNet storage key derivation docs.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util  # type: ignore
except ImportError:  # pragma: no cover
    import importlib.util
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = importlib.util.spec_from_file_location("cairo_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "cairo_storage_var_aliasing"

_STORAGE_READ_RE = re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*read\s*\(",
    re.M,
)
_STORAGE_WRITE_RE = re.compile(
    r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*write\s*\(",
    re.M,
)

# Serialization fence markers: serialize, pack, .into(), from_felt252, TryInto, coerce
# Note: into() typically follows `.` so we cannot use \b before it.
_SERIALIZE_RE = re.compile(
    r"(?:\b(?:serialize|pack|from_felt252|TryInto|coerce|StorePacking)\b"
    r"|\.into\s*\(\s*\))",
    re.M,
)

_SUPPRESS_RE = re.compile(r"cairo-storage-ok", re.I)


def find_storage_aliasing(source: str) -> list[dict[str, Any]]:
    """Return findings for storage_var read+write pairs without serialization fence."""
    if not _util.is_cairo_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []

    for fn_name, body_start, body_end in _util.iter_fn_bodies(stripped):
        body = stripped[body_start:body_end]

        # Collect all read variables and their positions
        reads: dict[str, list[int]] = {}
        for m in _STORAGE_READ_RE.finditer(body):
            var = m.group("var")
            reads.setdefault(var, []).append(m.start())

        # Collect all write variables and their positions
        writes: dict[str, list[int]] = {}
        for m in _STORAGE_WRITE_RE.finditer(body):
            var = m.group("var")
            writes.setdefault(var, []).append(m.start())

        # Find vars that appear in both reads and writes
        for var in set(reads) & set(writes):
            # For each read, check if a write follows without a serialize fence
            for read_pos in reads[var]:
                for write_pos in writes[var]:
                    if write_pos <= read_pos:
                        continue  # write before read — different pattern
                    # Check for serialization fence between read_pos and write_pos
                    between = body[read_pos:write_pos]
                    if _SUPPRESS_RE.search(between):
                        continue
                    if _SERIALIZE_RE.search(between):
                        continue
                    # Flag: same var read then written without intermediate serialization
                    findings.append(
                        {
                            "var": var,
                            "fn_name": fn_name,
                            "read_offset": body_start + read_pos,
                            "write_offset": body_start + write_pos,
                        }
                    )
                    break  # one finding per (var, read) pair is enough

    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_storage_aliasing(source):
        line, col = _util.line_col(source, f["read_offset"])
        snippet = source[f["read_offset"]: f["read_offset"] + 200].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "storage_var": f["var"],
                "fn_name": f["fn_name"],
                "severity": "medium",
                "message": (
                    f"Storage variable `{f['var']}` is read (.read()) and then "
                    f"written (.write()) in fn `{f['fn_name']}` without an "
                    "intervening serialize/pack/into serialization fence. "
                    "This can cause silent aliasing if the felt value is "
                    "reinterpreted or truncated between read and write. "
                    "Ensure the written value is explicitly computed from the "
                    "read value with correct type serialization."
                ),
                "snippet": snippet,
            }
        )
    return hits
