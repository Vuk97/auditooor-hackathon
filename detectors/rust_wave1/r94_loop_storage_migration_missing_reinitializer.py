"""
r94_loop_storage_migration_missing_reinitializer.py

Flags upgraded contracts whose new version adds a storage variable
that was MOVED from another contract (evident from doc / comment
"// MOVED from X" or "// was in Y") — and no `reinitializer(N)` /
`initializeVN()` fn exists to set the new var.

Source: Solodit #53719 (EigenLayer DelegationManager withdrawalDelayBlocks).
Class: storage-migration-missing-reinitializer (both).
"""

from __future__ import annotations
import re
from _util import source_nocomment

_MIGRATION_MARKER_RE = re.compile(
    r"(//\s*moved\s+from|//\s*was\s+in|//\s*previously\s+in|"
    r"///\s*Migrated\s+from|doc\s*=\s*\"\s*moved\s+from)",
    re.IGNORECASE,
)
_REINITIALIZER_RE = re.compile(
    r"reinitializer\s*\(\s*\d+\s*\)|initializeV\d+|initialize_v\d+|"
    r"fn\s+reinitialize\s*\(|fn\s+migrate_init\s*\("
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    m = _MIGRATION_MARKER_RE.search(src) if False else None
    # source_nocomment strips comments; need raw source instead
    raw = source.decode("utf-8", errors="ignore")
    m = _MIGRATION_MARKER_RE.search(raw)
    if not m:
        return hits
    if _REINITIALIZER_RE.search(raw):
        return hits
    line = raw.count("\n", 0, m.start()) + 1
    hits.append({
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": raw[m.start():m.start()+200],
        "message": (
            "Storage var tagged MOVED/migrated from another contract "
            "but no reinitializer(N) / initializeVN / migrate_init fn "
            "exists to set it — variable stays at default forever "
            "(storage-migration-missing-reinitializer). See Solodit "
            "#53719 (EigenLayer)."
        ),
    })
    return hits
