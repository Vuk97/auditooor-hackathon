#!/usr/bin/env python3
"""Regression: the audit-firm PDF ETL FIRM_PREFIX must match the actual Wave-1
listing dir prefix / firm shape-tag, and parse_listing must recover the PDF URL
from the top-level `record_source_url` field (newer listings) not only from
required_preconditions. Two drifts silently zeroed the cyfrin + openzeppelin
record drains (listings_seen=0). 2026-07-08 (corpus->capability drain loop, box F).
"""
import json
import re
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_LISTINGS = _REPO / "audit/corpus_tags/tags/audit_firm_public_reports"


def _firm_prefix(etl_path: Path) -> str:
    m = re.search(r'FIRM_PREFIX = "([^"]+)"', etl_path.read_text())
    return m.group(1) if m else ""


def _listing_firm_tags(prefix: str) -> set[str]:
    """firm-* shape-tags of listings whose dir starts with `prefix`__."""
    tags: set[str] = set()
    if not _LISTINGS.is_dir():
        return tags
    for child in _LISTINGS.iterdir():
        if not child.is_dir() or not child.name.startswith(prefix + "__"):
            continue
        rj = child / "record.json"
        if not rj.is_file():
            continue
        try:
            data = json.loads(rj.read_text())
        except Exception:
            continue
        for t in (data.get("function_shape") or {}).get("shape_tags") or []:
            if isinstance(t, str) and t.startswith("firm-"):
                tags.add(t[len("firm-"):])
    return tags


class T(unittest.TestCase):
    def _etls(self):
        return sorted((_REPO / "tools").glob("hackerman-etl-from-audit-firm-pdf-*.py"))

    @unittest.skipUnless(_LISTINGS.is_dir(), "listings tree not present")
    def test_firm_prefix_matches_listing_dirs_and_tag(self):
        """Every firm ETL whose prefix has listing dirs must have its FIRM_PREFIX
        equal to those listings' firm shape-tag (else parse_listing rejects all)."""
        checked = 0
        for etl in self._etls():
            prefix = _firm_prefix(etl)
            if not prefix:
                continue
            dirs = [c for c in _LISTINGS.iterdir()
                    if c.is_dir() and c.name.startswith(prefix + "__")]
            if not dirs:
                continue  # no listings for this firm in this tree - skip
            checked += 1
            tags = _listing_firm_tags(prefix)
            self.assertIn(prefix, tags,
                          f"{etl.name}: FIRM_PREFIX={prefix!r} not in listing "
                          f"firm-tags {sorted(tags)} - drift zeroes the drain")
        self.assertGreater(checked, 0, "no firm listings matched any ETL prefix")

    def test_cyfrin_and_oz_prefixes_are_the_fixed_values(self):
        cy = _firm_prefix(_REPO / "tools/hackerman-etl-from-audit-firm-pdf-cyfrin.py")
        oz = _firm_prefix(_REPO / "tools/hackerman-etl-from-audit-firm-pdf-openzeppelin.py")
        self.assertEqual(cy, "cyfrin-audit-reports")
        self.assertEqual(oz, "openzeppelin-contracts-audits")

    def test_parse_listing_reads_record_source_url(self):
        """The record_source_url fallback source line is present in both ETLs."""
        for name in ("cyfrin", "openzeppelin"):
            src = (_REPO / f"tools/hackerman-etl-from-audit-firm-pdf-{name}.py").read_text()
            self.assertIn("record_source_url", src,
                          f"{name} ETL missing record_source_url pdf_url fallback")


if __name__ == "__main__":
    unittest.main()
