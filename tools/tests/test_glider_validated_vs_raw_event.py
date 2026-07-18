#!/usr/bin/env python3
"""Lock test for the Base-Azul validated-vs-raw-event Glider query.

The Glider runtime is not a dependency of the auditooor test suite, so this
test keeps the contract deliberately static: the query must exist, parse as
Python, expose the intended metadata, and retain the raw-after-validated
heuristics that distinguish the Cantina M-2 shape from generic event checks.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
QUERY = (
    ROOT
    / "external"
    / "glider-query-db"
    / "queries"
    / "validated-vs-raw-event-emission.py"
)


@unittest.skipUnless(
    QUERY.exists(),
    f"external/glider-query-db not checked out: {QUERY}",
)
class ValidatedVsRawEventQueryTests(unittest.TestCase):
    def test_query_is_self_contained_and_targets_raw_event_bytes(self) -> None:
        self.assertTrue(QUERY.exists(), QUERY)
        source = QUERY.read_text()

        ast.parse(source, filename=str(QUERY))
        self.assertIn("@title: Validated State Replaced By Raw Event Bytes", source)
        self.assertIn("@severity: Medium", source)
        self.assertIn("abi.decode", source)
        self.assertIn("emit ", source)
        self.assertIn("raw_idx > emit_idx", source)
        self.assertIn("decode_idx < emit_idx", source)


if __name__ == "__main__":
    unittest.main()
