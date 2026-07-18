#!/usr/bin/env python3
"""Regression guard for `make audit` memory-context forwarding semantics.

NBQ-006 requires the main audit entrypoint to expose/forward memory-context
strictness consistently with flow-gate behavior.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"


class MakeAuditDltApplicabilityWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.src = MAKEFILE.read_text(encoding="utf-8")

    def test_usage_mentions_memory_context_strict_flags(self) -> None:
        self.assertIn("REQUIRE_MEMORY_CONTEXT=1", self.src)
        self.assertIn("STRICT_MEMORY_CONTEXT=1", self.src)

    def test_short_circuit_memory_auto_link_honors_strict_mode(self) -> None:
        self.assertRegex(
            self.src,
            re.compile(
                r"failed to refresh memory requirements during freshness short-circuit"
                r".*REQUIRE_MEMORY_CONTEXT:-0.*STRICT_MEMORY_CONTEXT:-0.*exit \$\$mem_rc",
                re.DOTALL,
            ),
        )

    def test_short_circuit_memory_context_load_honors_strict_mode(self) -> None:
        self.assertRegex(
            self.src,
            re.compile(
                r"failed to refresh memory context receipt during freshness short-circuit"
                r".*REQUIRE_MEMORY_CONTEXT:-0.*STRICT_MEMORY_CONTEXT:-0.*exit \$\$mem_rc",
                re.DOTALL,
            ),
        )

    def test_audit_progress_invocation_forwards_memory_context_env(self) -> None:
        self.assertRegex(
            self.src,
            re.compile(
                r'REQUIRE_MEMORY_CONTEXT="\$\(REQUIRE_MEMORY_CONTEXT\)".*'
                r'STRICT_MEMORY_CONTEXT="\$\(STRICT_MEMORY_CONTEXT\)".*'
                r'python3 tools/audit-progress\.py',
                re.DOTALL,
            ),
        )

    def test_audit_summary_surfaces_mcp_receipt_and_engage_report_context(self) -> None:
        self.assertIn(".auditooor/memory_context_receipt.json", self.src)
        self.assertIn('make engage-report-mcp-feed WS=\\"$(_WS_RESOLVED)\\"', self.src)
        self.assertIn("json.dumps", self.src)


if __name__ == "__main__":
    unittest.main()
