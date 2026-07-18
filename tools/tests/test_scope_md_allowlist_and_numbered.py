#!/usr/bin/env python3
# <!-- r36-rebuttal: lane SCOPE-MD-ALLOWLIST-NUMBERED registered in commit message -->
"""Strata 2026-06-30: an Immunefi SCOPE.md with a NUMBERED in-scope target list
("1. tranches/Tranche.sol ...") parsed to ZERO in_scope_paths (_BULLET_RE only
matched -/*), and the in_scope DEFAULT was advisory-in-scope, so 46 OOS files
(Strategy=149 units, DiscreteAccounting, lens/, swap/) leaked into the worklist.

Two fixes pinned here:
  (1) _BULLET_RE matches numbered lists (1. / 2)) too.
  (2) is_path_in_scope flips the default to OOS when an explicit in-scope allowlist
      was declared (in_scope_paths non-empty); whole-repo docs (no enumerated paths)
      keep the advisory in-scope default unchanged.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scope-md-parser.py"


def _load():
    spec = importlib.util.spec_from_file_location("scope_md_parser", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["scope_md_parser"] = m  # dataclass needs the module registered
    spec.loader.exec_module(m)
    return m


smp = _load()

_ENUMERATED = """# SCOPE

## IN SCOPE (exactly 3 targets)
1. tranches/Tranche.sol - the meta vault
2. tranches/Accounting.sol - TVL calc
3. governance/ (DIR - all .sol)

## OUT OF SCOPE
- 51%/sybil/centralization
"""

_WHOLE_REPO = """# SCOPE

## In scope
Everything in this repo is in scope (no enumerated paths).

## Out of scope
- test files
"""


class ScopeAllowlistTest(unittest.TestCase):
    def _parse(self, text):
        d = Path(tempfile.mkdtemp(prefix="scope_")) / "SCOPE.md"
        d.write_text(text, encoding="utf-8")
        return smp.parse_scope_md(d)

    def test_numbered_in_scope_targets_extracted(self):
        mf = self._parse(_ENUMERATED)
        joined = " ".join(mf.in_scope_paths).lower()
        self.assertIn("tranches/tranche", joined)
        self.assertIn("tranches/accounting", joined)
        self.assertIn("governance", joined)

    def test_enumerated_allowlist_makes_unlisted_oos(self):
        mf = self._parse(_ENUMERATED)
        # an in-scope target -> in scope
        ok, _ = smp.is_path_in_scope("src/contracts/tranches/Tranche.sol", mf)
        self.assertTrue(ok)
        # an UNLISTED file (Strategy.sol) -> OOS under allowlist semantics
        oos, reason = smp.is_path_in_scope("src/contracts/tranches/Strategy.sol", mf)
        self.assertFalse(oos, reason)
        # discrete accounting must NOT be matched by the 'tranches/accounting' token
        oos2, _ = smp.is_path_in_scope("src/contracts/tranches/DiscreteAccounting.sol", mf)
        self.assertFalse(oos2)

    def test_whole_repo_doc_keeps_default_in_scope(self):
        mf = self._parse(_WHOLE_REPO)
        self.assertEqual(mf.in_scope_paths, [])
        ok, reason = smp.is_path_in_scope("src/anything/Foo.sol", mf)
        self.assertTrue(ok, "no enumerated allowlist -> advisory in-scope default unchanged")


if __name__ == "__main__":
    unittest.main(verbosity=2)
