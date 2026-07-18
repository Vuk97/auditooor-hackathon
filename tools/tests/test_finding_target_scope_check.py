"""test_finding_target_scope_check.py

Tests the finding-target-scope-check gate: is a finding's ROOT-CAUSE file an
enumerated in-scope TARGET or an in-repo OOS dependency? Regression is the strata
SharesCooldown case (root cause in a non-enumerated file -> flagged, not fileable
as primary). Anti-false-negative: flags for review, never a false-OOS hard-kill.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "finding-target-scope-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("finding_target_scope_check", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["finding_target_scope_check"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


G = _load()

# strata's enumerated in-scope targets (subset), NONE of which is SharesCooldown.
_ENUM = [
    {"file": "src/contracts/contracts/tranches/Tranche.sol", "function": "withdraw"},
    {"file": "src/contracts/contracts/tranches/base/cooldown/UnstakeCooldown.sol", "function": "finalize"},
    {"file": "src/contracts/contracts/tranches/Accounting.sol", "function": "totalAssets"},
]


def _ws(td: str, enum=_ENUM) -> pathlib.Path:
    ws = pathlib.Path(td)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    if enum is not None:
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps(r) for r in enum) + "\n", encoding="utf-8")
    return ws


def _finding(ws: pathlib.Path, body: str) -> pathlib.Path:
    p = ws / "finding.md"
    p.write_text(body, encoding="utf-8")
    return p


class TestFindingTargetScope(unittest.TestCase):
    def test_sharescooldown_oos_dependency_is_flagged(self):
        """The regression: root cause in SharesCooldown.sol (NOT enumerated), no
        in-scope impact target -> flagged not-fileable-as-primary."""
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            f = _finding(ws,
                "# Zero-nonce metaKey collision\n\n## Root Cause\n"
                "`SharesCooldown.sol:139` mints nonce=0 -> metaKey=bytes12(0) collides "
                "with the sentinel; `SharesCooldown.sol:539` never deletes it.\n")
            res = G.check_finding(f, ws)
            self.assertEqual(res["root_cause_file"], "SharesCooldown.sol")
            self.assertEqual(res["verdict"], "flag-root-cause-in-oos-dependency")
            self.assertFalse(G._permits(res["verdict"]))

    def test_inscope_root_cause_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            f = _finding(ws,
                "# MIN_SHARES last-withdrawer freeze\n\n## Root Cause\n"
                "`Tranche.sol:453` reverts when totalSupply < MIN_SHARES with no >0 arm.\n")
            res = G.check_finding(f, ws)
            self.assertEqual(res["root_cause_file"], "Tranche.sol")
            self.assertEqual(res["verdict"], "pass-root-cause-in-scope")

    def test_r38_in_scope_impact_target_cited_keeps(self):
        """OOS root cause but an enumerated in-scope file is cited as impact -> keep
        (R38 primacy-of-impact may apply); do NOT false-OOS-kill."""
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            f = _finding(ws,
                "# OOS-lib bug drains the vault\n\n## Root Cause\n"
                "`SomeLib.sol:10` miscomputes.\n\n## Impact\n"
                "Drains `Tranche.sol` deposits (permanent loss of in-scope funds).\n")
            res = G.check_finding(f, ws)
            self.assertEqual(res["verdict"], "pass-in-scope-impact-target-cited")
            self.assertTrue(G._permits(res["verdict"]))

    def test_rebuttal_permits(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            f = _finding(ws,
                "# Bug\n\n## Root Cause\n`OffScope.sol:5` bug.\n\n"
                "oos-target-rebuttal: operator confirms primary impact on in-scope bridge\n")
            res = G.check_finding(f, ws)
            self.assertEqual(res["verdict"], "pass-rebuttal")

    def test_no_enumeration_warn_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td, enum=None)  # no inscope_units.jsonl
            f = _finding(ws, "# Bug\n## Root Cause\n`OffScope.sol:5`\n")
            res = G.check_finding(f, ws)
            self.assertEqual(res["verdict"], "pass-no-enumeration")
            self.assertTrue(G._permits(res["verdict"]))

    def test_indeterminate_root_cause_warn_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _ws(td)
            f = _finding(ws, "# Bug with no file citations at all\n\nprose only\n")
            res = G.check_finding(f, ws)
            self.assertEqual(res["verdict"], "pass-indeterminate-root-cause")
            self.assertTrue(G._permits(res["verdict"]))


if __name__ == "__main__":
    unittest.main()
