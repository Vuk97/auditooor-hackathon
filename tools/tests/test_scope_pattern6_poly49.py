#!/usr/bin/env python3
"""capability-v3 iter-005 T3 — scope-reasoner pattern #6 (`attribution_reconstructible`).

Locks the 6th out-of-scope pattern introduced for POLY-49-class
rejections (`User attribution reconstructible from subsequent
ERC1155.TransferBatch in same tx` and siblings: off-chain interpretation
required, oracle-dependent impact, L2 sequencer-state correlation,
subjective market intent).

Hermetic: every scenario is either (a) a committed synthetic fixture
under `tools/tests/fixtures/scope_reasoner/`, or (b) a fixture dropped
into a `tempfile.TemporaryDirectory` with no SCOPE.md to exercise the
`cannot_judge` codepath. No network calls, no mutation of real
submissions.

Three tests:

1. `test_poly49_fixture_flagged_as_likely_oos_attribution_reconstructible`
   — the committed POLY-49 synthetic fixture fires the
   `attribution_reconstructible` pattern. Primary positive gate.

2. `test_in_scope_fixture_returns_in_scope`
   — the companion in-scope counter-fixture (a real fund-loss draft
   with on-chain attribution) does NOT fire ANY pattern. Zero-FP lock
   for pattern #6.

3. `test_missing_scope_fixture_returns_cannot_judge`
   — when the draft is isolated in a tmp directory with no ancestor
   SCOPE.md, the reasoner returns an empty `scope_file` and a flag
   with `severity="advisory"`, which Check #23 translates to
   `cannot_judge`. Locks the honest-missing-context behaviour.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REASONER = ROOT / "tools" / "scope-reasoner.py"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "scope_reasoner"

POLY49_FIXTURE = FIXTURES / "poly49_attribution_reconstructible_fixture.md"
IN_SCOPE_COUNTERFIXTURE = FIXTURES / "poly49_in_scope_counterfixture.md"
CANNOT_JUDGE_FIXTURE = FIXTURES / "poly49_cannot_judge_fixture.md"


def _run_reasoner(draft: Path, scope: Path | None = None) -> dict:
    cmd = [sys.executable, str(REASONER), "--draft", str(draft)]
    if scope is not None:
        cmd += ["--scope", str(scope)]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(proc.stdout)


class Pattern6Poly49Tests(unittest.TestCase):
    def test_poly49_fixture_flagged_as_likely_oos_attribution_reconstructible(
        self,
    ) -> None:
        """Primary lock: the synthetic POLY-49 fixture must fire the
        `attribution_reconstructible` pattern via the reasoner. This
        guards against silent pattern removal / regex breakage and
        locks the name the Check #23 failure code composes with
        (`pattern=attribution_reconstructible`).
        """
        self.assertTrue(POLY49_FIXTURE.exists(), POLY49_FIXTURE)

        result = _run_reasoner(POLY49_FIXTURE)
        names = [f["pattern_name"] for f in result.get("flags", [])]
        self.assertIn(
            "attribution_reconstructible",
            names,
            f"expected 'attribution_reconstructible' in {names} (raw: {result})",
        )

        # Every flag entry for this pattern must carry the declared MEDIUM
        # severity and cite the POLY-49 reference.
        attr_flags = [
            f for f in result["flags"] if f["pattern_name"] == "attribution_reconstructible"
        ]
        self.assertEqual(len(attr_flags), 1, attr_flags)
        self.assertEqual(attr_flags[0]["declared_severity"], "MEDIUM", attr_flags[0])
        self.assertIn("POLY-49", attr_flags[0]["reference"], attr_flags[0])

    def test_in_scope_fixture_returns_in_scope(self) -> None:
        """Zero-FP lock. A legitimate fund-loss draft with purely
        on-chain attribution must NOT fire pattern #6 (nor any other
        pattern). If this test ever regresses the reasoner's false-
        positive rate on attribution-adjacent claims, it means the
        pattern is over-eager on generic words like `attribution` /
        `subsequent` / `off-chain`.
        """
        self.assertTrue(IN_SCOPE_COUNTERFIXTURE.exists(), IN_SCOPE_COUNTERFIXTURE)

        result = _run_reasoner(IN_SCOPE_COUNTERFIXTURE)
        names = [f["pattern_name"] for f in result.get("flags", [])]
        self.assertNotIn(
            "attribution_reconstructible",
            names,
            f"false positive: {names} on in-scope counter-fixture (raw: {result})",
        )
        # Stricter lock: the whole flag set is empty on this fixture.
        # If any other pattern starts flagging this draft, we need to
        # audit why — the counter-fixture is designed to be clean.
        self.assertEqual(
            result.get("flags", []),
            [],
            f"unexpected flags on in-scope counter-fixture: {result}",
        )
        self.assertEqual(result.get("risk_level"), "none", result)

    def test_missing_scope_fixture_returns_cannot_judge(self) -> None:
        """Honest-missing-context lock. When a draft firing pattern #6
        has no ancestor SCOPE.md, the reasoner returns an empty
        `scope_file` string. Check #23 consumes that shape as
        `cannot_judge` — never upgrading to `likely_oos`.

        We isolate the fixture into a tmp directory so `derive_scope_path`
        cannot walk up into the real repo and find THIS repo's SCOPE.md
        (or similar). The copy in tmp is the only filesystem write; no
        real submission is touched.
        """
        self.assertTrue(CANNOT_JUDGE_FIXTURE.exists(), CANNOT_JUDGE_FIXTURE)

        with tempfile.TemporaryDirectory() as tmp:
            isolated = Path(tmp) / "draft.md"
            shutil.copyfile(CANNOT_JUDGE_FIXTURE, isolated)

            result = _run_reasoner(isolated)
            # No SCOPE.md anywhere above `isolated` → scope_file empty.
            self.assertEqual(result.get("scope_file", ""), "", result)
            # Pattern still fires — but with severity=advisory
            # (equivalent to Check #23's `cannot_judge`/advisory lane).
            names = [f["pattern_name"] for f in result.get("flags", [])]
            self.assertIn("attribution_reconstructible", names, result)
            attr_flags = [
                f
                for f in result["flags"]
                if f["pattern_name"] == "attribution_reconstructible"
            ]
            self.assertEqual(len(attr_flags), 1, attr_flags)
            self.assertEqual(attr_flags[0]["severity"], "advisory", attr_flags[0])
            self.assertFalse(attr_flags[0]["scope_clause_hit"], attr_flags[0])
            # And the top-level risk_level stays at `advisory`, never
            # `likely-OOS` (no clause correlation possible).
            self.assertEqual(result.get("risk_level"), "advisory", result)


if __name__ == "__main__":
    unittest.main()
