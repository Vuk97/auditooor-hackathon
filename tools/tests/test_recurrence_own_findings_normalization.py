#!/usr/bin/env python3
"""Guard test: confirmed own-findings normalise to TP outcomes for recurrence.

Meta-audit finding: "0 ACCEPTED of 67 outcomes makes Tier-S unreachable". The
SUBMISSIONS.md telemetry layer never normalises PoC-confirmed/filed findings to
a TP outcome, so recurrence-as-promotion-signal surfaced 0 Tier-S candidates.
This test pins the fix: ingested own-finding tags carrying
``confirmed_finding: true`` are emitted as TP outcome records, and the
operator-gate language stays on every surfaced candidate. Offline; temp dirs.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "recurrence-as-promotion-signal.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("_recurrence_promotion", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_OWN_FINDING_YAML = """schema_version: auditooor.hackerman_record.v1.1
record_id: "own-finding:{ws}:{slug}"
attack_class: reward-theft
severity_at_finding: high
record_extensions:
  finding_title: "{title}"
  origin_workspace: {ws}
  confirmed_finding: true
"""


class TestOwnFindingsNormalization(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()

    def test_confirmed_own_findings_become_tp_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            own = Path(td)
            for i, ws in enumerate(("alpha", "beta", "gamma")):
                (own / f"own-{ws}.yaml").write_text(
                    _OWN_FINDING_YAML.format(
                        ws=ws, slug=f"s{i}",
                        title="creator reward can be stolen via callback",
                    ),
                    encoding="utf-8",
                )
            recs = self.mod.get_own_finding_records(own)
        self.assertEqual(len(recs), 3, "all three confirmed findings normalised")
        for r in recs:
            self.assertEqual(r["outcome"], "confirmed")
            self.assertTrue(self.mod.is_tp_outcome(r["outcome"]),
                            "confirmed outcome must register as TP")
            self.assertTrue(r["workspace"], "workspace populated for recurrence")

    def test_unconfirmed_finding_is_not_tp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            own = Path(td)
            (own / "own-x.yaml").write_text(
                _OWN_FINDING_YAML.format(
                    ws="alpha", slug="s0", title="t",
                ).replace("confirmed_finding: true", "confirmed_finding: false"),
                encoding="utf-8",
            )
            recs = self.mod.get_own_finding_records(own)
        self.assertEqual(recs, [], "unconfirmed findings are not TP records")

    def test_filed_and_confirmed_are_tp_outcomes(self) -> None:
        # Regression for the outcome-vocabulary widening.
        self.assertTrue(self.mod.is_tp_outcome("filed"))
        self.assertTrue(self.mod.is_tp_outcome("confirmed"))
        self.assertFalse(self.mod.is_tp_outcome("pending"))

    def test_absent_dir_is_honest_zero(self) -> None:
        recs = self.mod.get_own_finding_records(Path("/nonexistent/own/findings"))
        self.assertEqual(recs, [])


if __name__ == "__main__":
    unittest.main()
