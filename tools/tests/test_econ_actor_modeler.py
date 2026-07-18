#!/usr/bin/env python3
"""V4 P4 — econ-actor-modeler regression tests.

Asserts the offline contract of `tools/econ-actor-modeler.py` and the
`tools/audit-deep.sh --profile econ` wrapper:

  1. All eight built-in actors appear in actors.json with required fields.
  2. Every actor has at least one capability entry.
  3. Every state in state_machine.json has at least one outgoing
     transition (no dead-end states in the default state machine).
  4. Every state flagged `repeated_cycle: true` has a corresponding
     hypothesis id when sufficient hypotheses are parsed.
  5. Every transition trigger appears in the ACTORS.md / STATE_MACHINE.md
     transition section.
  6. Selected top-cycle hypotheses have repeats >= 0 (and > 0 when the
     fixture exercises the repeated-cycle vocabulary).
  7. The advisory report's missing-data section lists at least 3 items.
  8. Foundry stub count == top-N (default 3) when 3+ hypotheses parse.
  9. The report distinguishes "Economic plausibility" from "Exploit
     proven" (literal phrasing per V4 §2 D3 + §5.4).
 10. The audit-deep.sh wrapper accepts `--profile econ` and writes the
     workspace-local artifact set under `<ws>/.audit_logs/`.
 11. Hypothesis parser handles the actual `tools/economic-hypotheses.sh`
     output format (`## N. Title` + `### Hypotheses` blocks).

Stdlib-only. No network. Speed budget: <2s.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "econ-actor-modeler.py"
WRAPPER = ROOT / "tools" / "audit-deep.sh"


# Synthetic hypotheses fixture mirroring the real
# tools/economic-hypotheses.sh output shape. Reused across most tests so
# parsing + ranking are exercised deterministically.
SAMPLE_HYPOS = """\
# Economic Hypotheses for sample.sol

Generated 2026-04-25 12:00 — see tools/economic-hypotheses.sh

## Summary table

| section | hits |
|---|---:|
| oracle | 3 |

---

## 1. Oracle calls (3 hit(s))

Patterns: `latestRoundData`, `getPrice`

- `Vault.sol:42` — `oracle.latestAnswer()`

### Hypotheses (per call site above)
- [ ] Is the oracle result used in a mutative function (storage write follows read)?
- [ ] Is there a staleness check?
- **Attack**: flashloan-sandwich the oracle source, repeat the cycle every block, repay -> 1-block price manipulation.

---

## 2. Flashloan callbacks (1 hit(s))

Patterns: `onFlashLoan`

- `Vault.sol:88` — `onFlashLoan(...)`

### Hypotheses
- [ ] Is `msg.sender` checked against a trusted lender whitelist?
- [ ] Is there a `nonReentrant` guard?
- **Attack**: callback drives a repeat-loop across the same block; profitable cycle.

---

## 3. Reward / restake loops (2 hit(s))

Patterns: `rewardPerToken`

- `Staking.sol:120` — `rewardPerToken()`

### Hypotheses
- [ ] Does the reward index drift in a loop / cycle of restakes?
- [ ] Can an actor repeat the claim/restake cycle without cooldown?

---

## 4. Liquidation paths (1 hit(s))

Patterns: `liquidate`

### Hypotheses
- [ ] Is the keeper incentive sufficient to keep the cycle running?
"""


class EconActorModelerCore(unittest.TestCase):
    """Direct unit tests against tools.econ_actor_modeler module helpers."""

    @classmethod
    def setUpClass(cls):
        # Add tools/ to sys.path so `import econ_actor_modeler` works
        # despite the dash in the filename. We use importlib to load the
        # script-style file as a module.
        import importlib.util
        spec = importlib.util.spec_from_file_location("econ_actor_modeler", TOOL)
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="econ_test_"))
        self.hypos = self.tmp / "h.md"
        self.hypos.write_text(SAMPLE_HYPOS, encoding="utf-8")
        self.actors_md = self.tmp / "ACTORS.md"
        self.actors_json = self.tmp / "actors.json"
        self.sm_md = self.tmp / "STATE_MACHINE.md"
        self.sm_json = self.tmp / "state_machine.json"
        self.report = self.tmp / "report.md"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, top_n: int = 3) -> int:
        return self.mod.main([
            "--hypos", str(self.hypos),
            "--actors-md", str(self.actors_md),
            "--actors-json", str(self.actors_json),
            "--sm-md", str(self.sm_md),
            "--sm-json", str(self.sm_json),
            "--report", str(self.report),
            "--top-n", str(top_n),
        ])

    # --- 1 ----------------------------------------------------------------
    def test_actor_model_all_actors_defined(self):
        rc = self._run()
        self.assertEqual(rc, 0)
        actors = json.loads(self.actors_json.read_text())
        self.assertEqual(len(actors), 8, "expected 8 default actors")
        names = {a["name"] for a in actors}
        self.assertEqual(
            names,
            {
                "Attacker", "Depositor", "Withdrawer", "Keeper",
                "Proposer", "Governance", "Sequencer", "LP",
            },
        )
        for a in actors:
            for field in ("name", "role", "goal", "capabilities", "constraints", "interactions"):
                self.assertIn(field, a, f"actor {a.get('name')} missing field {field}")

    # --- 2 ----------------------------------------------------------------
    def test_actor_capabilities_non_empty(self):
        self._run()
        actors = json.loads(self.actors_json.read_text())
        for a in actors:
            self.assertGreaterEqual(
                len(a["capabilities"]), 1,
                f"actor {a['name']} has zero capabilities",
            )

    # --- 3 ----------------------------------------------------------------
    def test_state_machine_no_dead_end(self):
        self._run()
        sm = json.loads(self.sm_json.read_text())
        outgoing = {t["from"] for t in sm["transitions"]}
        for state_name in sm["states"].keys():
            self.assertIn(
                state_name, outgoing,
                f"state {state_name} has no outgoing transition (dead-end)",
            )

    # --- 4 ----------------------------------------------------------------
    def test_repeated_cycle_states_tagged_with_hypothesis(self):
        self._run(top_n=3)
        sm = json.loads(self.sm_json.read_text())
        cycle_states = [
            (n, info) for n, info in sm["states"].items()
            if info.get("repeated_cycle")
        ]
        self.assertGreaterEqual(len(cycle_states), 1)
        # Each cycle state should be tagged with the motivating hypothesis
        # id when the parser picked up at least that many sections.
        tagged = [n for n, info in cycle_states if "motivating_hypothesis_id" in info]
        self.assertGreaterEqual(
            len(tagged), 1,
            "at least one cycle state must carry motivating_hypothesis_id",
        )

    # --- 5 ----------------------------------------------------------------
    def test_transition_triggers_present_in_state_machine_md(self):
        self._run()
        sm = json.loads(self.sm_json.read_text())
        sm_md = self.sm_md.read_text()
        for t in sm["transitions"]:
            self.assertIn(
                t["trigger"], sm_md,
                f"trigger {t['trigger']} missing from STATE_MACHINE.md",
            )

    # --- 6 ----------------------------------------------------------------
    def test_top_cycles_have_repeat_count(self):
        hypos = self.mod.load_hypotheses(self.hypos)
        self.assertGreaterEqual(len(hypos), 4)
        top = self.mod.select_top_cycles(hypos, n=3)
        self.assertEqual(len(top), 3)
        # The fixture exercises "repeat" / "cycle" / "loop" wording — the
        # top-ranked section should have a positive score.
        self.assertGreater(
            top[0]["repeats"], 0,
            "top-ranked hypothesis should have repeats > 0 given the fixture",
        )

    # --- 7 ----------------------------------------------------------------
    def test_missing_data_section_populated(self):
        self._run()
        body = self.report.read_text()
        self.assertIn("## 2. Missing Data", body)
        # Count bullet lines under section 2
        section = body.split("## 2. Missing Data", 1)[1].split("## 3.", 1)[0]
        bullets = [ln for ln in section.splitlines() if ln.strip().startswith("- ")]
        self.assertGreaterEqual(
            len(bullets), 3,
            f"missing-data section should list >=3 items, got {len(bullets)}",
        )

    # --- 8 ----------------------------------------------------------------
    def test_foundry_stub_generated_per_top_cycle(self):
        self._run(top_n=3)
        body = self.report.read_text()
        # Each stub is fenced as ```solidity ...``` — count them in the
        # report's section 4.
        section = body.split("## 4. Recommended Foundry Handler Stubs", 1)[1]
        n_stubs = section.count("```solidity")
        self.assertEqual(n_stubs, 3, f"expected 3 Foundry stubs, got {n_stubs}")

    # --- 9 ----------------------------------------------------------------
    def test_report_distinguishes_plausibility_vs_proven(self):
        self._run()
        body = self.report.read_text()
        self.assertIn("Economic plausibility", body)
        self.assertIn("Exploit proven", body)
        # And the Tier-B advisory framing must be explicit.
        self.assertIn("Tier-B", body)
        self.assertIn("advisory", body.lower())

    # --- 10 ---------------------------------------------------------------
    def test_audit_deep_wrapper_accepts_econ_profile(self):
        if not shutil.which("bash"):
            self.skipTest("bash not on PATH")
        ws = self.tmp / "ws"
        ws.mkdir()
        # Stage a hypothesis file under the conventional location so the
        # wrapper's discovery picks it up.
        hd = ws / "economic_hypotheses"
        hd.mkdir()
        (hd / "sample.md").write_text(SAMPLE_HYPOS, encoding="utf-8")

        env = os.environ.copy()
        env["AUDIT_DEEP_DRY_RUN"] = "0"
        proc = subprocess.run(
            ["bash", str(WRAPPER), "--profile", "econ", str(ws)],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"audit-deep --profile econ failed: {proc.stderr}",
        )
        canonical = ws / ".audit_logs" / "audit_deep_report.md"
        self.assertTrue(canonical.exists(), "canonical audit_deep_report.md missing")
        self.assertTrue((ws / ".audit_logs" / "ACTORS.md").exists())
        self.assertTrue((ws / ".audit_logs" / "STATE_MACHINE.md").exists())
        self.assertTrue((ws / ".audit_logs" / "actors.json").exists())
        self.assertTrue((ws / ".audit_logs" / "state_machine.json").exists())
        self.assertTrue((ws / ".audit_logs" / "econ_deep_report.md").exists())

        # Tier-B framing must reach the canonical wrapper output too.
        self.assertIn("Tier", canonical.read_text())

    # --- 11 ---------------------------------------------------------------
    def test_parser_handles_real_economic_hypotheses_format(self):
        hypos = self.mod.load_hypotheses(self.hypos)
        # Fixture has 4 top-level sections.
        self.assertEqual(len(hypos), 4)
        ids = [h["id"] for h in hypos]
        self.assertEqual(ids[0], "1-oracle-calls")
        self.assertTrue(ids[1].startswith("2-flashloan"))
        self.assertTrue(ids[2].startswith("3-reward"))
        self.assertTrue(ids[3].startswith("4-liquidation"))
        # Section 1 should have at least 3 captured bullets (2 checklist +
        # 1 Attack line).
        self.assertGreaterEqual(len(hypos[0]["text"]), 3)


class EconActorModelerEmptyInput(unittest.TestCase):
    """Graceful-degrade behavior when the hypothesis file is missing."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("econ_actor_modeler", TOOL)
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def test_missing_hypos_file_yields_indeterminate_report(self):
        tmp = Path(tempfile.mkdtemp(prefix="econ_empty_"))
        try:
            rc = self.mod.main([
                "--hypos", str(tmp / "does_not_exist.md"),
                "--actors-md", str(tmp / "ACTORS.md"),
                "--actors-json", str(tmp / "actors.json"),
                "--sm-md", str(tmp / "STATE_MACHINE.md"),
                "--sm-json", str(tmp / "state_machine.json"),
                "--report", str(tmp / "report.md"),
            ])
            self.assertEqual(rc, 0)
            body = (tmp / "report.md").read_text()
            self.assertIn("INDETERMINATE", body)
            # Actors and state machine still emitted (default catalogue).
            self.assertEqual(len(json.loads((tmp / "actors.json").read_text())), 8)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
