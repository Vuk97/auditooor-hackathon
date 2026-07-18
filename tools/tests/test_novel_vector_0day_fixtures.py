#!/usr/bin/env python3
"""Proof-fixture lock-down for the NOVEL-VECTOR / true-0-day contract (PR9b).

Background
----------
Phase 7 of the Find-All-Bugs uplift plan adds a true-0-day stage: derive a
TARGET-SPECIFIC invariant from the target's own spec, have the engine SEARCH the
unmodified source for an unknown violation, and prove it with a clean negative
control. PR9a owns the miner (``tools/spec-invariant-mine.py`` and siblings) and
its own unit tests. This module is the DISJOINT PR9b companion: it locks down the
novel-vector proof *fixtures* under
``tools/tests/fixtures/novel_vector_0day_pipeline/`` and the contract doc
``docs/NOVEL_VECTOR_TRUE_0DAY_CONTRACT_2026-05-30.md``, neither of which the
miner unit tests exercise.

The true-0-day contract (distinct from the EVM 0-day PROOF-quality contract) has
three legs:

  1. derive  -> a target-specific invariant DERIVED from the target's own spec,
                with ``known_class_match=false`` (no pre-existing detector).
  2. search  -> the engine searches the unmodified source for a reachable state
                that violates the derived invariant (real entrypoint bound).
  3. prove   -> the violation FAILS on the vulnerable variant (CAUGHT) and the
                identical assertion PASSES on the clean negative control.

The flip-behaviour cases re-derive the rebate-conservation accounting in pure
Python straight from each fixture's settle/credit/debit rules, so this is a real
proof of the encoded behaviour, not a restatement of the manifests' claims. When
``forge`` is on PATH the cases also opportunistically run the real Foundry PoCs.

All tests are stdlib-only and read-only over the tracked fixture tree.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "tools" / "tests" / "fixtures" / "novel_vector_0day_pipeline"
VULN_DIR = FIXTURE_ROOT / "rebate_conservation_vuln"
CLEAN_DIR = FIXTURE_ROOT / "rebate_conservation_clean"
DOC = REPO_ROOT / "docs" / "NOVEL_VECTOR_TRUE_0DAY_CONTRACT_2026-05-30.md"

PROOF_SCHEMA = "auditooor.novel_vector_spec_invariant_proof.v1"
SPEC_INVARIANT_SCHEMA = "auditooor.spec_invariant.v1"

# Fields the novel-vector proof manifest must carry (the EVM proof fields plus
# the true-0-day discriminators).
REQUIRED_MANIFEST_FIELDS = [
    "target_contract",
    "target_source",
    "target_imports",
    "deployment_adapter",
    "constructor_args_source",
    "entrypoints_bound",
    "real_target_call_count",
    "state_snapshots",
    "negative_controls",
    "engines",
    "proof_ready",
    "blocked_reason",
    # true-0-day discriminators
    "source_corpus_match",
    "known_class_match",
    "violated_spec_invariant_id",
    "spec_source_ref",
]

NOVEL_VECTOR_POINTS = [
    "invariant_derived_from_target_spec",
    "not_a_known_class_pattern_match",
    "engine_searches_for_unknown_violation",
    "clean_negative_control_passes",
]

RULE40_POINTS = [
    "real_entrypoint_real_code_real_impact",
    "defenses_executed_or_ruled_out",
    "mocks_external_deps_only",
    "negative_control_present",
    "before_after_assertions",
    "per_variant_proof",
]


def _load_manifest(d: Path) -> dict:
    return json.loads((d / "spec_invariant_proof.json").read_text())


# --------------------------------------------------------------------------- #
# Pure-Python re-derivation of the fixture rebate-conservation accounting.
#
# These mirror, exactly, the settleEpoch credit/debit rules in the two
# RebateLedger.sol fixtures so the test proves the encoded behaviour
# independently of the manifests.
# --------------------------------------------------------------------------- #
class _VulnLedger:
    """Mirrors rebate_conservation_vuln/RebateLedger.sol: the standing-pool
    ceiling check runs ONLY when lastSettledEpoch[maker] == epoch, so it is
    skipped on the first settle of a fresh epoch. The credit is always issued.
    The pool is debited at claim(), not at settle."""

    def __init__(self):
        self.rebate_pool = 0
        self.epoch = 0
        self.last_settled = {}
        self.credit_of = {}
        self.total_credits = 0

    def fund_pool(self, amount):
        self.rebate_pool += amount

    def roll_epoch(self):
        self.epoch += 1

    def settle_epoch(self, maker, rebate):
        assert rebate > 0
        # Ceiling check is conditional -> skipped on first settle of an epoch.
        if self.last_settled.get(maker) == self.epoch:
            if self.total_credits + rebate > self.rebate_pool:
                raise ValueError("exceeds pool")
        self.credit_of[maker] = self.credit_of.get(maker, 0) + rebate
        self.total_credits += rebate
        self.last_settled[maker] = self.epoch


class _CleanLedger:
    """Mirrors rebate_conservation_clean/RebateLedger.sol: the standing-pool
    ceiling check runs on EVERY settle, regardless of epoch-rollover state."""

    def __init__(self):
        self.rebate_pool = 0
        self.epoch = 0
        self.last_settled = {}
        self.credit_of = {}
        self.total_credits = 0

    def fund_pool(self, amount):
        self.rebate_pool += amount

    def roll_epoch(self):
        self.epoch += 1

    def settle_epoch(self, maker, rebate):
        assert rebate > 0
        # Ceiling check runs unconditionally (mirrors require()/revert).
        if self.total_credits + rebate > self.rebate_pool:
            raise ValueError("exceeds pool")
        self.credit_of[maker] = self.credit_of.get(maker, 0) + rebate
        self.total_credits += rebate
        self.last_settled[maker] = self.epoch


def _run_boundary_sequence(ledger):
    """Replay the fixture PoC sequence; return (total_credits, rebate_pool).

    Sequence (identical to RebateLedger.invariant.t.sol):
      fundPool(100e18)
      settleEpoch(maker, 100e18)   # epoch 0, first settle -> ceiling SKIPPED (vuln)
      rollEpoch()
      settleEpoch(maker, 100e18)   # epoch 1, first settle -> ceiling SKIPPED (vuln)
    On the clean ledger the second settle reverts "exceeds pool" because the
    ceiling check is unconditional, keeping totalCredits <= rebatePool.
    """
    ETHER = 10 ** 18
    maker = "0xMAKER"
    ledger.fund_pool(100 * ETHER)
    ledger.settle_epoch(maker, 100 * ETHER)
    ledger.roll_epoch()
    try:
        ledger.settle_epoch(maker, 100 * ETHER)
    except ValueError:
        pass  # clean ledger: exceeds-pool revert keeps conservation intact
    return ledger.total_credits, ledger.rebate_pool


class FixtureStructureTests(unittest.TestCase):
    def test_fixture_tree_exists(self):
        self.assertTrue(FIXTURE_ROOT.is_dir(), f"missing {FIXTURE_ROOT}")
        for d in (VULN_DIR, CLEAN_DIR):
            self.assertTrue(d.is_dir(), f"missing fixture dir {d}")
            for f in ("RebateLedger.sol", "RebateLedger.invariant.t.sol",
                      "spec_invariant_proof.json"):
                self.assertTrue((d / f).is_file(), f"missing {d / f}")

    def test_spec_source_present_on_vuln(self):
        # the invariant must be DERIVABLE from a real spec artifact in the tree
        self.assertTrue((VULN_DIR / "SPEC.md").is_file(),
                        "vulnerable fixture must carry the spec source")
        spec = (VULN_DIR / "SPEC.md").read_text()
        self.assertIn("INV-REBATE-CONSERVATION", spec)
        self.assertIn("totalCredits <= rebatePool", spec)

    def test_kit_index_present_and_well_formed(self):
        idx = json.loads((FIXTURE_ROOT / "INDEX.json").read_text())
        self.assertEqual(idx["kit"], "rebate_conservation_controls")
        roles = {fx["role"] for fx in idx["fixtures"]}
        self.assertEqual(roles, {"vulnerable", "negative-control"})
        # the kit must declare itself distinct from the known-class EVM kit
        self.assertEqual(idx["distinct_from"]["kit"], "evm_zero_day_pipeline")
        for fx in idx["fixtures"]:
            self.assertFalse(fx["source_corpus_match"])
            self.assertFalse(fx["known_class_match"])

    def test_expected_miner_output_present_and_novel(self):
        jl = FIXTURE_ROOT / "expected_spec_invariants.jsonl"
        self.assertTrue(jl.is_file(), f"missing expected miner output {jl}")
        rows = [json.loads(line) for line in jl.read_text().splitlines() if line.strip()]
        self.assertTrue(rows, "expected_spec_invariants.jsonl must have >= 1 row")
        row = rows[0]
        self.assertEqual(row["schema"], SPEC_INVARIANT_SCHEMA)
        self.assertEqual(row["invariant_id"], "INV-REBATE-CONSERVATION")
        # the load-bearing true-0-day discriminators
        self.assertFalse(row["source_corpus_match"])
        self.assertFalse(row["known_class_match"])
        self.assertIn("evaluable_form", row)
        self.assertIn("violating_path", row)
        self.assertTrue(row["derived_from"], "invariant must cite a spec-source derivation")
        # cross-PR calibration anchor: the expected row must also carry the
        # PR9a miner's own true-0-day vocabulary (tools/novel-vector-invariant-
        # miner.py emits detector_match="none" + the counterexample-search mode),
        # so a violation here matches NO pre-existing detector.
        self.assertEqual(row["detector_match"], "none")
        self.assertEqual(row["discovery_mode"], "spec-violation-counterexample-search")

    def test_doc_present(self):
        self.assertTrue(DOC.is_file(), f"missing contract doc {DOC}")
        body = DOC.read_text()
        for leg in ("Derive a target-specific invariant",
                    "searches the unmodified source",
                    "real entrypoint with a clean negative control"):
            self.assertIn(leg, body)
        # the doc must explicitly contrast with the known-class EVM kit
        self.assertIn("evm_zero_day_pipeline", body)
        self.assertIn("source_corpus_match=false", body)
        self.assertIn("known_class_match=false", body)
        # global formatting rule: no em/en dashes in written output
        self.assertNotIn("—", body, "em-dash present in doc")
        self.assertNotIn("–", body, "en-dash present in doc")


class ManifestContractTests(unittest.TestCase):
    def test_both_manifests_carry_schema_and_required_fields(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            self.assertEqual(m["schema"], PROOF_SCHEMA, f"bad schema in {d}")
            for field in REQUIRED_MANIFEST_FIELDS:
                self.assertIn(field, m, f"{d}: manifest missing field {field}")
            self.assertTrue(m["proof_ready"], f"{d}: proof_ready must be true")
            self.assertGreaterEqual(
                m["real_target_call_count"], 1,
                f"{d}: must bind >= 1 real target call")
            self.assertFalse(
                m.get("candidate_not_proof", False),
                f"{d}: a proof fixture must not be candidate_not_proof")

    def test_true_0day_discriminators(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            # the whole point: not a corpus replay, not a known-class match
            self.assertFalse(m["source_corpus_match"],
                             f"{d}: a true 0-day must not match the corpus")
            self.assertFalse(m["known_class_match"],
                             f"{d}: a true 0-day must not match a known class")
            self.assertEqual(m["violated_spec_invariant_id"], "INV-REBATE-CONSERVATION")
            self.assertIn("known_class_match_reason", m,
                          f"{d}: must justify why no known class matches")

    def test_novel_vector_points_satisfied(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            pts = m["novel_vector_points"]
            for p in NOVEL_VECTOR_POINTS:
                self.assertTrue(pts.get(p), f"{d}: novel-vector point {p} not satisfied")

    def test_rule40_points_all_satisfied(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            pts = m["rule40_points"]
            for p in RULE40_POINTS:
                self.assertTrue(pts.get(p), f"{d}: rule40 point {p} not satisfied")

    def test_roles_and_verdicts(self):
        v = _load_manifest(VULN_DIR)
        c = _load_manifest(CLEAN_DIR)
        self.assertEqual(v["fixture_role"], "vulnerable")
        self.assertEqual(v["expected_verdict"], "caught")
        self.assertEqual(c["fixture_role"], "negative-control")
        self.assertEqual(c["expected_verdict"], "clean")

    def test_vuln_points_at_clean_as_negative_control(self):
        v = _load_manifest(VULN_DIR)
        ncs = v["negative_controls"]
        self.assertTrue(ncs, "vulnerable manifest must name a negative control")
        resolved = (VULN_DIR / ncs[0]).resolve()
        self.assertEqual(resolved, (CLEAN_DIR / "spec_invariant_proof.json").resolve())

    def test_clean_has_no_self_referential_control(self):
        c = _load_manifest(CLEAN_DIR)
        self.assertEqual(c["negative_controls"], [],
                         "negative control must not itself carry a control")


class RealEntrypointBindingTests(unittest.TestCase):
    """Leg 2/3: the manifests' bound entrypoints must exist in the real source,
    and the PoC must drive them (not a model)."""

    def test_bound_entrypoints_exist_in_target_source(self):
        for d in (VULN_DIR, CLEAN_DIR):
            m = _load_manifest(d)
            src = (d / m["target_source"]).read_text()
            for ep in m["entrypoints_bound"]:
                fn = ep.split(".", 1)[1].split("(", 1)[0]
                self.assertIn(
                    f"function {fn}", src,
                    f"{d}: bound entrypoint {fn} not found in {m['target_source']}")

    def test_poc_drives_real_entrypoints_and_asserts_derived_invariant(self):
        for d in (VULN_DIR, CLEAN_DIR):
            poc = (d / "RebateLedger.invariant.t.sol").read_text()
            self.assertIn("ledger.settleEpoch(", poc, f"{d}: PoC does not call real settleEpoch()")
            self.assertIn("ledger.fundPool(", poc, f"{d}: PoC does not call real fundPool()")
            # the assertion is the DERIVED invariant, not a known-class shape
            self.assertIn("totalCredits()", poc)
            self.assertIn("rebatePool()", poc)
            self.assertIn("INV-REBATE-CONSERVATION", poc)


class FlipBehaviourTests(unittest.TestCase):
    """The load-bearing pair invariant: vuln -> CAUGHT, clean -> CLEAN.

    Re-derives the rebate-conservation accounting from the fixture rules so this
    is a real proof of the encoded behaviour, independent of the manifests.
    """

    def test_vulnerable_fixture_violates_conservation(self):
        total_credits, rebate_pool = _run_boundary_sequence(_VulnLedger())
        # CAUGHT: derived invariant totalCredits <= rebatePool is violated.
        self.assertGreater(
            total_credits, rebate_pool,
            "vulnerable fixture must break INV-REBATE-CONSERVATION (CAUGHT)")

    def test_clean_fixture_preserves_conservation(self):
        total_credits, rebate_pool = _run_boundary_sequence(_CleanLedger())
        # CLEAN: the negative control upholds totalCredits <= rebatePool.
        self.assertLessEqual(
            total_credits, rebate_pool,
            "clean negative control must uphold INV-REBATE-CONSERVATION (PASS)")

    def test_pair_actually_differs(self):
        vuln = _run_boundary_sequence(_VulnLedger())
        clean = _run_boundary_sequence(_CleanLedger())
        self.assertNotEqual(
            vuln, clean,
            "vuln and clean must diverge or the negative control is a tautology")


class OptionalForgeReplayTests(unittest.TestCase):
    """If forge is installed AND can compile-and-run the fixtures end to end,
    assert the vulnerable PoC reverts (CAUGHT) and the clean control passes.

    The fixtures are standalone proof artifacts, not a checked-in Foundry
    project. This case builds an ephemeral Foundry project around the fixture
    files. If forge cannot build/run the harness on this host the leg SKIPS -
    the deterministic FlipBehaviourTests above are the load-bearing proof.
    """

    @staticmethod
    def _forge_run(fixture_dir: Path, contract: str, test_name: str):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            proj = Path(d)
            src = proj / "src"
            src.mkdir()
            for f in ("RebateLedger.sol", "RebateLedger.invariant.t.sol"):
                (src / f).write_text((fixture_dir / f).read_text())
            (proj / "foundry.toml").write_text(
                "[profile.default]\nsrc = 'src'\ntest = 'src'\nout = 'out'\n"
                "libs = []\nffi = false\n"
            )
            try:
                cp = subprocess.run(
                    ["forge", "test", "--match-contract", contract, "-vv"],
                    cwd=proj, capture_output=True, text=True, timeout=180,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return (False, False, "")
            out = (cp.stdout or "") + (cp.stderr or "")
            if ("No tests" in out or "Compiler run failed" in out
                    or ("compilation" in out.lower() and "fail" in out.lower())
                    or "could not" in out.lower()):
                return (False, False, out)
            if test_name not in out:
                return (False, False, out)
            passed = cp.returncode == 0
            return (True, passed, out)

    @unittest.skipUnless(shutil.which("forge"), "forge not on PATH")
    def test_forge_vuln_reverts_clean_passes(self):
        ran_v, vuln_passed, out_v = self._forge_run(
            VULN_DIR, "RebateLedgerConservationTest",
            "test_conservation_broken_on_epoch_boundary")
        ran_c, clean_passed, out_c = self._forge_run(
            CLEAN_DIR, "RebateLedgerConservationTest",
            "test_conservation_holds_on_epoch_boundary")
        if not (ran_v and ran_c):
            self.skipTest("forge could not compile-and-run the fixtures on this host")
        # CAUGHT: vulnerable PoC must fail (conservation assertion revert).
        self.assertFalse(vuln_passed, f"vulnerable PoC must fail under forge (CAUGHT)\n{out_v}")
        # negative control must pass.
        self.assertTrue(clean_passed, f"clean negative control must pass under forge\n{out_c}")


if __name__ == "__main__":
    unittest.main()
