"""Tests for rust.panic.untrusted_ingress_unguarded_panic (class-B RU1).

Non-vacuous: a guarded ingress fn (len-check dominates) -> no hit; an
unguarded ingress fn (param -> [idx], no check) -> hit; a non-ingress local
-> no hit. A guard placed AFTER the sink (does not dominate) -> hit, so the
guard-dominance ORDERING check is load-bearing (mutating it flips a case).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent
RUNNER_PATH = TOOLS_DIR / "rust-detector-runner.py"
PID = "rust.panic.untrusted_ingress_unguarded_panic"


def _load_runner():
    spec = importlib.util.spec_from_file_location("rust_detector_runner",
                                                  RUNNER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner"] = mod
    spec.loader.exec_module(mod)
    return mod


# Guarded: len-check dominates the slice-index -> MUST NOT fire.
GUARDED = """
pub fn decode(bytes: &[u8]) -> Result<u32, ()> {
    if bytes.len() != 4 {
        return Err(());
    }
    let a = bytes[0];
    let b = bytes[3];
    Ok(a as u32 + b as u32)
}
"""

# Unguarded: ingress param slice-indexed with no dominating guard -> fire.
UNGUARDED = """
pub fn decode(input: &[u8]) -> u32 {
    let a = input[0];
    let b = input[7];
    a as u32 + b as u32
}
"""

# Non-ingress: a locally-computed Vec indexed, not a param -> no fire.
NON_INGRESS = """
pub fn compute() -> u8 {
    let scratch: Vec<u8> = vec![1, 2, 3];
    scratch[2]
}
"""

# Guard AFTER the sink (does not dominate) -> MUST fire. This is the case
# that flips if the dominance ORDERING check is mutated to mere presence.
GUARD_AFTER = """
pub fn decode(data: &[u8]) -> Result<u8, ()> {
    let first = data[9];
    if data.len() != 10 {
        return Err(());
    }
    Ok(first)
}
"""

# --- DEFECT 1(a): test-context FP guard ---------------------------------
# A #[rstest] fn with an ingress-typed fixture param indexes it -> the param
# is a CONST fixture, not attacker ingress, so it MUST NOT fire. The same body
# with the attribute stripped (see TEST_ATTR_STRIPPED) DOES fire -> proves the
# test-context skip is load-bearing, not a blanket suppressor.
TEST_ATTR_FN = """
#[rstest]
fn check_decode(data: &[u8]) -> u8 {
    data[9]
}
"""

TEST_ATTR_STRIPPED = """
fn check_decode(data: &[u8]) -> u8 {
    data[9]
}
"""

# A fn inside a `#[cfg(test)] mod` is test-context -> MUST NOT fire.
CFG_TEST_MOD_FN = """
#[cfg(test)]
mod tests {
    fn helper(input: &[u8]) -> u8 {
        input[3]
    }
}
"""

# --- DEFECT 1(b): outbound-serialize FP guard ---------------------------
# `payload` matches the ingress-NAME set but here it is a typed struct being
# SERIALIZED (outbound), and the `.unwrap()` is on the serialize result - not a
# reachable-panic-on-untrusted-INPUT. MUST NOT fire.
OUTBOUND_SERIALIZE = """
pub fn build_request(payload: RequestBody) -> Vec<u8> {
    serde_json::to_vec(&payload).unwrap()
}
"""

# Control: the same ingress name used as a genuine INBOUND index -> DOES fire
# (proves the outbound skip keys on serialize, not on the name `payload`).
INBOUND_PAYLOAD_INDEX = """
pub fn parse(payload: &[u8]) -> u8 {
    payload[9]
}
"""

# --- DEFECT 2: untethered early-Err over-suppression --------------------
# An UNRELATED early `return Err(())` (about `flag`, not `data`) must NOT
# suppress the later genuine `data[99]` ingress index -> MUST fire.
UNRELATED_ERR = """
pub fn parse(flag: bool, data: &[u8]) -> Result<u8, ()> {
    if !flag {
        return Err(());
    }
    Ok(data[99])
}
"""

# Non-vacuity witness for DEFECT 2: a `return Err` whose condition co-mentions
# the ingress var `data` (a real validity guard, no `.len()`) STILL suppresses.
# A naive "delete the Err arm" over-fix would wrongly fire this -> it must not.
TETHERED_ERR = """
pub fn parse(data: &[u8]) -> Result<u8, ()> {
    if data.first() != Some(&0xAA) {
        return Err(());
    }
    Ok(data[99])
}
"""

# An `ensure!` whose condition names the ingress var suppresses; an ensure!
# about an unrelated value does NOT.
ENSURE_TETHERED = """
pub fn parse(data: &[u8]) -> u8 {
    ensure!(data.first().is_some(), "bad");
    data[99]
}
"""

ENSURE_UNRELATED = """
pub fn parse(flag: bool, data: &[u8]) -> u8 {
    ensure!(flag, "bad");
    data[99]
}
"""


def _hit_count(mod, src: str) -> int:
    with tempfile.TemporaryDirectory() as ws:
        (Path(ws) / "fixture.rs").write_text(src, encoding="utf-8")
        summary = mod.scan_workspace(Path(ws))
        return summary["patterns"][PID]["hit_count"]


class UntrustedPanicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def test_guarded_no_hit(self):
        self.assertEqual(_hit_count(self.mod, GUARDED), 0,
                         "len-guard dominates the sink; must not fire")

    def test_unguarded_hits(self):
        self.assertGreaterEqual(_hit_count(self.mod, UNGUARDED), 1,
                                "unguarded ingress slice-index must fire")

    def test_non_ingress_local_no_hit(self):
        self.assertEqual(_hit_count(self.mod, NON_INGRESS), 0,
                         "a non-ingress local var must not fire")

    def test_guard_after_sink_still_hits(self):
        # Load-bearing: proves dominance (ordering) is checked, not presence.
        self.assertGreaterEqual(_hit_count(self.mod, GUARD_AFTER), 1,
                                "guard placed after the sink does not dominate")

    def test_hit_carries_advisory_contract(self):
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "f.rs").write_text(UNGUARDED, encoding="utf-8")
            summary = self.mod.scan_workspace(Path(ws))
            hit = summary["patterns"][PID]["hits"][0]
            self.assertEqual(hit["extra"]["candidate_status"], "default-to-kill")
            self.assertIn("impact_contract", hit["extra"])

    # -- DEFECT 1(a): test-context is not attacker ingress -----------------
    def test_rstest_fixture_param_no_hit(self):
        self.assertEqual(_hit_count(self.mod, TEST_ATTR_FN), 0,
                         "#[rstest] fixture param is const, not ingress")

    def test_test_attr_stripped_fires(self):
        # Non-vacuity: without the #[rstest] attr the SAME body fires, so the
        # skip is load-bearing (not a blanket suppressor of this shape).
        self.assertGreaterEqual(_hit_count(self.mod, TEST_ATTR_STRIPPED), 1,
                                "same body without the test attr must fire")

    def test_cfg_test_mod_no_hit(self):
        self.assertEqual(_hit_count(self.mod, CFG_TEST_MOD_FN), 0,
                         "a fn inside #[cfg(test)] mod is test-context")

    def test_tests_dir_path_no_hit(self):
        # A fn in a tests/ integration file is test-context even with no attr.
        with tempfile.TemporaryDirectory() as ws:
            p = Path(ws) / "tests" / "it.rs"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(TEST_ATTR_STRIPPED, encoding="utf-8")
            summary = self.mod.scan_workspace(Path(ws))
            self.assertEqual(summary["patterns"][PID]["hit_count"], 0)

    # -- DEFECT 1(b): outbound serialize is not inbound ingress ------------
    def test_outbound_serialize_no_hit(self):
        self.assertEqual(_hit_count(self.mod, OUTBOUND_SERIALIZE), 0,
                         "an outbound serialized payload is not ingress")

    def test_inbound_payload_index_fires(self):
        # Non-vacuity: the outbound skip keys on serialize, not the name.
        self.assertGreaterEqual(_hit_count(self.mod, INBOUND_PAYLOAD_INDEX), 1,
                                "a genuine inbound payload index must fire")

    # -- DEFECT 2: untethered early-Err must not over-suppress -------------
    def test_unrelated_early_err_still_fires(self):
        self.assertGreaterEqual(_hit_count(self.mod, UNRELATED_ERR), 1,
                                "an Err about a different value must not "
                                "suppress a later genuine ingress index")

    def test_tethered_err_still_suppresses(self):
        # Non-vacuity: a `return Err` co-mentioning the ingress var is a real
        # validity guard and STILL suppresses (a naive delete-the-arm over-fix
        # would wrongly fire this).
        self.assertEqual(_hit_count(self.mod, TETHERED_ERR), 0,
                         "an Err tethered to the ingress var dominates")

    def test_ensure_tethered_suppresses(self):
        self.assertEqual(_hit_count(self.mod, ENSURE_TETHERED), 0,
                         "an ensure! naming the ingress var dominates")

    def test_ensure_unrelated_still_fires(self):
        self.assertGreaterEqual(_hit_count(self.mod, ENSURE_UNRELATED), 1,
                                "an ensure! about a different value must not "
                                "suppress a later genuine ingress index")


if __name__ == "__main__":
    unittest.main()
