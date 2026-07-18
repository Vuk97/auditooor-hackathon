#!/usr/bin/env python3
"""R4-e13 cross-client-consensus-divergence - non-vacuous regression.

Pins tools/cross-client-consensus-divergence.py, a GENERAL consensus-
enforcement screen (never a bug shape). The screened invariant:

    "Every consensus-critical spec rule implemented by a client of a shared
     external spec is DIFFERENTIALLY EXERCISED (identical input -> equal
     accept/reject + post-state) against a co-equal implementation. A rule x
     client-pair cell never differentially exercised is a never-enumerated
     matrix cell = false-GREEN."

Every emitted cell is verdict="needs-fuzz" (advisory-first, NO auto-credit,
never fail-closed by default).

Fixtures are built in a tmp tree (no shared fixture dir touched):
  - PLANTED POSITIVE : a consensus-critical rule site (state-transition) with
    NO differential harness -> the screen fires exactly that cell.
  - GUARDED NEGATIVE : the SAME rule site plus a shared-spec differential
    harness (StateTest post-state oracle) -> silent.
  - NEUTRALIZE CORE  : force the differential-exercise predicate to always-True
    -> the planted positive MUST stop firing (proves the predicate is load-
    bearing, not vacuous). Symmetrically neutralize the rule-site classifier.

Mutation-verify anchor (real fleet, read-only, temp copy): see the module
docstring for cross-client-consensus-divergence and the workflow schema -
go-ethereum tests/state_test.go is the shared-spec state-transition oracle;
deleting it on a TEMP COPY flips state-transition/gas/tx-validity from
exercised -> never-enumerated and the screen fires.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "cross_client_consensus_divergence",
        TOOLS / "cross-client-consensus-divergence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


R4 = _load_tool()


# --- fixture source snippets (general Go/consensus shapes) ------------------

# A consensus-critical STATE-TRANSITION rule site (non-test source).
_STATE_TRANSITION_SRC = """\
package core

// ApplyMessage runs the state transition for a single message and returns
// the post-state execution result. Consensus-critical.
func ApplyMessage(evm *EVM, msg *Message, gp *GasPool) (*ExecutionResult, error) {
    st := NewStateTransition(evm, msg, gp)
    return st.Execute()
}

func (st *StateTransition) Execute() (*ExecutionResult, error) {
    return &ExecutionResult{}, nil
}
"""

# An ENCODING-canonicalization rule site (non-test source).
_ENCODING_SRC = """\
package rlp

func EncodeRLP(w io.Writer, val interface{}) error { return nil }
func DecodeBytes(b []byte, val interface{}) error { return nil }
"""

# A shared-external-spec STATE differential harness: identical input ->
# equal post-state root + expected accept/reject. Exercises the state-
# transition / gas / tx-validity trio.
_STATE_DIFF_HARNESS = """\
package tests

// StateTest replays the shared ethereum/tests StateTests fixtures and asserts
// the post-state root and ExpectException (accept/reject) match the spec.
func TestState(t *testing.T) {
    var test StateTest
    got := execStateTest(t, test)
    if got.Root != test.expectedRoot {
        t.Fatalf("post-state root mismatch: divergence candidate")
    }
}
"""


def _write(base: pathlib.Path, rel: str, content: str):
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _mk_tree(files: dict[str, str]) -> pathlib.Path:
    base = pathlib.Path(tempfile.mkdtemp(prefix="r4_"))
    for rel, content in files.items():
        _write(base, rel, content)
    return base


class TestCrossClientConsensusDivergence(unittest.TestCase):

    def setUp(self):
        self._trees: list[pathlib.Path] = []

    def tearDown(self):
        import shutil
        for t in self._trees:
            shutil.rmtree(t, ignore_errors=True)

    def _scan(self, files):
        base = _mk_tree(files)
        self._trees.append(base)
        return R4.scan(str(base))

    # --- planted positive ---------------------------------------------------
    def test_planted_positive_fires_needs_fuzz(self):
        cells, acc, harnesses = self._scan({
            "geth/core/state_transition.go": _STATE_TRANSITION_SRC,
        })
        self.assertEqual(acc["differential_harnesses"], 0)
        self.assertGreaterEqual(acc["rule_sites"], 1)
        self.assertIn("state-transition", acc["categories_never_exercised"])
        st_cells = [c for c in cells if c["rule_category"] == "state-transition"]
        self.assertTrue(st_cells, "an unexercised state-transition rule must fire")
        for c in st_cells:
            self.assertEqual(c["verdict"], "needs-fuzz")
            self.assertFalse(c["auto_credit"])

    # --- guarded negative ---------------------------------------------------
    def test_guarded_negative_is_silent(self):
        cells, acc, harnesses = self._scan({
            "geth/core/state_transition.go": _STATE_TRANSITION_SRC,
            "geth/tests/state_test.go": _STATE_DIFF_HARNESS,
        })
        self.assertEqual(acc["differential_harnesses"], 1)
        self.assertIn("state-transition", acc["categories_exercised"])
        st_cells = [c for c in cells if c["rule_category"] == "state-transition"]
        self.assertEqual(st_cells, [],
                         "a differentially-exercised rule must NOT fire")

    # --- never-enumerated CATEGORY (uncovered category present in source) ----
    def test_uncovered_category_flagged_even_with_a_harness(self):
        # State harness present (covers state trio) but ENCODING rule sites have
        # no encoding differential -> encoding stays a never-enumerated cell.
        cells, acc, _ = self._scan({
            "geth/core/state_transition.go": _STATE_TRANSITION_SRC,
            "geth/rlp/encode.go": _ENCODING_SRC,
            "geth/tests/state_test.go": _STATE_DIFF_HARNESS,
        })
        self.assertIn("encoding-canonicalization",
                      acc["categories_never_exercised"])
        self.assertNotIn("state-transition", acc["categories_never_exercised"])
        enc = [c for c in cells if c["rule_category"] == "encoding-canonicalization"]
        self.assertTrue(enc, "an unexercised encoding rule must fire")

    # --- test files are never counted as rule SITES -------------------------
    def test_test_file_is_not_a_rule_site(self):
        # The differential harness itself contains an execStateTest fn that
        # would match a category regex - it must be excluded as a test path.
        cells, acc, _ = self._scan({
            "geth/tests/state_test.go": _STATE_DIFF_HARNESS,
        })
        self.assertEqual(acc["rule_sites"], 0,
                         "functions defined in test files are not rule sites")
        self.assertEqual(cells, [])

    # --- strict-mode fail-close semantics (advisory-first by default) -------
    def test_strict_return_code_and_default_advisory(self):
        base = _mk_tree({"geth/core/state_transition.go": _STATE_TRANSITION_SRC})
        self._trees.append(base)
        import subprocess
        tool = str(TOOLS / "cross-client-consensus-divergence.py")
        # default advisory -> exit 0 even with needs-fuzz cells
        env = {"PATH": "/usr/bin:/bin:/usr/local/bin"}
        r_adv = subprocess.run(
            [sys.executable, tool, "--root", str(base)],
            capture_output=True, text=True, env=env)
        self.assertEqual(r_adv.returncode, 0, "default is advisory-first (exit 0)")
        # strict -> exit 1 on a never-enumerated cell
        r_strict = subprocess.run(
            [sys.executable, tool, "--root", str(base), "--strict"],
            capture_output=True, text=True, env=env)
        self.assertEqual(r_strict.returncode, 1,
                         "strict fail-closes on a never-enumerated cell")

    # --- NON-VACUITY: neutralize the core differential-exercise predicate ----
    def test_exercise_predicate_is_load_bearing(self):
        files = {"geth/core/state_transition.go": _STATE_TRANSITION_SRC}
        # baseline: fires
        cells, _, _ = self._scan(files)
        self.assertTrue([c for c in cells
                         if c["rule_category"] == "state-transition"])
        # neutralize: pretend every category is always exercised
        orig = R4._category_is_exercised
        try:
            R4._category_is_exercised = lambda cat, exercised: True
            cells2, acc2, _ = self._scan(files)
            self.assertEqual(cells2, [],
                             "with the exercise predicate defeated the screen "
                             "must go silent (predicate is load-bearing)")
            self.assertEqual(acc2["categories_never_exercised"], [])
        finally:
            R4._category_is_exercised = orig

    # --- NON-VACUITY: neutralize the rule-site classifier -------------------
    def test_rule_site_classifier_is_load_bearing(self):
        files = {"geth/core/state_transition.go": _STATE_TRANSITION_SRC}
        cells, _, _ = self._scan(files)
        self.assertTrue(cells)
        orig = R4._classify_rule_site
        try:
            R4._classify_rule_site = lambda rel, fn: None
            cells2, acc2, _ = self._scan(files)
            self.assertEqual(cells2, [],
                             "with no rule sites enumerated nothing can fire")
            self.assertEqual(acc2["rule_sites"], 0)
        finally:
            R4._classify_rule_site = orig


if __name__ == "__main__":
    unittest.main()
