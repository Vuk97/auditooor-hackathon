"""Tests for the unconditional-ok-return-in-security-fn Rust detector.

Detector lives at::

    tools/detectors/rust/unconditional-ok-return-in-security-fn.py

Generalizes the Hyperbridge OPSuccinct H6/H4 finding: a security-named
fn (verify_*/validate_*/check_*/authorize_*/authenticate_*/assert_*/
ensure_*/is_valid*) that returns Ok(())/Ok(<simple>)/true unconditionally
with no branching, no `?`, and no error path.

r36-rebuttal: build lane CAP-BUILD-4; registered via
tools/agent-pathspec-register.py with TTL 90m for the 4 files this
lane writes (detector + 2 fixtures + this test).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DETECTOR_PATH = (
    REPO_ROOT / "tools" / "detectors" / "rust"
    / "unconditional-ok-return-in-security-fn.py"
)
FIXTURES_DIR = REPO_ROOT / "detectors" / "fixtures" / "rust"
POS_FIXTURE = FIXTURES_DIR / "positive" / "opsuccinct_unconditional.rs"
NEG_FIXTURE = FIXTURES_DIR / "negative" / "properly_guarded.rs"


def _load_detector():
    name = "unconditional_ok_return_in_security_fn"
    spec = importlib.util.spec_from_file_location(name, DETECTOR_PATH)
    assert spec and spec.loader, f"cannot load spec for {DETECTOR_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestUnconditionalOkReturnDetector(unittest.TestCase):
    """Coverage for the OPSuccinct-shape detector."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector()

    # -- positive fixture (OPSuccinct shape) -----------------------------
    def test_fires_on_positive_fixture_file(self):
        """5 flagged fns in the OPSuccinct mirror fixture must all fire."""
        self.assertTrue(POS_FIXTURE.exists(), f"missing: {POS_FIXTURE}")
        hits = self.mod.scan_file(str(POS_FIXTURE))
        self.assertGreaterEqual(
            len(hits), 5,
            f"expected >=5 hits on positive fixture, got {len(hits)}: {hits}",
        )
        fn_names_in_msgs = " ".join(msg for _, msg in hits)
        for name in (
            "verify_not_challenged",
            "validate_proof_window",
            "check_finality",
            "is_valid_attestation",
            "authorize_caller",
        ):
            self.assertIn(
                f"`{name}`", fn_names_in_msgs,
                f"expected fn {name} in hit messages",
            )

    # -- negative fixture (real guards) ----------------------------------
    def test_silent_on_negative_fixture_file(self):
        """Guarded / delegated / placeholder fns must NOT fire."""
        self.assertTrue(NEG_FIXTURE.exists(), f"missing: {NEG_FIXTURE}")
        hits = self.mod.scan_file(str(NEG_FIXTURE))
        self.assertEqual(
            len(hits), 0,
            f"expected 0 hits on negative fixture, got {hits}",
        )

    # -- directory walk: positive present, negative silent ---------------
    def test_scan_directory_collects_only_positive_hits(self):
        all_hits = self.mod.scan(str(FIXTURES_DIR))
        pos_hits = [h for h in all_hits if "positive" in h[0]]
        neg_hits = [h for h in all_hits if "negative" in h[0]]
        self.assertGreaterEqual(len(pos_hits), 5, f"pos hits: {pos_hits}")
        self.assertEqual(
            len(neg_hits), 0,
            f"negative subtree must be silent, got: {neg_hits}",
        )

    # -- inline shape tests ----------------------------------------------
    def _scan_inline(self, src: str) -> list[tuple[int, str]]:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "a.rs"
            f.write_text(src, encoding="utf-8")
            return self.mod.scan_file(str(f))

    def test_inline_minimal_ok_unit_fires(self):
        hits = self._scan_inline(textwrap.dedent("""\
            pub fn verify_caller(_who: u32) -> Result<(), ()> {
                Ok(())
            }
        """))
        self.assertEqual(len(hits), 1, f"expected 1 hit, got {hits}")

    def test_inline_ok_with_simple_payload_fires(self):
        hits = self._scan_inline(textwrap.dedent("""\
            pub fn check_active(_id: u32) -> Result<bool, ()> {
                Ok(true)
            }
        """))
        self.assertEqual(len(hits), 1, f"expected 1 hit, got {hits}")

    def test_inline_branching_does_not_fire(self):
        hits = self._scan_inline(textwrap.dedent("""\
            pub fn verify_caller(who: u32) -> Result<(), ()> {
                if who == 0 {
                    return Err(());
                }
                Ok(())
            }
        """))
        self.assertEqual(len(hits), 0, f"branching path must be silent: {hits}")

    def test_inline_question_mark_propagation_does_not_fire(self):
        hits = self._scan_inline(textwrap.dedent("""\
            pub fn validate_payload(b: &[u8]) -> Result<(), ()> {
                let _x = inner_helper(b)?;
                Ok(())
            }
            fn inner_helper(_b: &[u8]) -> Result<u8, ()> {
                Ok(0)
            }
        """))
        self.assertEqual(
            len(hits), 0,
            f"`?` propagation must suppress fire: {hits}",
        )

    def test_inline_placeholder_unimplemented_does_not_fire(self):
        hits = self._scan_inline(textwrap.dedent("""\
            pub fn verify_stub(_b: &[u8]) -> Result<(), ()> {
                unimplemented!("not yet")
            }
        """))
        self.assertEqual(
            len(hits), 0,
            f"unimplemented!() placeholder must suppress fire: {hits}",
        )

    def test_inline_non_security_name_does_not_fire(self):
        hits = self._scan_inline(textwrap.dedent("""\
            pub fn build_payload(_b: &[u8]) -> Result<(), ()> {
                Ok(())
            }
        """))
        self.assertEqual(
            len(hits), 0,
            f"non-security-named fn must not fire: {hits}",
        )

    def test_inline_return_true_form_fires(self):
        hits = self._scan_inline(textwrap.dedent("""\
            pub fn is_valid_input(_b: &[u8]) -> bool {
                true
            }
        """))
        self.assertEqual(len(hits), 1, f"expected 1 hit, got {hits}")


if __name__ == "__main__":
    unittest.main()
