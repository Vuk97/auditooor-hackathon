"""Lane H (SEI 2026-07-05): hunt-coverage-gate credits byte-identical legacy version
snapshots when their canonical sibling is scanned.

A Cosmos-EVM L1 (SEI) ships ~10 height-gated legacy copies of each precompile
(precompiles/gov/legacy/v6xx/gov.go) for historical replay. A legacy copy whose function
body is byte-identical to its SCANNED canonical sibling has no independent bug surface;
counting it as queued-not-scanned is dead-weight duplication. Only exempt when the
canonical is scanned AND the bodies match exactly - a differing legacy copy (real
version-delta) stays queued (never-false-pass).
"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "hcg", str(Path(__file__).resolve().parents[1] / "hunt-coverage-gate.py")
)
hcg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hcg)

_CANON = (
    "package x\n"
    "func (k Keeper) Deposit(a int) bool {\n\treturn a > 0\n}\n"
    "func (k Keeper) Vote(b int) bool {\n\treturn b == 1\n}\n"
)
_LEGACY_IDENTICAL = _CANON  # byte-identical
_LEGACY_DIFF = (
    "package x\n"
    "func (k Keeper) Deposit(a int) bool {\n\treturn a >= 0\n}\n"  # changed guard
    "func (k Keeper) Vote(b int) bool {\n\treturn b == 1\n}\n"
)


class LegacyIdenticalExemptTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        canon = self.d / "src/sei-chain/precompiles/gov"
        legi = self.d / "src/sei-chain/precompiles/gov/legacy/v620"
        legd = self.d / "src/sei-chain/precompiles/gov/legacy/v630"
        for p in (canon, legi, legd):
            p.mkdir(parents=True, exist_ok=True)
        (canon / "gov.go").write_text(_CANON)
        (legi / "gov.go").write_text(_LEGACY_IDENTICAL)
        (legd / "gov.go").write_text(_LEGACY_DIFF)
        self.canon_unit = "src/sei-chain/precompiles/gov/gov.go::Deposit"
        self.leg_ident = "src/sei-chain/precompiles/gov/legacy/v620/gov.go::Deposit"
        self.leg_diff = "src/sei-chain/precompiles/gov/legacy/v630/gov.go::Deposit"

    def _f(self, unit, scanned):
        return hcg._unit_is_byte_identical_legacy_copy(self.d, unit, scanned)

    def test_identical_legacy_with_scanned_canonical_is_exempt(self):
        self.assertTrue(self._f(self.leg_ident, {self.canon_unit}))

    def test_identical_legacy_WITHOUT_scanned_canonical_NOT_exempt(self):
        # never-false-pass: canonical must actually be scanned
        self.assertFalse(self._f(self.leg_ident, set()))

    def test_differing_legacy_NOT_exempt_even_if_canonical_scanned(self):
        # never-false-pass: a real version-delta keeps its own obligation
        self.assertFalse(self._f(self.leg_diff, {self.canon_unit}))

    def test_canonical_unit_itself_not_exempt(self):
        self.assertFalse(self._f(self.canon_unit, {self.canon_unit}))

    def test_missing_fn_not_exempt(self):
        self.assertFalse(
            self._f(
                "src/sei-chain/precompiles/gov/legacy/v620/gov.go::DoesNotExist",
                {"src/sei-chain/precompiles/gov/gov.go::DoesNotExist"},
            )
        )


if __name__ == "__main__":
    unittest.main()
