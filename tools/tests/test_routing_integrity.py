"""B2 routing-integrity gate - non-vacuous mutation-verified regression.

The gate asserts a record's stored `target_languages` contains the NATIVE
language(s) derived from its attack class. The mutation test proves the gate is
NON-VACUOUS: an injected mis-route (a consensus class forced to solidity-only)
MUST flag; the corrected route MUST be silent; and a genuinely Solidity-only
class MUST stay silent (no over-correction / true-negative).
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "tools" / "lib" / "per_function_target_patterns.py"
GATE = ROOT / "tools" / "routing-integrity-check.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


LIBM = _load("pftp_rt", LIB)
GATEM = _load("gate_rt", GATE)

CONSENSUS_ANCHOR = ("wiki-description:multi-signer-consensus-mutation-of-"
                    "observed-state-breaks-digest")
CONSENSUS_TEXT = ("One signer reads a CCL config and mutates message."
                  "ConsistencyLevel; NonceVoter(ctx, MsgNonceVoter) calls "
                  "SetChainNonces(ctx, chainNonce).")


class TestNativeDerivation(unittest.TestCase):
    def test_consensus_routes_to_go_rust(self):
        native = LIBM.derive_native_target_languages(CONSENSUS_ANCHOR, CONSENSUS_TEXT)
        self.assertIn("go", native)
        self.assertIn("rust", native)

    def test_solidity_only_class_stays_solidity(self):
        for anchor in ("allowance-residue", "unlimited-approve-frontend",
                       "erc20-misuse"):
            native = LIBM.derive_native_target_languages(anchor, "stale approve()")
            self.assertEqual(native, ["solidity"],
                             f"{anchor} must not project to go/rust")

    def test_fail_open_when_undecidable(self):
        # A generic anchor with no native signal keeps declared languages.
        resolved, native, source = LIBM.resolve_target_languages(
            "arbitrary-call", "executeRaw dispatch",
            ["solidity", "rust", "go", "move"])
        self.assertEqual(native, [])
        self.assertEqual(source, "fail-open-existing")
        self.assertEqual(resolved, ["solidity", "rust", "go", "move"])

    def test_enrich_sets_native_routed_languages(self):
        rec = {"attack_class_anchor": CONSENSUS_ANCHOR,
               "question_text": CONSENSUS_TEXT,
               "target_languages": ["solidity"], "grep_patterns": []}
        out = LIBM.enrich_hacker_question_record(rec)
        self.assertIn("go", out["target_languages"])
        self.assertIn("rust", out["target_languages"])
        self.assertEqual(out["target_languages_routing_source"], "native-derived")


class TestGateMutationVerify(unittest.TestCase):
    def _scan(self, records):
        return GATEM.scan_records(records, LIBM)

    def test_misroute_is_flagged(self):
        # MUTATION: force the consensus class to solidity-only.
        misrouted = {"question_id": "MUT-1",
                     "attack_class_anchor": CONSENSUS_ANCHOR,
                     "question_text": CONSENSUS_TEXT,
                     "target_languages": ["solidity"]}
        mismatches, checked, decidable = self._scan([misrouted])
        self.assertEqual(len(mismatches), 1, "mis-route MUST flag (non-vacuous)")
        self.assertIn("go", mismatches[0]["missing_native_languages"])
        self.assertIn("rust", mismatches[0]["missing_native_languages"])

    def test_correct_route_is_silent(self):
        corrected = {"question_id": "OK-1",
                     "attack_class_anchor": CONSENSUS_ANCHOR,
                     "question_text": CONSENSUS_TEXT,
                     "target_languages": ["solidity", "go", "rust"]}
        mismatches, _c, _d = self._scan([corrected])
        self.assertEqual(mismatches, [], "correct route MUST be silent")

    def test_solidity_only_class_true_negative(self):
        sol = {"question_id": "SOL-1",
               "attack_class_anchor": "allowance-residue",
               "question_text": "stale ERC20 allowance after transferFrom",
               "target_languages": ["solidity"]}
        mismatches, _c, _d = self._scan([sol])
        self.assertEqual(mismatches, [],
                         "solidity-only class must NOT be flagged for lacking go/rust")

    def test_undecidable_not_flagged(self):
        generic = {"question_id": "GEN-1", "attack_class_anchor": "arbitrary-call",
                   "question_text": "executeRaw", "target_languages": ["solidity"]}
        mismatches, _c, decidable = self._scan([generic])
        self.assertEqual(mismatches, [])
        self.assertEqual(decidable, 0)


if __name__ == "__main__":
    unittest.main()
