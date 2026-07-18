#!/usr/bin/env python3
"""Signature-replay precondition detector (Glider gap W6 P3) - regression +
mutation-non-vacuity tests for the predicates added to
``tools/slither_predicates.py``:

  - ``signature_replay_suspects``          - per-function oracle; returns list of
                                             suspect dicts or DEGRADED (R80).
  - ``closure_signature_replay_suspects``  - own-body + callee-closure variant.
  - ``_fn_closure_calls_ecrecover``        - seed helper (ecrecover present?).
  - ``_fn_closure_reads_chainid``          - block.chainid reader.
  - ``_fn_closure_has_nonce_write``        - nonce/used-hash storage-write reader.

Two sub-rules under test:
  (a) MISSING-NONCE:  ecrecover present + NO nonce/used-hash storage write.
  (b) MISSING-CHAINID: ecrecover present + NO block.chainid read.

Honesty (R80): semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The degrade
path is tested without Slither. Mutation evidence:
``test_mutation_add_nonce_write_suppresses_missing_nonce`` adds a nonce write to
the base FLAGGED fixture and asserts that the missing-nonce flag flips away
(non-vacuity). Never-false-positive: ecrecover-absent, nonce-present, and
chainid-present fixtures all yield no suspects.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "callgraph_closure"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_sp():
    spec = importlib.util.spec_from_file_location(
        "slither_predicates", TOOLS / "slither_predicates.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load_sp()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401
        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(),
    "slither-analyzer not importable; signature-replay tests need a real compile",
)


def _compile(path: pathlib.Path):
    from slither import Slither
    return Slither(str(path))


def _get_fn(sl, cname, fname):
    for c in sl.contracts:
        if c.name == cname:
            for f in c.functions:
                if f.name == fname:
                    return c, f
    return None, None


# ---- Degrade path (no Slither needed) ----------------------------------------


class SigReplayDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_signature_replay_suspects_degrades(self):
        result = sp.signature_replay_suspects(self._Dummy())
        self.assertTrue(
            sp.is_degraded(result),
            "signature_replay_suspects must return DEGRADED on a non-navigable fn",
        )

    def test_closure_variant_degrades(self):
        result = sp.closure_signature_replay_suspects(self._Dummy())
        self.assertTrue(
            sp.is_degraded(result),
            "closure_signature_replay_suspects must return DEGRADED on non-navigable",
        )

    def test_seed_helpers_false_on_non_navigable(self):
        # Seed helpers degrade conservatively to False on a non-navigable fn,
        # so neither sub-rule fires on a bare object.
        self.assertFalse(sp._fn_closure_calls_ecrecover(self._Dummy()))
        self.assertFalse(sp._fn_closure_reads_chainid(self._Dummy()))
        self.assertFalse(sp._fn_closure_has_nonce_write(self._Dummy()))

    def test_no_suspects_on_none(self):
        # None is also non-navigable: should degrade or return [].
        result = sp.signature_replay_suspects(None)
        self.assertTrue(
            sp.is_degraded(result) or result == [],
            "None input must degrade or return []",
        )


# ---- __all__ export check (no Slither needed) --------------------------------


class SigReplayExportTest(unittest.TestCase):
    """Verify the two new predicates are in __all__."""

    def test_signature_replay_suspects_exported(self):
        self.assertIn(
            "signature_replay_suspects",
            sp.__all__,
            "signature_replay_suspects must be in __all__",
        )

    def test_closure_variant_exported(self):
        self.assertIn(
            "closure_signature_replay_suspects",
            sp.__all__,
            "closure_signature_replay_suspects must be in __all__",
        )


# ---- Semantic path: FLAGGED cases (require Slither) --------------------------


@SKIP_NO_SLITHER
class SigReplayFlaggedTest(unittest.TestCase):
    """Positive detection: functions that SHOULD be flagged."""

    def test_missing_nonce_flagged(self):
        # (a) ecrecover present, NO nonce write -> missing-nonce flagged.
        sl = _compile(FX / "sigreplay_missing_nonce_suspect.sol")
        _, fn = _get_fn(sl, "SigReplayMissingNonce", "verifyAndExecute")
        self.assertIsNotNone(fn, "fixture function not found")
        result = sp.signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(result))
        kinds = [r["kind"] for r in result]
        self.assertIn(
            "missing-nonce", kinds,
            f"expected missing-nonce in kinds, got: {kinds}",
        )

    def test_missing_chainid_flagged(self):
        # (b) ecrecover present + nonce consumed, but NO block.chainid -> chainid flagged.
        sl = _compile(FX / "sigreplay_missing_chainid_suspect.sol")
        _, fn = _get_fn(sl, "SigReplayMissingChainId", "verifyAndExecute")
        self.assertIsNotNone(fn, "fixture function not found")
        result = sp.signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(result))
        kinds = [r["kind"] for r in result]
        self.assertIn(
            "missing-chainid", kinds,
            f"expected missing-chainid in kinds, got: {kinds}",
        )
        # The chainid fixture HAS a nonce write, so missing-nonce must NOT fire.
        self.assertNotIn(
            "missing-nonce", kinds,
            "missing-nonce must NOT fire when nonce mapping is present",
        )

    def test_missing_nonce_result_shape(self):
        # Verify the result record carries the expected keys.
        sl = _compile(FX / "sigreplay_missing_nonce_suspect.sol")
        _, fn = _get_fn(sl, "SigReplayMissingNonce", "verifyAndExecute")
        result = sp.signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(result))
        nonce_recs = [r for r in result if r.get("kind") == "missing-nonce"]
        self.assertTrue(nonce_recs, "expected at least one missing-nonce record")
        r0 = nonce_recs[0]
        self.assertIn("contract", r0)
        self.assertIn("function", r0)
        self.assertIn("severity_hint", r0)
        self.assertEqual(r0["severity_hint"], "signature-replay")
        # ecrecover_line may be None when Slither IR does not resolve,
        # but the key must be present.
        self.assertIn("ecrecover_line", r0)

    def test_closure_variant_returns_own_body_suspects(self):
        sl = _compile(FX / "sigreplay_missing_nonce_suspect.sol")
        _, fn = _get_fn(sl, "SigReplayMissingNonce", "verifyAndExecute")
        result = sp.closure_signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(result))
        self.assertTrue(result, "closure variant must find suspects on flagged fixture")


# ---- Semantic path: CLEAN cases (never-false-positive) -----------------------


@SKIP_NO_SLITHER
class SigReplayCleanTest(unittest.TestCase):
    """Negative detection: functions that must NOT be flagged."""

    def test_nonce_and_chainid_both_present_clean(self):
        # CLEAN: nonce present + block.chainid present -> neither sub-rule fires.
        sl = _compile(FX / "sigreplay_nonce_present_clean.sol")
        _, fn = _get_fn(sl, "SigReplayNonceAndChainIdClean", "verifyAndExecute")
        self.assertIsNotNone(fn)
        result = sp.signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(result))
        self.assertEqual(
            result, [],
            f"nonce+chainid-present fixture must yield [], got: {result}",
        )

    def test_no_ecrecover_clean(self):
        # CLEAN: no ecrecover in the function -> seed absent -> neither sub-rule.
        sl = _compile(FX / "sigreplay_no_ecrecover_clean.sol")
        _, fn = _get_fn(sl, "SigReplayNoEcrecover", "withdraw")
        self.assertIsNotNone(fn)
        result = sp.signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(result))
        self.assertEqual(
            result, [],
            "no-ecrecover fixture must yield [] (seed absent)",
        )

    def test_usedhash_write_suppresses_missing_nonce(self):
        # CLEAN for missing-nonce: usedHashes[hash]=true is a per-message nonce
        # (matches the 'used' token in the nonce-name heuristic).
        sl = _compile(FX / "sigreplay_usedHash_clean.sol")
        _, fn = _get_fn(sl, "SigReplayUsedHashClean", "verifyAndExecute")
        self.assertIsNotNone(fn)
        result = sp.signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(result))
        kinds = [r["kind"] for r in result]
        self.assertNotIn(
            "missing-nonce", kinds,
            "usedHashes mapping write must suppress missing-nonce flag",
        )


# ---- Mutation evidence (non-vacuity) -----------------------------------------


@SKIP_NO_SLITHER
class SigReplayMutationTest(unittest.TestCase):
    """Non-vacuity: adding a nonce write to the base FLAGGED fixture must flip
    missing-nonce FLAGGED -> clean. This proves the oracle keys on the ABSENCE
    of a nonce write, not on any other property of the function."""

    def test_mutation_add_nonce_write_suppresses_missing_nonce(self):
        base_path = FX / "sigreplay_mutation_base.sol"
        src = base_path.read_text(encoding="utf-8")

        # Base: no nonce write -> missing-nonce FLAGGED.
        sl = _compile(base_path)
        _, fn = _get_fn(sl, "SigReplayMutationBase", "verifyAndExecute")
        self.assertIsNotNone(fn)
        base_result = sp.signature_replay_suspects(fn)
        self.assertFalse(sp.is_degraded(base_result))
        base_kinds = [r["kind"] for r in base_result]
        self.assertIn(
            "missing-nonce", base_kinds,
            "base fixture must produce missing-nonce (non-vacuity pre-condition)",
        )

        # Mutation: insert `nonces[signer]++;` before the closing call.
        # This one-edit change adds a nonce mapping write and MUST flip missing-nonce.
        mutated = src.replace(
            "        // No nonce write here - FLAGGED.",
            "        nonces[signer]++;  // MUTATION: nonce write added",
        )
        # Also declare the mapping (otherwise solc rejects the mutation).
        mutated = mutated.replace(
            "    address public owner;",
            "    address public owner;\n    mapping(address => uint256) public nonces;",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")

        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "sigreplay_mutation_base.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "SigReplayMutationBase", "verifyAndExecute")
            self.assertIsNotNone(mfn)
            mutated_result = sp.signature_replay_suspects(mfn)
            self.assertFalse(sp.is_degraded(mutated_result))
            mutated_kinds = [r["kind"] for r in mutated_result]
            self.assertNotIn(
                "missing-nonce", mutated_kinds,
                "adding a nonce write must SUPPRESS missing-nonce (non-vacuous: "
                "annotation flipped FLAGGED->clean under one-edit mutation)",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
