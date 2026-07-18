#!/usr/bin/env python3
"""RU10 - crypto-fn missing CryptoRng bound (weak-entropy) advisory axis.

Non-vacuous: each positive asserts a specific hit, each negative asserts the
absence; mutating the predicate (dropping the CryptoRng discriminator, the
crypto-scope gate, the scalar-sample FP-guard, or the fn-name shape) breaks a
case. Pins the mutation-verified monero-oxide sign_core-derived fixture pair
(clean guarded=0, mutant=1).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-detector-runner.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "RU10"


def _load():
    spec = importlib.util.spec_from_file_location("rust_detector_runner_ru10", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner_ru10"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _write(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _en_hits(ws: Path):
    os.environ["AUDITOOR_RUST_ENTROPY_AXIS"] = "1"
    summary = MOD.scan_workspace(ws)
    axis = summary.get("rust_entropy_axis", {})
    return axis.get("hypotheses", [])


class RU10Tests(unittest.TestCase):
    def test_missing_cryptorng_bound_fires(self):
        # sign fn generic over RngCore, NO CryptoRng bound, draws a scalar,
        # crypto scope -> fires (arm A).
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/a.rs", """
                fn sign_core<R: RngCore>(rng: &mut R, n: usize) -> Vec<Scalar> {
                    let mut s = Vec::new();
                    for _ in 0..n { s.push(Scalar::random(rng)); }
                    s
                }
                """)
            hits = _en_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["function"], "sign_core")
            self.assertEqual(hits[0]["extra"]["arm"], "missing_cryptorng_bound")

    def test_cryptorng_bound_present_suppresses(self):
        # THE discriminator: the secure control (RngCore + CryptoRng) is silent.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/b.rs", """
                fn sign_core<R: RngCore + CryptoRng>(rng: &mut R, n: usize) -> Vec<Scalar> {
                    let mut s = Vec::new();
                    for _ in 0..n { s.push(Scalar::random(rng)); }
                    s
                }
                """)
            self.assertEqual(len(_en_hits(ws)), 0)

    def test_weak_seeded_rng_fires(self):
        # arm B: a crypto sign fn drawing from seed_from_u64 fires even without
        # a RngCore generic.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crypto/schnorr/src/c.rs", """
                fn prove(msg: &[u8]) -> Scalar {
                    let mut rng = StdRng::seed_from_u64(42);
                    Scalar::random(&mut rng)
                }
                """)
            hits = _en_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["arm"], "weak_seeded_rng")

    def test_non_crypto_scope_suppressed(self):
        # FP-guard (a): generic over RngCore but NOT a crypto crate and no
        # curve/scalar/key primitive -> out of class, silent. (A shuffler.)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "utils/deck/src/d.rs", """
                fn sign_ticket<R: RngCore>(rng: &mut R, items: &mut Vec<u32>) {
                    let nonce = rng.next_u32();
                    items.push(nonce);
                }
                """)
            self.assertEqual(len(_en_hits(ws)), 0)

    def test_no_scalar_sample_suppressed(self):
        # FP-guard (b): crypto scope + RngCore generic but NO scalar/nonce draw
        # in the body (hashes only) -> the missing bound is inert, silent.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/e.rs", """
                fn sign_hash<R: RngCore>(_rng: &mut R, msg: &[u8]) -> Scalar {
                    let h = Scalar::hash(msg);
                    h
                }
                """)
            self.assertEqual(len(_en_hits(ws)), 0)

    def test_non_crypto_fn_name_suppressed(self):
        # fn-name shape gate: `assign` is NOT a sign/prove/nonce/keygen op.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/f.rs", """
                fn assign<R: RngCore>(rng: &mut R) -> Scalar {
                    Scalar::random(rng)
                }
                """)
            self.assertEqual(len(_en_hits(ws)), 0)

    def test_axis_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/a.rs", """
                fn sign_core<R: RngCore>(rng: &mut R, n: usize) -> Vec<Scalar> {
                    let mut s = Vec::new();
                    for _ in 0..n { s.push(Scalar::random(rng)); }
                    s
                }
                """)
            os.environ.pop("AUDITOOR_RUST_ENTROPY_AXIS", None)
            summary = MOD.scan_workspace(ws)
            self.assertNotIn("rust_entropy_axis", summary)

    def test_needs_fuzz_no_auto_credit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/a.rs", """
                fn sign_core<R: RngCore>(rng: &mut R, n: usize) -> Vec<Scalar> {
                    let mut s = Vec::new();
                    for _ in 0..n { s.push(Scalar::random(rng)); }
                    s
                }
                """)
            os.environ["AUDITOOR_RUST_ENTROPY_AXIS"] = "1"
            summary = MOD.scan_workspace(ws)
            axis = summary["rust_entropy_axis"]
            self.assertEqual(axis["verdict"], "needs-fuzz")
            self.assertFalse(axis["auto_credit"])
            h = axis["hypotheses"][0]
            self.assertEqual(h["extra"]["verdict"], "needs-fuzz")
            self.assertIsNone(h["extra"]["covered_by"])  # dedup: net-new vs RU1
            self.assertEqual(
                h["extra"]["impact_contract"]["status"], "advisory_needs_fuzz"
            )

    def test_committed_fixtures(self):
        # Mutation-kill: monero-oxide sign_core pair (clean guarded=0, mutant=1).
        clean = _en_hits(FIX / "clean")
        mut = _en_hits(FIX / "mutant")
        self.assertEqual(len(clean), 0)
        self.assertEqual(len(mut), 1)
        self.assertEqual(mut[0]["extra"]["function"], "sign_core")
        self.assertEqual(mut[0]["extra"]["arm"], "missing_cryptorng_bound")
        self.assertIsNone(mut[0]["extra"]["covered_by"])


if __name__ == "__main__":
    unittest.main()
