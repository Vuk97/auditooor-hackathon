from __future__ import annotations

import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES = WAVE1_DIR / "test_fixtures"

DETECTOR = "bridge_beefy_validator_set_domain_fire39"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        log_path = Path(tmp.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
                "--file",
                str(fixture),
                "--log",
                str(log_path),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(log_text)
        return (int(match.group(1)) if match else 0), log_text
    finally:
        log_path.unlink(missing_ok=True)


class RustBridgeBeefyValidatorSetDomainFire39Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = DETECTOR_PATH.read_text(encoding="utf-8")
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector_text)
        self.assertIn("attack_class: bridge-proof-domain-bypass", detector_text)
        self.assertIn(
            "context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c",
            detector_text,
        )
        self.assertIn("MCP receipt: .auditooor/memory_context_receipt.json", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("R40/R76/R80 caveat", detector_text)

    def test_positive_fixture_fires_on_validator_set_domain_omission(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("submit_beefy_validator_set_update", log_text)
        self.assertIn("bridge-proof-domain-bypass", log_text)
        self.assertIn("current_validator_set_id", log_text)
        self.assertIn("current_validator_set_root", log_text)
        self.assertIn("next_validator_set_id", log_text)
        self.assertIn("next_validator_set_root", log_text)
        self.assertIn("validator_set_length", log_text)

    def test_negative_fixture_is_silent_when_validator_set_fields_are_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("source_chain_id", positive)
        self.assertIn("destination_chain_id", positive)
        self.assertIn("client_namespace.0", positive)
        self.assertIn("current_set.id", positive)
        self.assertIn("current_set.root", positive)
        self.assertIn("next_set.id", positive)
        self.assertIn("next_set.root", positive)
        self.assertIn("verifier.verify_validator_set_update(proof_digest", positive)
        self.assertNotIn("BEEFY_VALIDATOR_SET_DOMAIN_FIRE39", positive)
        self.assertNotIn("current_set.id.to_be_bytes()", positive)

        self.assertIn("BEEFY_VALIDATOR_SET_DOMAIN_FIRE39", negative)
        self.assertIn("source_chain_id.to_be_bytes()", negative)
        self.assertIn("destination_chain_id.to_be_bytes()", negative)
        self.assertIn("client_namespace.0.to_be_bytes()", negative)
        self.assertIn("current_set.id.to_be_bytes()", negative)
        self.assertIn("current_set.root", negative)
        self.assertIn("next_set.id.to_be_bytes()", negative)
        self.assertIn("next_set.root", negative)
        self.assertLess(
            negative.index("current_set.id.to_be_bytes()"),
            negative.index("verifier.verify_validator_set_update"),
        )

    def test_explicit_proof_to_state_guards_are_silent_without_domain_constant(self) -> None:
        guarded_source = """
use std::collections::HashMap;
type Hash32 = [u8; 32];

#[derive(Clone, Copy)]
pub struct ValidatorSet { pub id: u64, pub root: Hash32, pub len: u32 }

pub struct BeefyValidatorProof {
    pub current_validator_set_id: u64,
    pub current_validator_set_root: Hash32,
    pub next_validator_set_id: u64,
    pub next_validator_set_root: Hash32,
    pub validator_set_len: u32,
    pub signed_commitment_hash: Hash32,
    pub mmr_root: Hash32,
    pub signatures: Vec<Hash32>,
}

pub struct BeefyVerifier;
impl BeefyVerifier {
    pub fn verify_validator_set_update(&self, _digest: Hash32, _sigs: Vec<Hash32>) -> bool {
        true
    }
}

pub struct BeefyBridgeClient {
    current_validator_set_id: u64,
    validator_sets: HashMap<u64, Hash32>,
    validator_set_lengths: HashMap<u64, u32>,
}

impl BeefyBridgeClient {
    pub fn import_beefy_validator_set(
        &mut self,
        current_set: ValidatorSet,
        next_set: ValidatorSet,
        proof: BeefyValidatorProof,
        verifier: &BeefyVerifier,
    ) -> Result<(), &'static str> {
        if proof.current_validator_set_id != current_set.id {
            return Err("wrong current id");
        }
        if proof.current_validator_set_root != current_set.root {
            return Err("wrong current root");
        }
        if proof.next_validator_set_id != next_set.id {
            return Err("wrong next id");
        }
        if proof.next_validator_set_root != next_set.root {
            return Err("wrong next root");
        }
        if proof.validator_set_len != next_set.len {
            return Err("wrong next length");
        }

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&proof.signed_commitment_hash);
        transcript.extend_from_slice(&proof.mmr_root);
        let proof_digest = blake2_256(&transcript);

        if !verifier.verify_validator_set_update(proof_digest, proof.signatures) {
            return Err("bad proof");
        }

        self.validator_sets.insert(next_set.id, next_set.root);
        self.validator_set_lengths.insert(next_set.id, next_set.len);
        self.current_validator_set_id = next_set.id;
        Ok(())
    }
}

fn blake2_256(_input: &[u8]) -> Hash32 { [0u8; 32] }
"""
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as tmp:
            tmp.write(guarded_source)
            fixture = Path(tmp.name)
        try:
            hits, log_text = _run_fixture(fixture)
            self.assertEqual(hits, 0, log_text)
        finally:
            fixture.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
