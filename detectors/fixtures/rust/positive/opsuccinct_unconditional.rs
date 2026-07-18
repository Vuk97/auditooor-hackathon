// POSITIVE fixture for unconditional_ok_return_in_security_fn detector.
//
// Mirrors the Hyperbridge OPSuccinct H6/H4 finding shape:
// `verify_not_challenged` returns Ok(()) unconditionally for the
// DisputeGameImpl::OPSuccinct branch. Caller assumes the challenge
// window was honored; the body never reads any challenge state.
//
// Real-world anchor: ismp-optimism/src/lib.rs (`verify_not_challenged`).

#![allow(unused, dead_code)]

use core::result::Result;

#[derive(Debug)]
pub enum Error {
    Challenged,
    Invalid,
}

pub struct DisputeGameImpl;
pub struct OracleProof;

pub struct OpSuccinctOracle;

impl OpSuccinctOracle {
    // FLAG: security-named fn returns Ok(()) unconditionally with no
    // branching, no `?` propagation, and no error path. This is the
    // OPSuccinct verify_not_challenged shape. Caller assumes invariant
    // enforcement that the body never performs.
    pub fn verify_not_challenged(&self, _game: DisputeGameImpl) -> Result<(), Error> {
        Ok(())
    }

    // FLAG: same pattern, `validate_` prefix instead of `verify_`. The
    // body returns Ok(()) unconditionally and reads no state, so any
    // caller relying on this guard is silently bypassed.
    pub fn validate_proof_window(&self, _proof: &OracleProof) -> Result<(), Error> {
        Ok(())
    }

    // FLAG: `check_` prefix with `Ok(true)` (simple Ok payload). Same
    // shape - no branching, no error path, no state read.
    pub fn check_finality(&self, _height: u64) -> Result<bool, Error> {
        Ok(true)
    }

    // FLAG: `is_valid_` prefix returning unconditional `true`. The bool
    // form of the unconditional-Ok pattern.
    pub fn is_valid_attestation(&self, _att: &[u8]) -> bool {
        true
    }

    // FLAG: `authorize_` prefix with explicit `return Ok(())` form.
    pub fn authorize_caller(&self, _caller: [u8; 20]) -> Result<(), Error> {
        return Ok(());
    }
}
