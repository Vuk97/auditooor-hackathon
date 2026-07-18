// NEGATIVE fixture for unconditional_ok_return_in_security_fn detector.
//
// Each function carries a security-relevant name AND a real guard:
// branching, error-return, `?` propagation, delegation, or a clearly
// labelled placeholder. The detector must remain silent.

#![allow(unused, dead_code)]

use core::result::Result;

#[derive(Debug)]
pub enum Error {
    Challenged,
    Invalid,
    Stale,
    Unauthorized,
    BadAttestation,
}

pub struct DisputeGameImpl {
    pub challenged: bool,
}

pub struct OracleProof {
    pub height: u64,
}

pub struct Oracle {
    pub finalized_height: u64,
    pub allowlist: Vec<[u8; 20]>,
}

pub struct Inner;

impl Inner {
    // Helper used by the delegating verify_payload below. Not a guard
    // candidate itself - represents an external library call the
    // delegation suppressor in the detector should recognise via the
    // `self.inner.verify(...)` call shape on the parent.
    pub fn do_work(&self, _bytes: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

pub struct Outer {
    pub inner: Inner,
}

impl Oracle {
    // CLEAN: branching on real state. The `if game.challenged` arm
    // returns Err. Caller's invariant assumption is actually enforced.
    pub fn verify_not_challenged(&self, game: DisputeGameImpl) -> Result<(), Error> {
        if game.challenged {
            return Err(Error::Challenged);
        }
        Ok(())
    }

    // CLEAN: `?` propagation forwards a real failure from a delegate.
    // The body has work to do even though the visible final expr is Ok.
    pub fn validate_proof_window(&self, proof: &OracleProof) -> Result<(), Error> {
        let _delta = self.compute_window(proof.height)?;
        Ok(())
    }

    fn compute_window(&self, _h: u64) -> Result<u64, Error> {
        Ok(0)
    }

    // CLEAN: `match` arm on actual state. The detector must not fire on
    // any function whose body has branching even if one arm is Ok(()).
    pub fn check_finality(&self, height: u64) -> Result<bool, Error> {
        match height <= self.finalized_height {
            true => Ok(true),
            false => Err(Error::Stale),
        }
    }

    // CLEAN: `bail!` short-circuit on a real precondition. The function
    // can fail, even if the happy path returns Ok(()).
    pub fn assert_height_finalized(&self, height: u64) -> Result<(), Error> {
        if height > self.finalized_height {
            return Err(Error::Stale);
        }
        Ok(())
    }

    // CLEAN: delegates to a sibling verifier helper; the work is
    // plausibly performed by the callee, and the body has a `?`-style
    // propagation through the helper's Result. Detector suppresses on
    // the verify_-prefixed delegation call.
    pub fn verify_payload(&self, bytes: &[u8]) -> Result<(), Error> {
        self.verify_inner_helper(bytes)?;
        Ok(())
    }

    fn verify_inner_helper(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

// CLEAN: trait default method that is honestly a placeholder. The
// detector must not fire on placeholder stubs (todo!/unimplemented!/
// unreachable!).
pub trait Verifier {
    fn verify_stub(&self) -> Result<(), Error> {
        unimplemented!("verifier not yet implemented")
    }
}

// CLEAN: explicit `unreachable!()` body. The fn is documented as a
// dead-code arm; no caller is supposed to reach it.
pub fn check_dead_arm() -> Result<(), Error> {
    unreachable!("this branch is structurally unreachable per type system")
}
