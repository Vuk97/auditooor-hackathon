use std::collections::HashSet;

pub struct MultiSigVerifier {
    pub signers: HashSet<[u8; 32]>,
    pub threshold: u32,
}

pub struct Signature {
    pub signer: [u8; 32],
    pub data: Vec<u8>,
}

impl MultiSigVerifier {
    pub fn new(threshold: u32, signers: HashSet<[u8; 32]>) -> Self {
        Self { signers, threshold }
    }

    pub fn verify_execution(&self, signatures: &[Signature]) -> Result<(), &'static str> {
        let mut acquired_threshold = 0u32;
        // BUG: No deduplication tracking — same signer can be counted multiple times

        for sig in signatures {
            if !self.signers.contains(&sig.signer) {
                continue;
            }
            // MISSING: check if signer was already counted
            acquired_threshold += 1;
            if acquired_threshold >= self.threshold {
                return Ok(());
            }
        }

        Err("threshold not met")
    }
}

fn main() {
    let mut signers = HashSet::new();
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    signers.insert(alice);
    signers.insert(bob);

    let verifier = MultiSigVerifier::new(2, signers);

    // Exploit: single valid signature repeated hits threshold
    let sigs = vec![
        Signature { signer: alice, data: vec![0xab] },
        Signature { signer: alice, data: vec![0xab] },
    ];
    assert!(verifier.verify_execution(&sigs).is_ok());
    println!("vulnerable: single sig replayed to pass threshold!");
}