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
        let mut seen_signers: HashSet<[u8; 32]> = HashSet::new();

        for sig in signatures {
            if !self.signers.contains(&sig.signer) {
                continue;
            }
            // DEDUPLICATION: only count each unique signer once
            if !seen_signers.insert(sig.signer) {
                continue; // signer already counted, skip duplicate
            }
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

    // Same sig twice — clean version rejects duplicate
    let sigs = vec![
        Signature { signer: alice, data: vec![0xab] },
        Signature { signer: alice, data: vec![0xab] },
    ];
    assert!(verifier.verify_execution(&sigs).is_err());
    println!("clean: duplicate sig correctly rejected");
}