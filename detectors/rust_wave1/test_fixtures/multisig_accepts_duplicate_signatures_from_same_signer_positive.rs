use std::collections::HashSet;

pub struct MultisigValidator {
    threshold: usize,
    attestors: HashSet<[u8; 20]>,
}

impl MultisigValidator {
    pub fn new(threshold: usize, attestors: Vec<[u8; 20]>) -> Self {
        Self {
            threshold,
            attestors: attestors.into_iter().collect(),
        }
    }

    pub fn validate_message(
        &self,
        message: &[u8],
        signatures: &[(Vec<u8>, [u8; 20])],
    ) -> Result<bool, &'static str> {
        let mut valid_count = 0;

        for (sig_bytes, recovered_addr) in signatures {
            // BUG: No deduplication check for duplicate signers
            // Each signature is counted independently

            if !self.attestors.contains(recovered_addr) {
                continue; // not an authorized attestor
            }

            // Verify signature (simplified: check non-empty and matching address)
            if sig_bytes.is_empty() {
                continue;
            }

            valid_count += 1;
        }

        Ok(valid_count >= self.threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_signatures_exploitable() {
        let attestors = vec![[1u8; 20], [2u8; 20], [3u8; 20]];
        let validator = MultisigValidator::new(2, attestors);

        let message = b"hello world";
        // Attacker has only one valid key but submits it twice
        let sig1 = (vec![1u8; 64], [1u8; 20]);
        let sig2 = (vec![1u8; 64], [1u8; 20]); // same signer, duplicate!

        let result = validator.validate_message(message, &[sig1, sig2]).unwrap();
        assert!(result); // BUG: passes with only 1 unique signer!
    }
}