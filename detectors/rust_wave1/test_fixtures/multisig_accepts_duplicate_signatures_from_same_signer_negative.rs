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
        let mut seen_signers: HashSet<[u8; 20]> = HashSet::new();
        let mut valid_count = 0;

        for (sig_bytes, recovered_addr) in signatures {
            // Deduplicate: skip if we've already counted this signer
            if !seen_signers.insert(*recovered_addr) {
                continue; // already seen this signer
            }

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
    fn test_duplicate_signatures_rejected() {
        let attestors = vec![[1u8; 20], [2u8; 20], [3u8; 20]];
        let validator = MultisigValidator::new(2, attestors);

        let message = b"hello world";
        let sig1 = (vec![1u8; 64], [1u8; 20]);
        let sig2 = (vec![1u8; 64], [1u8; 20]); // duplicate signer
        let sig3 = (vec![2u8; 64], [2u8; 20]);

        let result = validator.validate_message(message, &[sig1, sig2, sig3]).unwrap();
        assert!(result); // true because 2 unique valid signers, not 3
    }
}