// Vuln fixture for `reth-gas-limit-trie-disagreement`.
//
// `validate_header` hard-codes the gas-limit to 30_000_000 instead of
// reading it from the chain spec. Optimism-shape multi-client divergence
// post-mortem: when the chainspec raises the limit, this client rejects
// otherwise-valid headers.
#![allow(dead_code)]

pub struct Header {
    pub gas_limit: u64,
    pub number: u64,
}

pub fn validate_header(header: &Header) -> Result<(), &'static str> {
    // BUG: hard-coded magic number; no chainspec lookup.
    if header.gas_limit > 30_000_000 {
        return Err("gas_limit too high");
    }
    if header.number == 0 {
        return Err("genesis cannot be validated here");
    }
    Ok(())
}
