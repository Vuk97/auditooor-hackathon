// Clean fixture for `reth-gas-limit-trie-disagreement`.
//
// `validate_header` reads the gas limit bound from a `ChainSpec` /
// `chainspec` accessor. Detector must NOT fire because the body
// references `chain_spec` (negative regex token).
#![allow(dead_code)]

pub struct ChainSpec {
    pub max_gas_limit: u64,
}

pub struct Header {
    pub gas_limit: u64,
    pub number: u64,
}

pub fn validate_header(header: &Header, chain_spec: &ChainSpec) -> Result<(), &'static str> {
    // Defer to chainspec — peer-client compatible.
    if header.gas_limit > chain_spec.max_gas_limit {
        return Err("gas_limit exceeds chainspec");
    }
    Ok(())
}
