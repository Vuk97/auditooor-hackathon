pub struct Signature;
pub struct PublicKey;
pub struct Error;

pub fn sha256(_bytes: &[u8]) -> [u8; 32] {
    [0u8; 32]
}

pub fn verify_signature(
    _signer: &PublicKey,
    _digest: &[u8; 32],
    _signature: &Signature,
) -> Result<(), Error> {
    Ok(())
}

pub fn verify_program_payload_signature_binds_domain(
    chain_id: u64,
    network_id: u32,
    program_id: [u8; 32],
    module_id: u16,
    entrypoint: u8,
    nonce: u64,
    account_owner: [u8; 32],
    resource_domain: [u8; 32],
    payload: &[u8],
    signer: &PublicKey,
    signature: &Signature,
) -> Result<(), Error> {
    let mut digest_material = Vec::new();
    digest_material.extend_from_slice(&chain_id.to_le_bytes());
    digest_material.extend_from_slice(&network_id.to_le_bytes());
    digest_material.extend_from_slice(&program_id);
    digest_material.extend_from_slice(&module_id.to_le_bytes());
    digest_material.push(entrypoint);
    digest_material.extend_from_slice(&nonce.to_le_bytes());
    digest_material.extend_from_slice(&account_owner);
    digest_material.extend_from_slice(&resource_domain);
    digest_material.extend_from_slice(payload);

    let digest = sha256(&digest_material);
    verify_signature(signer, &digest, signature)?;
    Ok(())
}
