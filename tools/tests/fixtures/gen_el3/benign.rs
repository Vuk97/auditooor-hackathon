fn store_safe(raw: &[u8], store: &mut Store) -> Result<()> {
    let msg = Msg::try_from_slice(raw)?;
    let canon = msg.try_to_vec()?;
    store.set(sha256(&canon), canon);
    Ok(())
}
