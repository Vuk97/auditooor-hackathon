fn store_msg(raw: &[u8], store: &mut Store) -> Result<()> {
    let msg = Msg::try_from_slice(raw)?;
    let key = sha256(raw);
    store.set(key, raw);
    Ok(())
}
fn dedup(raw: &[u8], seen: &mut HashSet<Vec<u8>>) -> bool {
    let m = Msg::try_from_slice(raw).unwrap();
    if seen.contains(raw) { return true; }
    seen.insert(raw.to_vec());
    false
}
