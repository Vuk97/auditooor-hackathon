// processor.rs - calls apply_limit defined in a sibling module file
pub fn process_transfer(amount: u64) -> Result<u64, String> {
    let checked = apply_limit(amount)?;
    Ok(checked)
}
