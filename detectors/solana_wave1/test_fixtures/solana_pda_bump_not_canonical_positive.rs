// fixture: positive — PDA derived with non-canonical (caller-supplied) bump.
fn derive_vault(program_id: &Pubkey, user: &Pubkey, bump: u8) -> Pubkey {
    Pubkey::create_program_address(&[b"vault", user.as_ref(), &[bump]], program_id)
        .unwrap()
}

fn derive_config(program_id: &Pubkey, bump_arg: u8) -> Pubkey {
    let seeds: &[&[u8]] = &[b"config", &[bump_arg]];
    Pubkey::create_program_address(seeds, program_id).unwrap()
}

struct Pubkey;
impl Pubkey {
    fn create_program_address(_s: &[&[u8]], _p: &Pubkey) -> Result<Pubkey, ()> {
        Ok(Pubkey)
    }
    fn as_ref(&self) -> &[u8] { &[] }
}
