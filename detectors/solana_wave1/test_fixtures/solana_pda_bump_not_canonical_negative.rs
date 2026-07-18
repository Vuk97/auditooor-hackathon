// fixture: negative — PDA bump pinned to the canonical value.
fn derive_vault(program_id: &Pubkey, user: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", user.as_ref()], program_id)
}

fn derive_config(program_id: &Pubkey, bump_arg: u8) -> Pubkey {
    let (_expected, canonical_bump) =
        Pubkey::find_program_address(&[b"config"], program_id);
    assert_eq!(bump_arg, canonical_bump, "bump must be canonical");
    let seeds: &[&[u8]] = &[b"config", &[bump_arg]];
    Pubkey::create_program_address(seeds, program_id).unwrap()
}

struct Pubkey;
impl Pubkey {
    fn create_program_address(_s: &[&[u8]], _p: &Pubkey) -> Result<Pubkey, ()> {
        Ok(Pubkey)
    }
    fn find_program_address(_s: &[&[u8]], _p: &Pubkey) -> (Pubkey, u8) {
        (Pubkey, 255)
    }
    fn as_ref(&self) -> &[u8] { &[] }
}
