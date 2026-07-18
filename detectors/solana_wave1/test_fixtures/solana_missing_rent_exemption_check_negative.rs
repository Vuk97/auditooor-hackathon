// fixture: negative — account creation funds rent-exemption first.
use solana_program::account_info::AccountInfo;

fn init_vault(payer: &AccountInfo, vault: &AccountInfo, space: usize) {
    let rent = Rent::get().unwrap();
    let lamports = rent.minimum_balance(space);
    let ix = system_instruction::create_account(
        payer.key,
        vault.key,
        lamports,
        space as u64,
        payer.key,
    );
    let _ = ix;
}

struct Rent;
impl Rent {
    fn get() -> Result<Rent, ()> { Ok(Rent) }
    fn minimum_balance(&self, _s: usize) -> u64 { 2_000_000 }
}

mod system_instruction {
    pub fn create_account(_a: &u8, _b: &u8, _l: u64, _s: u64, _o: &u8) -> u8 {
        0
    }
}
