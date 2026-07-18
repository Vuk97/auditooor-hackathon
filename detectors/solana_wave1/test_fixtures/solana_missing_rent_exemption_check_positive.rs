// fixture: positive — account creation with no rent-exemption funding.
use solana_program::account_info::AccountInfo;

fn init_vault(payer: &AccountInfo, vault: &AccountInfo, space: u64) {
    let ix = system_instruction::create_account(
        payer.key,
        vault.key,
        1000,
        space,
        payer.key,
    );
    let _ = ix;
}

mod system_instruction {
    pub fn create_account(_a: &u8, _b: &u8, _l: u64, _s: u64, _o: &u8) -> u8 {
        0
    }
}
