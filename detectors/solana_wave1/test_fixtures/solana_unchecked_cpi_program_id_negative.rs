// fixture: negative — CPI target program id pinned before invoke.
use solana_program::account_info::AccountInfo;

fn forward_transfer(token_program: &AccountInfo, accounts: &[AccountInfo]) {
    if token_program.key() != spl_token::id() {
        panic!("fake token program");
    }
    let ix = build_transfer_ix();
    invoke(&ix, accounts).unwrap();
}

fn delegate_call(target: &AccountInfo, accounts: &[AccountInfo], seeds: &[&[u8]]) {
    require_keys_eq!(target.key(), EXPECTED_PROGRAM);
    let ix = build_transfer_ix();
    invoke_signed(&ix, accounts, &[seeds]).unwrap();
}

const EXPECTED_PROGRAM: u8 = 9;

macro_rules! require_keys_eq {
    ($a:expr, $b:expr) => {};
}

mod spl_token {
    pub fn id() -> u8 { 9 }
}

fn build_transfer_ix() -> u8 { 0 }
fn invoke(_ix: &u8, _a: &[AccountInfo]) -> Result<(), ()> { Ok(()) }
fn invoke_signed(_ix: &u8, _a: &[AccountInfo], _s: &[&[&[u8]]]) -> Result<(), ()> {
    Ok(())
}
