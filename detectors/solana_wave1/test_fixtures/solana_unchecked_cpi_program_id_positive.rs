// fixture: positive — CPI with unvalidated target program account.
use solana_program::account_info::AccountInfo;

fn forward_transfer(token_program: &AccountInfo, accounts: &[AccountInfo]) {
    let ix = build_transfer_ix();
    invoke(&ix, accounts).unwrap();
    let _ = token_program;
}

fn delegate_call(target: &AccountInfo, accounts: &[AccountInfo], seeds: &[&[u8]]) {
    let ix = build_transfer_ix();
    invoke_signed(&ix, accounts, &[seeds]).unwrap();
    let _ = target;
}

fn build_transfer_ix() -> u8 { 0 }
fn invoke(_ix: &u8, _a: &[AccountInfo]) -> Result<(), ()> { Ok(()) }
fn invoke_signed(_ix: &u8, _a: &[AccountInfo], _s: &[&[&[u8]]]) -> Result<(), ()> {
    Ok(())
}
