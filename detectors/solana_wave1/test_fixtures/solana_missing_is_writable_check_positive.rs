// fixture: positive — mutating AccountInfo data/lamports, no is_writable check.
use solana_program::account_info::AccountInfo;

fn credit(vault: &AccountInfo, amount: u64) {
    let mut lamports = vault.try_borrow_mut_lamports().unwrap();
    **lamports += amount;
}

fn write_state(account: &AccountInfo, byte: u8) {
    let mut data = account.data.borrow_mut();
    data[0] = byte;
}
