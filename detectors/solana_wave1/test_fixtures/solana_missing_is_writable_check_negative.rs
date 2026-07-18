// fixture: negative — mutation guarded by is_writable assertion.
use solana_program::account_info::AccountInfo;

fn credit(vault: &AccountInfo, amount: u64) {
    assert!(vault.is_writable, "vault must be writable");
    let mut lamports = vault.try_borrow_mut_lamports().unwrap();
    **lamports += amount;
}

fn write_state(account: &AccountInfo, byte: u8) {
    if !account.is_writable {
        panic!("account not writable");
    }
    let mut data = account.data.borrow_mut();
    data[0] = byte;
}
