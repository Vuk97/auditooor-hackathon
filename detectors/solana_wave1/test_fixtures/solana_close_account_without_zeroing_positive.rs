// fixture: positive — account closed by draining lamports, data left intact.
use solana_program::account_info::AccountInfo;

fn close_vault(vault: &AccountInfo, recipient: &AccountInfo) {
    let amount = vault.lamports();
    **recipient.lamports.borrow_mut() += amount;
    **vault.lamports.borrow_mut() = 0;
}

fn close_position(pos: &AccountInfo, dest: &AccountInfo) {
    let amount = pos.lamports();
    **dest.lamports.borrow_mut() += amount;
    **pos.lamports.borrow_mut() = 0;
}
