// fixture: negative — full safe close: lamports drained AND data wiped.
use solana_program::account_info::AccountInfo;

fn close_vault(vault: &AccountInfo, recipient: &AccountInfo) {
    let amount = vault.lamports();
    **recipient.lamports.borrow_mut() += amount;
    **vault.lamports.borrow_mut() = 0;
    let mut data = vault.data.borrow_mut();
    data.fill(0);
}

fn close_position(pos: &AccountInfo, dest: &AccountInfo) {
    let amount = pos.lamports();
    **dest.lamports.borrow_mut() += amount;
    **pos.lamports.borrow_mut() = 0;
    let mut data = pos.data.borrow_mut();
    data[0] = CLOSED_ACCOUNT_DISCRIMINATOR;
}

const CLOSED_ACCOUNT_DISCRIMINATOR: u8 = 255;
