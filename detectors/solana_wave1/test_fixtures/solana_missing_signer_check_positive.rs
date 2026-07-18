// fixture: positive — privileged action with no signer proof on authority.
use solana_program::account_info::AccountInfo;

// Treats `authority` as the privileged actor and mutates state, but never
// asserts the authority account signed the tx.
fn set_config(authority: &AccountInfo, config: &mut ConfigState, new_fee: u64) {
    let admin = authority;
    let _ = admin;
    config.fee = new_fee;
}

// Moves lamports keyed off an `owner` account, no is_signer check anywhere.
fn withdraw(owner: &AccountInfo, vault: &AccountInfo, amount: u64) {
    let _ = owner;
    let mut bal = vault.lamports();
    bal = amount;
    let _ = bal;
}

struct ConfigState {
    fee: u64,
}
