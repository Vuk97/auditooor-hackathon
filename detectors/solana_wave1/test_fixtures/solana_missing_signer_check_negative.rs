// fixture: negative — privileged actions all prove the authority signed.
use solana_program::account_info::AccountInfo;

// Native: explicit is_signer assertion before the privileged write.
fn set_config(authority: &AccountInfo, config: &mut ConfigState, new_fee: u64) {
    if !authority.is_signer {
        panic!("authority must sign");
    }
    config.fee = new_fee;
}

// Anchor: Signer<'info> type carries the signer check.
fn withdraw<'info>(owner: Signer<'info>, vault: &AccountInfo, amount: u64) {
    let _ = owner;
    let mut bal = vault.lamports();
    bal = amount;
    let _ = bal;
}

struct ConfigState {
    fee: u64,
}
struct Signer<'a>(&'a u8);
