// fixture: negative — native AccountInfo data read guarded by owner check.
use solana_program::account_info::AccountInfo;

fn load_vault(vault: &AccountInfo, program_id: &Pubkey) -> VaultState {
    if vault.owner != program_id {
        panic!("bad owner");
    }
    let data = vault.try_borrow_data().unwrap();
    VaultState::try_from_slice(&data).unwrap()
}

fn read_position(pos: &AccountInfo, program_id: &Pubkey) -> u64 {
    check_program_account(pos, program_id);
    let raw = pos.data.borrow();
    raw[0] as u64
}

fn check_program_account(_a: &AccountInfo, _p: &Pubkey) {}

struct Pubkey;
struct VaultState;
impl VaultState {
    fn try_from_slice(_b: &[u8]) -> Result<VaultState, ()> {
        Ok(VaultState)
    }
}
