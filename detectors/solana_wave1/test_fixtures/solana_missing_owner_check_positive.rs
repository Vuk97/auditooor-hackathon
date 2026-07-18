// fixture: positive — native AccountInfo data read with no owner check.
use solana_program::account_info::AccountInfo;

fn load_vault(vault: &AccountInfo) -> VaultState {
    let data = vault.try_borrow_data().unwrap();
    VaultState::try_from_slice(&data).unwrap()
}

fn read_position(pos: &AccountInfo) -> u64 {
    let raw = pos.data.borrow();
    raw[0] as u64
}

struct VaultState;
impl VaultState {
    fn try_from_slice(_b: &[u8]) -> Result<VaultState, ()> {
        Ok(VaultState)
    }
}
