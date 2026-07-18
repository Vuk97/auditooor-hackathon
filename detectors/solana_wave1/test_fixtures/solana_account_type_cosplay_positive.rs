// fixture: positive — deserialize into typed struct, no discriminator check.
use solana_program::account_info::AccountInfo;

fn load_admin(account: &AccountInfo) -> AdminState {
    let data = account.data.borrow();
    AdminState::try_from_slice(&data).unwrap()
}

fn load_user(account: &AccountInfo) -> UserState {
    let data = account.data.borrow();
    UserState::deserialize(&mut &data[..]).unwrap()
}

struct AdminState;
struct UserState;
impl AdminState {
    fn try_from_slice(_b: &[u8]) -> Result<AdminState, ()> { Ok(AdminState) }
}
impl UserState {
    fn deserialize(_b: &mut &[u8]) -> Result<UserState, ()> { Ok(UserState) }
}
