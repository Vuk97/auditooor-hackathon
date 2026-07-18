// fixture: negative — deserialize guarded by account-type discriminator check.
use solana_program::account_info::AccountInfo;

fn load_admin(account: &AccountInfo) -> AdminState {
    let data = account.data.borrow();
    let state = AdminState::try_from_slice(&data).unwrap();
    require!(state.account_type == AccountType::Admin, "type cosplay");
    state
}

fn load_user(account: &AccountInfo) -> UserState {
    let data = account.data.borrow();
    assert_eq!(data[0], DISCRIMINATOR, "wrong discriminator");
    UserState::deserialize(&mut &data[..]).unwrap()
}

const DISCRIMINATOR: u8 = 2;

macro_rules! require {
    ($c:expr, $m:expr) => {};
}

enum AccountType { Admin }
struct AdminState { account_type: AccountType }
struct UserState;
impl AdminState {
    fn try_from_slice(_b: &[u8]) -> Result<AdminState, ()> {
        Ok(AdminState { account_type: AccountType::Admin })
    }
}
impl UserState {
    fn deserialize(_b: &mut &[u8]) -> Result<UserState, ()> { Ok(UserState) }
}
