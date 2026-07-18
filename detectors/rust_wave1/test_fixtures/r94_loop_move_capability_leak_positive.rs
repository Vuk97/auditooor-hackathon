use soroban_sdk::{contract, contractimpl};
pub struct TreasuryCap<T> { _phantom: core::marker::PhantomData<T> }
pub struct T;
#[contract]
pub struct Module;
#[contractimpl]
impl Module {
    // BUG: returns a TreasuryCap without consuming
    pub fn make_cap(_arg: u64) -> TreasuryCap<T> {
        TreasuryCap { _phantom: core::marker::PhantomData }
    }
    // BUG: accepts AdminCap but doesn't transfer/move_to/destroy
    pub fn do_admin_stuff(cap: AdminCap, _arg: u64) {
        let _ = cap;
    }
}
pub struct AdminCap;
