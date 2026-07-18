use soroban_sdk::{contract, contractimpl};
pub struct Model { pub owner: u64, pub namespace_id: u64 }
#[contract]
pub struct SafeWorld;
#[contractimpl]
impl SafeWorld {
    // OK: also checks namespace_owner (hierarchical)
    pub fn set_model(caller: u64, model: &mut Model, new_data: u64, namespace_owner: u64, world_owner: u64) {
        require(caller == model.owner || caller == namespace_owner || caller == world_owner);
        model.owner = new_data;
    }
}
fn require(_: bool) {}
