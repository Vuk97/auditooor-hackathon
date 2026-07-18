use soroban_sdk::{contract, contractimpl};
pub struct Model { pub owner: u64 }
#[contract]
pub struct World;
#[contractimpl]
impl World {
    // BUG: only local owner check, no namespace/world-owner consult
    pub fn set_model(caller: u64, model: &mut Model, new_data: u64) {
        require(caller == model.owner);
        model.owner = new_data;
    }
}
fn require(_: bool) {}
