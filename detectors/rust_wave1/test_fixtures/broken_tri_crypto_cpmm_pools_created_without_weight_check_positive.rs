use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub enum PoolKind { CPMM, Stable }
fn save_pool(_assets: &Vec<Address>, _kind: PoolKind) {}
#[contract]
pub struct PoolFactory;
#[contractimpl]
impl PoolFactory {
    pub fn create_pool(assets: Vec<Address>, kind: PoolKind) {
        let k = match kind {
            PoolKind::CPMM => PoolKind::CPMM,
            PoolKind::Stable => PoolKind::Stable,
        };
        save_pool(&assets, k);
    }
}
