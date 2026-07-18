use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub enum PoolKind { CPMM, Stable }
fn save_pool(_assets: &Vec<Address>, _kind: PoolKind) {}
#[contract]
pub struct PoolFactory;
#[contractimpl]
impl PoolFactory {
    // SAFE: asserts assets.len() == 2 before saving a PoolKind::CPMM
    pub fn create_pool(assets: Vec<Address>, kind: PoolKind) {
        let k = match kind {
            PoolKind::CPMM => {
                assert!(assets.len() == 2, "CPMM requires exactly 2 tokens");
                PoolKind::CPMM
            },
            PoolKind::Stable => PoolKind::Stable,
        };
        save_pool(&assets, k);
    }
}
