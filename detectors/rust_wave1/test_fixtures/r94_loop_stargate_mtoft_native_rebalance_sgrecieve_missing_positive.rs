use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct StargateRouter;
impl StargateRouter {
    fn swap(&self, _dst_chain: u16, _recipient: Address, _amount: u64) {}
}
#[contract]
pub struct MTOFT;
#[contractimpl]
impl MTOFT {
    // BUG: bridges native ETH without attaching sgReceive composer callback
    pub fn rebalance(dst_chain: u16, dst_mtoft: Address, amount: u64) {
        let stargate_router = StargateRouter;
        stargate_router.swap(dst_chain, dst_mtoft, amount);
    }
}
