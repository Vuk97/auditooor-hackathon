use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct StargateRouter;
impl StargateRouter {
    fn swap(&self, _dst_chain: u16, _recipient: Address, _amount: u64, _composer: Address) {}
}
#[contract]
pub struct MTOFT;
#[contractimpl]
impl MTOFT {
    // SAFE: attaches composer (sg_receive) callback to pick up ETH on arrival
    pub fn rebalance(dst_chain: u16, dst_mtoft: Address, amount: u64) {
        let stargate_router = StargateRouter;
        let sg_receive_composer: Address = dst_mtoft;  // dst mTOFT implements sg_receive
        stargate_router.swap(dst_chain, dst_mtoft, amount, sg_receive_composer);
    }
}
