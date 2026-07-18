use soroban_sdk::{contract, contractimpl};
type G1 = [u8; 48];
type G2 = [u8; 96];
fn g1_add(_a: &G1, _b: &G1) -> G1 { [0; 48] }
fn pairing_eq(_a: &G1, _b: &G2, _c: &G1, _d: &G2) -> bool { true }
#[contract]
pub struct BlsWallet;
#[contractimpl]
impl BlsWallet {
    // BUG: aggregates pubkeys without proof-of-possession check
    pub fn process_bundle(pubkeys: Vec<G1>, msgs: Vec<G2>, agg_sig: G1) -> bool {
        let mut agg_pk = [0u8; 48];
        for pk in pubkeys.iter() {
            agg_pk = g1_add(&agg_pk, pk);
        }
        pairing_eq(&agg_sig, &msgs[0], &agg_pk, &msgs[0])
    }
}
