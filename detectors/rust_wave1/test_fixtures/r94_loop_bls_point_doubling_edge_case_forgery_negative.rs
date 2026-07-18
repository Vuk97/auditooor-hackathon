use soroban_sdk::{contract, contractimpl};
#[derive(Clone, Copy)]
pub struct G1 { x: u64, y: u64 }
fn field_inv(_a: u64) -> u64 { 1 }
fn is_infinity(p: &G1) -> bool { p.y == 0 }
#[contract]
pub struct BlsCircuit;
#[contractimpl]
impl BlsCircuit {
    // SAFE: checks is_infinity / y == 0 branch before slope calc
    pub fn double_point(p: G1) -> G1 {
        if is_infinity(&p) || p.y == 0 {
            return G1 { x: 0, y: 0 };
        }
        let slope = (3 * p.x * p.x) * field_inv(2 * p.y);
        let x3 = slope * slope - 2 * p.x;
        let y3 = slope * (p.x - x3) - p.y;
        G1 { x: x3, y: y3 }
    }
}
