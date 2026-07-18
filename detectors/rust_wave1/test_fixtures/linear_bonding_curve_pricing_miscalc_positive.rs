use std::ops::{Add, Mul};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Uint128(u128);

impl Uint128 {
    pub fn new(val: u128) -> Self { Uint128(val) }
    pub fn u128(&self) -> u128 { self.0 }
}

impl Add for Uint128 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output { Uint128(self.0 + rhs.0) }
}

impl Mul for Uint128 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output { Uint128(self.0 * rhs.0) }
}

pub struct LinearBondingCurve {
    pub base_price: Uint128,
    pub delta: Uint128,
}

impl LinearBondingCurve {
    /// VULNERABLE: uses price * n instead of sum of progression
    /// This computes (base + delta * n) * n which is wrong for batch > 1
    pub fn batch_buy_price(&self, n: Uint128) -> Uint128 {
        let n_val = n.u128();
        let base = self.base_price.u128();
        let delta = self.delta.u128();
        
        // BUG: calculates price(n) * n instead of sum_{i=1..n} price(i)
        let price_n = base + delta * n_val;
        let wrong_total = price_n * n_val;
        Uint128::new(wrong_total)
    }
    
    /// Price for single item at position n (1-indexed)
    pub fn price_at(&self, n: Uint128) -> Uint128 {
        self.base_price + self.delta * n
    }
}

fn main() {
    let curve = LinearBondingCurve {
        base_price: Uint128::new(100),
        delta: Uint128::new(10),
    };
    
    // Batch of 3: vulnerable code returns (100 + 30) * 3 = 390
    // Correct would be 110 + 120 + 130 = 360
    let batch = Uint128::new(3);
    let total = curve.batch_buy_price(batch);
    // This assertion would fail with correct implementation
    assert_eq!(total, Uint128::new(390));
    println!("Vulnerable: batch price = {}", total.u128());
}
