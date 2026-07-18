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
    /// Correct: computes sum of linear progression for batch pricing
    /// sum_{i=1..n} (base + delta * i) = n * base + delta * n * (n + 1) / 2
    pub fn batch_buy_price(&self, n: Uint128) -> Uint128 {
        let n_val = n.u128();
        let base = self.base_price.u128();
        let delta = self.delta.u128();
        
        // Correct formula: n * base + delta * n * (n + 1) / 2
        let sum = n_val * base + delta * n_val * (n_val + 1) / 2;
        Uint128::new(sum)
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
    
    // Batch of 3: prices are 110, 120, 130 = sum 360
    let batch = Uint128::new(3);
    let total = curve.batch_buy_price(batch);
    assert_eq!(total, Uint128::new(360));
    println!("Clean: batch price = {}", total.u128());
}
