use std::marker::PhantomData;

/// Price oracle trait — only provides stETH per token, no market rate
trait StEthRateOracle {
    fn steth_per_token(&self) -> u128;
}

/// VULNERABLE: Assumes stETH always equals ETH 1:1
struct WstEthDerivativeVulnerable<T: StEthRateOracle> {
    oracle: T,
    _marker: PhantomData<T>,
}

impl<T: StEthRateOracle> WstEthDerivativeVulnerable<T> {
    fn new(oracle: T) -> Self {
        Self { oracle, _marker: PhantomData }
    }

    /// BUG: Directly returns stETH amount as ETH value, assuming 1:1 peg
    /// This overvalues wstETH when stETH depegs below ETH
    fn eth_value(&self, wsteth_amount: u128) -> u128 {
        // VULNERABLE: No conversion from stETH to ETH market price
        // Implicitly assumes 1 stETH == 1 ETH
        wsteth_amount * self.oracle.steth_per_token() / 1_000_000_000_000_000_000u128
    }

    /// Another variant: explicitly treating stETH as ETH equivalent
    fn deposit_value(&self, wsteth_amount: u128) -> u128 {
        let steth_equivalent = self.eth_value(wsteth_amount);
        // BUG: Returning stETH amount labeled as "ETH" without peg adjustment
        steth_equivalent // Assumes 1:1, no eth_per_steth() check
    }
}

struct MockOracle {
    steth_per_token: u128,
}

impl StEthRateOracle for MockOracle {
    fn steth_per_token(&self) -> u128 { self.steth_per_token }
}

fn main() {
    // During depeg: stETH at 0.95 ETH, but contract doesn't know
    let oracle = MockOracle {
        steth_per_token: 1_100_000_000_000_000_000u128, // 1.1 stETH per wstETH
    };
    let derivative = WstEthDerivativeVulnerable::new(oracle);
    let val = derivative.eth_value(1_000_000_000_000_000_000u128);
    // Returns 1.1 "ETH" but actual value is 1.045 ETH — OVERVALUED by ~5.3%
    assert_eq!(val, 1_100_000_000_000_000_000u128); // Bug: no depeg discount
    println!("Vulnerable valuation (overstated): {}", val);
}
