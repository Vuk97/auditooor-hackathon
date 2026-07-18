use std::marker::PhantomData;

/// Price oracle trait for ETH-denominated asset pricing
trait EthPriceOracle {
    fn steth_per_token(&self) -> u128;
    fn eth_per_steth(&self) -> u128; // External ETH/stETH market rate
}

/// Correct wstETH derivative: accounts for stETH/ETH depeg risk
struct WstEthDerivativeSafe<T: EthPriceOracle> {
    oracle: T,
    _marker: PhantomData<T>,
}

impl<T: EthPriceOracle> WstEthDerivativeSafe<T> {
    fn new(oracle: T) -> Self {
        Self { oracle, _marker: PhantomData }
    }

    /// Returns ETH value of wstETH, accounting for stETH/ETH market rate
    /// stETH may depeg from ETH (e.g., during market stress)
    fn eth_value(&self, wsteth_amount: u128) -> u128 {
        let steth_amount = wsteth_amount * self.oracle.steth_per_token() / 1_000_000_000_000_000_000u128;
        // Apply market ETH/stETH rate to get true ETH value
        let eth_value = steth_amount * self.oracle.eth_per_steth() / 1_000_000_000_000_000_000u128;
        eth_value
    }

    /// Alternative: use Chainlink or other oracle for ETH/stETH
    fn eth_value_with_oracle(&self, wsteth_amount: u128, eth_steth_price: u128) -> u128 {
        let steth_amount = wsteth_amount * self.oracle.steth_per_token() / 1_000_000_000_000_000_000u128;
        steth_amount * eth_steth_price / 1_000_000_000_000_000_000u128
    }
}

struct MockOracle {
    steth_per_token: u128,
    eth_per_steth: u128,
}

impl EthPriceOracle for MockOracle {
    fn steth_per_token(&self) -> u128 { self.steth_per_token }
    fn eth_per_steth(&self) -> u128 { self.eth_per_steth }
}

fn main() {
    // stETH trading at 0.95 ETH (depeg scenario)
    let oracle = MockOracle {
        steth_per_token: 1_100_000_000_000_000_000u128, // 1.1 stETH per wstETH
        eth_per_steth: 950_000_000_000_000_000u128,     // 0.95 ETH per stETH
    };
    let derivative = WstEthDerivativeSafe::new(oracle);
    let val = derivative.eth_value(1_000_000_000_000_000_000u128);
    assert_eq!(val, 1_045_000_000_000_000_000u128); // 1.045 ETH, correctly discounted
    println!("Safe valuation: {}", val);
}
