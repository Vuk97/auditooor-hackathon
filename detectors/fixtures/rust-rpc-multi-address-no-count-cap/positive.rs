// positive.rs - SHOULD fire: valid_addresses iterates over address strings
// via .iter().map(|addr| addr.parse()).collect() with NO address-count cap.

use std::collections::HashSet;

type Address = String;
type Result<T> = std::result::Result<T, String>;

/// Simulates the ValidateAddresses trait default method (no len guard).
trait ValidateAddresses {
    fn valid_addresses(&self) -> Result<HashSet<Address>> {
        let valid_addresses: HashSet<Address> = self
            .addresses()
            .iter()
            .map(|address| {
                address
                    .parse()
                    .map_err(|e| format!("invalid address: {e}"))
            })
            .collect::<Result<_>>()?;

        Ok(valid_addresses)
    }

    fn addresses(&self) -> &[String];
}

struct GetAddressBalanceRequest {
    addresses: Vec<String>,
}

impl ValidateAddresses for GetAddressBalanceRequest {
    fn addresses(&self) -> &[String] {
        &self.addresses
    }
}
