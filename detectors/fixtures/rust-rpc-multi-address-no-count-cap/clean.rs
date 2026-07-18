// clean.rs - should NOT fire: valid_addresses has a per-request address-count cap.

use std::collections::HashSet;

const MAX_ADDRESSES_PER_REQUEST: usize = 50;

type Address = String;
type Result<T> = std::result::Result<T, String>;

/// Safe version: rejects requests with too many addresses before iterating.
trait ValidateAddresses {
    fn valid_addresses(&self) -> Result<HashSet<Address>> {
        // Count guard: reject oversized requests before any parse work.
        if self.addresses().len() > MAX_ADDRESSES_PER_REQUEST {
            return Err(format!(
                "too many addresses: max is {}",
                MAX_ADDRESSES_PER_REQUEST
            ));
        }

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
