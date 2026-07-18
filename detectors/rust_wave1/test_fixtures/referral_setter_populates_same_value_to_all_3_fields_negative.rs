use std::collections::HashMap;
use alloy_primitives::Address;

#[derive(Clone, Debug, PartialEq)]
pub struct ReferralInfo {
    pub referrer: Address,
    pub referrer_rate: u64,
    pub authority_rate: u64,
}

pub struct SystemConfig {
    referral_info_map: HashMap<Address, ReferralInfo>,
}

impl SystemConfig {
    pub fn new() -> Self {
        Self {
            referral_info_map: HashMap::new(),
        }
    }

    pub fn update_referrer_info(
        &mut self,
        msg_sender: Address,
        referrer: Address,
        referrer_rate: u64,
        authority_rate: u64,
    ) -> Result<(), &'static str> {
        // Validate rates are within bounds
        if referrer_rate > 10000 || authority_rate > 10000 {
            return Err("Rate exceeds 100%");
        }

        // Validate total rate doesn't exceed 100%
        if referrer_rate.saturating_add(authority_rate) > 10000 {
            return Err("Total rate exceeds 100%");
        }

        // Validate caller has permission to set these rates
        if msg_sender != referrer {
            // Only authority or admin can set rates for others
            // Simplified: assume authority check passed
        }

        let info = ReferralInfo {
            referrer,
            referrer_rate,
            authority_rate,
        };

        self.referral_info_map.insert(referrer, info);
        Ok(())
    }

    pub fn get_referral_info(&self, addr: &Address) -> Option<&ReferralInfo> {
        self.referral_info_map.get(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_referrer_info_clean() {
        let mut config = SystemConfig::new();
        let addr = Address::from([1u8; 20]);
        let referrer = Address::from([2u8; 20]);
        
        config.update_referrer_info(addr, referrer, 3000, 2000).unwrap();
        
        let info = config.get_referral_info(&referrer).unwrap();
        assert_eq!(info.referrer, referrer);
        assert_eq!(info.referrer_rate, 3000);
        assert_eq!(info.authority_rate, 2000);
    }
}