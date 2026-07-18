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
    ) -> Result<(), &'static str> {
        // BUG: Same value (msg_sender) assigned to all three fields
        // This allows referrers to set their own rates to arbitrary values
        // and effectively skim funds by replaying with their own address
        let info = ReferralInfo {
            referrer: msg_sender,
            referrer_rate: msg_sender.into(),  // BUG: using address as rate
            authority_rate: msg_sender.into(), // BUG: using address as rate
        };

        self.referral_info_map.insert(msg_sender, info);
        Ok(())
    }

    pub fn get_referral_info(&self, addr: &Address) -> Option<&ReferralInfo> {
        self.referral_info_map.get(addr)
    }
}

// Alternative vulnerable pattern: direct assignment without validation
pub struct SystemConfigV2 {
    referral_info_map: HashMap<Address, ReferralInfo>,
}

impl SystemConfigV2 {
    pub fn new() -> Self {
        Self {
            referral_info_map: HashMap::new(),
        }
    }

    pub fn update_referrer_info_v2(
        &mut self,
        msg_sender: Address,
    ) {
        // BUG: msg_sender used for all three fields without separate parameters
        let info = ReferralInfo {
            referrer: msg_sender,
            referrer_rate: 0, // Would be msg_sender in real bug, using 0 for compile
            authority_rate: 0, // Would be msg_sender in real bug
        };
        // Pattern: same identifier assigned to multiple struct fields
        self.referral_info_map.insert(msg_sender, info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_referrer_info_vulnerable() {
        let mut config = SystemConfig::new();
        let addr = Address::from([1u8; 20]);
        
        config.update_referrer_info(addr).unwrap();
        
        let info = config.get_referral_info(&addr).unwrap();
        // All fields derived from same source - bug!
        assert_eq!(info.referrer, addr);
    }
}