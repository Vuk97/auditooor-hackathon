use std::collections::HashMap;

// Clean: royalty distribution with proper truncation handling
// Residual dust is tracked and distributed fairly, not siphoned by last caller

pub struct RoyaltyDistribution {
    pub total_amount: u64,
    pub recipients: Vec<(String, u64)>, // (address, basis_points)
}

impl RoyaltyDistribution {
    pub fn new(total_amount: u64) -> Self {
        Self {
            total_amount,
            recipients: Vec::new(),
        }
    }

    pub fn add_recipient(&mut self, address: String, basis_points: u64) {
        self.recipients.push((address, basis_points));
    }

    /// Clean: distribute with proper dust handling - track remainder and add to first recipient
    pub fn distribute(&self) -> HashMap<String, u64> {
        let total_basis: u64 = self.recipients.iter().map(|(_, bp)| bp).sum();
        assert!(total_basis > 0, "Total basis points must be > 0");
        
        let mut distributions = HashMap::new();
        let mut total_distributed: u64 = 0;
        
        // Calculate each share, track running total
        for (i, (addr, bp)) in self.recipients.iter().enumerate() {
            let share = (self.total_amount * bp) / total_basis;
            distributions.insert(addr.clone(), share);
            total_distributed += share;
            
            // Last recipient gets any dust (deterministic, not caller-dependent)
            if i == self.recipients.len() - 1 {
                let dust = self.total_amount - total_distributed;
                if dust > 0 {
                    *distributions.get_mut(addr).unwrap() += dust;
                }
            }
        }
        
        distributions
    }
    
    /// Alternative clean: use checked math and explicit remainder handling
    pub fn distribute_fair(&self) -> HashMap<String, u64> {
        let total_basis: u64 = self.recipients.iter().map(|(_, bp)| bp).sum();
        assert!(total_basis > 0);
        
        let mut distributions = HashMap::new();
        let mut remainder = self.total_amount;
        
        for (i, (addr, bp)) in self.recipients.iter().enumerate() {
            if i == self.recipients.len() - 1 {
                // Last gets remainder to ensure exact distribution
                distributions.insert(addr.clone(), remainder);
                break;
            }
            
            let share = (self.total_amount * bp) / total_basis;
            distributions.insert(addr.clone(), share);
            remainder -= share;
        }
        
        distributions
    }
}

fn main() {
    let mut dist = RoyaltyDistribution::new(10000);
    dist.add_recipient("artist".to_string(), 7000);  // 70%
    dist.add_recipient("platform".to_string(), 2500); // 25%
    dist.add_recipient("charity".to_string(), 500);   // 5%
    
    let result = dist.distribute();
    let total: u64 = result.values().sum();
    assert_eq!(total, 10000, "All funds must be distributed");
    println!("Total distributed: {}", total);
}