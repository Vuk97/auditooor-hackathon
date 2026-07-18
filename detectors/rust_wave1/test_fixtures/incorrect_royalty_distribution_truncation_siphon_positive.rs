use std::collections::HashMap;

// Vulnerable: royalty distribution with truncation siphon
// Each share rounded independently, residual left in contract, last caller takes it

pub struct RoyaltyDistribution {
    pub total_amount: u64,
    pub recipients: Vec<(String, u64)>, // (address, basis_points)
    pub balances: HashMap<String, u64>,
}

impl RoyaltyDistribution {
    pub fn new(total_amount: u64) -> Self {
        Self {
            total_amount,
            recipients: Vec::new(),
            balances: HashMap::new(),
        }
    }

    pub fn add_recipient(&mut self, address: String, basis_points: u64) {
        self.recipients.push((address, basis_points));
    }

    /// VULNERABLE: each share rounded down independently, truncation accumulates
    /// Residual stays in contract balance, exploitable by whoever calls last
    pub fn distribute_vulnerable(&mut self) {
        let total_basis: u64 = self.recipients.iter().map(|(_, bp)| bp).sum();
        assert!(total_basis > 0, "Total basis points must be > 0");
        
        // BUG: independent truncation per recipient
        for (addr, bp) in &self.recipients {
            let share = (self.total_amount * bp) / total_basis; // truncates down
            *self.balances.entry(addr.clone()).or_insert(0) += share;
            // Missing: no tracking of total distributed, no dust handling
        }
        
        // Residual remains in self.total_amount - never redistributed
        // Attacker can call a separate "claim_residual" function (not shown)
        // or the contract keeps it until someone exploits the leftover
    }
    
    /// VULNERABLE variant: explicit loop with truncation, caller-dependent residual claim
    pub fn distribute_and_allow_claim_residual(&mut self, caller: String) {
        let total_basis: u64 = self.recipients.iter().map(|(_, bp)| bp).sum();
        let mut total_distributed: u64 = 0;
        
        for (addr, bp) in &self.recipients {
            let share = (self.total_amount * bp) / total_basis; // truncates down
            *self.balances.entry(addr.clone()).or_insert(0) += share;
            total_distributed += share;
        }
        
        // BUG: residual sent to caller instead of proper distribution
        let residual = self.total_amount - total_distributed;
        if residual > 0 {
            // SIPHON: caller gets the truncation dust
            *self.balances.entry(caller).or_insert(0) += residual;
        }
    }
    
    pub fn get_balance(&self, addr: &str) -> u64 {
        self.balances.get(addr).copied().unwrap_or(0)
    }
}

fn main() {
    let mut dist = RoyaltyDistribution::new(10000);
    dist.add_recipient("artist".to_string(), 7000);  // 70% -> 7000
    dist.add_recipient("platform".to_string(), 2500); // 25% -> 2500  
    dist.add_recipient("charity".to_string(), 500);   // 5% -> 500? No: (10000*500)/10000=500
    // But with 10003 and 3 recipients: 7002, 2500, 500 = 10002, residual 1
    
    dist.distribute_vulnerable();
    
    let total: u64 = dist.balances.values().sum();
    println!("Total distributed: {} (residual trapped in contract)", total);
    
    // Demonstrate siphon variant
    let mut dist2 = RoyaltyDistribution::new(10003);
    dist2.add_recipient("artist".to_string(), 7000);
    dist2.add_recipient("platform".to_string(), 2500);
    dist2.add_recipient("charity".to_string(), 500);
    dist2.distribute_and_allow_claim_residual("attacker".to_string());
    println!("Attacker got residual: {}", dist2.get_balance("attacker"));
}