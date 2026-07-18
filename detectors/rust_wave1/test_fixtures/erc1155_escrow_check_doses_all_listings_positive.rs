use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Listing {
    seller: [u8; 32],
    token_id: u64,
    amount: u64,
    price_per_unit: u64,
}

struct Marketplace {
    listings: HashMap<u64, Vec<Listing>>,
    balances: HashMap<(u64, [u8; 32]), u64>,
}

impl Marketplace {
    fn new() -> Self {
        Self {
            listings: HashMap::new(),
            balances: HashMap::new(),
        }
    }

    fn set_balance(&mut self, token_id: u64, owner: [u8; 32], amount: u64) {
        self.balances.insert((token_id, owner), amount);
    }

    fn get_balance(&self, token_id: u64, owner: [u8; 32]) -> u64 {
        self.balances.get(&(token_id, owner)).copied().unwrap_or(0)
    }

    fn add_listing(&mut self, listing_id: u64, listing: Listing) {
        self.listings.entry(listing_id).or_default().push(listing);
    }

    fn is_listing_valid(&self, listing: &Listing, marketplace_addr: [u8; 32]) -> bool {
        let escrow_balance = self.get_balance(listing.token_id, marketplace_addr);
        escrow_balance >= listing.amount
    }

    fn get_total_amount_for_token(&self, token_id: u64, marketplace_addr: [u8; 32]) -> u64 {
        let mut total = 0u64;
        for listings in self.listings.values() {
            for listing in listings {
                if listing.token_id == token_id {
                    total = total.saturating_add(listing.amount);
                }
            }
        }
        total
    }

    fn validate_all_listings_for_token(&self, token_id: u64, marketplace_addr: [u8; 32]) -> Result<(), String> {
        let total_needed = self.get_total_amount_for_token(token_id, marketplace_addr);
        let escrow_balance = self.get_balance(token_id, marketplace_addr);
        
        if escrow_balance < total_needed {
            return Err(format!(
                "Escrow balance {} insufficient for total needed {} across all listings",
                escrow_balance, total_needed
            ));
        }
        
        for (listing_id, listings) in &self.listings {
            for listing in listings {
                if listing.token_id == token_id {
                    if !self.is_listing_valid(listing, marketplace_addr) {
                        return Err(format!(
                            "Listing {} invalid: escrow lacks balance",
                            listing_id
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn execute_listing(&self, listing_id: u64, listing_index: usize, marketplace_addr: [u8; 32]) -> Result<u64, String> {
        let listings = self.listings.get(&listing_id)
            .ok_or("Listing not found")?;
        let listing = listings.get(listing_index)
            .ok_or("Invalid listing index")?;
        
        if !self.is_listing_valid(listing, marketplace_addr) {
            return Err("Listing is invalid".to_string());
        }
        
        let total_for_token = self.get_total_amount_for_token(listing.token_id, marketplace_addr);
        let escrow_balance = self.get_balance(listing.token_id, marketplace_addr);
        if escrow_balance < total_for_token {
            return Err("Escrow insufficient for all listings".to_string());
        }
        
        Ok(listing.price_per_unit * listing.amount)
    }
}

fn main() {
    let mut marketplace = Marketplace::new();
    let seller = [1u8; 32];
    let marketplace_addr = [2u8; 32];
    
    marketplace.set_balance(1, marketplace_addr, 100);
    
    marketplace.add_listing(1, Listing {
        seller,
        token_id: 1,
        amount: 50,
        price_per_unit: 10,
    });
    
    marketplace.add_listing(2, Listing {
        seller,
        token_id: 1,
        amount: 60,
        price_per_unit: 10,
    });
    
    let result = marketplace.execute_listing(1, 0, marketplace_addr);
    assert!(result.is_err());
    
    let valid = marketplace.validate_all_listings_for_token(1, marketplace_addr);
    assert!(valid.is_err());
    
    marketplace.set_balance(1, marketplace_addr, 200);
    let result = marketplace.execute_listing(1, 0, marketplace_addr);
    assert!(result.is_ok());
    
    marketplace.set_balance(1, marketplace_addr, 90);
    let result = marketplace.execute_listing(1, 0, marketplace_addr);
    assert!(result.is_err());
}