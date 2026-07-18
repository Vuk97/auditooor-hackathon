use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Rental {
    pub nft_id: u64,
    pub renter: u64,
    pub lender: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub escrow_amount: u64,
}

pub struct RentalState {
    pub rentals: HashMap<u64, Rental>,
    pub escrow: HashMap<u64, u64>,
    pub nft_owner: HashMap<u64, u64>,
    pub caller: u64,
}

impl RentalState {
    pub fn new() -> Self {
        Self {
            rentals: HashMap::new(),
            escrow: HashMap::new(),
            nft_owner: HashMap::new(),
            caller: 0,
        }
    }

    pub fn set_caller(&mut self, caller: u64) {
        self.caller = caller;
    }

    pub fn start_rental(&mut self, nft_id: u64, renter: u64, lender: u64, escrow: u64) {
        let rental = Rental {
            nft_id,
            renter,
            lender,
            start_time: 100,
            end_time: 1000,
            escrow_amount: escrow,
        };
        self.rentals.insert(nft_id, rental);
        self.escrow.insert(nft_id, escrow);
        self.nft_owner.insert(nft_id, renter);
    }

    pub fn stop_rental(&mut self, nft_id: u64) -> Result<(), String> {
        let rental = self.rentals.get(&nft_id).ok_or("Rental not found")?;
        
        // SECURITY FIX: Verify caller is authorized to stop the rental
        if self.caller != rental.renter && self.caller != rental.lender {
            return Err("Unauthorized: only renter or lender can stop rental".to_string());
        }
        
        let escrow = self.escrow.remove(&nft_id).unwrap_or(0);
        
        // Return NFT to lender
        self.nft_owner.insert(nft_id, rental.lender);
        
        // Release escrow to lender
        println!("Released escrow {} to lender {}", escrow, rental.lender);
        
        self.rentals.remove(&nft_id);
        
        Ok(())
    }
}

fn main() {
    let mut state = RentalState::new();
    state.start_rental(1, 100, 200, 500);
    
    // Renter stops rental - authorized
    state.set_caller(100);
    assert!(state.stop_rental(1).is_ok());
    
    // Verify NFT returned to lender
    assert_eq!(state.nft_owner.get(&1), Some(&200));
}