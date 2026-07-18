use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TokenId(u64);

#[derive(Clone, Debug)]
struct Auction {
    token_id: TokenId,
    seller: u64,
    min_bid: u64,
    highest_bid: Option<u64>,
    highest_bidder: Option<u64>,
    escrowed: bool,
}

struct AuctionHouse {
    auctions: HashMap<u64, Auction>,
    // BUG: No token_locks mapping to prevent duplicate auctions
    next_auction_id: u64,
}

impl AuctionHouse {
    fn new() -> Self {
        Self {
            auctions: HashMap::new(),
            next_auction_id: 1,
        }
    }

    fn create_reserve_auction(&mut self, seller: u64, token_id: TokenId, min_bid: u64) -> u64 {
        // BUG: No check if token is already in an active auction
        let auction_id = self.next_auction_id;
        self.next_auction_id += 1;
        
        let auction = Auction {
            token_id,
            seller,
            min_bid,
            highest_bid: None,
            highest_bidder: None,
            escrowed: true,
        };
        
        self.auctions.insert(auction_id, auction);
        auction_id
    }

    fn settle_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
        self.auctions.remove(&auction_id)
            .ok_or("Auction not found")?;
        Ok(())
    }

    fn cancel_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
        self.auctions.remove(&auction_id)
            .ok_or("Auction not found")?;
        Ok(())
    }
}

fn main() {
    let mut house = AuctionHouse::new();
    let token = TokenId(42);
    
    // BUG: Can create multiple simultaneous auctions for same token
    let a1 = house.create_reserve_auction(1, token.clone(), 100);
    let a2 = house.create_reserve_auction(1, token.clone(), 200);
    
    assert_ne!(a1, a2);
    assert_eq!(house.auctions.len(), 2); // Both exist simultaneously
    
    // If a2 takes the NFT, a1's bidders' funds are stuck
    house.settle_auction(a2).unwrap();
    // a1 still exists but NFT is gone - bidders can't recover
}