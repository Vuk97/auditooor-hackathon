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
    token_locks: HashMap<TokenId, u64>, // token_id -> auction_id
    next_auction_id: u64,
}

impl AuctionHouse {
    fn new() -> Self {
        Self {
            auctions: HashMap::new(),
            token_locks: HashMap::new(),
            next_auction_id: 1,
        }
    }

    fn create_reserve_auction(&mut self, seller: u64, token_id: TokenId, min_bid: u64) -> Result<u64, &'static str> {
        // FIX: Check if token is already locked in another auction
        if self.token_locks.contains_key(&token_id) {
            return Err("Token already locked in active auction");
        }
        
        let auction_id = self.next_auction_id;
        self.next_auction_id += 1;
        
        let auction = Auction {
            token_id: token_id.clone(),
            seller,
            min_bid,
            highest_bid: None,
            highest_bidder: None,
            escrowed: true,
        };
        
        self.auctions.insert(auction_id, auction);
        self.token_locks.insert(token_id, auction_id);
        
        Ok(auction_id)
    }

    fn settle_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
        let auction = self.auctions.remove(&auction_id)
            .ok_or("Auction not found")?;
        self.token_locks.remove(&auction.token_id);
        Ok(())
    }

    fn cancel_auction(&mut self, auction_id: u64) -> Result<(), &'static str> {
        let auction = self.auctions.remove(&auction_id)
            .ok_or("Auction not found")?;
        self.token_locks.remove(&auction.token_id);
        Ok(())
    }
}

fn main() {
    let mut house = AuctionHouse::new();
    let token = TokenId(42);
    
    let a1 = house.create_reserve_auction(1, token.clone(), 100).unwrap();
    let a2 = house.create_reserve_auction(1, token.clone(), 200);
    assert!(a2.is_err()); // Second auction blocked
    
    house.settle_auction(a1).unwrap();
    let a3 = house.create_reserve_auction(1, token.clone(), 300).unwrap();
    assert_eq!(a3, 2);
}