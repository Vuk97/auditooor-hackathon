use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ListingId(u64);

#[derive(Debug, Clone, Copy)]
struct Bid {
    bidder: u64,
    amount: u64,
}

#[derive(Debug, Clone, Copy)]
enum AuctionType {
    English,
    Dutch { start_price: u64, end_price: u64, duration: u64 },
}

struct AuctionHouse {
    bids: HashMap<ListingId, Vec<Bid>>,
    best_bid_for_listing: HashMap<ListingId, Bid>,
    escrowed: HashMap<u64, u64>,
}

impl AuctionHouse {
    fn new() -> Self {
        Self {
            bids: HashMap::new(),
            best_bid_for_listing: HashMap::new(),
            escrowed: HashMap::new(),
        }
    }

    fn _bid_for_auction(&mut self, listing_id: ListingId, bidder: u64, amount: u64, auction_type: AuctionType) -> Result<(), &'static str> {
        let bid = Bid { bidder, amount };
        
        self.bids.entry(listing_id).or_default().push(bid);
        
        let current_best = self.best_bid_for_listing.get(&listing_id);
        if current_best.map_or(true, |b| amount > b.amount) {
            if let Some(prev) = current_best {
                *self.escrowed.entry(prev.bidder).or_insert(0) += prev.amount;
            }
            self.best_bid_for_listing.insert(listing_id, bid);
            *self.escrowed.entry(bidder).or_insert(0) += amount;
        }
        
        Ok(())
    }

    fn get_dutch_price(&self, start_price: u64, end_price: u64, duration: u64) -> u64 {
        let elapsed = 100u64;
        if elapsed >= duration {
            end_price
        } else {
            let decay = (start_price - end_price) * elapsed / duration;
            start_price - decay
        }
    }

    fn close_auction(&mut self, listing_id: ListingId) -> Option<Bid> {
        self.bids.remove(&listing_id);
        self.best_bid_for_listing.remove(&listing_id)
    }
}

fn main() {
    let mut house = AuctionHouse::new();
    let listing = ListingId(1);
    
    let dutch_params = AuctionType::Dutch { start_price: 1000, end_price: 100, duration: 1000 };
    
    let _ = house._bid_for_auction(listing, 1, 500, dutch_params);
    let _ = house._bid_for_auction(listing, 2, 501, dutch_params);
    let _ = house._bid_for_auction(listing, 3, 502, dutch_params);
    let _ = house._bid_for_auction(listing, 4, 503, dutch_params);
    
    let winner = house.close_auction(listing);
    println!("Winner: {:?}", winner);
    println!("Escrowed funds locked for non-winners");
}