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
    best_bid: HashMap<ListingId, Bid>,
    escrowed: HashMap<u64, u64>,
}

impl AuctionHouse {
    fn new() -> Self {
        Self {
            bids: HashMap::new(),
            best_bid: HashMap::new(),
            escrowed: HashMap::new(),
        }
    }

    fn bid_for_listing(&mut self, listing_id: ListingId, bidder: u64, amount: u64, auction_type: AuctionType) -> Result<(), &'static str> {
        match auction_type {
            AuctionType::English => {
                let bid = Bid { bidder, amount };
                self.bids.entry(listing_id).or_default().push(bid);
                
                let current_best = self.best_bid.get(&listing_id);
                if current_best.map_or(true, |b| amount > b.amount) {
                    if let Some(prev) = current_best {
                        *self.escrowed.entry(prev.bidder).or_insert(0) += prev.amount;
                    }
                    self.best_bid.insert(listing_id, bid);
                    *self.escrowed.entry(bidder).or_insert(0) += amount;
                }
                Ok(())
            }
            AuctionType::Dutch { start_price, end_price, duration } => {
                let current_price = self.get_dutch_price(start_price, end_price, duration);
                if amount != current_price {
                    return Err("Dutch auction bid must match current price");
                }
                let bid = Bid { bidder, amount };
                *self.escrowed.entry(bidder).or_insert(0) += amount;
                self.best_bid.insert(listing_id, bid);
                Ok(())
            }
        }
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

    fn close_auction(&mut self, listing_id: ListingId, auction_type: AuctionType) -> Option<Bid> {
        match auction_type {
            AuctionType::English => self.best_bid.remove(&listing_id),
            AuctionType::Dutch { .. } => {
                self.bids.remove(&listing_id);
                self.best_bid.remove(&listing_id)
            }
        }
    }
}

fn main() {
    let mut house = AuctionHouse::new();
    let listing = ListingId(1);
    let _ = house.bid_for_listing(listing, 1, 100, AuctionType::Dutch { start_price: 1000, end_price: 100, duration: 1000 });
    let winner = house.close_auction(listing, AuctionType::Dutch { start_price: 1000, end_price: 100, duration: 1000 });
    println!("Winner: {:?}", winner);
}