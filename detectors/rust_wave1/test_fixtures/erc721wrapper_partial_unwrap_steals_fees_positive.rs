use std::collections::HashMap;

#[derive(Clone, Debug)]
struct TokenId(u64);

#[derive(Clone, Debug)]
struct Position {
    liquidity: u128,
    fee_growth_inside0_last: u128,
    fee_growth_inside1_last: u128,
}

struct ERC721Wrapper {
    positions: HashMap<TokenId, Position>,
    supply: HashMap<u64, u128>,
    owner_of: HashMap<u64, TokenId>,
}

impl ERC721Wrapper {
    fn new() -> Self {
        Self {
            positions: HashMap::new(),
            supply: HashMap::new(),
            owner_of: HashMap::new(),
        }
    }

    fn wrap(&mut self, token_id: TokenId, position: Position, recipient: u64) {
        let amount = position.liquidity;
        self.positions.insert(token_id.clone(), position);
        self.owner_of.insert(recipient, token_id);
        *self.supply.entry(recipient).or_insert(0) += amount;
    }

    fn unwrap_full(&mut self, recipient: u64) -> Option<(TokenId, Position)> {
        let token_id = self.owner_of.remove(&recipient)?;
        let position = self.positions.remove(&token_id)?;
        let amount = position.liquidity;
        *self.supply.get_mut(&recipient)? -= amount;
        if self.supply[&recipient] == 0 {
            self.supply.remove(&recipient);
        }
        Some((token_id, position))
    }

    fn unwrap_partial(&mut self, amount: u128, recipient: u64) -> Option<TokenId> {
        let token_id = self.owner_of.get(&recipient)?.clone();
        let position = self.positions.get(&token_id)?;
        
        if position.liquidity < amount {
            return None;
        }
        
        self.positions.insert(token_id.clone(), position.clone());
        
        let mut new_position = position.clone();
        new_position.liquidity -= amount;
        self.positions.insert(token_id.clone(), new_position);
        
        *self.supply.get_mut(&recipient)? -= amount;
        
        Some(token_id.clone())
    }

    fn collect_fees(&mut self, token_id: &TokenId) -> (u128, u128) {
        let position = self.positions.get_mut(token_id)?;
        let fees0 = position.fee_growth_inside0_last;
        let fees1 = position.fee_growth_inside1_last;
        position.fee_growth_inside0_last = 0;
        position.fee_growth_inside1_last = 0;
        (fees0, fees1)
    }
}

fn main() {
    let mut wrapper = ERC721Wrapper::new();
    let token = TokenId(1);
    let pos = Position { liquidity: 1000, fee_growth_inside0_last: 100, fee_growth_inside1_last: 200 };
    wrapper.wrap(token.clone(), pos, 42);
    
    let unwrapped = wrapper.unwrap_partial(500, 42);
    assert!(unwrapped.is_some());
    
    let fees = wrapper.collect_fees(&token);
    assert_eq!(fees, (100, 200));
    
    let pos2 = Position { liquidity: 500, fee_growth_inside0_last: 0, fee_growth_inside1_last: 0 };
    wrapper.wrap(token.clone(), pos2, 42);
}