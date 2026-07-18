use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Position {
    pub collateral: u64,
    pub debt: u64,
}

pub struct Vault {
    pub min_health_factor: u64,
    pub positions: HashMap<u64, Position>,
    pub next_position_id: u64,
}

#[derive(Clone, Debug)]
pub struct SwapParams {
    pub amount_in: u64,
    pub min_amount_out: u64,
    pub max_slippage_bps: u16,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            min_health_factor: 150,
            positions: HashMap::new(),
            next_position_id: 1,
        }
    }

    fn execute_swap(&mut self, params: &SwapParams) -> u64 {
        let amount_out = params.amount_in;
        let slippage = amount_out * params.max_slippage_bps as u64 / 10000;
        amount_out.saturating_sub(slippage)
    }

    pub fn open_position(
        &mut self,
        collateral: u64,
        debt: u64,
        swap_params: SwapParams,
    ) -> u64 {
        let position_id = self.next_position_id;
        self.next_position_id += 1;

        let received = self.execute_swap(&swap_params);

        let health_factor = if debt > 0 {
            (collateral + received) * 100 / debt
        } else {
            u64::MAX
        };

        assert!(
            health_factor >= self.min_health_factor,
            "Position would be unhealthy"
        );

        let position = Position { collateral, debt };
        self.positions.insert(position_id, position);
        position_id
    }

    pub fn close_position(&mut self, position_id: u64, swap_params: SwapParams) {
        let position = self.positions.get(&position_id).expect("Position not found");

        let received = self.execute_swap(&swap_params);

        let health_factor = if position.debt > 0 {
            received * 100 / position.debt
        } else {
            u64::MAX
        };

        assert!(
            health_factor >= self.min_health_factor,
            "Close would leave bad debt"
        );

        self.positions.remove(&position_id);
    }
}

fn main() {
    let mut vault = Vault::new();

    let safe_swap = SwapParams {
        amount_in: 1000,
        min_amount_out: 900,
        max_slippage_bps: 100,
    };

    let pos_id = vault.open_position(5000, 3000, safe_swap.clone());
    vault.close_position(pos_id, safe_swap);
}