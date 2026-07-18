use soroban_sdk::{contract, contractimpl, Env};

pub struct UserConfiguration {
    pub data: u128,
}

impl UserConfiguration {
    pub fn set_using_as_collateral(&mut self, idx: u8, using: bool) {
        if idx >= 64 {
            return;
        }
        let shift = (idx as u32) * 2;
        let mask = 1u128 << shift;
        if using {
            self.data |= mask;
        } else {
            self.data &= !mask;
        }
    }

    pub fn is_borrowing(&self, idx: u8) -> bool {
        if idx >= 64 {
            return false;
        }
        (self.data >> (idx * 2)) & 1 == 1
    }

    pub fn set_borrowing(&mut self, idx: u8, v: bool) {
        if idx >= 64 {
            return;
        }
        let shift = (idx as u32) * 2 + 1;
        let mask = 1u128 << shift;
        if v {
            self.data |= mask;
        } else {
            self.data &= !mask;
        }
    }
}

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn mark(_env: Env, idx: u8) {
        if idx >= 64 {
            return;
        }
        let mut cfg = UserConfiguration { data: 0 };
        cfg.set_borrowing(idx, true);
    }

    // Safe loop bound = MAX_RESERVES(64)
    pub fn bitmap_fill() -> u128 {
        let mut out = 0u128;
        for i in 0..64u32 {
            out |= 1u128 << (i * 2);
        }
        out
    }
}
