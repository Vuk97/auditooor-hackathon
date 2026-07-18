use soroban_sdk::{contract, contractimpl, Env};

pub struct UserConfiguration {
    pub data: u128,
}

impl UserConfiguration {
    // VULN: param `idx` used in shift without a < 64 bound check
    pub fn set_using_as_collateral(&mut self, idx: u8, using: bool) {
        let shift = (idx as u32) * 2;
        let mask = 1u128 << shift;
        if using {
            self.data |= mask;
        } else {
            self.data &= !mask;
        }
    }

    // VULN: is_borrowing without a guard, uses idx*2 shift
    pub fn is_borrowing(&self, idx: u8) -> bool {
        (self.data >> (idx * 2)) & 1 == 1
    }
}

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: call set_borrowing with unguarded param idx
    pub fn mark(env: Env, idx: u8) {
        let mut cfg = UserConfiguration { data: 0 };
        cfg.set_borrowing(idx, true);
    }

    // VULN: loop 0..128 using i*2 as shift exponent
    pub fn bitmap_fill() -> u128 {
        let mut out = 0u128;
        for i in 0..128 {
            out |= 1u128 << (i * 2);
        }
        out
    }
}

impl UserConfiguration {
    pub fn set_borrowing(&mut self, _idx: u8, _v: bool) {}
}
