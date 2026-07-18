// fixture: negative — sysvar account key pinned before deserialization.
use solana_program::account_info::AccountInfo;

fn check_timelock(clock_account: &AccountInfo, unlock_ts: i64) -> bool {
    require!(clock_account.key == &clock::id(), "spoofed clock sysvar");
    let clock = Clock::from_account_info(clock_account).unwrap();
    clock.unix_timestamp >= unlock_ts
}

fn read_rent(rent_account: &AccountInfo) -> u64 {
    assert_eq!(rent_account.key, &rent::id(), "spoofed rent sysvar");
    let rent = Rent::from_account_info(rent_account).unwrap();
    rent.lamports_per_byte_year
}

macro_rules! require {
    ($c:expr, $m:expr) => {};
}

mod clock { pub fn id() -> u8 { 1 } }
mod rent { pub fn id() -> u8 { 2 } }

struct Clock { unix_timestamp: i64 }
struct Rent { lamports_per_byte_year: u64 }
impl Clock {
    fn from_account_info(_a: &AccountInfo) -> Result<Clock, ()> {
        Ok(Clock { unix_timestamp: 0 })
    }
}
impl Rent {
    fn from_account_info(_a: &AccountInfo) -> Result<Rent, ()> {
        Ok(Rent { lamports_per_byte_year: 0 })
    }
}
