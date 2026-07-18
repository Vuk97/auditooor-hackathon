// fixture: positive — sysvar read from supplied account, no key validation.
use solana_program::account_info::AccountInfo;

fn check_timelock(clock_account: &AccountInfo, unlock_ts: i64) -> bool {
    let clock = Clock::from_account_info(clock_account).unwrap();
    clock.unix_timestamp >= unlock_ts
}

fn read_rent(rent_account: &AccountInfo) -> u64 {
    let rent = Rent::from_account_info(rent_account).unwrap();
    rent.lamports_per_byte_year
}

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
