pub struct Address([u8; 32]);

pub struct Env;
pub struct Storage;
pub struct InstanceStorage;

impl Env {
    pub fn storage(&self) -> Storage {
        Storage
    }
}

impl Storage {
    pub fn instance(&self) -> InstanceStorage {
        InstanceStorage
    }
}

impl InstanceStorage {
    pub fn set<T>(&self, _key: &str, _value: &T) {}
}

pub struct Config;

impl Config {
    pub fn configure_accounts(env: Env, treasury: Address, operator: Address) -> Result<(), &'static str> {
        env.storage().instance().set("treasury", &treasury);
        env.storage().instance().set("operator", &operator);
        Ok(())
    }
}

pub struct Jetton;

impl Jetton {
    pub fn recv_internal(sender_address: u64, amount: u128, op: u32, total_supply: &mut u128) {
        let burn_notification_op = 0x7bdd97de;
        if op == burn_notification_op {
            *total_supply -= amount;
            let _untrusted_sender = sender_address;
        }
    }
}

pub type AccountId = u64;

pub struct Ledger;

impl Ledger {
    pub fn mint_to(&mut self, _destination: AccountId, _amount: u128) {}
}

pub struct RewardMinter {
    pub ledger: Ledger,
    pub accounting: Vec<AccountId>,
}

impl RewardMinter {
    pub fn mint_reward(&mut self, destination: AccountId, amount: u128) -> Result<(), &'static str> {
        self.ledger.mint_to(destination, amount);
        self.accounting.push(destination);
        Ok(())
    }
}
