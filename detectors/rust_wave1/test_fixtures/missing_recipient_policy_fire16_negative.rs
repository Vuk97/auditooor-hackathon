pub struct Address([u8; 32]);

impl Address {
    pub fn default() -> Self {
        Address([0; 32])
    }

    pub fn require_auth(&self) {}
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

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
        if treasury == Address::default() {
            return Err("zero treasury");
        }
        operator.require_auth();
        env.storage().instance().set("treasury", &treasury);
        env.storage().instance().set("operator", &operator);
        Ok(())
    }
}

pub struct Jetton;

impl Jetton {
    pub fn recv_internal(sender_address: u64, amount: u128, op: u32, total_supply: &mut u128) -> Result<(), &'static str> {
        let burn_notification_op = 0x7bdd97de;
        let expected_master = 7;
        if sender_address != expected_master {
            return Err("bad sender");
        }
        if op == burn_notification_op {
            *total_supply -= amount;
        }
        Ok(())
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
        if destination == 0 {
            return Err("zero destination");
        }
        self.ledger.mint_to(destination, amount);
        self.accounting.push(destination);
        Ok(())
    }
}
