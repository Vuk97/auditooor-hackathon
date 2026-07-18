pub type AccountId = u64;
pub type Pubkey = u64;

pub struct Ledger;

impl Ledger {
    pub fn credit(&mut self, _recipient: AccountId, _amount: u128) {}
    pub fn release_to(&mut self, _owner: AccountId, _amount: u128) {}
}

pub struct RewardVault {
    pub ledger: Ledger,
    pub beneficiaries: Vec<AccountId>,
    pub expected_recipient: AccountId,
}

impl RewardVault {
    pub fn credit_bound_recipient(&mut self, recipient: AccountId, amount: u128) {
        require(recipient == self.expected_recipient);
        self.ledger.credit(recipient, amount);
        self.beneficiaries.push(recipient);
    }
}

pub struct Vaa {
    pub origin_chain: u16,
    pub origin_address: [u8; 32],
    pub cointype: [u8; 32],
}

pub struct Registry;

impl Registry {
    pub fn contains(&self, _coin_type: [u8; 32]) -> bool {
        true
    }
}

pub struct Bridge;

impl Bridge {
    pub fn create_wrapped(vaa: Vaa, registry: Registry) {
        require(registry.contains(vaa.cointype));
        let wrapped_asset = derive_wrapped(vaa.origin_chain, vaa.origin_address, vaa.cointype);
        deploy(wrapped_asset);
    }
}

pub struct Ctx;

pub struct CpiContext;

impl CpiContext {
    pub fn new(_account: Pubkey, _accounts: &[Pubkey]) {}
}

pub struct Vault;

impl Vault {
    pub fn deposit_with_bound_remaining_accounts(_ctx: Ctx, _amount: u128, expected: Pubkey) {
        let remaining_accounts: &[Pubkey] = &[];
        require(remaining_accounts.len() == 1);
        require(remaining_accounts[0].key() == expected);
        spl_ibc::cpi::set_stake(CpiContext::new(remaining_accounts[0], remaining_accounts));
    }
}

pub struct CallbackPayload {
    pub owner: AccountId,
}

pub struct CallbackEscrow {
    pub ledger: Ledger,
    pub expected_owner: AccountId,
}

impl CallbackEscrow {
    pub fn release_from_bound_callback(&mut self, payload: CallbackPayload, amount: u128) {
        require(payload.owner == self.expected_owner);
        self.ledger.release_to(payload.owner, amount);
    }
}

fn derive_wrapped(_chain: u16, _addr: [u8; 32], _coin_type: [u8; 32]) -> [u8; 32] {
    [0; 32]
}

fn deploy(_asset: [u8; 32]) {}

fn require(_ok: bool) {}

impl Pubkey {
    pub fn key(&self) -> Pubkey {
        *self
    }
}

mod spl_ibc {
    pub mod cpi {
        pub fn set_stake<T>(_ctx: T) {}
    }
}
