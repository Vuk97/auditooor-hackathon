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
}

impl RewardVault {
    pub fn credit_unbound_recipient(&mut self, recipient: AccountId, amount: u128) {
        self.ledger.credit(recipient, amount);
        self.beneficiaries.push(recipient);
    }
}

pub struct Vaa {
    pub origin_chain: u16,
    pub origin_address: [u8; 32],
    pub cointype: [u8; 32],
}

pub struct Bridge;

impl Bridge {
    pub fn create_wrapped(vaa: Vaa) {
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
    pub fn deposit_with_unbound_remaining_accounts(_ctx: Ctx, _amount: u128) {
        let remaining_accounts: &[Pubkey] = &[];
        for account in remaining_accounts.iter() {
            spl_ibc::cpi::set_stake(CpiContext::new(*account, remaining_accounts));
        }
    }
}

pub struct CallbackPayload {
    pub owner: AccountId,
}

pub struct CallbackEscrow {
    pub ledger: Ledger,
}

impl CallbackEscrow {
    pub fn release_from_callback(&mut self, payload: CallbackPayload, amount: u128) {
        self.ledger.release_to(payload.owner, amount);
    }
}

fn derive_wrapped(_chain: u16, _addr: [u8; 32], _coin_type: [u8; 32]) -> [u8; 32] {
    [0; 32]
}

fn deploy(_asset: [u8; 32]) {}

mod spl_ibc {
    pub mod cpi {
        pub fn set_stake<T>(_ctx: T) {}
    }
}
