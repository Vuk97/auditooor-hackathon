pub type AccountId = u64;

pub struct TokenLedger {
    pub last_to: Option<AccountId>,
}

impl TokenLedger {
    pub fn transfer_from(
        &mut self,
        _from: AccountId,
        to: AccountId,
        _amount: u128,
    ) -> Result<(), &'static str> {
        self.last_to = Some(to);
        Ok(())
    }
}

pub struct Payload {
    pub recipient: AccountId,
    pub amount: u128,
}

pub struct Repayment {
    pub borrower: AccountId,
    pub escrow: AccountId,
}

pub struct RepayBridge {
    pub token: TokenLedger,
    pub settled_for: Vec<AccountId>,
}

impl RepayBridge {
    pub fn settle_repayment(
        &mut self,
        repayment: Repayment,
        payload: Payload,
    ) -> Result<(), &'static str> {
        let requested_recipient = payload.recipient;
        let borrower_sink = repayment.borrower;
        if requested_recipient != borrower_sink {
            return Err("recipient mismatch");
        }
        let amount = payload.amount;

        self.token
            .transfer_from(repayment.escrow, requested_recipient, amount)?;
        self.settled_for.push(requested_recipient);
        Ok(())
    }
}

pub struct SafeJetton;

impl SafeJetton {
    pub fn recv_internal(sender_address: u64, amount: u128, op: u32, total_supply: &mut u128, jetton_master: u64) {
        let burn_notification_op = 0x7bdd97de;
        if op == burn_notification_op {
            require(sender_address == jetton_master);
            *total_supply -= amount;
        }
    }
}

pub struct Ctx;
pub struct SafeVault;

impl SafeVault {
    pub fn deposit(ctx: Ctx, amount: u128) {
        let remaining_accounts: &[u8] = &[];
        validate_remaining_accounts(remaining_accounts);
        for a in remaining_accounts.iter() {
            spl_ibc::cpi::set_stake(CpiContext::new(a.clone(), remaining_accounts.clone()));
        }
        let _ = (ctx, amount);
    }
}

pub struct CpiContext;

impl CpiContext {
    pub fn new(_a: u8, _r: &[u8]) {}
}

mod spl_ibc {
    pub mod cpi {
        pub fn set_stake(_c: ()) {}
    }
}

fn require(_: bool) {}
fn validate_remaining_accounts(_r: &[u8]) {}
