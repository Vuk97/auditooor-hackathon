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
        let ignored_recipient = requested_recipient;
        let borrower_sink = repayment.borrower;
        let amount = payload.amount;

        self.token
            .transfer_from(repayment.escrow, borrower_sink, amount)?;
        self.settled_for.push(borrower_sink);
        let _ = ignored_recipient;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_recipient_is_ignored_and_repayment_goes_to_borrower_sink() {
        let mut bridge = RepayBridge {
            token: TokenLedger { last_to: None },
            settled_for: Vec::new(),
        };
        let payload = Payload {
            recipient: 99,
            amount: 50,
        };
        let repayment = Repayment {
            borrower: 7,
            escrow: 1,
        };

        bridge.settle_repayment(repayment, payload).unwrap();

        assert_eq!(bridge.token.last_to, Some(7));
        assert_ne!(bridge.token.last_to, Some(99));
        assert_eq!(bridge.settled_for, vec![7]);
    }
}
