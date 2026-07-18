pub enum OpTxType {
    Deposit = 0x7e,
}

pub struct BasePayloadAttributes {
    pub transactions: Option<Vec<Vec<u8>>>,
}

pub struct AttributesWithParent {
    pub attributes: BasePayloadAttributes,
}

impl AttributesWithParent {
    /// FIX: unwrap the Option, then inspect every transaction in the inner Vec.
    pub fn is_deposits_only(&self) -> bool {
        self.attributes.transactions.as_ref().is_some_and(|txs| {
            !txs.is_empty()
                && txs
                    .iter()
                    .all(|tx| tx.first().copied() == Some(OpTxType::Deposit as u8))
        })
    }
}
