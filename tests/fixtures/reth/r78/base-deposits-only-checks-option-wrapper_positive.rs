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
    /// BUG: this iterates the Option wrapper. For Some(vec![deposit, legacy]),
    /// the closure runs once with the whole Vec and checks only Vec[0].
    pub fn is_deposits_only(&self) -> bool {
        self.attributes
            .transactions
            .iter()
            .all(|tx| tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8))
    }
}
