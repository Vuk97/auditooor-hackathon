/// Rust fixture for value-moving-functions guard tests.
///
/// Included fns (must be detected):
///   - deposit: real balance write via self.balances[user] += amount
///   - withdraw: compound indexed assignment self.balances[user] -= amount
///   - push_amount: Vec::push on an amounts container
///   - cosmwasm_send: CosmWasm BankMsg::Send usage
///
/// Excluded fns (must NOT be detected - annotated with #[test]):
///   - test_deposit_noop: inline #[test] fn in a production file
///   - bench_deposit: no #[test] but no value-moving body
///
/// The file lives in src/ so it is NOT excluded by OOS path rules.

// --- simulated production structs ---

pub struct Vault {
    pub balances: std::collections::HashMap<String, u64>,
    pub amounts: Vec<u64>,
}

impl Vault {
    pub fn deposit(&mut self, user: String, amount: u64) {
        let bal = self.balances.entry(user).or_insert(0);
        *bal += amount;
    }

    pub fn withdraw(&mut self, user: String, amount: u64) {
        let bal = self.balances.entry(user).or_insert(0);
        *bal -= amount;
    }

    pub fn push_amount(&mut self, amount: u64) {
        self.amounts.push(amount);
    }
}

// CosmWasm-style send function (standalone, not in impl block)
pub fn cosmwasm_send(recipient: String, amount: u64) -> cosmwasm_std::Response {
    let msg = cosmwasm_std::BankMsg::Send {
        to_address: recipient,
        amount: vec![cosmwasm_std::Coin { denom: "uusd".into(), amount: amount.into() }],
    };
    cosmwasm_std::Response::new().add_message(msg)
}

// Pure getter - must NOT be detected
pub fn get_balance(vault: &Vault, user: &str) -> u64 {
    *vault.balances.get(user).unwrap_or(&0)
}

// Inline test fn that lives in a production file - must NOT be detected
#[test]
fn test_deposit_noop() {
    // This fn has a balance write but is annotated #[test] - must be excluded.
    let mut v = Vault { balances: std::collections::HashMap::new(), amounts: vec![] };
    v.balances.insert("alice".into(), 100);
    let bal = v.balances.entry("alice".into()).or_insert(0);
    *bal += 50;
    assert_eq!(*bal, 150);
}

// tokio::test variant - must NOT be detected
#[tokio::test]
async fn test_withdraw_async() {
    let mut v = Vault { balances: std::collections::HashMap::new(), amounts: vec![] };
    let bal = v.balances.entry("bob".into()).or_insert(100);
    *bal -= 50;
}
