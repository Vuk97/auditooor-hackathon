use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Executor;
#[contractimpl]
impl Executor {
    // BUG: try/catch decodes raw reason via String::from_utf8 with no length guard
    pub fn execute_callback(target: u64, data: &[u8]) {
        let _ = (target, data);
        let result: Result<(), &[u8]> = Err(&[0u8, 0, 0, 100]);
        match result {
            Ok(_) => {}
            Err(reason) => {
                let s = String::from_utf8(reason.to_vec());
                let _ = s;
            }
        }
    }
}
