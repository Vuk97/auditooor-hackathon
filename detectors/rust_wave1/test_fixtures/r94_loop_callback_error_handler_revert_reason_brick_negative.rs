use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeExecutor;
#[contractimpl]
impl SafeExecutor {
    // OK: bounds-checks reason length before decoding
    pub fn execute_callback(target: u64, data: &[u8]) {
        let _ = (target, data);
        let result: Result<(), &[u8]> = Err(&[0u8, 0, 0, 100]);
        const MAX_REASON_LEN: usize = 256;
        match result {
            Ok(_) => {}
            Err(reason) => {
                if reason.len() <= MAX_REASON_LEN {
                    let s = String::from_utf8(reason.to_vec());
                    let _ = s;
                }
            }
        }
    }
}
