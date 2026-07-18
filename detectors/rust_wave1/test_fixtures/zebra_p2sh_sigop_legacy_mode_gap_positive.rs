struct Code(Vec<u8>);

struct Script {
    bytes: Vec<u8>,
}

impl Script {
    fn is_pay_to_script_hash(&self) -> bool {
        self.bytes.len() == 23
    }
}

struct Input {
    unlock_script: Script,
}

struct Output {
    lock_script: Script,
}

struct Interpreter;

impl Interpreter {
    fn legacy_sigop_count_script(&self, _script: &Code) -> Result<u32, ()> {
        Ok(20)
    }
}

fn get_interpreter() -> Interpreter {
    Interpreter
}

fn extract_p2sh_redeem_script(unlock_script: &Script) -> Vec<u8> {
    unlock_script.bytes.clone()
}

pub fn p2sh_input_sigop_count(input: &Input, spent_output: &Output) -> u32 {
    if !spent_output.lock_script.is_pay_to_script_hash() {
        return 0;
    }

    let redeemed_bytes = extract_p2sh_redeem_script(&input.unlock_script);
    let interpreter = get_interpreter();
    interpreter
        .legacy_sigop_count_script(&Code(redeemed_bytes))
        .unwrap_or(0)
}
