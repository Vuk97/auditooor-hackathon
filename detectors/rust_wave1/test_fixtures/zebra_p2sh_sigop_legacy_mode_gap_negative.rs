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

fn extract_p2sh_redeem_script(unlock_script: &Script) -> Script {
    Script {
        bytes: unlock_script.bytes.clone(),
    }
}

fn accurate_p2sh_sigop_count(_redeem_script: &Script) -> u32 {
    1
}

pub fn p2sh_input_sigop_count(input: &Input, spent_output: &Output) -> u32 {
    if !spent_output.lock_script.is_pay_to_script_hash() {
        return 0;
    }

    let redeem_script = extract_p2sh_redeem_script(&input.unlock_script);
    accurate_p2sh_sigop_count(&redeem_script)
}
