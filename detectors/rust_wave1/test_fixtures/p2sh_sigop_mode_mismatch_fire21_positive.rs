enum ScriptMode {
    Legacy,
    PostUpgrade,
}

struct Script {
    bytes: Vec<u8>,
}

impl Script {
    fn is_pay_to_script_hash(&self) -> bool {
        self.bytes.len() == 23
    }
}

struct TxInput {
    unlock_script: Script,
}

struct SpentOutput {
    lock_script: Script,
}

struct Transaction {
    inputs: Vec<TxInput>,
}

struct BlockContext {
    height: u32,
    network_upgrade_active: bool,
}

fn extract_p2sh_redeem_script(unlock_script: &Script) -> Script {
    Script {
        bytes: unlock_script.bytes.clone(),
    }
}

fn count_sigops(_redeem_script: &Script, _mode: ScriptMode) -> u32 {
    20
}

pub fn validate_block_p2sh_sigops(
    tx: &Transaction,
    spent_outputs: &[SpentOutput],
    block_context: &BlockContext,
) -> u32 {
    let mut sigops = 0;

    for (input, spent_output) in tx.inputs.iter().zip(spent_outputs.iter()) {
        if !spent_output.lock_script.is_pay_to_script_hash() {
            continue;
        }

        let redeem_script = extract_p2sh_redeem_script(&input.unlock_script);

        // BUG: the block has height and network-upgrade context, but the P2SH
        // redeem script is always counted with legacy rules.
        let script_mode = ScriptMode::Legacy;
        if block_context.network_upgrade_active || block_context.height > 1_000_000 {
            sigops += count_sigops(&redeem_script, script_mode);
        }
    }

    sigops
}
