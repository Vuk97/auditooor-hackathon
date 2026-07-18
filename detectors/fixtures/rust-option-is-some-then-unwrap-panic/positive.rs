// positive.rs: should fire - is_some() guard followed by .unwrap() on same var

fn compute_activation_root(activation_height: Option<u32>, current_height: u32) -> Vec<u8> {
    let final_root: Vec<u8> =
        if activation_height.is_some() && current_height >= activation_height.unwrap() {
            vec![1u8; 32]
        } else {
            vec![0u8; 32]
        };
    final_root
}

// second shape: is_some() check in condition, unwrap in body
fn get_protocol_value(maybe_val: Option<u64>) -> u64 {
    if maybe_val.is_some() {
        maybe_val.unwrap() * 2
    } else {
        0
    }
}
