// clean.rs: should NOT fire - safe patterns only

// Safe: if let Some re-extracts the variable properly
fn safe_activation(activation_height: Option<u32>, current_height: u32) -> Vec<u8> {
    if let Some(height) = activation_height {
        if current_height >= height {
            return vec![1u8; 32];
        }
    }
    vec![0u8; 32]
}

// Safe: match statement
fn safe_match(maybe_val: Option<u64>) -> u64 {
    match maybe_val {
        Some(v) => v * 2,
        None => 0,
    }
}

// Safe: using .map() / .unwrap_or()
fn safe_map(maybe_val: Option<u64>) -> u64 {
    maybe_val.map(|v| v * 2).unwrap_or(0)
}

// Safe: .unwrap_or_default()
fn safe_unwrap_or(maybe_val: Option<u64>) -> u64 {
    maybe_val.unwrap_or_default()
}

// Safe: is_some() check but NO unwrap() on the same var anywhere in function
fn check_only(maybe_val: Option<u64>) -> bool {
    maybe_val.is_some()
}
