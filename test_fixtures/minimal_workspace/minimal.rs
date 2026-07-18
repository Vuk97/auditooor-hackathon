// Minimal fixture for workspace-scan-orchestrator smoke tests.
pub fn add(a: u64, b: u64) -> u64 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        assert_eq!(add(1, 2), 3);
    }
}
