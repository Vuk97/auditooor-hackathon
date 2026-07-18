// Negative fixture: not a Plonky2 file. No virtual proof targets.
// Should produce zero findings.
struct MockProver {
    constraints: Vec<String>,
}

impl MockProver {
    fn add_virtual_proof_with_pis(&mut self, _data: &str) -> String {
        "proof_target".to_string()
    }
    fn set_proof_with_pis_target(&mut self, target: &str, _proof: &str) {
        println!("set {} witness", target);
    }
}

fn test_ordinary_code() {
    let mut p = MockProver { constraints: vec![] };
    let t = p.add_virtual_proof_with_pis("schema");
    p.set_proof_with_pis_target(&t, "some_proof");
}
