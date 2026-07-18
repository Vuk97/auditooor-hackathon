// Positive fixture: array indexed with user-controlled `index` without
// bounds check. Prover can panic the circuit with an OOB index.
use dep::std;

fn lookup_table(table: [Field; 16], index: u32) -> Field {
    // BUG: no assert(index < 16) before indexing
    // If index >= 16, prover panics or produces undefined behavior
    table[index]
}

fn main(table: [Field; 16], idx: pub u32) -> pub Field {
    // idx comes from public input — attacker-controlled
    lookup_table(table, idx)
}
