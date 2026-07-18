// Negative fixture: bounds check present before array indexing.
// Should produce zero findings.
use dep::std;

fn safe_lookup(table: [Field; 16], index: u32) -> Field {
    // Bounds check before indexing — no OOB risk flagged
    assert(index < 16);
    table[index]
}

fn main(table: [Field; 16], idx: pub u32) -> pub Field {
    safe_lookup(table, idx)
}
