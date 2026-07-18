// Negative fixture: only for-loop variable used for indexing (range-bounded)
// and literal integer indices. No dynamic unbounded access.
use dep::std;

fn sum_array(arr: [Field; 8]) -> Field {
    let mut total: Field = 0;
    // Loop variable `i` is bounded by 0..8 — safe
    for i in 0..8 {
        total += arr[i];
    }
    // Literal index 0 — safe
    let first = arr[0];
    total + first
}

fn main(arr: [Field; 8]) -> pub Field {
    sum_array(arr)
}
