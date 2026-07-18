// Positive fixture: deprecated `constrain` keyword inside unconstrained fn.
// Same issue: constraint not enforced in ZK circuit.
use dep::std;

unconstrained fn hint_sort(arr: [Field; 4]) -> [Field; 4] {
    let mut sorted = arr;
    // Bubble sort (hint, runs outside circuit)
    for i in 0..4 {
        for j in 0..3 {
            if sorted[j] > sorted[j+1] {
                let tmp = sorted[j];
                sorted[j] = sorted[j+1];
                sorted[j+1] = tmp;
            }
        }
    }
    // BUG: constrain inside unconstrained fn — not a ZK constraint
    constrain(sorted[0] <= sorted[1]);
    sorted
}

fn main(arr: [Field; 4]) -> pub [Field; 4] {
    hint_sort(arr)
}
