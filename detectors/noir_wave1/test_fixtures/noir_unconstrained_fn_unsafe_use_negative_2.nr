// Negative fixture: no unconstrained functions defined. All fns are
// standard constrained. Should produce zero findings.
use dep::std;

fn add_two(a: Field, b: Field) -> Field {
    a + b
}

fn multiply(a: Field, b: Field) -> Field {
    a * b
}

fn main(x: pub Field, y: pub Field) {
    let sum = add_two(x, y);
    let product = multiply(x, y);
    assert(sum + product == x + y + x * y);
}
