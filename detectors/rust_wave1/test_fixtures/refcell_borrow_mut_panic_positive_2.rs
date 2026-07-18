// POSITIVE: Double borrow_mut() on same RefCell — second call panics.
// A RefCell only allows ONE mutable borrow at a time.

use std::cell::RefCell;

struct Node {
    data: RefCell<i32>,
}

impl Node {
    fn double_mutate(&self) {
        let mut first = self.data.borrow_mut();  // first mutable borrow
        *first += 1;
        // VULN: second borrow_mut() while `first` is still live — panics
        let mut second = self.data.borrow_mut();
        *second *= 2;
    }
}
