// POSITIVE: borrow_mut() called while a borrow() guard is still live.
// `rb` from `cell.borrow()` is live when `cell.borrow_mut()` is called
// on the next line — panics at runtime.

use std::cell::RefCell;

fn process_with_panic(cell: &RefCell<Vec<u8>>) {
    let rb = cell.borrow();      // live borrow guard
    let len = rb.len();
    // VULN: calling borrow_mut() while `rb` is still live — panics
    let mut wg = cell.borrow_mut();
    wg.push(len as u8);
}

fn main() {
    let c = RefCell::new(vec![1, 2, 3]);
    process_with_panic(&c);
}
