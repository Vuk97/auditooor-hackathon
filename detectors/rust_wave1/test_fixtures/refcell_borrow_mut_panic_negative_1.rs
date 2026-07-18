// NEGATIVE: borrow guard is explicitly dropped before borrow_mut().

use std::cell::RefCell;

fn safe_process(cell: &RefCell<Vec<u8>>) {
    let len = {
        let rb = cell.borrow();
        rb.len()
        // rb dropped here at end of block
    };
    // No live borrow here — borrow_mut() is safe
    let mut wg = cell.borrow_mut();
    wg.push(len as u8);
}
