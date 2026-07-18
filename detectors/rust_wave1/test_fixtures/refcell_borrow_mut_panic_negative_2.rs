// NEGATIVE: try_borrow_mut() is used instead of borrow_mut() — no panic.
// try_borrow_mut() returns Err(BorrowMutError) instead of panicking.

use std::cell::RefCell;

fn safe_try_borrow(cell: &RefCell<Vec<u8>>) {
    let rb = cell.borrow();
    let len = rb.len();
    // SAFE: try_borrow_mut returns Result, does not panic
    match cell.try_borrow_mut() {
        Ok(mut wg) => {
            drop(rb); // explicit drop before using wg
            wg.push(len as u8);
        }
        Err(_) => {
            eprintln!("already borrowed");
        }
    }
}
