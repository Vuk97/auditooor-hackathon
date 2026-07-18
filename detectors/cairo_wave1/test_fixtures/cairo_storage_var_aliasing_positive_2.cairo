// Positive fixture: storage_var `counter` read and immediately written
// back with no transformation — phantom no-op write that masks a bug.
use starknet::storage::StoragePointerReadAccess;
use starknet::storage::StoragePointerWriteAccess;

#[storage]
struct Storage {
    counter: felt252,
}

fn increment_broken(ref self: ContractState) {
    // Read the counter
    let val = self.counter.read();

    // Do some work
    let doubled = val * 2;

    // BUG: writes val (original) not doubled — no serialization fence check
    // catches this as a suspicious no-op pattern
    self.counter.write(val);  // should be: self.counter.write(doubled)
}
