// Negative fixture: storage_var read and written, but with explicit
// serialization (into()) between them. Properly fenced.
use starknet::storage::StoragePointerReadAccess;
use starknet::storage::StoragePointerWriteAccess;

#[storage]
struct Storage {
    packed_data: felt252,
}

fn update_packed(ref self: ContractState, new_val: u128) {
    // Read current packed value
    let current = self.packed_data.read();

    // Properly serialize new value before writing
    let serialized: felt252 = new_val.into();

    // Write with explicit serialization — no aliasing risk flagged
    self.packed_data.write(serialized);
}
