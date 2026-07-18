// Positive fixture: storage_var `balance` is read then written without
// any serialization fence between the read and write operations.
use starknet::ContractAddress;
use starknet::storage::StoragePointerReadAccess;
use starknet::storage::StoragePointerWriteAccess;

#[storage]
struct Storage {
    balance: felt252,
}

fn transfer(ref self: ContractState, amount: felt252) {
    // Read balance
    let current = self.balance.read();

    // No serialize/pack/into between read and write
    // Just direct arithmetic and write-back
    let new_balance = current - amount;

    // BUG: write back without serialization fence
    // If balance storage slot is aliased or type changes, this silent re-write
    // can corrupt state
    self.balance.write(new_balance);
}
