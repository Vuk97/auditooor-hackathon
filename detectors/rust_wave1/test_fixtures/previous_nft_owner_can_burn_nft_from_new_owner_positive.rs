use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
struct ShortRecord {
    owner: u64, // current owner id
    data: u128,
}

struct Registry {
    records: HashMap<u64, ShortRecord>,
    owner_to_record: HashMap<u64, u64>, // owner_id -> record_id
}

impl Registry {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
            owner_to_record: HashMap::new(),
        }
    }

    fn mint(&mut self, record_id: u64, owner: u64, data: u128) {
        let sr = ShortRecord { owner, data };
        self.records.insert(record_id, sr);
        self.owner_to_record.insert(owner, record_id);
    }

    fn transfer(&mut self, record_id: u64, new_owner: u64) -> Result<(), &'static str> {
        let sr = self.records.get_mut(&record_id).ok_or("not found")?;
        let old_owner = sr.owner;
        
        // BUG: owner_to_record mapping NOT updated on transfer
        // stale mapping remains: old_owner -> record_id
        
        // only update the record's owner field
        sr.owner = new_owner;
        // forgot: self.owner_to_record.remove(&old_owner);
        // forgot: self.owner_to_record.insert(new_owner, record_id);
        
        Ok(())
    }

    fn burn(&mut self, caller: u64, record_id: u64) -> Result<(), &'static str> {
        // BUG: reads ownership from STALE mapping instead of record
        let mapped_record = self.owner_to_record.get(&caller);
        
        if mapped_record != Some(&record_id) {
            return Err("not owner");
        }
        
        // BUG: also fails to clean up properly, but main issue is stale check
        self.records.remove(&record_id);
        
        Ok(())
    }
}

fn main() {
    let mut reg = Registry::new();
    reg.mint(1, 100, 1000);
    reg.transfer(1, 200).unwrap();
    
    // BUG: old owner CAN burn because owner_to_record still maps 100 -> 1
    assert!(reg.burn(100, 1).is_ok(), "vuln: previous owner burned new owner's NFT!");
    println!("vulnerable: exploit succeeded");
}