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
        
        // CRITICAL FIX: update owner_to_record mapping
        self.owner_to_record.remove(&old_owner);
        self.owner_to_record.insert(new_owner, record_id);
        
        // update the record's owner field
        sr.owner = new_owner;
        
        Ok(())
    }

    fn burn(&mut self, caller: u64, record_id: u64) -> Result<(), &'static str> {
        // CORRECT: derive ownership from the record itself, not stale mapping
        let sr = self.records.get(&record_id).ok_or("not found")?;
        
        if sr.owner != caller {
            return Err("not owner");
        }
        
        self.owner_to_record.remove(&caller);
        self.records.remove(&record_id);
        
        Ok(())
    }
}

fn main() {
    let mut reg = Registry::new();
    reg.mint(1, 100, 1000);
    reg.transfer(1, 200).unwrap();
    
    // old owner cannot burn
    assert!(reg.burn(100, 1).is_err());
    // new owner can burn
    assert!(reg.burn(200, 1).is_ok());
    println!("clean: all assertions passed");
}