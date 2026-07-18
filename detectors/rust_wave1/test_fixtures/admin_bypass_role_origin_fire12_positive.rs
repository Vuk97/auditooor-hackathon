use frame_support::{pallet_prelude::*, storage::types::StorageValue};
use std::collections::HashMap;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type Admin<T: Config> = StorageValue<_, T::AccountId>;

    #[pallet::storage]
    pub type RuntimeConfig<T: Config> = StorageValue<_, u32>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn set_config(origin: OriginFor<T>, new_admin: T::AccountId, new_fee_bps: u32) -> DispatchResult {
            let _ = origin;
            RuntimeConfig::<T>::put(new_fee_bps);
            Admin::<T>::put(new_admin);
            Ok(())
        }
    }
}

pub struct BoostController {
    delegations: HashMap<u64, u64>,
}

impl BoostController {
    pub fn new() -> Self {
        Self {
            delegations: HashMap::new(),
        }
    }

    pub fn update_user_boost(&mut self, user_id: u64, pool_id: u64) {
        self.delegations.insert(user_id, pool_id);
    }
}
