use frame_support::{ensure, pallet_prelude::*, storage::types::StorageValue};
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

    #[pallet::error]
    pub enum Error<T> {
        BadOrigin,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn set_config(origin: OriginFor<T>, new_admin: T::AccountId, new_fee_bps: u32) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let admin = Admin::<T>::get().ok_or(Error::<T>::BadOrigin)?;
            ensure!(who == admin, Error::<T>::BadOrigin);
            RuntimeConfig::<T>::put(new_fee_bps);
            Admin::<T>::put(new_admin);
            Ok(())
        }
    }
}

pub struct BoostController {
    delegations: HashMap<u64, u64>,
    owner: u64,
}

impl BoostController {
    pub fn new(owner: u64) -> Self {
        Self {
            delegations: HashMap::new(),
            owner,
        }
    }

    pub fn update_user_boost(&mut self, caller: u64, user_id: u64, pool_id: u64) -> Result<(), &'static str> {
        if caller != self.owner && caller != user_id {
            return Err("unauthorized");
        }
        self.delegations.insert(user_id, pool_id);
        Ok(())
    }
}

pub struct Profile {
    payout_address: [u8; 32],
}

impl Profile {
    pub fn set_payout_address(&mut self, new_address: [u8; 32]) {
        self.payout_address = new_address;
    }
}
