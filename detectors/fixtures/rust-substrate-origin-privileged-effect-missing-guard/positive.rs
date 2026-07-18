use frame_support::{ensure, pallet_prelude::*};
use frame_system::pallet_prelude::*;

#[pallet::pallet]
pub struct Pallet<T>(_);

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(0)]
    pub fn set_bridge_router(origin: OriginFor<T>, router: T::AccountId) -> DispatchResult {
        // Vulnerable: any signed or unsigned origin reaches privileged storage.
        BridgeRouter::<T>::put(router);
        Self::deposit_event(Event::BridgeRouterChanged);
        Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight(0)]
    pub fn force_set_validators(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
        // Vulnerable: ensure_signed proves only an arbitrary account.
        let caller = ensure_signed(origin)?;
        Validators::<T>::insert(who, caller);
        Ok(())
    }
}
