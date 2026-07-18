use frame_support::{ensure, pallet_prelude::*};
use frame_system::pallet_prelude::*;

#[pallet::pallet]
pub struct Pallet<T>(_);

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(0)]
    pub fn set_bridge_router(origin: OriginFor<T>, router: T::AccountId) -> DispatchResult {
        ensure_root(origin)?;
        BridgeRouter::<T>::put(router);
        Self::deposit_event(Event::BridgeRouterChanged);
        Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight(0)]
    pub fn force_set_validators(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
        let caller = ensure_signed(origin)?;
        ensure!(Admins::<T>::contains_key(&caller), Error::<T>::NotAdmin);
        Validators::<T>::insert(who, caller);
        Ok(())
    }
}
