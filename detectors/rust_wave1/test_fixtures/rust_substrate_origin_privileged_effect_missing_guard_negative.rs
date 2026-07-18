use frame_support::{ensure, pallet_prelude::*, storage::types::StorageValue};

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type BridgeIngressAllowed<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::storage]
    pub type MaxOutboundPerBlock<T: Config> = StorageValue<_, u128, ValueQuery>;

    #[pallet::storage]
    pub type Owner<T: Config> = StorageValue<_, T::AccountId>;

    #[pallet::error]
    pub enum Error<T> {
        BadOrigin,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn root_refresh_route(origin: OriginFor<T>, enabled: bool) -> DispatchResult {
            ensure_root(origin)?;
            BridgeIngressAllowed::<T>::put(enabled);
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(0)]
        pub fn owner_refresh_route(origin: OriginFor<T>, outbound_cap: u128) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let owner = Owner::<T>::get().ok_or(Error::<T>::BadOrigin)?;
            ensure!(who == owner, Error::<T>::BadOrigin);
            MaxOutboundPerBlock::<T>::put(outbound_cap);
            Ok(())
        }
    }
}
