use frame_support::{pallet_prelude::*, storage::types::StorageValue};

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

    #[pallet::event]
    pub enum Event<T: Config> {
        BridgeRouteRefreshed(bool, u128),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(0)]
        pub fn refresh_route(origin: OriginFor<T>, enabled: bool, outbound_cap: u128) -> DispatchResult {
            let _ = origin;
            BridgeIngressAllowed::<T>::put(enabled);
            MaxOutboundPerBlock::<T>::put(outbound_cap);
            Self::deposit_event(Event::BridgeRouteRefreshed(enabled, outbound_cap));
            Ok(())
        }
    }
}
