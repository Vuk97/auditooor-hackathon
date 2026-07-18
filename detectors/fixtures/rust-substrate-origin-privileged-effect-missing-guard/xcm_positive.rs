use frame_support::pallet_prelude::*;
use xcm::latest::prelude::*;

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(2)]
    #[pallet::weight(0)]
    pub fn route_remote_call(
        origin: OriginFor<T>,
        location: MultiLocation,
        call: Box<<T as Config>::RuntimeCall>,
    ) -> DispatchResult {
        let converted = T::OriginConverter::convert_origin(location, OriginKind::SovereignAccount)?;
        call.dispatch_bypass_filter(converted.into())?;
        Ok(())
    }
}
