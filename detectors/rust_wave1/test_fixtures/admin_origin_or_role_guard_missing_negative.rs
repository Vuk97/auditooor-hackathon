use frame_support::{ensure, pallet_prelude::*, storage::types::StorageValue};

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

use anchor_lang::prelude::*;

#[account]
pub struct ConfigAccount {
    pub admin: Pubkey,
    pub fee_bps: u64,
}

#[derive(Accounts)]
pub struct SetProgramConfig<'info> {
    #[account(mut, has_one = admin)]
    pub config: Account<'info, ConfigAccount>,
    pub admin: Signer<'info>,
}

pub fn set_program_config(ctx: Context<SetProgramConfig>, new_admin: Pubkey, fee_bps: u64) -> Result<()> {
    ctx.accounts.config.admin = new_admin;
    ctx.accounts.config.fee_bps = fee_bps;
    Ok(())
}
