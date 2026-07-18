use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response, StdError, StdResult};
use cw_storage_plus::{Item, Map};

pub struct Config {
    pub admin: Addr,
    pub code_id: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const WHITELIST: Map<&Addr, bool> = Map::new("whitelist");

pub fn upgrade_program(
    deps: DepsMut,
    info: MessageInfo,
    new_admin: Addr,
    new_code_id: u64,
) -> StdResult<Response> {
    let cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.admin {
        return Err(StdError::generic_err("unauthorized"));
    }

    CONFIG.save(
        deps.storage,
        &Config {
            admin: new_admin,
            code_id: new_code_id,
        },
    )?;
    Ok(Response::new())
}

pub fn set_whitelist(
    deps: DepsMut,
    info: MessageInfo,
    account: Addr,
    enabled: bool,
) -> StdResult<Response> {
    let cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.admin {
        return Err(StdError::generic_err("unauthorized"));
    }

    WHITELIST.save(deps.storage, &account, &enabled)?;
    Ok(Response::new())
}

pub fn set_display_name(name: String) -> String {
    name
}
