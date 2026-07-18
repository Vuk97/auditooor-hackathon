use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response, StdResult};
use cw_storage_plus::{Item, Map};

pub struct Config {
    pub admin: Addr,
    pub code_id: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const WHITELIST: Map<&Addr, bool> = Map::new("whitelist");

pub fn upgrade_program(
    deps: DepsMut,
    _info: MessageInfo,
    new_admin: Addr,
    new_code_id: u64,
) -> StdResult<Response> {
    CONFIG.update(deps.storage, |mut cfg| -> StdResult<Config> {
        cfg.admin = new_admin.clone();
        cfg.code_id = new_code_id;
        Ok(cfg)
    })?;
    Ok(Response::new())
}

pub fn set_whitelist(
    deps: DepsMut,
    _info: MessageInfo,
    account: Addr,
    enabled: bool,
) -> StdResult<Response> {
    WHITELIST.save(deps.storage, &account, &enabled)?;
    Ok(Response::new())
}

pub fn set_display_name(name: String) -> String {
    name
}
