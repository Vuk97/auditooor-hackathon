// BUG: SubMsg with ReplyOn::Success but no reply entry_point
use cosmwasm_std::{Response, SubMsg, CosmosMsg, ReplyOn};

pub fn execute_swap() -> Response {
    let submsg = SubMsg {
        id: 42,
        msg: CosmosMsg::Bank(/* ... */),
        reply_on: ReplyOn::Success,
        gas_limit: None,
    };
    Response::new().add_submessage(submsg)
}

// No `pub fn reply(...)` entry_point in this file
