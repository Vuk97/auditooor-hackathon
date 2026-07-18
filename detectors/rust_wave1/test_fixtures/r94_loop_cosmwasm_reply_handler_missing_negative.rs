// OK: SubMsg with ReplyOn::Success AND a reply entry_point
use cosmwasm_std::{Response, SubMsg, CosmosMsg, ReplyOn, DepsMut, Env, Reply};

pub fn execute_swap() -> Response {
    let submsg = SubMsg {
        id: 42,
        msg: CosmosMsg::Bank(/* ... */),
        reply_on: ReplyOn::Success,
        gas_limit: None,
    };
    Response::new().add_submessage(submsg)
}

#[entry_point]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Response {
    match msg.id {
        42 => handle_swap_reply(deps, msg),
        _ => Response::default(),
    }
}

fn handle_swap_reply(_d: DepsMut, _m: Reply) -> Response { Response::default() }
