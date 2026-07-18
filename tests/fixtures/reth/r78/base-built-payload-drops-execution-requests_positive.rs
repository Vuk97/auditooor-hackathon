pub struct BaseExecutionPayloadEnvelopeV4 {
    pub execution_payload: BaseExecutionPayloadV4,
    pub execution_requests: Vec<Vec<u8>>,
}

pub struct BaseExecutionPayloadV4;
pub struct OpBuiltPayload<N> {
    pub block: N,
    pub fees: u64,
}

impl BaseExecutionPayloadV4 {
    pub fn from_v3_with_withdrawals_root(_payload: (), _root: [u8; 32]) -> Self {
        Self
    }
}

impl<N> From<OpBuiltPayload<N>> for BaseExecutionPayloadEnvelopeV4 {
    fn from(value: OpBuiltPayload<N>) -> Self {
        let OpBuiltPayload { block: _, fees: _ } = value;
        let payload_v3 = ();
        let l2_withdrawals_root = [0u8; 32];

        Self {
            execution_payload: BaseExecutionPayloadV4::from_v3_with_withdrawals_root(
                payload_v3,
                l2_withdrawals_root,
            ),
            // BUG: request list is dropped during built-payload conversion.
            execution_requests: vec![],
        }
    }
}
