package positive

// Pattern B positive: three msgServer methods all read k.Authority —
// classic admin-key concentration (one signer gates many privileged ops).
type adminMsgServer struct {
	k *KeeperB
}

type KeeperB struct {
	Authority string
}

type CtxB struct {
	dummy int
}

type MsgUpdateFee struct {
	Authority string
}

type MsgUpdateFeeResponse struct {
	dummy int
}

type MsgUpdateOracle struct {
	Authority string
}

type MsgUpdateOracleResponse struct {
	dummy int
}

type MsgUpdateMarket struct {
	Authority string
}

type MsgUpdateMarketResponse struct {
	dummy int
}

func (ms adminMsgServer) UpdateFee(ctx CtxB, msg *MsgUpdateFee) (*MsgUpdateFeeResponse, error) {
	if msg.Authority != ms.k.Authority {
		return nil, nil
	}
	return &MsgUpdateFeeResponse{}, nil
}

func (ms adminMsgServer) UpdateOracle(ctx CtxB, msg *MsgUpdateOracle) (*MsgUpdateOracleResponse, error) {
	if msg.Authority != ms.k.Authority {
		return nil, nil
	}
	return &MsgUpdateOracleResponse{}, nil
}

func (ms adminMsgServer) UpdateMarket(ctx CtxB, msg *MsgUpdateMarket) (*MsgUpdateMarketResponse, error) {
	if msg.Authority != ms.k.Authority {
		return nil, nil
	}
	return &MsgUpdateMarketResponse{}, nil
}
