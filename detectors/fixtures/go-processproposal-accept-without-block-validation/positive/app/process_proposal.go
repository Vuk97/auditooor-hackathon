package app

type Context struct{}

type RequestProcessProposal struct {
	Txs [][]byte
}

type ResponseProcessProposal struct {
	Status ResponseProcessProposalStatus
}

type ResponseProcessProposalStatus int32

const ResponseProcessProposal_ACCEPT ResponseProcessProposalStatus = 1

type App struct{}

func (a App) ProcessProposal(ctx Context, req *RequestProcessProposal) (*ResponseProcessProposal, error) {
	a.stageProposalTxs(ctx, req.Txs)
	return &ResponseProcessProposal{Status: ResponseProcessProposal_ACCEPT}, nil
}

func (a App) stageProposalTxs(ctx Context, txs [][]byte) {}
