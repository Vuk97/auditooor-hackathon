package app

type Context struct{}

type RequestProcessProposal struct {
	Txs [][]byte
}

type ResponseProcessProposal struct {
	Status ResponseProcessProposalStatus
}

type ResponseProcessProposalStatus int32

const (
	ResponseProcessProposal_ACCEPT ResponseProcessProposalStatus = 1
	ResponseProcessProposal_REJECT ResponseProcessProposalStatus = 2
)

type App struct{}

func (a App) ProcessProposal(ctx Context, req *RequestProcessProposal) (*ResponseProcessProposal, error) {
	if err := a.ValidateProposal(ctx, req); err != nil {
		return &ResponseProcessProposal{Status: ResponseProcessProposal_REJECT}, nil
	}
	return &ResponseProcessProposal{Status: ResponseProcessProposal_ACCEPT}, nil
}

func (a App) ValidateProposal(ctx Context, req *RequestProcessProposal) error {
	for _, tx := range req.Txs {
		if err := a.RunTx(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}

func (a App) RunTx(ctx Context, tx []byte) error { return nil }
