package fire7positive

import "errors"

var ErrAlreadyInitialized = errors.New("already initialized")

type Keeper struct {
	state State
}

type State struct {
	Boss     string
	Owner    string
	Gateways map[uint64]string
}

type InitRequest struct {
	Boss          string
	InitialOwner  string
	RemoteChainID uint64
	RemoteGateway string
}

func (k *Keeper) Initialize(ctx Context, req InitRequest) error {
	if k.state.Boss != "" {
		return ErrAlreadyInitialized
	}

	k.state.Boss = req.Boss
	k.state.Owner = req.InitialOwner
	return nil
}

func (k *Keeper) RegisterRoute(ctx Context, req InitRequest) error {
	if _, ok := k.state.Gateways[req.RemoteChainID]; ok {
		return ErrAlreadyInitialized
	}

	k.state.Gateways[req.RemoteChainID] = req.RemoteGateway
	return nil
}

type Context struct{}
