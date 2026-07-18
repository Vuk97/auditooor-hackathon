package fire7negative

import "errors"

var ErrAlreadyInitialized = errors.New("already initialized")
var ErrUnauthorized = errors.New("unauthorized")

type Keeper struct {
	deployer string
	factory  string
	state    State
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
	Caller        string
}

func (k *Keeper) Initialize(ctx Context, req InitRequest) error {
	caller := req.Caller
	if caller != k.deployer {
		return ErrUnauthorized
	}
	if k.state.Boss != "" {
		return ErrAlreadyInitialized
	}

	k.state.Boss = req.Boss
	k.state.Owner = req.InitialOwner
	return nil
}

func (k *Keeper) RegisterRoute(ctx Context, req InitRequest) error {
	sender := req.Caller
	if sender != k.factory {
		return ErrUnauthorized
	}
	if _, ok := k.state.Gateways[req.RemoteChainID]; ok {
		return ErrAlreadyInitialized
	}

	k.state.Gateways[req.RemoteChainID] = req.RemoteGateway
	return nil
}

type Context struct{}
