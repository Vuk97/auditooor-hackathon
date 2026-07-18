// fixture: positive - subaccount whitelist authenticator default-allows
// unhandled message types, so x/sending-style subaccount messages bypass.
package authenticator

import "errors"

type Context struct{}

type AuthenticationRequest struct {
	Msg any
}

type MsgPlaceOrder struct {
	SubaccountId SubaccountID
}

type MsgCancelOrder struct {
	SubaccountId SubaccountID
}

type MsgWithdrawFromSubaccount struct {
	Sender SubaccountID
}

type SubaccountID struct {
	Number uint32
}

var ErrSubaccountVerification = errors.New("subaccount verification failed")

type SubaccountFilter struct {
	whitelist map[uint32]struct{}
}

func (m SubaccountFilter) Authenticate(ctx Context, request AuthenticationRequest) error {
	requestSubaccountNums := make([]uint32, 0)
	switch msg := request.Msg.(type) {
	case *MsgPlaceOrder:
		requestSubaccountNums = append(requestSubaccountNums, msg.SubaccountId.Number)
	case *MsgCancelOrder:
		requestSubaccountNums = append(requestSubaccountNums, msg.SubaccountId.Number)
	default:
		return nil
	}

	for _, subaccountNum := range requestSubaccountNums {
		if _, ok := m.whitelist[subaccountNum]; !ok {
			return ErrSubaccountVerification
		}
	}
	return nil
}
