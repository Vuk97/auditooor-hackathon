// fixture: negative - subaccount whitelist authenticator covers x/sending
// messages and fails closed on unknown request.Msg variants.
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

type MsgCreateTransfer struct {
	Sender SubaccountID
}

type MsgWithdrawFromSubaccount struct {
	Sender SubaccountID
}

type MsgDepositToSubaccount struct {
	Recipient SubaccountID
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
	case *MsgCreateTransfer:
		requestSubaccountNums = append(requestSubaccountNums, msg.Sender.Number)
	case *MsgWithdrawFromSubaccount:
		requestSubaccountNums = append(requestSubaccountNums, msg.Sender.Number)
	case *MsgDepositToSubaccount:
		requestSubaccountNums = append(requestSubaccountNums, msg.Recipient.Number)
	default:
		return ErrSubaccountVerification
	}

	for _, subaccountNum := range requestSubaccountNums {
		if _, ok := m.whitelist[subaccountNum]; !ok {
			return ErrSubaccountVerification
		}
	}
	return nil
}
