// fixture: negative - subaccount authorization is bound before use.
package keeper

import "fmt"

type Context struct{}

type AuthenticationRequest struct {
	Msg any
}

type SubaccountID struct {
	Owner  string
	Number uint32
}

type MsgPlaceOrder struct {
	SubaccountId SubaccountID
}

type MsgWithdrawFromSubaccount struct {
	Sender       string
	SubaccountId SubaccountID
}

type BankKeeper struct{}

type Keeper struct {
	bankKeeper BankKeeper
}

type MsgServer struct {
	keeper Keeper
}

func (BankKeeper) SendCoins(Context, SubaccountID) error { return nil }

func (k Keeper) CheckValidSubaccount(ctx Context, sender string, id SubaccountID) error {
	if sender != id.Owner {
		return fmt.Errorf("not owner")
	}
	return nil
}

type SubaccountFilter struct {
	whitelist map[uint32]struct{}
}

func (m SubaccountFilter) Authenticate(ctx Context, request AuthenticationRequest) error {
	requestSubaccountNums := make([]uint32, 0)
	switch msg := request.Msg.(type) {
	case *MsgPlaceOrder:
		requestSubaccountNums = append(requestSubaccountNums, msg.SubaccountId.Number)
	default:
		return errSubaccountVerification
	}

	for _, subaccountNum := range requestSubaccountNums {
		if _, ok := m.whitelist[subaccountNum]; !ok {
			return errSubaccountVerification
		}
	}
	return nil
}

func (s MsgServer) WithdrawFromSubaccount(ctx Context, msg MsgWithdrawFromSubaccount) error {
	if err := s.keeper.CheckValidSubaccount(ctx, msg.Sender, msg.SubaccountId); err != nil {
		return err
	}
	return s.keeper.bankKeeper.SendCoins(ctx, msg.SubaccountId)
}

var errSubaccountVerification = errorString("subaccount verification failed")

type errorString string

func (e errorString) Error() string { return string(e) }
