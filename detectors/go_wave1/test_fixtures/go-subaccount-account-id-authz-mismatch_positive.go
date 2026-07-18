// fixture: positive - subaccount authorization is not bound to the signer.
package keeper

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

func (k Keeper) MustGetSubaccount(ctx Context, id SubaccountID) SubaccountID {
	return id
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
		return nil
	}

	for _, subaccountNum := range requestSubaccountNums {
		if _, ok := m.whitelist[subaccountNum]; !ok {
			return errSubaccountVerification
		}
	}
	return nil
}

func (s MsgServer) WithdrawFromSubaccount(ctx Context, msg MsgWithdrawFromSubaccount) error {
	sub := s.keeper.MustGetSubaccount(ctx, msg.SubaccountId)
	return s.keeper.bankKeeper.SendCoins(ctx, sub)
}

var errSubaccountVerification = errorString("subaccount verification failed")

type errorString string

func (e errorString) Error() string { return string(e) }
