package ibcmodule

type Context struct{}

type Packet struct {
	Data []byte
}

func (p Packet) GetData() []byte          { return p.Data }
func (p Packet) GetSourceChannel() string { return "channel-0" }

type FungibleTokenPacketData struct {
	Denom    string
	Sender   string
	Receiver string
	Amount   int64
}

type IBCModule struct {
	rateLimitKeeper RateLimitKeeper
	bankKeeper      BankKeeper
}

type RateLimitKeeper struct{}
type BankKeeper struct{}

func (k RateLimitKeeper) CheckQuota(ctx Context, denom string, channel string, sender string, amount int64) error {
	return nil
}
func (k BankKeeper) SendCoinsFromModuleToAccount(ctx Context, module string, receiver string, amount int64) error {
	return nil
}

func decodeTransfer(data []byte) FungibleTokenPacketData {
	return FungibleTokenPacketData{}
}

func (im IBCModule) OnRecvPacket(ctx Context, packet Packet) error {
	data := decodeTransfer(packet.GetData())
	if err := im.rateLimitKeeper.CheckQuota(ctx, data.Denom, packet.GetSourceChannel(), data.Sender, data.Amount); err != nil {
		return err
	}
	return im.bankKeeper.SendCoinsFromModuleToAccount(ctx, "transfer", data.Receiver, data.Amount)
}
