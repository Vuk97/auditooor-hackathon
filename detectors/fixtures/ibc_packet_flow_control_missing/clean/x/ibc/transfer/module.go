package transfer

type Packet struct {
	Data []byte
}

type RateLimitKeeper struct{}
type BankKeeper struct{}

type IBCModule struct {
	rateLimitKeeper RateLimitKeeper
	bankKeeper      BankKeeper
}

func (RateLimitKeeper) CheckRateLimitAndUpdateFlow(Packet) error { return nil }
func (RateLimitKeeper) UndoReceive(Packet) error { return nil }
func (BankKeeper) SendCoinsFromModuleToAccount(Packet) error { return nil }
func (BankKeeper) SendCoins(Packet) error { return nil }

func decodePacket(packet Packet) Packet { return packet }

func (im IBCModule) OnRecvPacket(packet Packet) error {
	decoded := decodePacket(packet)
	if err := im.rateLimitKeeper.CheckRateLimitAndUpdateFlow(decoded); err != nil {
		return err
	}
	return im.bankKeeper.SendCoinsFromModuleToAccount(decoded)
}

func (im IBCModule) OnTimeoutPacket(packet Packet) error {
	refund := decodePacket(packet)
	if err := im.rateLimitKeeper.UndoReceive(refund); err != nil {
		return err
	}
	return im.bankKeeper.SendCoins(refund)
}
