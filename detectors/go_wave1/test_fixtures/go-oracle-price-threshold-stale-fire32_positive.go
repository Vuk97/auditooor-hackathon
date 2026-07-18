// fixture: positive - oracle values are consumed after only one guard family.
package keeper

import (
	"errors"
	"time"
)

const (
	quoteScale int64 = 1_000_000
	tickScale  int64 = 10_000
)

var (
	ErrBadDeviation = errors.New("bad deviation")
	ErrStalePrice   = errors.New("stale price")
	ErrWrongSource  = errors.New("wrong source")
)

type Context struct{}

func (Context) BlockTime() time.Time { return time.Now() }

type OraclePrice struct {
	Value     int64
	UpdatedAt time.Time
	SourceID  string
}

type IndexPrice struct {
	Price     int64
	UpdatedAt time.Time
	SourceID  string
}

type TwapTick struct {
	Tick      int64
	UpdatedAt time.Time
	SourceID  string
}

type Position struct {
	Account   string
	Debt      int64
	LastPrice int64
	Size      int64
}

type Oracle struct{}
type PriceFeed struct{}
type MarginKeeper struct{}
type SettlementKeeper struct{}

func (Oracle) GetPrice(ctx Context, marketID string) (OraclePrice, error) {
	return OraclePrice{}, nil
}

func (Oracle) GetTwap(ctx Context, pair string) (TwapTick, error) {
	return TwapTick{}, nil
}

func (PriceFeed) IndexPrice(ctx Context, asset string) (IndexPrice, error) {
	return IndexPrice{}, nil
}

func (MarginKeeper) OpenPosition(ctx Context, account string, margin int64) {}

func (SettlementKeeper) SettleLiquidation(ctx Context, account string, seized int64) {}
func (SettlementKeeper) SettleFunding(ctx Context, account string, payment int64) {}

type Keeper struct {
	oracle          Oracle
	priceFeed       PriceFeed
	margin          MarginKeeper
	settlement      SettlementKeeper
	maxAge          time.Duration
	maxDeviationBps int64
	trustedSourceID string
}

func deviationBps(a int64, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

func (k Keeper) LiquidateWithDeviationOnly(ctx Context, marketID string, position Position) error {
	price, err := k.oracle.GetPrice(ctx, marketID)
	if err != nil {
		return err
	}
	if deviationBps(price.Value, position.LastPrice) > k.maxDeviationBps {
		return ErrBadDeviation
	}
	seized := position.Debt * price.Value / quoteScale
	k.settlement.SettleLiquidation(ctx, position.Account, seized)
	return nil
}

func (k Keeper) OpenMarginWithTimestampOnly(ctx Context, asset string, account string, collateral int64) error {
	index, err := k.priceFeed.IndexPrice(ctx, asset)
	if err != nil {
		return err
	}
	if ctx.BlockTime().Sub(index.UpdatedAt) > k.maxAge {
		return ErrStalePrice
	}
	margin := collateral * index.Price / quoteScale
	k.margin.OpenPosition(ctx, account, margin)
	return nil
}

func (k Keeper) SettleFundingWithSourceOnly(ctx Context, pair string, position Position) error {
	twap, err := k.oracle.GetTwap(ctx, pair)
	if err != nil {
		return err
	}
	if twap.SourceID != k.trustedSourceID {
		return ErrWrongSource
	}
	payment := position.Size * twap.Tick / tickScale
	k.settlement.SettleFunding(ctx, position.Account, payment)
	return nil
}
