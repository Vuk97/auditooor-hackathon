// fixture: positive - timestamp-bearing oracle reports update protocol state before freshness checks.
package keeper

import "errors"

const priceScale int64 = 1_000_000

var (
	ErrBadConfidence = errors.New("bad confidence")
	ErrBadPrice      = errors.New("bad price")
	ErrStalePrice    = errors.New("stale price")
)

type Context struct {
	now int64
}

func (c Context) BlockTimeUnix() int64 { return c.now }

type ThresholdReport struct {
	Price           int64
	Value           int64
	Threshold       int64
	UpdatedAt       int64
	PublishTime     int64
	RoundID         uint64
	AnsweredInRound uint64
	Confidence      int64
}

type Oracle struct{}
type ThresholdFeed struct{}
type MedianFeed struct{}
type SettlementKeeper struct{}
type MarginKeeper struct{}

func (Oracle) LatestPrice(ctx Context, market string) (ThresholdReport, error) {
	return ThresholdReport{}, nil
}

func (Oracle) LatestRoundData(ctx Context, pair string) (ThresholdReport, error) {
	return ThresholdReport{}, nil
}

func (ThresholdFeed) FetchThreshold(ctx Context, market string) (ThresholdReport, error) {
	return ThresholdReport{}, nil
}

func (MedianFeed) ReadMedianPrice(ctx Context, asset string) (ThresholdReport, error) {
	return ThresholdReport{}, nil
}

func (SettlementKeeper) SettleLiquidation(ctx Context, account string, seized int64) {}
func (SettlementKeeper) SettleFunding(ctx Context, account string, payment int64) {}
func (MarginKeeper) OpenPosition(ctx Context, account string, margin int64) {}

type Position struct {
	Account string
	Debt    int64
	Size    int64
}

type Keeper struct {
	oracle         Oracle
	thresholdFeed  ThresholdFeed
	medianFeed     MedianFeed
	settlement     SettlementKeeper
	margin         MarginKeeper
	reserves       map[string]int64
	riskPrices     map[string]int64
	maxAge         int64
	maxConfidence  int64
	maxStaleness   int64
}

func (k Keeper) SettleLiquidationWithConfidenceOnly(ctx Context, market string, position Position) error {
	report, err := k.oracle.LatestPrice(ctx, market)
	if err != nil {
		return err
	}
	if report.Confidence > k.maxConfidence {
		return ErrBadConfidence
	}
	seized := position.Debt * report.Price / priceScale
	k.settlement.SettleLiquidation(ctx, position.Account, seized)
	return nil
}

func (k Keeper) UpdateReserveFromStaleThreshold(ctx Context, market string, currentReserve int64) error {
	threshold, err := k.thresholdFeed.FetchThreshold(ctx, market)
	if err != nil {
		return err
	}
	if threshold.Threshold <= 0 {
		return ErrBadPrice
	}
	reserve := currentReserve * threshold.Threshold / priceScale
	k.reserves[market] = reserve
	return nil
}

func (k Keeper) SettleFundingBeforeRoundFreshness(ctx Context, pair string, position Position) error {
	round, err := k.oracle.LatestRoundData(ctx, pair)
	if err != nil {
		return err
	}
	payment := position.Size * round.Value / priceScale
	k.settlement.SettleFunding(ctx, position.Account, payment)
	if round.AnsweredInRound < round.RoundID {
		return ErrStalePrice
	}
	return nil
}

func (k Keeper) OpenMarginWithConfiguredMaxAgeButNoCheck(ctx Context, asset string, account string, collateral int64) error {
	_ = k.maxAge
	median, err := k.medianFeed.ReadMedianPrice(ctx, asset)
	if err != nil {
		return err
	}
	margin := collateral * median.Price / priceScale
	k.margin.OpenPosition(ctx, account, margin)
	return nil
}

