// fixture: negative - stale oracle reports are rejected before protocol state updates.
package keeper

import "errors"

const priceScale int64 = 1_000_000

var (
	ErrBadConfidence = errors.New("bad confidence")
	ErrBadPair       = errors.New("bad pair")
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
	PairID          string
}

type Oracle struct{}
type ThresholdFeed struct{}
type MedianFeed struct{}
type SettlementKeeper struct{}
type MarginKeeper struct{}
type Metrics struct {
	LastOraclePrice int64
}

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
	metrics        Metrics
	reserves       map[string]int64
	riskPrices     map[string]int64
	maxAge         int64
	maxConfidence  int64
	maxStaleness   int64
}

func (k Keeper) ValidateFreshOracleThreshold(ctx Context, report ThresholdReport, market string) error {
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if report.PublishTime <= 0 {
		return ErrStalePrice
	}
	if report.Confidence > k.maxConfidence {
		return ErrBadConfidence
	}
	return nil
}

func (k Keeper) SettleLiquidationWithFreshnessAndConfidence(ctx Context, market string, position Position) error {
	report, err := k.oracle.LatestPrice(ctx, market)
	if err != nil {
		return err
	}
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	if report.Confidence > k.maxConfidence {
		return ErrBadConfidence
	}
	seized := position.Debt * report.Price / priceScale
	k.settlement.SettleLiquidation(ctx, position.Account, seized)
	return nil
}

func (k Keeper) UpdateReserveAfterHelperFreshness(ctx Context, market string, currentReserve int64) error {
	threshold, err := k.thresholdFeed.FetchThreshold(ctx, market)
	if err != nil {
		return err
	}
	if err := k.ValidateFreshOracleThreshold(ctx, threshold, market); err != nil {
		return err
	}
	if threshold.Threshold <= 0 {
		return ErrBadPrice
	}
	reserve := currentReserve * threshold.Threshold / priceScale
	k.reserves[market] = reserve
	return nil
}

func (k Keeper) SettleFundingAfterAnsweredRoundGuard(ctx Context, pair string, position Position) error {
	round, err := k.oracle.LatestRoundData(ctx, pair)
	if err != nil {
		return err
	}
	if round.AnsweredInRound < round.RoundID {
		return ErrStalePrice
	}
	payment := position.Size * round.Value / priceScale
	k.settlement.SettleFunding(ctx, position.Account, payment)
	return nil
}

func (k Keeper) OpenMarginWithDomainAndFreshness(ctx Context, asset string, account string, collateral int64) error {
	median, err := k.medianFeed.ReadMedianPrice(ctx, asset)
	if err != nil {
		return err
	}
	if median.PairID != asset {
		return ErrBadPair
	}
	if ctx.BlockTimeUnix()-median.UpdatedAt > k.maxStaleness {
		return ErrStalePrice
	}
	margin := collateral * median.Price / priceScale
	k.margin.OpenPosition(ctx, account, margin)
	return nil
}

func (k Keeper) StoreOracleMetricOnly(ctx Context, market string) error {
	report, err := k.oracle.LatestPrice(ctx, market)
	if err != nil {
		return err
	}
	k.metrics.LastOraclePrice = report.Price
	return nil
}

