// fixture: negative - oracle checks bind to the exact written pair or asset.
package keeper

import "errors"

const priceScale int64 = 1_000_000

var (
	ErrBadWindow  = errors.New("bad twap window")
	ErrDeviation  = errors.New("bad deviation")
	ErrStalePrice = errors.New("stale price")
	ErrWrongFeed  = errors.New("wrong feed")
	ErrWrongPair  = errors.New("wrong pair")
	ErrThreshold  = errors.New("bad threshold")
)

type Context struct {
	now int64
}

func (c Context) BlockTimeUnix() int64 { return c.now }

type PriceReport struct {
	Price      int64
	UpdatedAt  int64
	SourceID   string
	FeedID     string
	MarketID   string
	BaseDenom  string
	QuoteDenom string
	Threshold  int64
	Window     int64
}

type Oracle struct{}

func (Oracle) FetchPrice(ctx Context, pair string) (PriceReport, error) {
	return PriceReport{}, nil
}

func (Oracle) FetchMedian(ctx Context, marketID string) (PriceReport, error) {
	return PriceReport{}, nil
}

func (Oracle) LoadTWAP(ctx Context, baseDenom string, quoteDenom string) (PriceReport, error) {
	return PriceReport{}, nil
}

func absDiff(a int64, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

type Metrics struct {
	LastOraclePrice int64
}

type Keeper struct {
	oracle          Oracle
	metrics         Metrics
	marketPrices    map[string]int64
	medianPrices    map[string]int64
	twapPrices      map[string]int64
	thresholdPrices map[string]int64
	expectedFeeds   map[string]string
	expectedSources map[string]string
	lastPriceByPair map[string]int64
	maxAge          int64
	maxDeviationBps int64
	minThreshold    int64
	minWindow       int64
}

func (k Keeper) ValidateOraclePair(ctx Context, report PriceReport, pair string) error {
	if report.FeedID != k.expectedFeeds[pair] {
		return ErrWrongFeed
	}
	if absDiff(report.Price, k.lastPriceByPair[pair]) > k.maxDeviationBps {
		return ErrDeviation
	}
	return nil
}

func (k Keeper) UpdatePriceWithExpectedFeed(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	expectedFeed := k.expectedFeeds[pair]
	if report.FeedID != expectedFeed {
		return ErrWrongFeed
	}
	if absDiff(report.Price, k.lastPriceByPair[pair]) > k.maxDeviationBps {
		return ErrDeviation
	}
	k.marketPrices[pair] = report.Price
	return nil
}

func (k Keeper) AcceptMedianWithMarketBinding(ctx Context, marketID string) error {
	median, err := k.oracle.FetchMedian(ctx, marketID)
	if err != nil {
		return err
	}
	if median.MarketID != marketID {
		return ErrWrongPair
	}
	if median.SourceID != k.expectedSources[marketID] {
		return ErrWrongFeed
	}
	if median.Threshold < k.minThreshold {
		return ErrThreshold
	}
	k.medianPrices[marketID] = median.Price
	return nil
}

func (k Keeper) RecordTwapWithBaseQuoteBinding(ctx Context, baseDenom string, quoteDenom string) error {
	pairKey := baseDenom + "/" + quoteDenom
	twap, err := k.oracle.LoadTWAP(ctx, baseDenom, quoteDenom)
	if err != nil {
		return err
	}
	if twap.BaseDenom != baseDenom || twap.QuoteDenom != quoteDenom {
		return ErrWrongPair
	}
	if twap.SourceID != k.expectedSources[pairKey] {
		return ErrWrongFeed
	}
	if twap.Window < k.minWindow {
		return ErrBadWindow
	}
	k.twapPrices[pairKey] = twap.Price
	return nil
}

func (k Keeper) UpdateAssetThresholdWithValidator(ctx Context, asset string) error {
	report, err := k.oracle.FetchPrice(ctx, asset)
	if err != nil {
		return err
	}
	if err := k.ValidateOraclePair(ctx, report, asset); err != nil {
		return err
	}
	if report.Threshold < k.minThreshold {
		return ErrThreshold
	}
	k.thresholdPrices[asset] = report.Price / priceScale
	return nil
}

func (k Keeper) UpdatePriceWithFreshnessOnly(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge {
		return ErrStalePrice
	}
	k.marketPrices[pair] = report.Price
	return nil
}

func (k Keeper) StoreOracleMetric(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	k.metrics.LastOraclePrice = report.Price
	return nil
}
