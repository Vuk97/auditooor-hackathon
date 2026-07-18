// fixture: positive - oracle checks exist but are not bound to the written pair.
package keeper

import "errors"

const priceScale int64 = 1_000_000

var (
	ErrBadWindow  = errors.New("bad twap window")
	ErrDeviation  = errors.New("bad deviation")
	ErrWrongFeed  = errors.New("wrong feed")
	ErrWrongPair  = errors.New("wrong pair")
	ErrThreshold  = errors.New("bad threshold")
)

type Context struct{}

type PriceReport struct {
	Price      int64
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

type Keeper struct {
	oracle          Oracle
	marketPrices    map[string]int64
	medianPrices    map[string]int64
	twapPrices      map[string]int64
	thresholdPrices map[string]int64
	allowedFeeds    map[string]bool
	trustedSourceID string
	globalFeedID    string
	lastPrice       int64
	maxDeviationBps int64
	minThreshold    int64
	minWindow       int64
}

func (k Keeper) UpdatePriceWithGlobalFeedCheck(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if !k.allowedFeeds[report.FeedID] {
		return ErrWrongFeed
	}
	if absDiff(report.Price, k.lastPrice) > k.maxDeviationBps {
		return ErrDeviation
	}
	k.marketPrices[pair] = report.Price
	return nil
}

func (k Keeper) AcceptMedianWithUnboundMarketCheck(ctx Context, marketID string) error {
	median, err := k.oracle.FetchMedian(ctx, marketID)
	if err != nil {
		return err
	}
	if median.MarketID == "" {
		return ErrWrongPair
	}
	if median.Threshold < k.minThreshold {
		return ErrThreshold
	}
	k.medianPrices[marketID] = median.Price
	return nil
}

func (k Keeper) RecordTwapWithGlobalSourceOnly(ctx Context, baseDenom string, quoteDenom string) error {
	pairKey := baseDenom + "/" + quoteDenom
	twap, err := k.oracle.LoadTWAP(ctx, baseDenom, quoteDenom)
	if err != nil {
		return err
	}
	if twap.Window < k.minWindow {
		return ErrBadWindow
	}
	if twap.SourceID != k.trustedSourceID {
		return ErrWrongFeed
	}
	k.twapPrices[pairKey] = twap.Price
	return nil
}

func (k Keeper) UpdateAssetThresholdWithCallerSource(ctx Context, asset string, sourceID string) error {
	report, err := k.oracle.FetchPrice(ctx, asset)
	if err != nil {
		return err
	}
	if report.SourceID != sourceID {
		return ErrWrongFeed
	}
	if report.Threshold < k.minThreshold {
		return ErrThreshold
	}
	k.thresholdPrices[asset] = report.Price / priceScale
	return nil
}
