// fixture: negative - oracle guard inputs are enforced before return or state write.
package keeper

import "errors"

const priceScale int64 = 1_000_000

var (
	ErrBadRound   = errors.New("bad round")
	ErrBadVersion = errors.New("bad version")
	ErrBadPrice   = errors.New("bad price")
	ErrStalePrice = errors.New("stale price")
)

type Context struct {
	now int64
}

func (c Context) BlockTimeUnix() int64 { return c.now }

type RoundReport struct {
	Price           int64
	Answer          int64
	UpdatedAt       int64
	Timestamp       int64
	RoundID         uint64
	AnsweredInRound uint64
	Version         uint64
}

type ThresholdBounds struct {
	Min int64
	Max int64
}

type Oracle struct{}
type Metrics struct {
	LastOraclePrice int64
}

func (Oracle) LatestRoundData(ctx Context, pair string) (RoundReport, error) {
	return RoundReport{}, nil
}

func (Oracle) FetchPrice(ctx Context, pair string) (RoundReport, error) {
	return RoundReport{}, nil
}

func (Oracle) FetchThreshold(ctx Context, market string) (RoundReport, error) {
	return RoundReport{}, nil
}

type Keeper struct {
	oracle               Oracle
	metrics              Metrics
	marketPrices         map[string]int64
	acceptedPrices       map[string]int64
	riskPrices           map[string]int64
	thresholdPrices      map[string]int64
	maxAgeByMarket       map[string]int64
	expectedFeedVersions map[string]uint64
	oracleBounds         map[string]ThresholdBounds
	maxAge               int64
}

func (k Keeper) ValidateOracleRound(ctx Context, report RoundReport, pair string) error {
	if ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAgeByMarket[pair] {
		return ErrStalePrice
	}
	if report.AnsweredInRound < report.RoundID {
		return ErrBadRound
	}
	if report.Version != k.expectedFeedVersions[pair] {
		return ErrBadVersion
	}
	bounds := k.oracleBounds[pair]
	if report.Price < bounds.Min {
		return ErrBadPrice
	}
	if report.Price > bounds.Max {
		return ErrBadPrice
	}
	return nil
}

func (k Keeper) ReturnPriceAfterMaxAgeGuard(ctx Context, market string) (int64, error) {
	maxAge := k.maxAgeByMarket[market]
	report, err := k.oracle.LatestRoundData(ctx, market)
	if err != nil {
		return 0, err
	}
	if ctx.BlockTimeUnix()-report.UpdatedAt > maxAge {
		return 0, ErrStalePrice
	}
	return report.Answer, nil
}

func (k Keeper) StorePriceAfterAnsweredRoundGuard(ctx Context, pair string) error {
	report, err := k.oracle.LatestRoundData(ctx, pair)
	if err != nil {
		return err
	}
	if report.AnsweredInRound < report.RoundID {
		return ErrBadRound
	}
	k.marketPrices[pair] = report.Answer
	return nil
}

func (k Keeper) StorePriceAfterVersionGuard(ctx Context, pair string) error {
	expectedVersion := k.expectedFeedVersions[pair]
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if report.Version != expectedVersion {
		return ErrBadVersion
	}
	k.acceptedPrices[pair] = report.Price
	return nil
}

func (k Keeper) StoreThresholdAfterTimestampGuard(ctx Context, market string) error {
	report, err := k.oracle.FetchThreshold(ctx, market)
	if err != nil {
		return err
	}
	maxTimestamp := ctx.BlockTimeUnix() - k.maxAge
	if report.Timestamp < maxTimestamp {
		return ErrStalePrice
	}
	k.thresholdPrices[market] = report.Price / priceScale
	return nil
}

func (k Keeper) StoreRiskPriceAfterHelperValidation(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	if err := k.ValidateOracleRound(ctx, report, pair); err != nil {
		return err
	}
	k.riskPrices[pair] = report.Price
	return nil
}

func (k Keeper) StoreOracleMetricOnly(ctx Context, pair string) error {
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	k.metrics.LastOraclePrice = report.Price
	return nil
}
