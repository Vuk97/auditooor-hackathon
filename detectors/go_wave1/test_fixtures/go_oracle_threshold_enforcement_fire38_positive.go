// fixture: positive - oracle guard inputs are present but not enforced before acceptance.
package keeper

import "errors"

const priceScale int64 = 1_000_000

var (
	ErrBadRound    = errors.New("bad round")
	ErrBadVersion  = errors.New("bad version")
	ErrBadPrice    = errors.New("bad price")
	ErrStalePrice  = errors.New("stale price")
	ErrThreshold   = errors.New("threshold")
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
	marketPrices         map[string]int64
	acceptedPrices       map[string]int64
	riskPrices           map[string]int64
	thresholdPrices      map[string]int64
	maxAgeByMarket       map[string]int64
	expectedFeedVersions map[string]uint64
	oracleBounds         map[string]ThresholdBounds
	thresholds           map[string]int64
	maxAge               int64
}

func (k Keeper) ReturnPriceWithConfiguredMaxAgeButNoGuard(ctx Context, market string) (int64, error) {
	maxAge := k.maxAgeByMarket[market]
	report, err := k.oracle.LatestRoundData(ctx, market)
	if err != nil {
		return 0, err
	}
	_ = maxAge
	return report.Answer, nil
}

func (k Keeper) StorePriceBeforeAnsweredRoundGuard(ctx Context, pair string) error {
	report, err := k.oracle.LatestRoundData(ctx, pair)
	if err != nil {
		return err
	}
	answeredRoundOK := report.AnsweredInRound >= report.RoundID
	k.marketPrices[pair] = report.Answer
	if !answeredRoundOK {
		return ErrBadRound
	}
	return nil
}

func (k Keeper) StorePriceWithUnusedVersionCheck(ctx Context, pair string) error {
	expectedVersion := k.expectedFeedVersions[pair]
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	versionMatches := report.Version == expectedVersion
	_ = versionMatches
	k.acceptedPrices[pair] = report.Price
	return nil
}

func (k Keeper) StoreThresholdBeforeTimestampGuard(ctx Context, market string) error {
	report, err := k.oracle.FetchThreshold(ctx, market)
	if err != nil {
		return err
	}
	maxTimestamp := ctx.BlockTimeUnix() - k.maxAge
	k.thresholdPrices[market] = report.Price / priceScale
	if report.Timestamp < maxTimestamp {
		return ErrStalePrice
	}
	return nil
}

func (k Keeper) StoreRiskPriceWithLoadedThresholdsButNoReject(ctx Context, pair string) error {
	bounds := k.oracleBounds[pair]
	threshold := k.thresholds[pair]
	report, err := k.oracle.FetchPrice(ctx, pair)
	if err != nil {
		return err
	}
	_ = bounds
	_ = threshold
	k.riskPrices[pair] = report.Price
	return nil
}
