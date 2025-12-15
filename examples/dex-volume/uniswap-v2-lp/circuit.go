package uniswapv2lp

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves that a user provided liquidity to a Uniswap V2 pair
// by analyzing Mint events (liquidity additions).
//
// Use Cases:
// - Airdrop eligibility for liquidity providers
// - LP rewards distribution
// - Prove minimum liquidity provision
// - Time-weighted liquidity tracking

// AppCircuit proves liquidity provision on Uniswap V2
type AppCircuit struct {
	UserAddr       sdk.Uint248 // Address of the LP to verify
	MinLiquidityV0 sdk.Uint248 // Minimum token0 liquidity provided
	MinLiquidityV1 sdk.Uint248 // Minimum token1 liquidity provided
}

var _ sdk.AppCircuit = &AppCircuit{}

// Uniswap V2 Mint Event Signature
// event Mint(address indexed sender, uint amount0, uint amount1)
// Signature: 0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f
var EventIdMint = sdk.ParseEventID(
	hexutil.MustDecode("0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f"))

// Uniswap V2 pair addresses (Ethereum mainnet)
var (
	// USDC/WETH pair: 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc
	USDCWETHPair = sdk.ConstUint248(common.HexToAddress("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"))
	// USDC address: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 (token0)
	USDCAddress = sdk.ConstUint248(common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
	// WETH address: 0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2 (token1)
	WETHAddress = sdk.ConstUint248(common.HexToAddress("0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocate space for up to 20 Mint events
	// LPs typically add liquidity less frequently than traders swap
	return 20, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected Mint event pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Uniswap V2 Mint event structure:
		// Topics: [0] = event signature, [1] = sender (indexed)
		// Data: amount0, amount1 (uint256, non-indexed)

		// We track 3 fields per receipt:
		// [0] = sender address (topic field 1)
		// [1] = amount0 (USDC added - data field 0)
		// [2] = amount1 (WETH added - data field 1)

		// Verify all fields are from the correct pair contract
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, USDCWETHPair),
			u248.IsEqual(r.Fields[1].Contract, USDCWETHPair),
			u248.IsEqual(r.Fields[2].Contract, USDCWETHPair),
		)

		// Verify event IDs match Mint event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdMint),
			u248.IsEqual(r.Fields[1].EventID, EventIdMint),
			u248.IsEqual(r.Fields[2].EventID, EventIdMint),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// sender is topic field 1 (indexed)
			r.Fields[0].IsTopic,
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(1)),
			// amount0 is data field 0 (not a topic)
			u248.IsZero(r.Fields[1].IsTopic),
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(0)),
			// amount1 is data field 1 (not a topic)
			u248.IsZero(r.Fields[2].IsTopic),
			u248.IsEqual(r.Fields[2].Index, sdk.ConstUint248(1)),
		)

		// Verify the sender address matches the LP we're verifying
		userMatches := u248.IsEqual(api.ToUint248(r.Fields[0].Value), c.UserAddr)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect, userMatches)
	})

	// Extract token0 (USDC) liquidity from each Mint event
	liquidityToken0 := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[1].Value) // amount0
	})

	// Extract token1 (WETH) liquidity from each Mint event
	liquidityToken1 := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[2].Value) // amount1
	})

	// Sum total liquidity provided for each token
	totalLiquidityToken0 := sdk.Sum(liquidityToken0)
	totalLiquidityToken1 := sdk.Sum(liquidityToken1)

	// Assert that both tokens meet minimum thresholds
	u248.AssertIsLessOrEqual(c.MinLiquidityV0, totalLiquidityToken0)
	u248.AssertIsLessOrEqual(c.MinLiquidityV1, totalLiquidityToken1)

	// Count number of Mint events (liquidity additions)
	mintCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)             // Verified LP address
	api.OutputUint(248, totalLiquidityToken0) // Total USDC provided
	api.OutputUint(248, totalLiquidityToken1) // Total WETH provided
	api.OutputUint(64, mintCount)             // Number of liquidity additions

	return nil
}
