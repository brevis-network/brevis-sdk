package uniswapv2bidirectional

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves BIDIRECTIONAL trading volume on Uniswap V2 by analyzing
// both amount1In (WETH sent) and amount1Out (WETH received).
//
// This gives a complete picture of a user's trading activity, tracking both
// buying and selling of WETH.
//
// Use Cases:
// - Total trading volume (both directions)
// - Market making activity verification
// - Liquidity provision via trading
// - Two-way trading volume competitions

// AppCircuit proves bidirectional trading volume on Uniswap V2
type AppCircuit struct {
	UserAddr     sdk.Uint248 // Address of the trader to verify
	MinVolumeIn  sdk.Uint248 // Minimum WETH sent (buying token0)
	MinVolumeOut sdk.Uint248 // Minimum WETH received (selling token0)
}

var _ sdk.AppCircuit = &AppCircuit{}

// Uniswap V2 Swap Event Signature
// event Swap(address indexed sender, uint amount0In, uint amount1In, uint amount0Out, uint amount1Out, address indexed to)
// Signature: 0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822
var EventIdSwap = sdk.ParseEventID(
	hexutil.MustDecode("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"))

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
	// Allocate space for up to 50 swap receipts
	return 50, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Uniswap V2 Swap event structure:
		// Topics: [0] = event signature, [1] = sender (indexed), [2] = to (indexed)
		// Data: amount0In, amount1In, amount0Out, amount1Out (all uint256, non-indexed)

		// We track 4 fields per receipt (using all available slots):
		// [0] = amount1In (WETH sent - data field 1)
		// [1] = amount1Out (WETH received - data field 3)
		// [2] = sender address (topic field 1)
		// [3] = to address (topic field 2)

		// Verify all fields are from the correct pair contract
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, USDCWETHPair),
			u248.IsEqual(r.Fields[1].Contract, USDCWETHPair),
			u248.IsEqual(r.Fields[2].Contract, USDCWETHPair),
			u248.IsEqual(r.Fields[3].Contract, USDCWETHPair),
		)

		// Verify event IDs match Swap event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdSwap),
			u248.IsEqual(r.Fields[1].EventID, EventIdSwap),
			u248.IsEqual(r.Fields[2].EventID, EventIdSwap),
			u248.IsEqual(r.Fields[3].EventID, EventIdSwap),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// amount1In is data field 1 (not a topic)
			u248.IsZero(r.Fields[0].IsTopic),
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(1)),
			// amount1Out is data field 3 (not a topic)
			u248.IsZero(r.Fields[1].IsTopic),
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(3)),
			// sender is topic field 1 (indexed)
			r.Fields[2].IsTopic,
			u248.IsEqual(r.Fields[2].Index, sdk.ConstUint248(1)),
			// to is topic field 2 (indexed)
			r.Fields[3].IsTopic,
			u248.IsEqual(r.Fields[3].Index, sdk.ConstUint248(2)),
		)

		// Verify user is either sender OR recipient (bidirectional tracking)
		senderMatches := u248.IsEqual(api.ToUint248(r.Fields[2].Value), c.UserAddr)
		recipientMatches := u248.IsEqual(api.ToUint248(r.Fields[3].Value), c.UserAddr)
		userMatches := u248.Or(senderMatches, recipientMatches)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect, userMatches)
	})

	// Extract WETH sent (amount1In) from each swap
	volumesIn := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[0].Value) // amount1In
	})

	// Extract WETH received (amount1Out) from each swap
	volumesOut := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[1].Value) // amount1Out
	})

	// Sum total volume for each direction
	totalVolumeIn := sdk.Sum(volumesIn)
	totalVolumeOut := sdk.Sum(volumesOut)

	// Assert both directions meet minimum thresholds
	u248.AssertIsLessOrEqual(c.MinVolumeIn, totalVolumeIn)
	u248.AssertIsLessOrEqual(c.MinVolumeOut, totalVolumeOut)

	// Calculate total bidirectional volume
	totalVolume := u248.Add(totalVolumeIn, totalVolumeOut)

	// Count number of swaps
	swapCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)        // Verified user address
	api.OutputUint(248, totalVolumeIn)   // Total WETH sent
	api.OutputUint(248, totalVolumeOut)  // Total WETH received
	api.OutputUint(248, totalVolume)     // Total bidirectional volume
	api.OutputUint(64, swapCount)        // Number of swaps

	return nil
}
