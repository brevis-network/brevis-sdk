package compound

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves supply activity on Compound V2 by analyzing Mint events
// from cToken contracts.
//
// Compound uses cTokens (e.g., cUSDC, cETH) that represent deposits and accrue interest.
//
// Use Cases:
// - Airdrop eligibility for Compound suppliers
// - Lending protocol engagement rewards
// - cToken holder verification
// - Protocol liquidity provider tracking

// AppCircuit proves supply activity on Compound V2
type AppCircuit struct {
	UserAddr  sdk.Uint248 // Address of the supplier to verify
	MinSupply sdk.Uint248 // Minimum supply amount threshold
}

var _ sdk.AppCircuit = &AppCircuit{}

// Compound V2 Mint Event Signature
// event Mint(address minter, uint mintAmount, uint mintTokens)
// Signature: 0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f
var EventIdMint = sdk.ParseEventID(
	hexutil.MustDecode("0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f"))

// Compound V2 cToken addresses (Ethereum mainnet)
var (
	// cUSDC: 0x39AA39c021dfbaE8faC545936693aC917d5E7563
	cUSDCAddress = sdk.ConstUint248(common.HexToAddress("0x39AA39c021dfbaE8faC545936693aC917d5E7563"))
	// cETH: 0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5
	cETHAddress = sdk.ConstUint248(common.HexToAddress("0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5"))
	// cDAI: 0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643
	cDAIAddress = sdk.ConstUint248(common.HexToAddress("0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643"))

	// Underlying assets
	// USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
	USDCAddress = sdk.ConstUint248(common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocate space for up to 30 mint receipts
	return 30, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Compound V2 Mint event structure:
		// Topics: [0] = event signature
		// Data: minter (address), mintAmount (uint256), mintTokens (uint256)
		//
		// Note: This Mint event signature (0x4c209b5f...) is the same as Uniswap V2 Mint,
		// but the data structure is different:
		// - Uniswap: Mint(sender indexed, amount0, amount1)
		// - Compound: Mint(minter, mintAmount, mintTokens)

		// We track 2 fields per receipt:
		// [0] = mintAmount (data field 1) - underlying tokens supplied
		// [1] = minter (data field 0) - supplier address

		// Verify all fields are from the cUSDC contract
		// (In production, you might want to accept multiple cToken contracts)
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, cUSDCAddress),
			u248.IsEqual(r.Fields[1].Contract, cUSDCAddress),
		)

		// Verify event IDs match Mint event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdMint),
			u248.IsEqual(r.Fields[1].EventID, EventIdMint),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// mintAmount is data field 1 (not a topic)
			u248.IsZero(r.Fields[0].IsTopic),
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(1)),
			// minter is data field 0 (not a topic)
			u248.IsZero(r.Fields[1].IsTopic),
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(0)),
		)

		// Verify the minter address matches who we're verifying
		userMatches := u248.IsEqual(api.ToUint248(r.Fields[1].Value), c.UserAddr)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect, userMatches)
	})

	// Extract mint amounts (underlying tokens supplied)
	supplies := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[0].Value) // mintAmount
	})

	// Sum total supplies
	totalSupply := sdk.Sum(supplies)

	// Assert that total supply meets or exceeds minimum threshold
	u248.AssertIsLessOrEqual(c.MinSupply, totalSupply)

	// Count number of mint events
	mintCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)      // Verified supplier address
	api.OutputUint(248, totalSupply)   // Total amount supplied
	api.OutputUint(248, c.MinSupply)   // Minimum threshold
	api.OutputUint(64, mintCount)      // Number of supplies

	return nil
}
