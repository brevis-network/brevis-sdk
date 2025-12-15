package aave

import (
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This circuit proves deposit activity on Aave V3 by analyzing Supply events.
//
// Aave is a decentralized lending protocol where users can supply assets
// to earn interest or borrow assets.
//
// Use Cases:
// - Airdrop eligibility for depositors
// - Lending protocol engagement rewards
// - DeFi user classification (lenders vs borrowers)
// - Protocol TVL contributor verification

// AppCircuit proves deposit activity on Aave V3
type AppCircuit struct {
	UserAddr   sdk.Uint248 // Address of the depositor to verify
	MinDeposit sdk.Uint248 // Minimum deposit amount threshold
}

var _ sdk.AppCircuit = &AppCircuit{}

// Aave V3 Supply Event Signature
// event Supply(address indexed reserve, address user, address indexed onBehalfOf, uint256 amount, uint16 indexed referralCode)
// Signature: 0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61
var EventIdSupply = sdk.ParseEventID(
	hexutil.MustDecode("0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61"))

// Aave V3 Pool (Ethereum mainnet)
// Pool address: 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2
var (
	PoolAddress = sdk.ConstUint248(common.HexToAddress("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"))

	// Common reserve assets
	// USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
	USDCAddress = sdk.ConstUint248(common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
	// WETH: 0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2
	WETHAddress = sdk.ConstUint248(common.HexToAddress("0xC02aaA39b223FE8D0A3e5C4F27eAD9083C756Cc2"))
	// DAI: 0x6B175474E89094C44Da98b954EedeAC495271d0F
	DAIAddress = sdk.ConstUint248(common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F"))
)

func (c *AppCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocate space for up to 30 supply receipts
	// Deposits are typically less frequent than swaps
	return 30, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	u248 := api.Uint248

	receipts := sdk.NewDataStream(api, in.Receipts)

	// Validate all receipts match expected pattern
	sdk.AssertEach(receipts, func(r sdk.Receipt) sdk.Uint248 {
		// Aave V3 Supply event structure:
		// Topics: [0] = event signature, [1] = reserve (indexed),
		//         [2] = onBehalfOf (indexed), [3] = referralCode (indexed)
		// Data: user (address), amount (uint256)

		// We track 2 fields per receipt:
		// [0] = amount (data field 1) - deposit amount
		// [1] = user (data field 0) - depositor address
		//
		// Note: We're tracking 'user' not 'onBehalfOf' since user is the actual depositor

		// Verify all fields are from the Pool contract
		contractMatches := u248.And(
			u248.IsEqual(r.Fields[0].Contract, PoolAddress),
			u248.IsEqual(r.Fields[1].Contract, PoolAddress),
		)

		// Verify event IDs match Supply event
		eventIdMatches := u248.And(
			u248.IsEqual(r.Fields[0].EventID, EventIdSupply),
			u248.IsEqual(r.Fields[1].EventID, EventIdSupply),
		)

		// Verify field indices and types
		fieldIndicesCorrect := u248.And(
			// amount is data field 1 (not a topic)
			u248.IsZero(r.Fields[0].IsTopic),
			u248.IsEqual(r.Fields[0].Index, sdk.ConstUint248(1)),
			// user is data field 0 (not a topic)
			u248.IsZero(r.Fields[1].IsTopic),
			u248.IsEqual(r.Fields[1].Index, sdk.ConstUint248(0)),
		)

		// Verify the user address matches who we're verifying
		userMatches := u248.IsEqual(api.ToUint248(r.Fields[1].Value), c.UserAddr)

		return u248.And(contractMatches, eventIdMatches, fieldIndicesCorrect, userMatches)
	})

	// Extract deposit amounts from each supply event
	deposits := sdk.Map(receipts, func(r sdk.Receipt) sdk.Uint248 {
		return api.ToUint248(r.Fields[0].Value) // amount
	})

	// Sum total deposits
	totalDeposits := sdk.Sum(deposits)

	// Assert that total deposits meet or exceed minimum threshold
	u248.AssertIsLessOrEqual(c.MinDeposit, totalDeposits)

	// Count number of supply events
	supplyCount := sdk.Count(receipts)

	// Output results for on-chain verification
	api.OutputAddress(c.UserAddr)       // Verified depositor address
	api.OutputUint(248, totalDeposits)  // Total amount deposited
	api.OutputUint(248, c.MinDeposit)   // Minimum threshold
	api.OutputUint(64, supplyCount)     // Number of deposits

	return nil
}
