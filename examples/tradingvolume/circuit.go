package tradingvolume

import (
	"github.com/celer-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// This example circuit analyzes the swap events between USDC and ETH/WETH for a user.

// GuestCircuit is a developer-defined circuit that performs checks and data analysis
// over the input Receipt. The proof of this circuit is to be verified in Brevis
// in conjunction with various data validity checks. A final proof is then
// submitted on-chain and expose the output to the developer's contract.
// The Brevis side ensures that all receipts
type GuestCircuit struct {
	// You can define your own custom circuit inputs here, but note that they cannot
	// have the `gnark:",public"` tag.
	UserAddr sdk.Variable
}

// Your guest circuit must implement the sdk.GuestCircuit interface
var _ sdk.GuestCircuit = &GuestCircuit{}

// sdk.ParseXXX APIs are used to convert Go/EVM data types into circuit types.
// Note that you can only use these outside of circuit (making constant circuit
// variables)

var EventIdSwap = sdk.ParseEventID(
	hexutil.MustDecode("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"))
var EventIdTransfer = sdk.ParseEventID(
	hexutil.MustDecode("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"))

var RouterAddress = sdk.ParseAddress(
	common.HexToAddress("0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B"))
var UsdcPoolAddress = sdk.ParseAddress(
	common.HexToAddress("0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640"))
var UsdcAddress = sdk.ParseAddress(
	common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"))
var Salt = sdk.ParseBytes32(
	hexutil.MustDecode("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"))

func (c *GuestCircuit) Allocate() (maxReceipts, maxSlots, maxTransactions int) {
	// Allocating regions for different source data. Here, we are allocating 5 data
	// slots for "receipt" data, and none for other data types. Please note that if
	// you allocate it this way and compile your circuit, the circuit structure will
	// always have 5 processing "chips" for receipts and none for others. It means
	// your compiled circuit will always be only able to process up to 5 receipts and
	// cannot process other types unless you change the allocations and recompile.
	return 5, 0, 0
}

func (c *GuestCircuit) Define(api *sdk.CircuitAPI, witness sdk.Witness) error {
	// In order to use the nice methods such as .Map() and .Reduce(), raw data needs
	// to be wrapped in a DataStream. You could also use the raw data directly if you
	// are familiar with writing gnark circuits.
	receipts := sdk.NewDataStream(api, witness.Receipts)

	// Main application logic: Run the assert function on each receipt. The function
	// should return 1 if assertion successes and 0 otherwise
	receipts.AssertEach(func(l sdk.Receipt) sdk.Variable {
		// If the recipient field of the Swap event is uniswap router, it means the user
		// requested native token out. We need to instead check the user's address in the
		// Transfer event emitted by USDC contract
		recipientIsRouter := api.Equal(api.ToVariable(l.Fields[1].Value), RouterAddress)
		// the following line translates to "if recipient is router, then use `from` as
		// userAddr, else use `recipient`"
		userAddr := api.Select(
			recipientIsRouter, api.ToVariable(l.Fields[2].Value), api.ToVariable(l.Fields[1].Value))
		// asserts that the following equality checks each results in 1
		assertionPassed := api.And(
			// 1. Check that the user address related to the swaps is consistent across all
			// receipts
			api.Equal(userAddr, c.UserAddr),
			// 2. Check that the contract address of each log field is the expected contract
			api.Equal(l.Fields[0].Contract, UsdcPoolAddress),
			api.Equal(l.Fields[1].Contract, UsdcPoolAddress),
			api.Equal(l.Fields[2].Contract, UsdcAddress),
			// 3. Check the EventID of the fields are as expected
			api.Equal(l.Fields[0].EventID, EventIdSwap),
			api.Equal(l.Fields[1].EventID, EventIdSwap),
			api.Equal(l.Fields[2].EventID, EventIdTransfer),
			// 4. Check the index of the fields are as expected
			api.IsZero(l.Fields[0].IsTopic), // `amount0` is not a topic field
			api.Equal(l.Fields[0].Index, 0), // `amount0` is the 0th data field in the `Swap` event
			l.Fields[1].IsTopic,             // `recipient` is a topic field
			api.Equal(l.Fields[1].Index, 2), // `recipient` is the 2nd topic field in the `Swap` event
			l.Fields[2].IsTopic,             // `from` is a topic field
			api.Equal(l.Fields[2].Index, 1), // `from` is the 1st index field in the `Transfer` event
		)
		return assertionPassed
	})

	// Find out the minimum block number. This enables us to find out over what range
	// the user has a specific trading volume
	minBlockNum := receipts.Min(func(l sdk.Receipt) sdk.Variable { return l.BlockNum })

	// Sum up the volume of each trade
	sumVolume := receipts.Sum(func(l sdk.Receipt) sdk.Variable {
		return api.ABS(api.ToVariable(l.Fields[0].Value))
	})

	// Output will be reflected in app contract's callback in the form of
	// _circuitOutput: abi.encodePacked(uint256,uint248,uint64,address)
	// this variable Salt isn't used anywhere. it's just here to demonstrate how to output bytes32/uint256
	api.OutputBytes32(Salt)
	api.OutputUint(248, sumVolume)
	api.OutputUint(64, minBlockNum)
	api.OutputAddress(c.UserAddr)

	return nil
}