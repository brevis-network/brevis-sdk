package tradingvolume

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
)

// In this example, we want to analyze the `Swap` events emitted by Uniswap's
// UniversalRouter contract. Let's declare the fields we want to use:

func TestCircuit(t *testing.T) {
	app, err := sdk.NewBrevisApp(1)
	check(err)

	usdcPool := common.HexToAddress("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640")
	usdc := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	swapEvent := common.HexToHash("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67")
	amount0 := common.BytesToHash(big.NewInt(724999999).Bytes())
	recipient := common.HexToHash("0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B")
	transferEvent := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
	from := common.HexToHash("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")

	// Adding a receipt query into the querier
	// In this tx, the user sold USDC and took native ETH out
	app.AddReceipt(sdk.ReceiptData{
		BlockNum: big.NewInt(18064070),
		TxHash:   common.HexToHash("53b37ec7975d217295f4bdadf8043b261fc49dccc16da9b9fc8b9530845a5794"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			{Contract: usdcPool, LogPos: 3, EventID: swapEvent, IsTopic: false, FieldIndex: 0, Value: amount0},  // field: USDCPool.Swap.amount0
			{Contract: usdcPool, LogPos: 3, EventID: swapEvent, IsTopic: true, FieldIndex: 2, Value: recipient}, // field: USDCPool.Swap.recipient (topic field)
			{Contract: usdc, LogPos: 2, EventID: transferEvent, IsTopic: true, FieldIndex: 1, Value: from},      // field: USDC.Transfer.from
		},
	})
	// More receipts can be added, but in this example we only add one to keep it simple
	// app.AddReceipt(...)
	// app.AddReceipt(...)

	// Initialize our AppCircuit and prepare the circuit assignment
	appCircuit := &AppCircuit{
		UserAddr: sdk.ConstUint248(common.HexToAddress("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")),
	}
	appCircuitAssignment := &AppCircuit{
		UserAddr: sdk.ConstUint248(common.HexToAddress("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")),
	}

	// Execute the added queries and package the query results into circuit inputs
	in, err := app.BuildCircuitInput(appCircuit)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	// Use the test package to check if the circuit can be solved using the given
	// assignment
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, in)
}

func TestE2E(t *testing.T) {
	app, err := sdk.NewBrevisApp(1)
	check(err)

	usdcPool := common.HexToAddress("0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640")
	usdc := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	swapEvent := common.HexToHash("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67")
	amount0 := common.BytesToHash(big.NewInt(724999999).Bytes())
	recipient := common.HexToHash("0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B")
	transferEvent := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
	from := common.HexToHash("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")

	// Adding a receipt query into the querier
	// In this tx, the user sold USDC and took native ETH out
	app.AddReceipt(sdk.ReceiptData{
		BlockNum: big.NewInt(18064070),
		TxHash:   common.HexToHash("53b37ec7975d217295f4bdadf8043b261fc49dccc16da9b9fc8b9530845a5794"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			{Contract: usdcPool, LogPos: 3, EventID: swapEvent, IsTopic: false, FieldIndex: 0, Value: amount0},  // field: USDCPool.Swap.amount0
			{Contract: usdcPool, LogPos: 3, EventID: swapEvent, IsTopic: true, FieldIndex: 2, Value: recipient}, // field: USDCPool.Swap.recipient (topic field)
			{Contract: usdc, LogPos: 2, EventID: transferEvent, IsTopic: true, FieldIndex: 1, Value: from},      // field: USDC.Transfer.from
		},
	})
	// More receipts can be added, but in this example we only add one to keep it simple
	// app.AddReceipt(...)
	// app.AddReceipt(...)

	// Initialize our AppCircuit and prepare the circuit assignment
	appCircuit := &AppCircuit{
		// you need to give every custom input an assignment or otherwise the circuit won't compile
		UserAddr: sdk.ConstUint248(0),
	}
	appCircuitAssignment := &AppCircuit{
		UserAddr: sdk.ConstUint248(common.HexToAddress("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")),
	}

	// Execute the added queries and package the query results into circuit inputs
	in, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	// Use the test package to check if the input can be proved with the given
	// circuit
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, in)

	///////////////////////////////////////////////////////////////////////////////
	// Compiling and Setup
	///////////////////////////////////////////////////////////////////////////////

	// The compiled circuit, proving key, and verifying key are saved to outDir, and
	// the downloaded SRS in the process is saved to srsDir
	outDir := "$HOME/circuitOut/tradingvolume"
	srsDir := "$HOME/kzgsrs"

	maxReceipt, maxStorage, _ := appCircuit.Allocate()
	compiledCircuit, pk, vk, err := sdk.Compile(appCircuit, outDir, srsDir, maxReceipt, maxStorage, sdk.NumMaxDataPoints)
	check(err)

	// Once you saved your ccs, pk, and vk files, you can read them back into memory
	// for use with the provided utils
	compiledCircuit, pk, vk, err = sdk.ReadSetupFrom(outDir)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Proving
	///////////////////////////////////////////////////////////////////////////////

	fmt.Println(">> prove")
	witness, publicWitness, err := sdk.NewFullWitness(appCircuitAssignment, in)
	check(err)
	proof, err := sdk.Prove(compiledCircuit, pk, witness)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Verifying
	///////////////////////////////////////////////////////////////////////////////

	// The verification of the proof generated by you is done on Brevis' side. But
	// you can also verify your own proof to make sure everything works fine and
	// pk/vk are serialized/deserialized properly
	err = sdk.Verify(vk, publicWitness, proof)
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
