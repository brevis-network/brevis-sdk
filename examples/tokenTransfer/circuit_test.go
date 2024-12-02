package tokenTransfer

import (
	"context"
	"fmt"
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"
	"github.com/brevis-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
)

func TestCircuit(t *testing.T) {
	rpc := "RPC_URL"
	localDir := "$HOME/circuitOut/myBrevisApp"
	app, err := sdk.NewBrevisApp(1, rpc, localDir)
	check(err)

	txHash := common.HexToHash(
		"0x8a7fc50330533cd0adbf71e1cfb51b1b6bbe2170b4ce65c02678cf08c8b17737")

	app.AddReceipt(sdk.ReceiptData{
		TxHash: txHash,
		Fields: []sdk.LogFieldData{
			{
				IsTopic:    true,
				LogPos:     0,
				FieldIndex: 1,
			},
			{
				IsTopic:    false,
				LogPos:     0,
				FieldIndex: 0,
			},
		},
	})

	appCircuit := &AppCircuit{}
	appCircuitAssignment := &AppCircuit{}

	circuitInput, err := app.BuildCircuitInput(appCircuit)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, circuitInput)
}

func TestE2E(t *testing.T) {
	rpc := "RPC_URL"
	outDir := "$HOME/circuitOut/age"
	app, err := sdk.NewBrevisApp(1, rpc, outDir)
	check(err)

	txHash := common.HexToHash(
		"0xcee7b1bb4ebf73429faf9fa131b4710859c80a306ca7a6b141880aca477065b0")

	app.AddReceipt(sdk.ReceiptData{
		TxHash: txHash,
		Fields: []sdk.LogFieldData{
			{
				IsTopic:    true,
				LogPos:     0,
				FieldIndex: 1,
			},
			{
				IsTopic:    false,
				LogPos:     0,
				FieldIndex: 0,
			},
		},
	})

	appCircuit := &AppCircuit{}
	appCircuitAssignment := &AppCircuit{}

	circuitInput, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	//test.IsSolved(t, appCircuit, appCircuitAssignment, circuitInput)
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, circuitInput)

	///////////////////////////////////////////////////////////////////////////////
	// Compiling and Setup
	///////////////////////////////////////////////////////////////////////////////

	srsDir := "$HOME/kzgsrs"
	// The compiled circuit, proving key, and verifying key are saved to outDir, and
	// the downloaded SRS in the process is saved to srsDir
	compiledCircuit, pk, vk, _, err := sdk.Compile(&AppCircuit{}, outDir, srsDir, app)
	check(err)

	fmt.Println("compilation/setup complete")

	///////////////////////////////////////////////////////////////////////////////
	// Proving
	///////////////////////////////////////////////////////////////////////////////

	// Once you saved your ccs, pk, and vk files, you can read them back into memory
	// for use with the provided utils
	compiledCircuit, pk, vk, _, err = sdk.ReadSetupFrom(&AppCircuit{}, outDir, app)
	check(err)

	witness, publicWitness, err := sdk.NewFullWitness(appCircuitAssignment, circuitInput)
	check(err)
	proof, err := sdk.Prove(compiledCircuit, pk, witness)
	check(err)
	err = sdk.Verify(vk, publicWitness, proof) // optional
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Initiating Brevis Request
	///////////////////////////////////////////////////////////////////////////////

	fmt.Println(">> Initiate Brevis Request")
	appContract := common.HexToAddress("0x73090023b8D731c4e87B3Ce9Ac4A9F4837b4C1bd")
	refundee := common.HexToAddress("0x164Ef8f77e1C88Fb2C724D3755488bE4a3ba4342")

	calldata, _, _, feeValue, err := app.PrepareRequest(vk, publicWitness, 1, 11155111, refundee, appContract, 400000, gwproto.QueryOption_ZK_MODE.Enum(), "")
	check(err)
	fmt.Printf("calldata 0x%x\nfeeValue %d Wei\n", calldata, feeValue)

	///////////////////////////////////////////////////////////////////////////////
	// Submit Proof to Brevis
	///////////////////////////////////////////////////////////////////////////////

	fmt.Println(">> Submit Proof to Brevis")
	err = app.SubmitProof(proof)
	check(err)

	// [Call BrevisProof.sendRequest() with the above calldata]

	// Poll Brevis gateway for query status till the final proof is submitted
	// on-chain by Brevis and your contract is called
	submitTx, err := app.WaitFinalProofSubmitted(context.Background())
	check(err)
	fmt.Printf("tx hash %s\n", submitTx)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
