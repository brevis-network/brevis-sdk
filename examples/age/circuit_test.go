package age

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
	localDir := "$HOME/circuitOut/myBrevisApp/input"
	numMaxDataPoints := 64
	app, err := sdk.NewBrevisApp(1, numMaxDataPoints, "RPC_URL", localDir)
	check(err)

	txHash := common.HexToHash(
		"0x6dc75e61220cc775aafa17796c20e49ac08030020fce710e3e546aa4e003454c")

	txData := sdk.TransactionData{
		Hash: txHash,
	}
	fmt.Printf("%+v\n", txData)
	app.AddTransaction(txData)

	appCircuit := &AppCircuit{}
	appCircuitAssignment := &AppCircuit{}

	circuitInput, err := app.BuildCircuitInput(appCircuit)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	//test.IsSolved(t, appCircuit, appCircuitAssignment, circuitInput)
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, circuitInput)
}

func TestE2E(t *testing.T) {
	localDir := "$HOME/circuitOut/myBrevisApp/input"
	numMaxDataPoints := 64
	app, err := sdk.NewBrevisApp(1, numMaxDataPoints, "RPC_URL", localDir)
	check(err)

	txHash := common.HexToHash(
		"0x6dc75e61220cc775aafa17796c20e49ac08030020fce710e3e546aa4e003454c")

	app.AddTransaction(sdk.TransactionData{
		Hash: txHash,
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

	outDir := "$HOME/circuitOut/age"
	srsDir := "$HOME/kzgsrs"
	// The compiled circuit, proving key, and verifying key are saved to outDir, and
	// the downloaded SRS in the process is saved to srsDir
	maxReceipt, maxStorage, _ := appCircuitAssignment.Allocate()

	compiledCircuit, pk, vk, vkHash, err := sdk.Compile(&AppCircuit{}, outDir, srsDir, maxReceipt, maxStorage, numMaxDataPoints)
	check(err)

	fmt.Println("compilation/setup complete")

	///////////////////////////////////////////////////////////////////////////////
	// Proving
	///////////////////////////////////////////////////////////////////////////////

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

	calldata, _, _, feeValue, err := app.PrepareRequest(vk, publicWitness, 1, 11155111, refundee, appContract, 400000, gwproto.QueryOption_ZK_MODE.Enum(), "", vkHash)
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
