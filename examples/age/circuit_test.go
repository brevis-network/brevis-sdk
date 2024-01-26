package age

import (
	"context"
	"fmt"
	"github.com/celer-network/brevis-sdk/sdk"
	"github.com/celer-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
	"path/filepath"
	"testing"
)

func TestCircuit(t *testing.T) {
	q, err := sdk.NewQuerier("https://eth-mainnet.nodereal.io/v1/0af795b55d124a61b86836461ece1dee") // TODO use your eth rpc
	check(err)

	txHash := common.HexToHash(
		"8b805e46758497c6b32d0bf3cad3b3b435afeb0adb649857f24e424f75b79e46")

	q.AddTransaction(sdk.TransactionQuery{TxHash: txHash})

	guest := &GuestCircuit{}
	guestAssignment := &GuestCircuit{}

	circuitInput, err := q.BuildCircuitInput(context.Background(), guest)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	test.IsSolved(t, guest, guestAssignment, circuitInput)

	///////////////////////////////////////////////////////////////////////////////
	// Compiling and Setup
	///////////////////////////////////////////////////////////////////////////////

	outDir := "$HOME/circuitOut/age"
	srsDir := "$HOME/kzgsrs"

	// The compilation output is the description of the circuit's constraint system.
	// You should use sdk.WriteTo to serialize and save your circuit so that it can
	// be used in the proving step later.
	ccs, err := sdk.Compile(guest, circuitInput)
	check(err)
	err = sdk.WriteTo(ccs, filepath.Join(outDir, "ccs"))
	check(err)

	// Setup is a one-time effort per circuit. A cache dir can be provided to output
	// external dependencies. Once you have the verifying key you should also save
	// its hash in your contract so that when a proof via Brevis is submitted
	// on-chain you can verify that Brevis indeed used your verifying key to verify
	// your circuit computations
	pk, vk, err := sdk.Setup(ccs, srsDir)
	check(err)
	err = sdk.WriteTo(pk, filepath.Join(outDir, "pk"))
	check(err)
	err = sdk.WriteTo(vk, filepath.Join(outDir, "vk"))
	check(err)

	fmt.Println("compilation/setup complete")

	///////////////////////////////////////////////////////////////////////////////
	// Proving and Verifying
	///////////////////////////////////////////////////////////////////////////////

	//witness, publicWitness, err := sdk.NewFullWitness(guestAssignment, circuitInput)
	//check(err)
	//proof, err := sdk.Prove(ccs, pk, witness)
	//check(err)
	//err = sdk.WriteTo(proof, filepath.Join(outDir, "proof-"+txHash.Hex()))
	//check(err)
	//
	//// Test verifying the proof we just generated
	//err = sdk.Verify(vk, publicWitness, proof)
	//check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Initiating Brevis Request
	///////////////////////////////////////////////////////////////////////////////

	fmt.Println(">> Initiate Brevis Request")
	appContract := common.HexToAddress("0x403278A746A72Dc5E88c5D63E24B6B6dC9d94Fe8")
	refundee := common.HexToAddress("0x164Ef8f77e1C88Fb2C724D3755488bE4a3ba4342")

	calldata, feeValue, err := q.BuildSendRequestCalldata(vk, 1, 11155111, refundee, appContract)
	check(err)
	fmt.Printf("calldata %x\n", calldata)
	fmt.Printf("feeValue %d\n", feeValue)

	///////////////////////////////////////////////////////////////////////////////
	// Submit Proof to Brevis
	///////////////////////////////////////////////////////////////////////////////

	fmt.Println(">> Submit Prove to Brevis")

}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
