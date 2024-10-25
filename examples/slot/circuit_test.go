package slot

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
)

func TestCircuit(t *testing.T) {
	app, err := sdk.NewBrevisApp(1)
	check(err)

	account := common.HexToAddress("0x5427FEFA711Eff984124bFBB1AB6fbf5E3DA1820")
	// By specifying the optional parameter index = 1, the app will pin the stroage
	// data at a fixed spot in the DataInput. This allows us to later directly
	// access this "special" data in circuit.
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(18233760),
		Address:  account,
		Slot:     common.BytesToHash(slot),
		Value:    common.HexToHash("0xf380166f8490f24af32bf47d1aa217fba62b6575"),
	}, 1)
	// More slots can be added to be batch proven, but in this example we use only
	// one to keep it simple
	// app.AddStorage(...)
	// app.AddStorage(...)
	// app.AddStorage(...)

	appCircuit := &AppCircuit{}
	appCircuitAssignment := &AppCircuit{}

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

	account := common.HexToAddress("0x5427FEFA711Eff984124bFBB1AB6fbf5E3DA1820")
	// By specifying the optional parameter index = 1, the app will pin the stroage
	// data at a fixed spot in the DataInput. This allows us to later directly
	// access this "special" data in circuit.
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(18233760),
		Address:  account,
		Slot:     common.BytesToHash(slot),
		Value:    common.HexToHash("0xf380166f8490f24af32bf47d1aa217fba62b6575"),
	}, 1)
	// More slots can be added to be batch proven, but in this example we use only
	// one to keep it simple
	// app.AddStorage(...)
	// app.AddStorage(...)
	// app.AddStorage(...)

	appCircuit := &AppCircuit{}
	appCircuitAssignment := &AppCircuit{}

	in, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	// Use the test package to check if the circuit can be solved using the given
	// assignment
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, in)

	///////////////////////////////////////////////////////////////////////////////
	// Compiling and Setup
	///////////////////////////////////////////////////////////////////////////////

	// The compiled circuit, proving key, and verifying key are saved to outDir, and
	// the downloaded SRS in the process is saved to srsDir
	outDir := "$HOME/circuitOut/storage"
	srsDir := "$HOME/kzgsrs"
	compiledCircuit, pk, vk, _, err := sdk.Compile(appCircuit, outDir, srsDir)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Proving
	///////////////////////////////////////////////////////////////////////////////

	// Once you saved your ccs, pk, and vk files, you can read them back into memory
	// for use with the provided utils
	compiledCircuit, pk, vk, _, err = sdk.ReadSetupFrom(appCircuit, outDir)
	check(err)

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
