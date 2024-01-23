package slot

import (
	"context"
	"fmt"
	"github.com/celer-network/brevis-sdk/test"
	"path/filepath"
	"testing"

	"github.com/celer-network/brevis-sdk/sdk"
	"github.com/ethereum/go-ethereum/common"
)

func TestCircuit(t *testing.T) {
	q, err := sdk.NewQuerier("https://eth-mainnet.nodereal.io/v1/0af795b55d124a61b86836461ece1dee") // TODO use your eth rpc
	check(err)

	account := common.HexToAddress("0x5427FEFA711Eff984124bFBB1AB6fbf5E3DA1820")
	blockNum := 18233760
	// By specifying the optional parameter index = 1, the querier will give the
	// result of this storage slot query a fixed spot in the CircuitInput. This allows us
	// to later directly access this "special" data in circuit.
	q.AddStorageSlot(sdk.StorageSlotQuery{
		BlockNum: blockNum,
		Address:  account,
		Slot:     common.BytesToHash(slot),
	}, 1)
	// More slots can be added to be batch proven, but in this example we use only
	// one to keep it simple
	// q.AddStorageSlot(...)
	// q.AddStorageSlot(...)
	// q.AddStorageSlot(...)

	guest := &GuestCircuit{}
	guestAssignment := &GuestCircuit{}

	in, err := q.BuildCircuitInput(context.Background(), guest)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	// Use the test package to check if the circuit can be solved using the given
	// assignment
	test.ProverSucceeded(t, guest, guestAssignment, in)

	///////////////////////////////////////////////////////////////////////////////
	// Compiling and Setup
	///////////////////////////////////////////////////////////////////////////////

	outDir := "$HOME/circuitOut/storage"

	// The compilation output is the description of the circuit's constraint system.
	// You should use sdk.WriteTo to serialize and save your circuit so that it can
	// be used in the proving step later.
	ccs, err := sdk.Compile(guest, in)
	check(err)
	err = sdk.WriteTo(ccs, filepath.Join(outDir, "ccs"))
	check(err)

	// Setup is a one-time effort per circuit. A cache dir can be provided to output
	// external dependencies. Once you have the verifying key you should also save
	// its hash in your contract so that when a proof via Brevis is submitted
	// on-chain you can verify that Brevis indeed used your verifying key to verify
	// your circuit computations
	pk, vk, err := sdk.Setup(ccs, "$HOME/kzgsrs")
	check(err)
	err = sdk.WriteTo(pk, filepath.Join(outDir, "pk"))
	check(err)
	err = sdk.WriteTo(vk, filepath.Join(outDir, "vk"))
	check(err)

	// Once you saved your ccs, pk, and vk files, you can read them back into memory
	// for use with the provided utils
	ccs, err = sdk.ReadCircuitFrom(filepath.Join(outDir, "ccs"))
	check(err)
	pk, err = sdk.ReadPkFrom(filepath.Join(outDir, "pk"))
	check(err)
	vk, err = sdk.ReadVkFrom(filepath.Join(outDir, "vk"))
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Proving
	///////////////////////////////////////////////////////////////////////////////

	fmt.Println(">> prove")
	witness, publicWitness, err := sdk.NewFullWitness(guestAssignment, in)
	check(err)

	proof, err := sdk.Prove(ccs, pk, witness)
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
