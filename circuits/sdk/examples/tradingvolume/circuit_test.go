package tradingvolume

import (
	"context"
	"fmt"
	"github.com/celer-network/brevis-sdk/circuits/sdk/sdk"
	"github.com/celer-network/brevis-sdk/circuits/sdk/sdk/srs"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// In this example, we want to analyze the `Swap` events emitted by Uniswap's
// UniversalRouter contract. Let's declare the fields we want to use:

func TestCircuit(t *testing.T) {
	q, err := sdk.NewQuerier("") // TODO use your eth rpc
	check(err)

	// Adding a receipt query into the querier
	// In this tx, the user sold USDC and took native ETH out
	q.AddReceipt(sdk.ReceiptQuery{
		TxHash: common.HexToHash("53b37ec7975d217295f4bdadf8043b261fc49dccc16da9b9fc8b9530845a5794"),
		SubQueries: [3]sdk.LogFieldQuery{
			{LogIndex: 3, IsTopic: false, FieldIndex: 0}, // field: USDCPool.Swap.amount0
			{LogIndex: 3, IsTopic: true, FieldIndex: 2},  // field: USDCPool.Swap.recipient (topic field)
			{LogIndex: 2, IsTopic: true, FieldIndex: 1},  // field: USDC.Transfer.from
		},
	})
	// More receipts can be added, but in this example we only add one to keep it simple
	// q.AddReceipt(...)
	// q.AddReceipt(...)

	// Initialize our GuestCircuit and prepare the circuit assignment
	guest := &GuestCircuit{
		UserAddr: sdk.ParseAddress(common.HexToAddress("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")),
	}
	guestAssignment := &GuestCircuit{
		UserAddr: sdk.ParseAddress(common.HexToAddress("0xaefB31e9EEee2822f4C1cBC13B70948b0B5C0b3c")),
	}

	// Execute the added queries and package the query results into circuit inputs (witness)
	w, output, err := q.BuildWitness(context.Background(), guest)
	check(err)

	// `output` is the abi encoded data that we added through api.OutputXXX() in the guest circuit.
	// We want to use this later to call Brevis gateway so that when brevis submits the proof on-chain,
	// we can directly get our output data in the contract callback.
	// The following two lines aren't necessary, but let's check and see how it's related to
	// `Witness.OutputCommitment`
	fmt.Printf("output added through api.OutputXXX: %x\n", output)
	hashed := common.BytesToHash(crypto.Keccak256(output))
	fmt.Printf("output commitment: %x\n", output)
	require.Equal(t, w.OutputCommitment.Hash(), hashed)

	// Construct the host circuit from our guest circuit and the packaged query results
	host := sdk.NewHostCircuit(w, guest)
	assignment := sdk.NewHostCircuit(w.Clone(), guestAssignment)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	// Use gnark's test package to check if the circuit can be solved using the
	// given assignment
	assert := test.NewAssert(t)
	assert.ProverSucceeded(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

	///////////////////////////////////////////////////////////////////////////////
	// Compiling and Proving
	///////////////////////////////////////////////////////////////////////////////
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, host)
	check(err)

	fmt.Println("new srs")
	r1cs := ccs.(*cs.SparseR1CS)
	srsDir := os.ExpandEnv("$HOME/kzgsrs")
	// SRS (structured reference string) is used in the KZG commitment scheme. You
	// must download the Brevis provided SRS in your setup. The SRS files can get
	// pretty big (gigabytes), the srs package allows you to specify a dir for
	// caching the downloaded files.
	canonical, lagrange, err := srs.NewSRS(r1cs, "https://kzg-srs.s3.us-west-2.amazonaws.com", srsDir)
	check(err)
	fmt.Println("constraints", r1cs.GetNbConstraints())

	fmt.Println("generate witness")
	witnessFull, err := frontend.NewWitness(assignment, ecc.BLS12_377.ScalarField())
	check(err)

	witnessPublic, err := witnessFull.Public()
	check(err)

	fmt.Println("setup")
	// Setup is a one-time effort per circuit. You should use pk/vk.WriteTo to
	// serialize and save the proving/verifying keys to disk for later use.
	pk, vk, err := plonk.Setup(ccs, canonical, lagrange)
	check(err)

	// Once you have the verifying key you should also save its hash in your contract
	// so that when a proof via Brevis is submitted on-chain you can verify that
	// Brevis indeed used your verifying key to verify your circuit computations
	vkHash, err := sdk.VkHash(vk)
	check(err)
	fmt.Printf("verifying key hash: %x\n", vkHash)

	fmt.Println("prove")
	// pk can also be read from disk using pk.ReadFrom
	proof, err := plonk.Prove(ccs, pk, witnessFull)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Verifying
	///////////////////////////////////////////////////////////////////////////////

	// The verification of the proof generated by you is done on Brevis' side. But
	// you can also verify your own proof to make sure everything works fine and
	// pk/vk are serialized/deserialized properly
	fmt.Println("verify")
	err = plonk.Verify(proof, vk, witnessPublic)
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
