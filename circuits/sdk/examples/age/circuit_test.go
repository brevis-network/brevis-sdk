package age

import (
	"context"
	"github.com/celer-network/brevis-sdk/circuits/sdk/sdk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestCircuit(t *testing.T) {
	q, err := sdk.NewQuerier("") // TODO use your eth rpc
	check(err)

	blockNum := 18812391
	q.AddTransaction(sdk.TransactionQuery{
		TxHash: common.HexToHash("0ace75f32c286138f0ccf31c27089f521a60507d77c3ef4762bf9379fb008f55"),
	})

	addr := common.HexToAddress("0x3796Ca5ed43eb37C5C410765A5BfEfB49204cFB4")
	nonce := 10
	guest := &GuestCircuit{UserAddr: sdk.ParseAddress(addr), Nonce: nonce}
	guestAssignment := &GuestCircuit{UserAddr: sdk.ParseAddress(addr), Nonce: nonce}

	w, _, err := q.BuildWitness(context.Background(), guest)
	check(err)

	// checking commitment hash
	var packed []byte
	packed = append(packed, addr[:]...)
	packed = append(packed, common.LeftPadBytes(big.NewInt(int64(blockNum)).Bytes(), 8)...)
	packed = append(packed, common.LeftPadBytes(big.NewInt(int64(nonce)).Bytes(), 8)...)
	outputHash := crypto.Keccak256(packed)
	require.Equal(t, common.BytesToHash(outputHash), w.OutputCommitment.Hash())

	host := sdk.NewHostCircuit(w, guest)
	assignment := sdk.NewHostCircuit(w.Clone(), guestAssignment)

	assert := test.NewAssert(t)
	assert.ProverSucceeded(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

	assignment.Witness.OutputCommitment[0] = big.NewInt(0) // invalid witness
	assert.ProverFailed(host, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
