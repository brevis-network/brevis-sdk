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
	q, err := sdk.NewQuerier("https://eth-mainnet.nodereal.io/v1/0af795b55d124a61b86836461ece1dee") // TODO use your eth rpc
	check(err)

	q.AddTransaction(sdk.TransactionQuery{
		TxHash: common.HexToHash("8b805e46758497c6b32d0bf3cad3b3b435afeb0adb649857f24e424f75b79e46"),
	})

	addr := common.HexToAddress("0x773fb4DB8218C8BB532c26ADBb6A8FD526c50f61")
	guest := &GuestCircuit{UserAddr: sdk.ParseAddress(addr)}
	guestAssignment := &GuestCircuit{UserAddr: sdk.ParseAddress(addr)}

	w, _, err := q.BuildWitness(context.Background(), guest)
	check(err)

	// checking commitment hash
	var packed []byte
	packed = append(packed, addr[:]...)
	packed = append(packed, common.LeftPadBytes(big.NewInt(int64(17077844)).Bytes(), 8)...)
	packed = append(packed, common.LeftPadBytes(big.NewInt(int64(0)).Bytes(), 8)...)
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
