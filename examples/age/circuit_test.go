package age

import (
	"context"
	"github.com/celer-network/brevis-sdk/sdk"
	"github.com/celer-network/brevis-sdk/test"
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

	w, _, err := q.BuildCircuitInput(context.Background(), guest)
	check(err)

	// checking commitment hash
	var packed []byte
	packed = append(packed, addr[:]...)
	packed = append(packed, common.LeftPadBytes(big.NewInt(int64(17077844)).Bytes(), 8)...)
	packed = append(packed, common.LeftPadBytes(big.NewInt(int64(0)).Bytes(), 8)...)
	outputHash := crypto.Keccak256(packed)
	require.Equal(t, common.BytesToHash(outputHash), w.OutputCommitment.Hash())

	test.ProverSucceeded(t, guest, guestAssignment, w)
	test.ProverFailed(t, guest, guestAssignment, w)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
