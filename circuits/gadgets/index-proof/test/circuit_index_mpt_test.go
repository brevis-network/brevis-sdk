package test

import (
	"fmt"
	"github.com/celer-network/brevis-sdk/circuits/gadgets/index-proof/core"
	"github.com/celer-network/brevis-sdk/common/utils"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/rlp"
	"testing"
)

func Test_INDEX_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	for i := 0; i < 10000; i++ {
		var indexBuf []byte
		indexBuf = rlp.AppendUint64(indexBuf, uint64(i))
		input := utils.GetHexArray(fmt.Sprintf("%x", indexBuf), 6)
		if len(input) != 6 {
			log.Fatalf("invalid input, index: %d", i)
		}
		var witnessInput [6]frontend.Variable
		for x, y := range input {
			witnessInput[x] = y
		}
		witness := core.IndexCheckCircuit{
			Index:     i,
			RlpString: witnessInput,
		}
		err := test.IsSolved(&core.IndexCheckCircuit{}, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}
