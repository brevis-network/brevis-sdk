package sdk

import (
	pgoldilocks "github.com/OpenAssetStandards/poseidon-goldilocks-go"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestHash2HashCircuitDigest(t *testing.T) {
	assert := test.NewAssert(t)
	digest, err := GetHash2HashCircuitDigest(32, 32, 64)
	assert.NoError(err)
	log.Infof("digest: %x", digest)
	log.Infof("digest: %s", digest)
}

func TestGlPoseidonOnDigest(t *testing.T) {
	assert := test.NewAssert(t)
	var left, right, middle1, middle2, middle3 []uint64
	left = append(left, ReceiptCircuitDigestHash[:]...)
	left = append(left, StorageCircuitDigestHash[:]...)
	hashLeft, err := pgoldilocks.HashNoPadU64Array(left)
	assert.NoError(err)
	log.Infof("hash digest of receipt + storage: %d %d %d %d", hashLeft[0], hashLeft[1], hashLeft[2], hashLeft[3])

	right = append(right, TxCircuitDigestHash[:]...)
	right = append(right, TxCircuitDigestHash[:]...)
	hashRight, err := pgoldilocks.HashNoPadU64Array(right)
	assert.NoError(err)
	log.Infof("hash digest of transaction + transaction : %d %d %d %d", hashRight[0], hashRight[1], hashRight[2], hashRight[3])

	middle1 = append(middle1, hashLeft[:]...)
	middle1 = append(middle1, hashRight[:]...)

	middle2 = append(middle2, P2AggRecursionLeafCircuitDigestHash[:]...)
	middle2 = append(middle2, P2AggRecursionLeafCircuitDigestHash[:]...)

	hashA, err := pgoldilocks.HashNoPadU64Array(middle1)
	assert.NoError(err)
	hashB, err := pgoldilocks.HashNoPadU64Array(middle2)
	assert.NoError(err)

	middle3 = append(middle3, hashA[:]...)
	middle3 = append(middle3, hashB[:]...)

	hashMiddle, err := pgoldilocks.HashNoPadU64Array(middle3)

	log.Infof("hash digest of combile : %d %d %d %d", hashMiddle[0], hashMiddle[1], hashMiddle[2], hashMiddle[3])

}

func TestPlonky2RootDigest(t *testing.T) {
	assert := test.NewAssert(t)
	digest, err := GetPlonky2CircuitDigestFromWrapBn128(32, 32, 64)
	assert.NoError(err)
	log.Infof("plonky2RootNode digest after wrapbn128: %d %d %d %d", digest[0], digest[1], digest[2], digest[3])
}
