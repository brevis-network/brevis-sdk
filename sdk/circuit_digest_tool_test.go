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
	var res []uint64
	res = append(res, ReceiptCircuitDigestHash[:]...)
	res = append(res, StorageCircuitDigestHash[:]...)
	hash, err := pgoldilocks.HashNoPadU64Array(res)
	assert.NoError(err)
	log.Infof("hash: %x %x %x %x", hash[0], hash[1], hash[2], hash[3])
}
