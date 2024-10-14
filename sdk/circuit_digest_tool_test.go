package sdk

import (
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
