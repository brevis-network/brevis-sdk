package sdk

import (
	"testing"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/test"
)

func TestHash2HashCircuitDigest(t *testing.T) {
	assert := test.NewAssert(t)
	digest, err := GetHash2HashCircuitDigest(32, 32, 64, NewBrevisAppWithDigestsSetOnlyFromRemote().BrevisHashInfo)
	assert.NoError(err)
	log.Infof("digest: %x", digest)
	log.Infof("digest: %s", digest)
}
