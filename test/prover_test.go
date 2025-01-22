package test

import (
	"encoding/json"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/brevis-network/brevis-sdk/sdk/prover"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
	"io"
	"os"
	"testing"
)

func TestProveReqDecode(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)

	jsonFile, err := os.Open("./0x92ddc7163dea227a64d5a9b84137e96255eadbefaeac434eb878717ef8eee6bb")
	assert.NoError(err)
	data, err := io.ReadAll(jsonFile)
	assert.NoError(err)
	var info *prover.ProveRequest
	err = json.Unmarshal(data, &info)
	assert.NoError(err)

	var req sdkproto.ProveRequest
	err = proto.Unmarshal(info.Request, &req)
	assert.NoError(err)
}
