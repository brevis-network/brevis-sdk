package utils

import (
	"bytes"
	"github.com/celer-network/goutils/log"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

func GetRlpPathPrefixLength(nodeRlp string) (nodeType int, pathPrefixLength int) {
	input, err := hexutil.Decode(nodeRlp)

	if err != nil {
		log.Error("Failed to decode node rlp", nodeRlp, err.Error())
	}

	var decodeValue [][]byte
	err = rlp.Decode(bytes.NewReader(input), &decodeValue)

	if err != nil {
		log.Error("Failed to decode", err)
	}

	if len(decodeValue) == 17 {
		nodeType = 0
		pathPrefixLength = 0
		return
	} else if len(decodeValue) == 2 {
		nodeType = 1
		if decodeValue[0][0] == 0 {
			pathPrefixLength = 2
		} else {
			pathPrefixLength = 1
		}
		return
	}

	log.Error("Failed to decide node type", nodeRlp, decodeValue)

	nodeType = 0
	pathPrefixLength = 0
	return
}
