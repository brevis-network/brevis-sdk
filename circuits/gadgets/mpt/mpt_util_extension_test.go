package mpt

import (
	"strconv"
	"testing"

	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// 0xe21ba089c052492200484eca92e22fb5818f7a40e4513f6bcf48c8e9c216cbd49cd453

type MPTExtensionCheckCircuit struct {
	KeyNibbleLength      frontend.Variable
	NodeRefLength        frontend.Variable
	NodePathPrefixLength frontend.Variable
	Output               frontend.Variable
	RlpTotalLength       frontend.Variable
	KeyNibbles           [64]frontend.Variable
	NodeRefs             [64]frontend.Variable
	NodeRLP              []frontend.Variable
}

func (c *MPTExtensionCheckCircuit) Define(api frontend.API) error {

	extCheck := NewMPTExtensionCheck(64, 64)
	result := extCheck.CheckExtension(api, c.KeyNibbleLength, c.KeyNibbles[:], c.NodeRefLength, c.NodeRefs[:], c.NodeRLP[:], c.NodePathPrefixLength)
	log.Info(result.output, result.rlpTotalLength, c.Output, c.RlpTotalLength, c.NodePathPrefixLength, c)
	api.AssertIsEqual(result.output, c.Output)
	api.AssertIsEqual(result.rlpTotalLength, c.RlpTotalLength)
	return nil
}

func Test_STORAGE_MPT_EXTENSION_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	rlpHexString := "e21ba089c052492200484eca92e22fb5818f7a40e4513f6bcf48c8e9c216cbd49cd453"
	rlpHexLen := len(rlpHexString)
	var nodeRlp [1064]frontend.Variable
	for i := 0; i < 1064; i++ {
		if i < rlpHexLen {
			intValue, _ := strconv.ParseInt(string(rlpHexString[i]), 16, 64)
			nodeRlp[i] = intValue
		} else {
			nodeRlp[i] = 0
		}
	}

	keyNibblesHexString := "b"
	keyNibblesLen := len(keyNibblesHexString)
	var keyNibbles [StorageLeafMaxKeyHexLen]frontend.Variable

	for i := 0; i < StorageLeafMaxKeyHexLen; i++ {
		if i < keyNibblesLen {
			intValue, _ := strconv.ParseInt(string(keyNibblesHexString[i]), 16, 64)
			keyNibbles[i] = intValue
		} else {
			keyNibbles[i] = 0
		}
	}

	nodeRefHexString := "89c052492200484eca92e22fb5818f7a40e4513f6bcf48c8e9c216cbd49cd453"
	nodeRefHexLen := len(nodeRefHexString)
	var nodeRef [64]frontend.Variable
	for i := 0; i < 64; i++ {
		if i < nodeRefHexLen {
			intValue, _ := strconv.ParseInt(string(nodeRefHexString[i]), 16, 64)
			nodeRef[i] = intValue
		} else {
			nodeRef[i] = 0
		}
	}

	witness := &MPTExtensionCheckCircuit{
		KeyNibbleLength:      keyNibblesLen,
		KeyNibbles:           keyNibbles,
		NodeRefLength:        64,
		NodeRefs:             nodeRef,
		NodeRLP:              nodeRlp[:],
		NodePathPrefixLength: 1,
		Output:               4,
		RlpTotalLength:       rlpHexLen,
	}

	err := test.IsSolved(&MPTExtensionCheckCircuit{NodeRLP: make([]frontend.Variable, 136)}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MPTPaddedExtensionCheckCircuit struct {
	KeyNibbleLength      frontend.Variable
	NodeRefLength        frontend.Variable
	NodePathPrefixLength frontend.Variable
	Output               frontend.Variable
	RlpTotalLength       frontend.Variable
	KeyNibbles           [64]frontend.Variable
	NodeRefs             [64]frontend.Variable
	NodeRLP              [272]frontend.Variable
}

func (c *MPTPaddedExtensionCheckCircuit) Define(api frontend.API) error {

	extCheck := NewMPTExtensionCheck(64, 64)
	result := extCheck.CheckExtension(api, c.KeyNibbleLength, c.KeyNibbles[:], c.NodeRefLength, c.NodeRefs[:], c.NodeRLP[:], c.NodePathPrefixLength)
	log.Info(result.output, result.rlpTotalLength, c.Output, c.RlpTotalLength, c.NodePathPrefixLength, c)
	api.AssertIsEqual(result.output, c.Output)
	api.AssertIsEqual(result.rlpTotalLength, c.RlpTotalLength)
	return nil
}

func Test_STORAGE_MPT_PADDED_EXTENSION_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	rlpHexString := "0xe21ba089c052492200484eca92e22fb5818f7a40e4513f6bcf48c8e9c216cbd49cd453"
	rlpHexLen := len(rlpHexString) - 2

	rlpHexByte, _ := hexutil.Decode(rlpHexString)
	paddedRlpHexBytes := keccak.Pad101Bytes(rlpHexByte)

	var nodeRlp [272]frontend.Variable
	for i, b := range paddedRlpHexBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		nodeRlp[i*2] = n1
		nodeRlp[i*2+1] = n2
	}

	keyNibblesHexString := "b"
	keyNibblesLen := len(keyNibblesHexString)
	var keyNibbles [StorageLeafMaxKeyHexLen]frontend.Variable

	for i := 0; i < StorageLeafMaxKeyHexLen; i++ {
		if i < keyNibblesLen {
			intValue, _ := strconv.ParseInt(string(keyNibblesHexString[i]), 16, 64)
			keyNibbles[i] = intValue
		} else {
			keyNibbles[i] = 0
		}
	}

	nodeRefHexString := "89c052492200484eca92e22fb5818f7a40e4513f6bcf48c8e9c216cbd49cd453"
	nodeRefHexLen := len(nodeRefHexString)
	var nodeRef [64]frontend.Variable
	for i := 0; i < 64; i++ {
		if i < nodeRefHexLen {
			intValue, _ := strconv.ParseInt(string(nodeRefHexString[i]), 16, 64)
			nodeRef[i] = intValue
		} else {
			nodeRef[i] = 0
		}
	}

	witness := &MPTPaddedExtensionCheckCircuit{
		KeyNibbleLength:      keyNibblesLen,
		KeyNibbles:           keyNibbles,
		NodeRefLength:        64,
		NodeRefs:             nodeRef,
		NodeRLP:              nodeRlp,
		NodePathPrefixLength: 1,
		Output:               4,
		RlpTotalLength:       rlpHexLen,
	}

	err := test.IsSolved(&MPTPaddedExtensionCheckCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Test_TRANSACTIONS_MPT_PADDED_EXTENSION_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	rlpHexString := "0xe218a0caae4562211293571e9d837d4b2f1ad36566f5540b20b518e315d581623845c7"
	rlpHexLen := len(rlpHexString) - 2

	rlpHexByte, _ := hexutil.Decode(rlpHexString)
	paddedRlpHexBytes := keccak.Pad101Bytes(rlpHexByte)

	var nodeRlp [272]frontend.Variable
	for i, b := range paddedRlpHexBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		nodeRlp[i*2] = n1
		nodeRlp[i*2+1] = n2
	}

	keyNibblesHexString := "8"
	keyNibblesLen := len(keyNibblesHexString)
	var keyNibbles [StorageLeafMaxKeyHexLen]frontend.Variable

	for i := 0; i < StorageLeafMaxKeyHexLen; i++ {
		if i < keyNibblesLen {
			intValue, _ := strconv.ParseInt(string(keyNibblesHexString[i]), 16, 64)
			keyNibbles[i] = intValue
		} else {
			keyNibbles[i] = 0
		}
	}

	nodeRefHexString := "caae4562211293571e9d837d4b2f1ad36566f5540b20b518e315d581623845c7"
	nodeRefHexLen := len(nodeRefHexString)
	var nodeRef [64]frontend.Variable
	for i := 0; i < 64; i++ {
		if i < nodeRefHexLen {
			intValue, _ := strconv.ParseInt(string(nodeRefHexString[i]), 16, 64)
			nodeRef[i] = intValue
		} else {
			nodeRef[i] = 0
		}
	}

	witness := &MPTPaddedExtensionCheckCircuit{
		KeyNibbleLength:      keyNibblesLen,
		KeyNibbles:           keyNibbles,
		NodeRefLength:        64,
		NodeRefs:             nodeRef,
		NodeRLP:              nodeRlp,
		NodePathPrefixLength: 1,
		Output:               4,
		RlpTotalLength:       rlpHexLen,
	}

	err := test.IsSolved(&MPTPaddedExtensionCheckCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
