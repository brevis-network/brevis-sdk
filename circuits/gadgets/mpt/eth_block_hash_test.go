package mpt

import (
	"testing"

	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type EthBlockHashCircuit struct {
	HeaderRlp          [EthBlockHeadMaxBlockHexSize]frontend.Variable
	BlockRlpFieldNum   frontend.Variable
	BlockRlpRoundIndex frontend.Variable
	BlockHeaderHash    [64]frontend.Variable
	BlockTime          [8]frontend.Variable
}

func (c *EthBlockHashCircuit) Define(api frontend.API) error {
	var result = CheckEthBlockHash(api, c.HeaderRlp, c.BlockRlpFieldNum, c.BlockRlpRoundIndex)
	api.AssertIsEqual(result.Output, 1)
	for i := 0; i < 64; i++ {
		api.AssertIsEqual(result.BlockHash[i], c.BlockHeaderHash[i])
	}

	for i := 0; i < 8; i++ {
		api.AssertIsEqual(result.BlockTime[i], c.BlockTime[i])
	}
	return nil
}
func Test_Eth_Block_Hash(t *testing.T) {
	assert := test.NewAssert(t)

	// f9022fa0b0ff4a0678831b194b50d4147cef9cd4e360e8ac4569a8ccdcfee81f40d82acda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794690b9a9e9aa1c9db991c7721a92d351db4fac990a054820fb8648ea7eacfcdd0668e1a8afbe933341e787d0a09636ac19e11d8ec18a0bffc95ed579c768622108e9d04f8b8f7ee2629d19b016c865848da6639be70dca094c810c747828c9bebcb56c31ec854d1753d37c07bc87081be01a0699117b444b9010075a7e50fff80a746fae996a9c340da630b29104bd3062a11063915f5d645451a1ec743408605052001193b9dd342bdd893890863ab6bbcec0a9c3b03796c6cf19c967f21e53aadaa7ba37b4c12d943648a100191da67594ad270642ccc3c6e23db801f2052478b232d193818e4cdac45a69868f6099c9e8d4276465981ec1c65d1ab2fd24566fa4634cd6c0987be138e7910f5ef0943caf8792d27e80e31b3049abd64ef1192e1c3245349e895b5ade8a77404c0e79bfa0a206eeb6e9a8a5a42f18e4242ba4524450c60b46aa5df3f34d1494b87aebf28944c7f3d069828fbe3b77cbf68488c908624499fefa4e02813a53c0a584dbf6e566fc999c3c1f1d68180840103f9e88401c9c38083f70ce7846437ce7f8c406275696c64657230783639a04f5e3a77c67e55193fc97590474c6a09fe530f231d02ba6ba6c79e00fdc23a568800000000000000008508b5987915a0c3c77de387b43bdb4e36871270f1255e0f1d6255b00b87476e8a1bcb15d53788
	blockRlpHex := "0xf9022fa0b0ff4a0678831b194b50d4147cef9cd4e360e8ac4569a8ccdcfee81f40d82acda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794690b9a9e9aa1c9db991c7721a92d351db4fac990a054820fb8648ea7eacfcdd0668e1a8afbe933341e787d0a09636ac19e11d8ec18a0bffc95ed579c768622108e9d04f8b8f7ee2629d19b016c865848da6639be70dca094c810c747828c9bebcb56c31ec854d1753d37c07bc87081be01a0699117b444b9010075a7e50fff80a746fae996a9c340da630b29104bd3062a11063915f5d645451a1ec743408605052001193b9dd342bdd893890863ab6bbcec0a9c3b03796c6cf19c967f21e53aadaa7ba37b4c12d943648a100191da67594ad270642ccc3c6e23db801f2052478b232d193818e4cdac45a69868f6099c9e8d4276465981ec1c65d1ab2fd24566fa4634cd6c0987be138e7910f5ef0943caf8792d27e80e31b3049abd64ef1192e1c3245349e895b5ade8a77404c0e79bfa0a206eeb6e9a8a5a42f18e4242ba4524450c60b46aa5df3f34d1494b87aebf28944c7f3d069828fbe3b77cbf68488c908624499fefa4e02813a53c0a584dbf6e566fc999c3c1f1d68180840103f9e88401c9c38083f70ce7846437ce7f8c406275696c64657230783639a04f5e3a77c67e55193fc97590474c6a09fe530f231d02ba6ba6c79e00fdc23a568800000000000000008508b5987915a0c3c77de387b43bdb4e36871270f1255e0f1d6255b00b87476e8a1bcb15d53788"

	// 0x67c5d26ae6ef00adcf970d9b1876f0eaec41f94d88b7a0299e9d6109cdd9bcd8
	rlpBytes, _ := hexutil.Decode(blockRlpHex)

	blockRlpRoundIndex := keccak.GetRoundIndex(len(rlpBytes) * 8)

	paddedRlpBytes := keccak.Pad101Bytes(rlpBytes)

	var nibbles [EthBlockHeadMaxBlockHexSize]frontend.Variable
	for i, b := range paddedRlpBytes {
		nibbles[i*2] = b >> 4
		nibbles[i*2+1] = b & 0x0F
	}

	var blockTimeHex = "0x6437ce7f"
	blockTimeBytes, err := hexutil.Decode(blockTimeHex)

	var blockTimeNibbles [8]frontend.Variable
	for i, b := range blockTimeBytes {
		n1 := b >> 4
		n2 := b & 0x0F
		blockTimeNibbles[i*2] = n1
		blockTimeNibbles[i*2+1] = n2
	}
	hashRoot := "0x67c5d26ae6ef00adcf970d9b1876f0eaec41f94d88b7a0299e9d6109cdd9bcd8"
	hashRootBytes, _ := hexutil.Decode(hashRoot)

	hashRootNibble := getNibbleFromBytes(hashRootBytes)

	witness := &EthBlockHashCircuit{
		HeaderRlp:          nibbles,
		BlockRlpRoundIndex: blockRlpRoundIndex,
		BlockRlpFieldNum:   17,
		BlockHeaderHash:    hashRootNibble,
		BlockTime:          blockTimeNibbles,
	}

	err = test.IsSolved(&EthBlockHashCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func getNibbleFromBytes(data []byte) [64]frontend.Variable {
	var nibbles [64]frontend.Variable
	for i, b := range data {
		nibbles[i*2] = b >> 4
		nibbles[i*2+1] = b & 0x0F
	}
	return nibbles
}
