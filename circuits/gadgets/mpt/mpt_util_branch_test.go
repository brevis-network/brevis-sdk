package mpt

import (
	"strconv"
	"testing"

	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type MPTBranchCheckCircuit struct {
	KeyNibble      frontend.Variable
	NodeRefLength  frontend.Variable
	NodeRefs       [64]frontend.Variable
	NodeRLP        [1064]frontend.Variable
	Output         frontend.Variable
	RlpTotalLength frontend.Variable
}

func (c *MPTBranchCheckCircuit) Define(api frontend.API) error {
	leafCheck := NewMPTBranchCheck(64)
	result := leafCheck.CheckBranch(api, c.KeyNibble, c.NodeRefLength, c.NodeRefs[:], c.NodeRLP[:])
	api.AssertIsEqual(result.output, c.Output)
	api.AssertIsEqual(result.rlpTotalLength, c.RlpTotalLength)
	return nil
}

func Test_Storage_MPT_BRANCH_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	rlpHexString := "f90211a0c7273e80156fbab619b5aaf0db75247e09200d0216775befd6acb3fe6890b313a076e3a772db17877b07198d35c4950304aa8f05404dbc238baa3909250553a343a03f514a91f964128f66006334f89375f6454b7bebf285dc41e40be933f2ab8940a0836470c578c35ec5dfa847d0c4e3f3ac0242e3e80a371732561a715e2631d6bea0b3b59aae62cf99c9944cba79692dadfd968ddc89f8b258c1970cd2c41d2946f7a05c65dce7c3957ad2ed39b4114ff2fa9862e657d61be5c1e42750bdd756573d8fa0b07f76f45160eb4efcaad56c74222ed1cc552f88284ae67bb067caed0601152da0c514504d65f66b75461e15f9d7daff3bcb7f8603a57064507526ff957d9929d7a01f3dbb57b8d7e82205967d9f48cf4319995b9b36f7c5b147c5667acf94aa8d9ea0167b5ac5f7539ba28090015631aad247254c9810f0a0d3511b57c0e98586c10ba091bcaed8e663f6de8ddac3d1133853a633b1b81772c77deb0f75ea3e4797b7a8a03b8c64f1885e7824b81f50ed11be36e4ec71010b058a1b9c9205bd2ffcc6624fa0a05ceed91445b71f0e422546d95ef6d74b02bdc989eea010c4ea81316f8f5498a019315d4c08011517963064d036227878e4bc7fb6040f0e77c01ad3f0ee8c366da043a89110322186f9b7beee526b633c27d52e38b9dfa82f36cad624f8afb56b98a04c2d14b66813e9a580b3aaaa7b2b6612b912f3aa8255ca1641e5490712b3618880"
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

	nodeRefHexString := "3f514a91f964128f66006334f89375f6454b7bebf285dc41e40be933f2ab8940"
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

	witness := &MPTBranchCheckCircuit{
		KeyNibble:      2,
		NodeRefLength:  64,
		NodeRefs:       nodeRef,
		NodeRLP:        nodeRlp,
		Output:         4,
		RlpTotalLength: rlpHexLen,
	}

	err := test.IsSolved(&MPTBranchCheckCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Test_Account_MPT_BRANCH_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	rlpHexString := "f90211a0406e0bf09bd3457c926220d59e64bb17f0b418fae4b6b284fea6ce075418fd8ea0461a6c921ebb815af6cddcc9300d5ad7b1b9ee53ac4faf0befef0cf2108af8f9a0f263c22c9d19c7fb6a0a2c4d17b39dffc90bddc3b4bc9d93250d04365fd1ab67a03909f80af3c1ea2f04a0b7798e3dd9a98b047d65700048c89d20a17913e408f8a0d7d80424bba51b84612945f8694358776bc55f08c6555b893c7b564b83c64ea8a0c2e11ce682b3b0e6514d5b21ea7383d2f7932c196ae204283c74def594cdb3c3a0be70688b104365a36d70a6117701557c2ab8bb18addf31e07e0a533e8fbb362aa071a8d6d5974cbf118c930783ab9daaa25d1d98fb1d91f4be935f6781f132e4a9a0f364b1317fcd0c322eb9e2cf0f04bc252d95d32cb12fd9f2ca9c25bef7aa8c3aa08974454ddd9640774901e4b9a360cd620af2c91749fbc7dff49ca5a958dc7b75a02a9376bd5d7428c8626ab5a97c41569b53fcb115e909d5e58b03c8b2144a38a2a03d61ff8a74c9a31a39b28fa329e527fba9986c779cdb2577c73bbe7511819c34a098665890978208c5614ee4404f278f97246b4a5e52453512dae8da6fc66e6827a093910d6ff3511c4c2f45665ffa647f994597b4e886e32a5b882badd3ded533d7a013c2a41a4d056a2d90499934bc429ab36799bf3d453e6d2648d6f3ba18ca4a31a0e4d7a6f3b0d8078e49a9fd95f6f5bc0003fb4043dfeda52290bf2b7241be143680"
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

	nodeRefHexString := "f364b1317fcd0c322eb9e2cf0f04bc252d95d32cb12fd9f2ca9c25bef7aa8c3a"
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

	witness := &MPTBranchCheckCircuit{
		KeyNibble:      8,
		NodeRefLength:  64,
		NodeRefs:       nodeRef,
		NodeRLP:        nodeRlp,
		Output:         4,
		RlpTotalLength: rlpHexLen,
	}

	err := test.IsSolved(&MPTBranchCheckCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

const BranchNodeRound = 4
const BitsPerNibble = 4

type MPTPaddedBranchCheckCircuit struct {
	KeyNibble      frontend.Variable // the index in the branch nodes
	NodeRefLength  frontend.Variable
	NodeRefs       [64]frontend.Variable
	NodeRLP        [BranchNodeRound * 1088 / BitsPerNibble]frontend.Variable
	Output         frontend.Variable
	RlpTotalLength frontend.Variable
}

func (c *MPTPaddedBranchCheckCircuit) Define(api frontend.API) error {
	leafCheck := NewMPTBranchCheck(64)
	result := leafCheck.CheckBranch(api, c.KeyNibble, c.NodeRefLength, c.NodeRefs[:], c.NodeRLP[:])
	api.AssertIsEqual(result.output, c.Output)
	api.AssertIsEqual(result.rlpTotalLength, c.RlpTotalLength)
	return nil
}

func Test_STORAGE_MPT_PADDED_BRANCH_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	rlpHexString := "0xf90211a0406e0bf09bd3457c926220d59e64bb17f0b418fae4b6b284fea6ce075418fd8ea0461a6c921ebb815af6cddcc9300d5ad7b1b9ee53ac4faf0befef0cf2108af8f9a0f263c22c9d19c7fb6a0a2c4d17b39dffc90bddc3b4bc9d93250d04365fd1ab67a03909f80af3c1ea2f04a0b7798e3dd9a98b047d65700048c89d20a17913e408f8a0d7d80424bba51b84612945f8694358776bc55f08c6555b893c7b564b83c64ea8a0c2e11ce682b3b0e6514d5b21ea7383d2f7932c196ae204283c74def594cdb3c3a0be70688b104365a36d70a6117701557c2ab8bb18addf31e07e0a533e8fbb362aa071a8d6d5974cbf118c930783ab9daaa25d1d98fb1d91f4be935f6781f132e4a9a0f364b1317fcd0c322eb9e2cf0f04bc252d95d32cb12fd9f2ca9c25bef7aa8c3aa08974454ddd9640774901e4b9a360cd620af2c91749fbc7dff49ca5a958dc7b75a02a9376bd5d7428c8626ab5a97c41569b53fcb115e909d5e58b03c8b2144a38a2a03d61ff8a74c9a31a39b28fa329e527fba9986c779cdb2577c73bbe7511819c34a098665890978208c5614ee4404f278f97246b4a5e52453512dae8da6fc66e6827a093910d6ff3511c4c2f45665ffa647f994597b4e886e32a5b882badd3ded533d7a013c2a41a4d056a2d90499934bc429ab36799bf3d453e6d2648d6f3ba18ca4a31a0e4d7a6f3b0d8078e49a9fd95f6f5bc0003fb4043dfeda52290bf2b7241be143680"
	rlpHexLen := len(rlpHexString) - 2

	rlpHexBytes, _ := hexutil.Decode(rlpHexString)
	paddedRlphexHexBytes := keccak.Pad101Bytes(rlpHexBytes)

	var nodeRlp [BranchNodeRound * 1088 / BitsPerNibble]frontend.Variable

	for i, b := range paddedRlphexHexBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		nodeRlp[i*2] = n1
		nodeRlp[i*2+1] = n2
	}

	nodeRefHexString := "f364b1317fcd0c322eb9e2cf0f04bc252d95d32cb12fd9f2ca9c25bef7aa8c3a"
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

	witness := &MPTPaddedBranchCheckCircuit{
		KeyNibble:      8,
		NodeRefLength:  64,
		NodeRefs:       nodeRef,
		NodeRLP:        nodeRlp,
		Output:         4,
		RlpTotalLength: rlpHexLen,
	}

	err := test.IsSolved(&MPTPaddedBranchCheckCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Test_TRANSACTIONS_MPT_PADDED_BRANCH_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	rlpHexString := "0xf90131a093ce4f2441373b4033c87bd5a60e4cf50bb66ee9c0cd0463174c8b48d4f8021ba00f6457cc3175d8d28686ade17c46a977cb87a9be833b3127eb824be51f0c3872a052e18f40076d468b0ddb0a561ba8aa0f7303fdfbede920c4a9fcee67af088d58a0bfe5adeea0914e9e24037af8daa1ee890131819d77a40113e8f4c40898abbc78a0425e844c3ca2380fdd0c6b6902fa7d570d0efce6d00e4df7361058db2a84b023a0958c0c028b7a8fe0a3d5961620582cad1f557604937a104f77246246118a24c7a0f6fa22ff5962dfbe5ed810ec2ee72e3bebb708384b2869ae8fb0e6d168cbd387a02293143368314d71deeb53f975d8adcdbfd19b024c77886a566db2ec79f3d665a09e0afa2325a04bae0b2b30ce5d3d4de41919e0a88263a4c5b9815f95aa668bb38080808080808080"
	rlpHexLen := len(rlpHexString) - 2

	rlpHexBytes, _ := hexutil.Decode(rlpHexString)
	paddedRlphexHexBytes := keccak.Pad101Bytes(rlpHexBytes)

	var nodeRlp [BranchNodeRound * 1088 / BitsPerNibble]frontend.Variable

	for i, b := range paddedRlphexHexBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		nodeRlp[i*2] = n1
		nodeRlp[i*2+1] = n2
	}

	for i := len(paddedRlphexHexBytes) * 2; i < len(nodeRlp); i++ {
		nodeRlp[i] = 0
	}

	nodeRefHexString := "958c0c028b7a8fe0a3d5961620582cad1f557604937a104f77246246118a24c7"
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

	witness := &MPTPaddedBranchCheckCircuit{
		KeyNibble:      5,
		NodeRefLength:  64,
		NodeRefs:       nodeRef,
		NodeRLP:        nodeRlp,
		Output:         4,
		RlpTotalLength: rlpHexLen,
	}

	err := test.IsSolved(&MPTPaddedBranchCheckCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
