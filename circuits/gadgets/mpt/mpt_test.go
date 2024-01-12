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

// api frontend.API,
// 	maxDepth int,
// 	keyLength int,
// 	maxValueLength int,
// 	key []frontend.Variable, // [keyLength]
// 	value []frontend.Variable, // [maxValueLength]
// 	rootHash [64]frontend.Variable, // Root hash should be 32-bytes long value. Divide it by 4-bits ===> 0xcf78 will be [c, f, 7, 8]
// 	keyFragmentStarts []frontend.Variable, // [maxDepth]
// 	leafRlp []frontend.Variable,
// 	leafRlpBlock [keccak.MAX_ROUNDS][17]frontend.Variable,
// 	{
//    "id": 1,
//    "jsonrpc": "2.0",
//    "result": {
//        "accountProof": [
//            "0xf90211a00d162a90cc98cd348dd63d06b703bbb14d7fd2c6c761db80e7a6f66ddff0f1b9a017b94248e1b4477264dcca94a60710a6a793a388c1dee4088fb1d152db83eb21a04405f640e8109ab75d26d15f8b1e772abc457c318fae8226fe79428a1a6972e2a0bf7b227b166ebb14c0eb43e59eb82db0be4e50f70b999ba0d6d36b35c43a918fa0114b6cdb703ce04ec4d9e9c26ad9d7c91a49284274d45c31f43555dff913478ca0d3d396f35acca50e5f72dd511fc6f21d85b208dc4a0e94e1e9126165f8cba5c3a002e8a71f52989e179be1e9963ba0a99ad02b09a12aeed9cf2ad979ac0cc8469ba0be2f6790b96041f153e8a79b0a724b2d52ed43b551231a15e422814aeeb4b80fa0cd83ed8b6fbcf3a8ca3f8ec1393207734f0571cc35f78897f2e872768692ddf9a05e3f811e1b811b406d0eb194ae9c6365c81573e137f843b04cb69deacd1a56f4a083b1860415d0307f5bc486cbaf2c13c249eb06858dc22078b0b72b2f02c221e4a0de882631ad649444bad096044278057872652b2f2be50ed31db6576303cef825a01da1698859da144149dddcb94e84dd5f9e06776485f50ad84b980b3b8f3bfdeca04c936402586c74b583ac14405b3f2d3cea9816c6a99e78675125d25bec079c27a067c056ae36112e03a9a82264baf46427d4c42038f7c21e8712ab99e9b95329e4a02afe072592f486c5d8f5d8d55d2a7c9dbff770d2a3b50ce66fcab74b056d241080",
//            "0xf90211a0d96b5906ad1dbd3dd7e7e1d324a170286a4f9943515f7fbafd2d562dd2c8ba61a0a4deca80713ee0ce54aaf3248cfd236089acb89ed608dc607b5a202f7b25f9aba04335291a2dd91617264bf9326fda011feca2ab251d15a69c814d7f032ee7eea8a0d5bc0cbb78a2e2d9e60bec9a1b9125d56c874a6c8ec7024b37b3089274da4171a01697fe04785ae52edf36b8a9e7a3c25d4048582b024a7bed70d67539a6842ed8a0101fdba44fefb2658319a3161a3c2574e228f4950d5020174222077d8b55169aa0902d35feff54a6f6747bf5a97f89b765d6e15e810a0c52b54dcc3111d8663a92a070815347cc92b12749fb004e127f1d50a67ded2457c7db07bb13a076fc5490fda0c7d1bb2daadd958e3606b5ad6190d0300738466e8c5cf4714149bc09662c239ca0a409aa06ed3d38dddb270a62e249564957269144de4532d3b1abef82f5318e08a0cae452fbb7126e950826461e6f388bd78e5475c36d8906e9de1fd298d32678b6a073b72f39241615aa03bb362f159d2ec22da4f4ba13381287ddc2da638a77a275a062e5e6bcf7933cb91381eff32b914ef778078dbdb17b0ca6fca63764e7655ad0a0fad250f14027cb4c3d5c2cc442343508c2514e0e956da627d33d2a2127241626a062cb56340dc7625f28b844f4659be23a4852b0db4b0127a8795675fe7a33e33ba066ef53d844fb059e573787a6059696491fa99bc9bc20116aac40ab5ba4bbdcdc80",
//            "0xf90211a0bd25481ed2cfcd98f252f8a28a2f4502ee8d30c825a3904fdff25dbd9ed9e914a015f308a1e93f448bcaa646c799e38d5c964308def9ad22aaf2244143e5da7126a06a74b0f7035c4210c4e7ac5f2f9054172d37694fd068f95981e96d1b2bf3e832a087075caf5ff5a0d1860d6147eded828e88ed88a2b2854fd49d78ae6b20afaacca0b77a0ba7ff052380b0d97be9fb1b3dd75d567fbbadda644f67f0e4b31a21320fa0d9af16d3a55850a4a46409138d5c9ad9480ca9e38e7601bc29cc80d8f9a952c0a0e6af61a74a3c9cf881f7e80a10b99d81ed05f4226c161bea04a6fa1a04566923a07e3dd67a4b2afe67791023d11606af66c208661d77414deec0cfef2962696e73a0c9333dc582a961201c7626c7f2de20b3ac6b77c015bdf7a3a836b34708deef4fa059045084b103eb0d96688c76aeb201d7dc4132e95c2f7e8cc0439bd679f825a3a061cca30c8ac80ec121c6e78fc92b6294e0d8fc57821eae5bd7c58396b405e122a06f3d374a16bd1c36120e2ffac5a41ab90b42f20c278b6600bca39b9252335bf7a0ec68bcf3c0651ad171da0b911dfe53cf10f4c4444af033477e60845153b1772aa037d618199c372208549c6597e9d197647aa401db2ad5b1e35501010c58bd5abba0f3c65cd901b1fbd81d628f60ad9c33188121224f9c68ab02f16ea199473875c1a0b206e5f7bff92f3c75e8bdfe016daf754418ef29b7690834f2ca70f82670264080",
//            "0xf90211a0f35ad525dad01aad2e1ab4aef40ec50590492989e98b933acadf72e3a9ff5015a0f38e11441966b59c7dc6866b8b81ed5309a02fd7e23c4c1d2da033270689b19fa06c92585500dd326622a6c30db378989e25081bc258bd591bf6941ff63e93f751a00a2c4ceab92c054fbca72e6729906056c3d61d311bd444c3715a41620e74c5a5a0dba167053899c77531ec7c99852ebeb41b36189c17899ebfee7169a9b89a97e1a012ce8f82f6385914ae10aff5d36acf1e3603dd5fcc7de28ee0f9a6edb1587ca9a0674736734837ef5fef2c5350b6f85a3c0b19cece508ee50f209c2d41f515a880a01c98c03084f8bb23f2faba82d83e3895bab71c4824acb20b948cb0ffd632840ca04e7677650505553c497a7b04dd6e19a14c7edf75bcfd5af033ea32c94b566883a044f1993aeba82965418ce634e9450e79d39adf2862a532e8a578e6fdb37e2d61a0fc4152d4fae1e80e67e1e0be2cc3b7478b05025f4b384d7014733ff9dec06930a00ccd6745ab5c1f7037761f29c8225d337307e7aed23a82cf66d9414a22aee7d2a07124bd941b3b46fb6cb3d9ca5df1eda1fc4521356021d202356ccb95a3b893e2a07ec4a93ffb3c8f61175cd115f9db73633780c72d21ef956c169724d3f40e9073a0149db05b0659ae129629caec9ccc072099784f2e03e989ca7060e3275ec49866a06370dfad44ec54900fcb82ea56806c3bbef38fd9eed98b0c3f0243744de6a16580",
//            "0xf90211a02f931a83cfd7c01090d5349a289946e383bc04189f8fffd7fb2537e4fb49bf6da0b7e7e9d17274ace70f0dfa5ac97c440aa913ca7f02c332a359260f90237ff9e6a0db0cbb9e675bb2ab9af3e5a625e630387517bf517122a489c9d57bebab6f481aa076eb22d926037e3bafe764d199b20032c3474cd9033de499a26264e54d2044d7a046d045724bf03e10c7bedbf6d5080c9332f66903241d3ea395f708ebf092c086a0ef5f72e5c0aab9d9533ef2cea97e216ba21565f703895856b47a8d7061a7ff1aa0ec935a943d2ccfc0eaac37ad4a79882679124b9c8c1d429180c5f8d1a30594fba06da4015699b1d8bba8a29461376c08efa8a19dcaadaa9dd5ad3f974b722e9451a0e95edebae3023bf7be16a184c79bcc5551cf1899c3b0dbdba9d2c3572a694558a05fe0bd5af5579fde1caa3e81d6d24951f58f40b9403da64a723f34f9568a8044a0e6bed9711e77402a2e0591988eb5c169f89cbf3b0b4bba1f345f52ac9fd3b67ba09885c623893200bb8534c295f914c5449aa9eb1985b7996ab635966528b7c35ba0ccdef844c5c22cc83f1609aff67e07fc90cf5888851490dc74e9b9aca6b6a179a058cce3f21bf394546c8b7d3a630e47c082ae69638d77c3ba6e2d289ab14ad108a07d921203a93b8eacb2c1571f92c76aa169f4ab86a9842f117e73bbd51999481fa08e45e542c1f1e6557898a58fc1b735abffd92b2080c3fbb9db48614039aedd1f80",
//            "0xf90211a0a74ba47be05de3d4c0d0679ddd65671b2edcd2c2fc8a515f339bf96dc819989aa0167265e8d4ec5cbe58c31d66dfaec040beac486a0b3579a005e9a8e5cda0bd9da069303cb60c8c73f674106c9be73affbeee4fd968bfc7caddbba563ef3058862ca0347f3ae704fda567ee2a8500a66372ae6d3382470134eb11b9e02a3b66765a72a038a97838107fca74c226e40d76edf24d6c50855e5ea4fad109064445ee94aaa4a039d0b988011d2fbbea3caa3e767966c15f91ad660c0b0ceda55c9a7d8bc0165ca0d783ecbac6f22ffedd1ffa283ebfd91c8eb60ccb0b20fff069453184b88175d8a04da248f768bf259c55d5799079d6f14fc794acc739a671290b76058308cca994a066414a464d72682b82c9b31911bd2309a3b158df7dfb9b2ab81bbe69c2f81ee8a0e638ebc66c36051be12e2325fca958c140b7d57a92e4a91023c030ff894d4963a0574cca7c490e18787d7f3d081126f5c125ee55f3bf521a3b7d0a90ef8addb881a06648ada18e10fb0da02706b298e7bdcfbf0c713785d9e313539e730deeaa5979a00ab7b1ffe501ce8f84d02da223c1b7b689dfe848bf3494e72dc1abed22e06ceba01a0c403f9cea4481a90f21e589351f8929c8f5b08689d61c4845b8374cff895ea01b632bfa881eb34abcff6d7f6d83d08544a71939fff97f7aa17777f49880baa5a018b6826147e993d47caca4ca7af0f67478065417eaa568ca0986a3f8324dfbf680",
//            "0xf8f1a02c430a208e87bb64c62bf2347c3cf69f99f89f40ccbb37386108a32aa068f0d1a0b8e5e1b7c10ff3182fa419a28d28c4ec4e8edb77d2db82b697e2b0a52b00fd5aa0f0af726f723ea2a0dd81bb6b29e79c02f94daddb607937979ac5b5046643ec9e80a0a27486ec63ede0a7d8c58e5e66a55b17fa3675945ce84089bc72f6c9b9831b8c8080a070f1e4ead66b21e79a2c4a4c464671643e13607df7cd1d897b5d5c3e80fad50ca005aba886461a095576daf2738dc71726586e146ad66b1d86099a1a09c20e025f80a06223814e0eb10e19bb1d1d071b3c2cd1d1710fea16c45861794e80b013c15b3a808080808080",
//            "0xf8669d3fc02dcfd124e531bad562224bed6fce91a548e85fcea1774414965548b846f8440180a0a5a2c8404ccfe404a8a35567b191fa00c3a7a100fae34ca096848f9aa4573cb7a08736329b580cfc0c0c39ee6700515e0bc51652afb614640db9e34a5d784933e8"
//        ],
//        "address": "0x1c479675ad559dc151f6ec7ed3fbf8cee79582b6",
//        "balance": "0x0",
//        "codeHash": "0x8736329b580cfc0c0c39ee6700515e0bc51652afb614640db9e34a5d784933e8",
//        "nonce": "0x1",
//        "storageHash": "0xa5a2c8404ccfe404a8a35567b191fa00c3a7a100fae34ca096848f9aa4573cb7",
//        "storageProof": [
//            {
//                "key": "0x0",
//                "proof": [
//                    "0xf90131a0fa6e054c2c439fc2abe9e9a6556f1a99e3f81427b6dea99812b7343baf99223480a092b4425f42e0cf07df86f597e542a3324fea636a70fae45994915086baf3a64980a0f51f7276e16f6da66ccadc65e5190b812a90280323543a4f2b9ef72632b7a6c7a06057100e219c5fd8ae9dc9375e427d3dbb1cc7657ff825d36d00fc76a50aa8f780a0eee55d8aefc2b366e06af516a7fcde1087fec31acc24dfb42147402d63418938a0cdab10f26dce19f49b7c4ecb8bf415f23965c2ec3093ce979250d76df0d1b98b80a0d848b7b6b7bb6a41401fb7b4ddba03a64f6d064c76b0c03ea079ceb040c358a3a0194a8948872eca3f966a9096a6b175d9b5e8b78ca3c60aab9e0a4bc696085cbf808080a0fc146039b6f93c07ac8e441975972d5fd55d60890a8aabe0dbc997e4dc405e3980",
//                    "0xe6a0390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56384830b8431"
//                ],
//                "value": "0xb8431"
//            }
//        ]
//    }
//} frontend.Variable,
// 	leafPathPrefixLength frontend.Variable,
// 	nodeRlp [][]frontend.Variable, // [maxDepth - 1][maxBranchRlpHexLen]
// 	nodeRlpBlock [keccak.MAX_ROUNDS][17]frontend.Variable,
// 	nodeRoundIndex frontend.Variable,
// 	nodePathPrefixLength []frontend.Variable, // [maxDepth - 1]
// 	nodeTypes []frontend.Variable, // [maxDepth - 1]
// 	depth frontend.Variable,

type MPTInclusionCircuit struct {
	Key                  []frontend.Variable
	Value                []frontend.Variable
	RootHash             [64]frontend.Variable
	KeyFragmentStarts    []frontend.Variable
	LeafRlp              [272]frontend.Variable
	LeafRlpRoundIndex    frontend.Variable
	LeafPathPrefixLength frontend.Variable
	NodeRlp              [MaxDepth - 1][272 * 4]frontend.Variable
	NodeRlpRoundIndexes  [MaxDepth - 1]frontend.Variable
	NodePathPrefixLength []frontend.Variable
	NodeTypes            []frontend.Variable
	Depth                frontend.Variable
	Output               frontend.Variable
	OutputValueLength    frontend.Variable
}

func (c *MPTInclusionCircuit) Define(api frontend.API) error {
	// leafCheck := NewMPTLeafCheck(len(c.KeyNibbles), len(c.Values))
	// result := leafCheck.CheckLeaf(api, c.KeyNibbleLen, c.KeyNibbles[:], c.Values[:], c.LeafRlp[:], c.LeafPathPrefixLength)
	// api.AssertIsEqual(result.result.output, c.Output)

	var nodeRlp [][]frontend.Variable
	for i := 0; i < len(c.NodeRlp); i++ {
		nodeRlp = append(nodeRlp, c.NodeRlp[i][:])
	}

	result := CheckMPTInclusionFixedKeyLength(
		api,
		MaxDepth,
		AccountKeyLength,
		MaxValueLengthForStorage,
		c.Key,
		c.Value,
		c.RootHash,
		c.KeyFragmentStarts,
		c.LeafRlp[:],
		c.LeafRlpRoundIndex,
		c.LeafPathPrefixLength,
		nodeRlp,
		c.NodeRlpRoundIndexes[:],
		c.NodePathPrefixLength,
		c.NodeTypes,
		c.Depth,
	)

	api.AssertIsEqual(result.Output, c.Output)
	api.AssertIsEqual(result.ValueLength, c.OutputValueLength)

	return nil
}

func Test_Storage_MPT_INCLUSION(t *testing.T) {
	assert := test.NewAssert(t)

	depth := 3

	keyRlpHexString := "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
	keyHexLen := len(keyRlpHexString)
	var keyRlpHex [AccountKeyLength]frontend.Variable
	for i := 0; i < AccountKeyLength; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
			keyRlpHex[i] = intValue
		} else {
			keyRlpHex[i] = 0
		}
	}

	valueRlpHexString := "94bc50cbd395314a43302e3bf56677755e5a543a8c"
	valueHexLen := len(valueRlpHexString)
	var valueRlpHex [MaxValueLengthForStorage]frontend.Variable
	for i := 0; i < MaxValueLengthForStorage; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueRlpHexString[i]), 16, 64)
			valueRlpHex[i] = intValue
		} else {
			valueRlpHex[i] = 0
		}
	}

	rootHashHexString := "1eb0e8ed889315b2a7f6e076d0939a6ed1fe4e3d9b0eeb366c47ec5e8a52fd3f"
	// rootHashHexLen := len(rootHashHexString)
	var rootHashHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(rootHashHexString[i]), 16, 64)
		rootHashHex[i] = intValue
	}

	var keyFragmentStarts [MaxDepth]frontend.Variable
	for i := 0; i < MaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > 2 {
			keyFragmentStarts[i] = 64
		}
	}

	leafRlpHexString := "0xf7a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594bc50cbd395314a43302e3bf56677755e5a543a8c"
	// pad leaf,And convert it to nibbles
	leafRlpBytes, _ := hexutil.Decode(leafRlpHexString)
	paddedLeafRlpBytes := keccak.Pad101Bytes(leafRlpBytes)

	var paddedLeafRlpHex [272]frontend.Variable
	for i, b := range paddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	var leafPathPrefixLength int // 20 0decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
	if (64-depth+1)%2 == 0 {
		leafPathPrefixLength = 2
	} else {
		leafPathPrefixLength = 1
	}

	nodeRlp0HexString := "0xf90211a0c7273e80156fbab619b5aaf0db75247e09200d0216775befd6acb3fe6890b313a076e3a772db17877b07198d35c4950304aa8f05404dbc238baa3909250553a343a03f514a91f964128f66006334f89375f6454b7bebf285dc41e40be933f2ab8940a0836470c578c35ec5dfa847d0c4e3f3ac0242e3e80a371732561a715e2631d6bea0b3b59aae62cf99c9944cba79692dadfd968ddc89f8b258c1970cd2c41d2946f7a05c65dce7c3957ad2ed39b4114ff2fa9862e657d61be5c1e42750bdd756573d8fa0b07f76f45160eb4efcaad56c74222ed1cc552f88284ae67bb067caed0601152da0c514504d65f66b75461e15f9d7daff3bcb7f8603a57064507526ff957d9929d7a01f3dbb57b8d7e82205967d9f48cf4319995b9b36f7c5b147c5667acf94aa8d9ea0167b5ac5f7539ba28090015631aad247254c9810f0a0d3511b57c0e98586c10ba091bcaed8e663f6de8ddac3d1133853a633b1b81772c77deb0f75ea3e4797b7a8a03b8c64f1885e7824b81f50ed11be36e4ec71010b058a1b9c9205bd2ffcc6624fa0a05ceed91445b71f0e422546d95ef6d74b02bdc989eea010c4ea81316f8f5498a019315d4c08011517963064d036227878e4bc7fb6040f0e77c01ad3f0ee8c366da043a89110322186f9b7beee526b633c27d52e38b9dfa82f36cad624f8afb56b98a04c2d14b66813e9a580b3aaaa7b2b6612b912f3aa8255ca1641e5490712b3618880"
	nodeRlp0Bytes, _ := hexutil.Decode(nodeRlp0HexString)
	paddedNodeRlp0Bytes := keccak.Pad101Bytes(nodeRlp0Bytes)
	var paddedNodeRlp0Hex [BranchNodeMaxBlockSize]frontend.Variable
	for i, b := range paddedNodeRlp0Bytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedNodeRlp0Hex[i*2] = n1
		paddedNodeRlp0Hex[i*2+1] = n2
	}

	nodeRlp1HexString := "0xf8d18080808080a0f7b56be8dd71e675bf18c14afe0936d94d8883b9bbfcaee55e261a0b1dae1ea580a0c81a7ed63fb141b3f0302002ec0d5dcedeab671835adc6bc4d7f17e030717dd980a0d0a95e510d498a8b510ea71f8842528f438fc7e43e996c27e87774a52bee2c1aa0ff1f3593598f45c98daa085532e5051fe09da692b75e03a881cf29b1411fa92480a09d65e3575d4d5b52401675206aac2a225ae72d9ef0044e521fd13af454925d9ea0fa5a015c91c948b3b811f3960cba4a588fad127ca6c1026f5ee5171273074cc4808080"

	nodeRlp1Bytes, _ := hexutil.Decode(nodeRlp1HexString)
	paddedNodeRlp1Bytes := keccak.Pad101Bytes(nodeRlp1Bytes)
	var paddedNodeRlp1Hex [BranchNodeMaxBlockSize]frontend.Variable
	for i, b := range paddedNodeRlp1Bytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedNodeRlp1Hex[i*2] = n1
		paddedNodeRlp1Hex[i*2+1] = n2
	}

	for i := len(paddedNodeRlp1Bytes) * 2; i < 272*4; i++ {
		paddedNodeRlp1Hex[i] = 0
	}

	var nodeRlp [MaxDepth - 1][BranchNodeMaxBlockSize]frontend.Variable
	var nodeRlpRoundIndexes [MaxDepth - 1]frontend.Variable
	nodeRlp[0] = paddedNodeRlp0Hex

	nodeRlpRoundIndexes[0] = keccak.GetKeccakRoundIndex(len(nodeRlp0HexString) - 2)
	nodeRlp[1] = paddedNodeRlp1Hex
	nodeRlpRoundIndexes[1] = keccak.GetKeccakRoundIndex(len(nodeRlp1HexString) - 2)

	for i := 2; i < MaxDepth-1; i++ {
		var empty [1088]frontend.Variable
		for j := 0; j < 1088; j++ {
			empty[j] = 0
		}
		nodeRlp[i] = empty
		nodeRlpRoundIndexes[i] = 0
	}

	var nodePathPrefixLength [MaxDepth - 1]frontend.Variable
	for i := 0; i < MaxDepth-1; i++ {
		nodePathPrefixLength[i] = 0
	}

	var nodeTypes [MaxDepth - 1]frontend.Variable
	for i := 0; i < MaxDepth-1; i++ {
		nodeTypes[i] = 0
	}

	output := 1

	witness := &MPTInclusionCircuit{
		Key:                  keyRlpHex[:],
		Value:                valueRlpHex[:],
		RootHash:             rootHashHex,
		KeyFragmentStarts:    keyFragmentStarts[:],
		LeafRlp:              paddedLeafRlpHex,
		LeafPathPrefixLength: leafPathPrefixLength,
		LeafRlpRoundIndex:    0,
		NodeRlp:              nodeRlp,
		NodePathPrefixLength: nodePathPrefixLength[:],
		NodeTypes:            nodeTypes[:],
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		Depth:                depth,
		Output:               output,
		OutputValueLength:    valueHexLen,
	}

	err := test.IsSolved(&MPTInclusionCircuit{
		Key:                  make([]frontend.Variable, AccountKeyLength), // [AccountKeyLength]frontend.Variable,
		Value:                make([]frontend.Variable, MaxValueLengthForStorage),
		KeyFragmentStarts:    make([]frontend.Variable, MaxDepth),
		NodePathPrefixLength: make([]frontend.Variable, MaxDepth-1),
		NodeTypes:            make([]frontend.Variable, MaxDepth-1),
	}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type AccountMPTInclusionCircuit struct {
	Key                  []frontend.Variable
	Value                []frontend.Variable
	RootHash             [64]frontend.Variable
	KeyFragmentStarts    []frontend.Variable
	LeafRlp              [272 * 2]frontend.Variable
	LeafRlpRoundIndex    frontend.Variable
	LeafPathPrefixLength frontend.Variable
	NodeRlp              [MaxDepth - 1][272 * 4]frontend.Variable
	NodeRlpRoundIndexes  [MaxDepth - 1]frontend.Variable
	NodePathPrefixLength []frontend.Variable
	NodeTypes            []frontend.Variable
	Depth                frontend.Variable
	Output               frontend.Variable
	OutputValueLength    frontend.Variable
}

func (c *AccountMPTInclusionCircuit) Define(api frontend.API) error {
	// leafCheck := NewMPTLeafCheck(len(c.KeyNibbles), len(c.Values))
	// result := leafCheck.CheckLeaf(api, c.KeyNibbleLen, c.KeyNibbles[:], c.Values[:], c.LeafRlp[:], c.LeafPathPrefixLength)
	// api.AssertIsEqual(result.result.output, c.Output)

	var nodeRlp [][]frontend.Variable
	for i := 0; i < len(c.NodeRlp); i++ {
		nodeRlp = append(nodeRlp, c.NodeRlp[i][:])
	}

	result := CheckMPTInclusionFixedKeyLength(
		api,
		MaxDepth,
		AccountKeyLength,
		MaxValueLengthForAccount,
		c.Key,
		c.Value,
		c.RootHash,
		c.KeyFragmentStarts,
		c.LeafRlp[:],
		c.LeafRlpRoundIndex,
		c.LeafPathPrefixLength,
		nodeRlp,
		c.NodeRlpRoundIndexes[:],
		c.NodePathPrefixLength,
		c.NodeTypes,
		c.Depth,
	)

	api.AssertIsEqual(result.Output, c.Output)
	api.AssertIsEqual(result.ValueLength, c.OutputValueLength)

	return nil
}

func Test_Account_MPT_INCLUSION(t *testing.T) {
	assert := test.NewAssert(t)

	depth := 9

	keyRlpHexString := "8d2a6e4b67bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bf"
	keyHexLen := len(keyRlpHexString)
	var keyRlpHex [AccountKeyLength]frontend.Variable
	for i := 0; i < AccountKeyLength; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
			keyRlpHex[i] = intValue
		} else {
			keyRlpHex[i] = 0
		}
	}

	valueRlpHexString := "f8440280a01eb0e8ed889315b2a7f6e076d0939a6ed1fe4e3d9b0eeb366c47ec5e8a52fd3fa0cc34a85a74e46f422c2b06b16156799b7c313a71390b4465cbc463bd99d76764"
	valueHexLen := len(valueRlpHexString)
	var valueRlpHex [MaxValueLengthForAccount]frontend.Variable
	for i := 0; i < MaxValueLengthForAccount; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueRlpHexString[i]), 16, 64)
			valueRlpHex[i] = intValue
		} else {
			valueRlpHex[i] = 0
		}
	}

	rootHashHexString := "f72182306fb66caffdf8100fc8ba2941c86bcbd63e4cfb2215a9bbff05bccf77"
	var rootHashHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(rootHashHexString[i]), 16, 64)
		rootHashHex[i] = intValue
	}

	var keyFragmentStarts [MaxDepth]frontend.Variable
	for i := 0; i < MaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > depth-1 {
			keyFragmentStarts[i] = 64
		}
	}

	leafRlpHexString := "0xf8669d2067bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bfb846f8440280a01eb0e8ed889315b2a7f6e076d0939a6ed1fe4e3d9b0eeb366c47ec5e8a52fd3fa0cc34a85a74e46f422c2b06b16156799b7c313a71390b4465cbc463bd99d76764"
	// pad leaf,And convert it to nibbles
	leafRlpBytes, _ := hexutil.Decode(leafRlpHexString)
	paddedLeafRlpBytes := keccak.Pad101Bytes(leafRlpBytes)

	var paddedLeafRlpHex [272 * 2]frontend.Variable
	for i, b := range paddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	for i := len(paddedLeafRlpBytes) * 2; i < 272*2; i++ {
		paddedLeafRlpHex[i] = 0
	}

	leafRlpRoundIndex := keccak.GetKeccakRoundIndex(len(leafRlpHexString) - 2)

	/// 64 - (depth - 1) ===> length of nibbles represented by branch/extension node
	/// depth = len(accountProof[])/len(storageProof[])
	var leafPathPrefixLength int // 20 67bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bf
	if (64-depth+1)%2 == 0 {
		leafPathPrefixLength = 2
	} else {
		leafPathPrefixLength = 1
	}

	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]
	nodeRlpHexStrings := []string{
		"0xf90211a0406e0bf09bd3457c926220d59e64bb17f0b418fae4b6b284fea6ce075418fd8ea0461a6c921ebb815af6cddcc9300d5ad7b1b9ee53ac4faf0befef0cf2108af8f9a0f263c22c9d19c7fb6a0a2c4d17b39dffc90bddc3b4bc9d93250d04365fd1ab67a03909f80af3c1ea2f04a0b7798e3dd9a98b047d65700048c89d20a17913e408f8a0d7d80424bba51b84612945f8694358776bc55f08c6555b893c7b564b83c64ea8a0c2e11ce682b3b0e6514d5b21ea7383d2f7932c196ae204283c74def594cdb3c3a0be70688b104365a36d70a6117701557c2ab8bb18addf31e07e0a533e8fbb362aa071a8d6d5974cbf118c930783ab9daaa25d1d98fb1d91f4be935f6781f132e4a9a0f364b1317fcd0c322eb9e2cf0f04bc252d95d32cb12fd9f2ca9c25bef7aa8c3aa08974454ddd9640774901e4b9a360cd620af2c91749fbc7dff49ca5a958dc7b75a02a9376bd5d7428c8626ab5a97c41569b53fcb115e909d5e58b03c8b2144a38a2a03d61ff8a74c9a31a39b28fa329e527fba9986c779cdb2577c73bbe7511819c34a098665890978208c5614ee4404f278f97246b4a5e52453512dae8da6fc66e6827a093910d6ff3511c4c2f45665ffa647f994597b4e886e32a5b882badd3ded533d7a013c2a41a4d056a2d90499934bc429ab36799bf3d453e6d2648d6f3ba18ca4a31a0e4d7a6f3b0d8078e49a9fd95f6f5bc0003fb4043dfeda52290bf2b7241be143680",
		"0xf90211a0bb4a7c71496885d65960cbd9a58e894db20c101c8d76b6c7e6dd67d91eb1bd79a0ff9e0c0377cc2bb3c9b045e86aa4fb05a0229cc8b0de9fc771390b8f22bb7fe3a02b4ee21a2503d789a661c7a83e90bcca4ee89b393aa28989030c26b46f44ab7da0d51d137f9c1773be45c4126e0dfdead8feb649999670349c7eeac64de27a065ca0008496b4ebbbaff4950b6a69456efab276f0e943fe0a2c64104e07f87d48cb17a09c1ae8bcb0bb13c08429bdda11ddf044d85902dd881a145d23aaa043244501ada0b3c9d0bdab3da2f23409cbe405ca72e7c5ef930726bde0597afaca840f882c1aa0d14f493f457a53906686f8f238c09e0ba0b0ad801d43cdbc09204337fa7d8815a01819c9f65968140d0c4400145cfdd55466009cbfb101735d9bec4ab3ff298812a020acbfc6442ca9dd306bc737c1c7a2a6d657d94e70c4f870afa1b892f3567074a0b3e5e9bbaaca9d8224cd35a226f3ca3f672a6628da3d1f535548f221d191b65aa0a71651deab79eae3ae854990dad7867d05692cf59638a49375d1e8876330b9c4a07d425f76898d80bb9dd1a5809cc6d860b370322e2858c9424c3816988b3d36baa02712ec3edd3c9b4ba5a2c3c54552948e44fae0176ff91093a7bea2287322e444a0d6d91e277fa890428a80e32cfa6534070cf624d452e573b7b090d29660433b7ea0fdf781ebd4e006bbf706acc76ba0b4797c0e166af57c7bd148c1910ec7bd002780",
		"0xf90211a0bf35ef2b1747663bbd99b4f024e536abc2c06c88844fc92ad8ca488a2bc98ca6a0b1a63f2a0b574991c25e23aabac7b18050350c5bb8911118d98fff10dcf08d78a001f2bbfd87bdb4f8c3ec2deb3cf997250c3a4a04c2da627d1fac8c38cac8642fa092fd1bb246a0836b56edc3ae3a2196941ea8f0e34d5163ee725353c4f732ebe0a0427ffbf84124b4dd5330bfacaa0e4dfa8ed603fc1704da85f877edec2eae6759a05da578180ab8a77d24b2c122048b0e63c26dc8d304342590eb6daf5c90c402a6a03d1a80e9381c868e2a68b7d139571430b432b3c13689ad8bb4881e192ac2de8da0f658cfda1291c656ea8875e99f615da82a67ed843ee3514ba4ce176fc8180283a069ae5d08910bb436e9e98fd377e4e92322756138fa1e5be74fe05f97022db23aa01590eecaf4fc4cce7d4f598c5aee837b0509d9479de89302b2ac5a2ec68b5509a0a39f6c3334eabf836fbca44956f2f92f11fdfce355c3f320dff8c0999137f1cfa0e53fe6b5e10de49951bffb04b27bb231168a7cb25e4e974eab51fc3d794935bba085832791c6484617851d4559e4ce85b36e1d76ab82eea4a7dbe86bba69a4b2f8a06c91d9bd58e52c54a1cfc4207671a599af1174563d71ec37045e84559b196d57a00ff514c28b443a23e04cb1fd455ea35deba6b73b36e059bf8d39902c12e38051a0c24260f4c3ddeef7d1dab75b1df229822221fe5f6f78321631032e19e0f051fc80",
		"0xf90211a0b86e955848e314c2676c4f76657856ee890620e733e3ecb75805f0bbefb88fcea08a4b8f6eda73d2ceee028640695faf84e8a4a83fee244657f3ca00489f9e8f44a04dc9d8729e99e90e19b6879e1916467e0b8e548710c36cc66f20df4dea100ca0a098dc59d1869e7e23915e89258645a4d7671606b0d0968712a05152a9e4750ddea04192a645bde6551be4ee1edd3e010623c8d39e3c809847e0f1848e7837cdff27a056903dbf4cf25878b17db6031c1455582393cb91044f8d3b0c57944037b2be30a0327802c81547edfd3c1fbd3f53e4ffd58881711f96251cd8517579ed1c49543aa04c76f42207ddc50b1bb256dccae24216e690014c1809121f7ef3faa3a42ae2e0a00d8bc046ccb4613aaeb5133597615f9a928b379d16929ffcd200f90433b74981a03dce146747bf8ecfa10bbd50a23b85cb4f775c69bc70c96f6be4c94334e8c04ba01d55f45fc0efa28785da1f5256a8654f4e87c91f9c2eea4bb1db17576de73924a07ad28eb9cbc828c4ce435fd196ca27bb290f343c9597efe728422342cd94709fa072e0f611ff71fd32f33f54cc13c536a347307feac35a26c51b01090555691a74a0561bccf70e06055f5cc48af996ae7ef5beef40ff950aa0ec50d0b90bab1d846fa056621a1346d700083b96c7af0780d1a4857759ebed32c43cfc15c037c464d7ada043790b0d0a0ec17e676b00f41521038bb8f706f2e913d85fc25925c0984d90b880",
		"0xf90211a001528bb59f2d89e238daddf866c27f27f29aaf84fdbecdb7f870526d343d83c1a08d0e8f1f7b28e9044e41862e5fa18aa410a3ff775c7895c45cd0eb1ae44d9e06a05fbfb568d0f8c232698569c835dfb63848c7e51d28e7a5dc396470f2778fb2efa084aa1cb3c9985af2aab7e5f8809b72ba90e596ce936309b30c799702f2267255a04fe7b20d0705b18e0cf7aecd56631eeba442b4b122b44f244698181632590035a02ba0f78ff7bc99ea415f98fb1a2ff9fe0c84ef0a49aefb455e24b4a1d3ab7a30a0737106e5264d248d51cde695e6a3f622eafa10f524f9cd12ebb75ee5e41520d3a0ed2c2f0d00c53e62bae05969e543d6aa42af3858231e45da4ce80ff1c297d25ca0153f203c405d75220d9d5061372607b5b8ad4753283f5e2e47e6c5bb474618e6a0fc759da45db9ab2e910f04cc13e4d556bf97d62d7f3f60fba4c3e9a24ffa00d9a07a2b6d77fcff0e1c9996d217b44867680f267a7aa867d4769bb3d43f5682a79ba020c48436738940da37047d95707c29ef8bc962aef8f6d29555bcb851ae5f7d3da027b22aab664516a5f3682da36abc058808865b2c0ed578e798d8c004d3a636cea0510e0d0637544112fa15c575caaae025bb7c80c064b7b8a6a64dabaca35f10bca0b6dc0e22de8398fdf52bac5db6fd857a43540912e5eb82cf90e4284535bdb3e9a0c763176691af1a2922c2238936fa6a39cf9cdd7666c55c82fc868d30ea73aff380",
		"0xf90211a06e5930cb8f539f2ef96106c29d30030fb310ec8f8edeb83d5fd8f08caf5a0d3da01fa663887877e0d6e0f0d8e9debe2e9174ddeab5c841b60f2a05e3186cd0a9fca0dfc0df65274d9cbf39834f4ea27e5f7a41a7bbedbbb92f5831d00ac4d3cd4b64a08d3e8dc1b7c2ad8fca1e3214c6c83571b6f3b476aeb82858e26cf11cdb6e8b02a0a6267791bb89eeec6441f1a09e6c8bfd600d590d2e77c07c14a5ce230d115310a00059bdb448ff05c289efad56d7bf565d21b9466afec808bd009bf01aa01b89aea0f899eb064de30dc6f13154c34825b6c613e219d00813a7f3c9b5888f43e9a3a7a02fa64d5fdb11b9c405305298d11883563228466b4e7154359e4c40d5a936cbe1a01abd563ff42b415d266330299e37575d8319fe7afcd10313658402dde269446ba046f679b90d046666e9ac1df74f65a7b461ee7d7a76e5b935fb54cc1c72a3230da03ea9f0a7484361992da5a05f32cd45720eef60400707e15735f06b6f6dddd812a000577ed4088fd13dba6c700e4ae19931dc512c0220784c0f8fd52097d6238878a00d4e7b6593a3af2ad8117fe49d9968e18b07ee5ed81ba1d21c4209473028ef7ca0be988fecfbc375f070ab28820ae86467a2c959ca759ac56494d2ecc304ca6d71a08a22572b0dab9a0715629df7cd7a19219a96debd5f4ce887087f3714faa6d240a01baee95a323a6ae44246072ae1226229c21355117c4721fe879552a97982cf0e80",
		"0xf90191a0c22efe4967760047a503780c2e80d215329d3fc4d3c22562c938eb6991d3b259a0cf5923019519a9adf08334f59b31ef1cab3f3b28c070a0b760338687e90cabfea0af61a174641b841c35c1eaa23e72817749a39fe1e58eb9097e592e266f6ffd25a07553261c4cfacae12d04d14dcb597a0f94d6b817eeb797fb78c9e1c76a26716ea05683bcb1b9b81418f5607856f92972327531143b944cd6ffec6a471d3fb1b2fba0f04f7ffd5b21c59cb563398b2d75522320a99807f22cdd62f9b5d2b86b387491a0fba61dc248f33faa6da6f1c856e339451e0f6e833f2e09434c3a4180b018229ba0a21faea6eddf94568efe7770430cbc01b56da0ede5e1a1d098e8c243c3546d82a027983cfaeb169218677cf2a6d8cf42ff924458178fb2d12093407aac6440de70a0989609d1a0a49e000c5cc293f973658fc37d5839ae2979d35a6c0e78d4470154a0c40bfdc33b2f7d200ce6b61370c2890fa0b202be3904130da68e63b6ab86089e808080a0f9e70d6e5a4f1d50008588c4e4d28985a83009f853edd2c29edc56576b4f11e48080",
		"0xf85180808080a0deaab39c886e0601409672763ab78663fbc0aa328689b2c553eb1515b4c4e460808080808080a00c7eab0286642501eb5d88954aa73ba3bd67a8b79137972c774f6212b4f697578080808080",
	}

	realDataLength := len(nodeRlpHexStrings)

	var nodeRlp [MaxDepth - 1][BranchNodeMaxBlockSize]frontend.Variable
	var nodeRlpRoundIndexes [MaxDepth - 1]frontend.Variable
	var nodePathPrefixLength [MaxDepth - 1]frontend.Variable
	var nodeTypes [MaxDepth - 1]frontend.Variable

	for i := 0; i < MaxDepth-1; i++ {
		if i < realDataLength {
			// Feed actual data
			rlpHexString := nodeRlpHexStrings[i]
			bytes, _ := hexutil.Decode(rlpHexString)
			paddedBytes := keccak.Pad101Bytes(bytes)
			var rlp [BranchNodeMaxBlockSize]frontend.Variable
			for i, b := range paddedBytes {
				n1 := b >> 4
				n2 := b & 0x0F
				rlp[i*2] = n1
				rlp[i*2+1] = n2
			}

			for j := len(paddedBytes) * 2; j < 272*4; j++ {
				rlp[j] = 0
			}

			nodeRlp[i] = rlp

			nodeRlpRoundIndexes[i] = keccak.GetKeccakRoundIndex(len(rlpHexString) - 2)
		} else {
			// Add placeholder data
			var empty [1088]frontend.Variable
			for j := 0; j < 1088; j++ {
				empty[j] = 0
			}
			nodeRlp[i] = empty
			nodeRlpRoundIndexes[i] = 0
		}

		// TODO: add support for extension node
		nodePathPrefixLength[i] = 0
		nodeTypes[i] = 0
	}

	output := 1

	witness := &AccountMPTInclusionCircuit{
		Key:                  keyRlpHex[:],
		Value:                valueRlpHex[:],
		RootHash:             rootHashHex,
		KeyFragmentStarts:    keyFragmentStarts[:],
		LeafRlp:              paddedLeafRlpHex,
		LeafPathPrefixLength: leafPathPrefixLength,
		LeafRlpRoundIndex:    leafRlpRoundIndex,
		NodeRlp:              nodeRlp,
		NodePathPrefixLength: nodePathPrefixLength[:],
		NodeTypes:            nodeTypes[:],
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		Depth:                depth,
		Output:               output,
		OutputValueLength:    valueHexLen,
	}

	err := test.IsSolved(&AccountMPTInclusionCircuit{
		Key:                  make([]frontend.Variable, AccountKeyLength), // [AccountKeyLength]frontend.Variable,
		Value:                make([]frontend.Variable, MaxValueLengthForAccount),
		KeyFragmentStarts:    make([]frontend.Variable, MaxDepth),
		NodePathPrefixLength: make([]frontend.Variable, MaxDepth-1),
		NodeTypes:            make([]frontend.Variable, MaxDepth-1),
	}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Test_Storage_MPT_with_Extension_INCLUSION(t *testing.T) {
	assert := test.NewAssert(t)

	depth := 7

	keyRlpHexString := "ed65b032d5a5fa3a5b6544566ee46a0f6b8fe8b1375ec878dc3be6580b078495"
	keyHexLen := len(keyRlpHexString)
	var keyRlpHex [AccountKeyLength]frontend.Variable
	for i := 0; i < AccountKeyLength; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
			keyRlpHex[i] = intValue
		} else {
			keyRlpHex[i] = 0
		}
	}

	valueRlpHexString := "94b88f61e6fbda83fbfffabe364112137480398018"
	valueHexLen := len(valueRlpHexString)
	var valueRlpHex [MaxValueLengthForAccount]frontend.Variable
	for i := 0; i < MaxValueLengthForAccount; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueRlpHexString[i]), 16, 64)
			valueRlpHex[i] = intValue
		} else {
			valueRlpHex[i] = 0
		}
	}

	rootHashHexString := "ae2792244417bc1749b9cd9a0bdc1c4a6cf32f147b37202c8cb3590777659aec"
	var rootHashHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(rootHashHexString[i]), 16, 64)
		rootHashHex[i] = intValue
	}

	var keyFragmentStarts [MaxDepth]frontend.Variable
	for i := 0; i < MaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > depth-1 {
			keyFragmentStarts[i] = 64
		}
	}

	leafRlpHexString := "0xf59e2032d5a5fa3a5b6544566ee46a0f6b8fe8b1375ec878dc3be6580b0784959594b88f61e6fbda83fbfffabe364112137480398018"
	// pad leaf,And convert it to nibbles
	leafRlpBytes, _ := hexutil.Decode(leafRlpHexString)
	paddedLeafRlpBytes := keccak.Pad101Bytes(leafRlpBytes)

	var paddedLeafRlpHex [272 * 2]frontend.Variable
	for i, b := range paddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	for i := len(paddedLeafRlpBytes) * 2; i < 272*2; i++ {
		paddedLeafRlpHex[i] = 0
	}

	leafRlpRoundIndex := keccak.GetKeccakRoundIndex(len(leafRlpHexString) - 2)

	/// 64 - (depth - 1) ===> length of nibbles represented by branch/extension node
	/// depth = len(accountProof[])/len(storageProof[])
	var leafPathPrefixLength int // 20 67bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bf
	if (64-depth+1)%2 == 0 {
		leafPathPrefixLength = 2
	} else {
		leafPathPrefixLength = 1
	}

	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]

	// dc65b032d5a5fa3a5b6544566ee46a0f6b8fe8b1375ec878dc3be6580b078495
	nodeRlpHexStrings := []string{
		"0xf90211a0d4685523e01e980b1b15d593ef92a29892200b5d17e90f73993b8e48e3ec9a95a003f511a02bb79c930a03fec8e45bc4e565c2f5c2b90f52cc80c767093709464fa0d41ebc458f8d7414b77b42f2eed10415b4fa909cee9307fb501cfe9c2fec279ea0b23482112d497f931e5666641e3c014aab48b3564305d13faafca89390af2d66a0a22495f1ac26ed51c08f0b205b4a22ed361631866f0223f2a7612d10f2da1aa8a0d23fc4baca54bf532faa572b55622e40f873652c2b009a6ab8e06f29938a2e59a0f1ad7ab771e65d865eb5d1ee1b77c9cb910948461295b5641106f9187f7038efa0a99aafc3ec45c268f5b1146ffae78242d15e52b06a54f3d5fe9a15bf509caa91a005c3571519c40841e1fcb6c952a5bf9b76ffd0d59f7dccfec5122f445e8624ada04626e7701acc68de8fd0445ee304972a14959da40f590f8fb20c654b9b1bea5ca0a68db0617f5b4c6cdb530ed14366c16cdba3fb9016703b744a24197223636fe5a0d9e294b08bf26233e15498659a650e2983d1c1059e7ef385c634656f0528f12ca03420511341a2c3fdc2070e74190e436d95c078a580bb932305fb2fbbe5ab5c9ca0a0fe187c8edcf62afb18bf29bea69b5488b26dcbe0f8204cd08b5662f052a00fa07dd0e8bb2f5b617b770995d61f4d99c567f18ad30fd3f9ad3082b88181f136a8a032c255b3531196dd5a31ebf1f404bbb6b90bb29653da9a832d2ccc9dcb21dd8b80",
		"0xf90211a066aac6f5a978c9e665e5b96d883eb80d0e1f011f8f80c9b1bd8cc88f391e53d1a09f1e43a0ba666e17f4e8110975f41c8be4420648f031550a4451d155ea4111aaa0ce2228dd7cb87eb5aed542d89fbbf9eee90c1ba5aaf19ee29dce7b619d041674a0890e6c2cf4624136625643b3154674c397e0b08effd788fc27fcb18926ba5cb0a0dc890ad9cf16560b060cd50a93d4244849feb05f1689018320ca9574601c8d6ea0f924f6d0a26d2a61bb234723e7e55291e2b1f4a3241a5510e76d04a0491b9449a03a840866532e46f6dd33260dfe292c5bff75039959739f797ab93cba556f354da01b9c0e99aa504904e8f7416d71fa0d4998e7a304b757b91e8810193833c80d6ca0f7900ec7f53f2c541b1a78f11287c8f289dd8c421273fd608418cc499ccf0404a0ada8e0a618ebfa284edbc4af8d391a587a987f3d4678c028b2efc8e8ac4c999ba066ddcfb5915268482b9ee3cf1eea53901c0c330990874e4209ac768f9d5dd853a0d0711e509cf79f2bd6f1b90e705d684f5c8e3f9cc0ff1e02d4f8081b90ab1248a071c7ee1b33f6728766477a69ad8bd9f7ca0c4458c2e83c026d642d22ee86df64a009bf0423dfe0066180db1691dad70751399fa5edca86806c7c8dfd1c4622a9b4a08eba45bf77f2eaf1f10a33161839a6d4f51ac0064e23a536eff7b3b43e4c7ea4a0260e99a040e70b7a27ee00868f70fb2993b53a233da888352858aa4a7f781a3680",
		"0xf90211a02f4ea6d48dfaf65990a0b2bbaf4896f2c52e53e97b87b4332c7c18f636b5dd13a028b1ec20afe5399857f2dc0a87ceabd2a48b89f4c5b490f9f9a8c5a7f97e8e5ca006adc06451c399170d1fc5f377890aafba61ccfbe6c53dffc8eaff55d9c4f3e1a04c1a4950b3ffe3afc91ec936e45e428b89d31e125fce160f003d629ac1a851bba074d3e762114776c8b7d8e931c2e1a85f8b0f07d2a13f58fcfdf7f7ecf09a5ddfa0fc73976a1116deee277d1e6b8b2b3a5f6d49e8b3919c7a4b139464263ec77bdea0d13c9b7c09da7b3ffb6efd23e1211c18a6cdf9838cbd3334eea36d44cc957c9aa08bc12fa996ba4ec4c0183a37ebef86539bca71eac2e2e13b8b5a3569c8505b0ba057dc2540a00930a63b5083c3c226aa83abbbb8ccff45e1d0815d081a162bfdfba000a42dee911b03cc329f00e6ec61a6b9977e866d6cb6c07a9231c5cbcdadd7f3a0b9be4ea998b0cc465e1089a94fc165c047dda678c18cf78896f632c2467f704da02e50c8f770a6e610f8b339d084bd2e5742314b9c5c412ffdcf053baed85c9ff0a015f78e31dc3a16f53d45671c02f16a8a3e3d4fa4d4ede524f0a4be786a81761fa089bccb4fc0828f1e3f81cd4f49c55786fe5af6b454ae380eee5c0c8af3c60a50a0661c68c9542fc76626f522b3eec3807d5616a90d212ae9cbf216017980e0f98fa0931ed5b398df16ad539db32202bc7e15f1029bfc71b2ccad33818e4894cda40980",
		"0xf8d1808080a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df80a01f50e7ee4b847bceba7fb3f01fdafe949327b8aec724ff106bcb40749031a0098080a02b44776d99642c66e34eaccf146329beea4c6e96b3b6ddc9c32d51b784c4954180a00f8f2c713a079d09bfa73a8cdd1bdd3e4ff0b51fb17994af6b52edd77efa894b80a0bebb7a7c17a816c67b7084abfe93c5ee283e69f4303a35b185b98fe97cff0eaaa000bc3930843cc34573210bdb92bfecc32db5bbd2a713cb497f1a8d1b936e6dcc808080",
		"0xe21ba089c052492200484eca92e22fb5818f7a40e4513f6bcf48c8e9c216cbd49cd453",
		"0xf851a0bdf8d474c3279b73b2a86db9496f68daa1f418dff55a25c1a76031be0e603cf78080808080808080a0935117feec98c461b9860cc69df695460bfef3fc08e33e47c07ad409b2e7cc6d80808080808080",
	}

	realDataLength := len(nodeRlpHexStrings)

	var nodeRlp [MaxDepth - 1][BranchNodeMaxBlockSize]frontend.Variable
	var nodeRlpRoundIndexes [MaxDepth - 1]frontend.Variable
	var nodePathPrefixLength [MaxDepth - 1]frontend.Variable
	var nodeTypes [MaxDepth - 1]frontend.Variable

	for i := 0; i < MaxDepth-1; i++ {
		if i < realDataLength {
			// Feed actual data
			rlpHexString := nodeRlpHexStrings[i]
			bytes, _ := hexutil.Decode(rlpHexString)
			paddedBytes := keccak.Pad101Bytes(bytes)
			var rlp [BranchNodeMaxBlockSize]frontend.Variable
			for i, b := range paddedBytes {
				n1 := b >> 4
				n2 := b & 0x0F
				rlp[i*2] = n1
				rlp[i*2+1] = n2
			}

			for j := len(paddedBytes) * 2; j < 272*4; j++ {
				rlp[j] = 0
			}

			nodeRlp[i] = rlp

			nodeRlpRoundIndexes[i] = keccak.GetKeccakRoundIndex(len(rlpHexString) - 2)
		} else {
			// Add placeholder data
			var empty [1088]frontend.Variable
			for j := 0; j < 1088; j++ {
				empty[j] = 0
			}
			nodeRlp[i] = empty
			nodeRlpRoundIndexes[i] = 0
		}

		// TODO: add support for extension node
		if i == 4 {
			nodePathPrefixLength[i] = 1
			nodeTypes[i] = 1
		} else {
			nodePathPrefixLength[i] = 0
			nodeTypes[i] = 0
		}
	}

	output := 1

	witness := &AccountMPTInclusionCircuit{
		Key:                  keyRlpHex[:],
		Value:                valueRlpHex[:],
		RootHash:             rootHashHex,
		KeyFragmentStarts:    keyFragmentStarts[:],
		LeafRlp:              paddedLeafRlpHex,
		LeafPathPrefixLength: leafPathPrefixLength,
		LeafRlpRoundIndex:    leafRlpRoundIndex,
		NodeRlp:              nodeRlp,
		NodePathPrefixLength: nodePathPrefixLength[:],
		NodeTypes:            nodeTypes[:],
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		Depth:                depth,
		Output:               output,
		OutputValueLength:    valueHexLen,
	}

	err := test.IsSolved(&AccountMPTInclusionCircuit{
		Key:                  make([]frontend.Variable, AccountKeyLength), // [AccountKeyLength]frontend.Variable,
		Value:                make([]frontend.Variable, MaxValueLengthForAccount),
		KeyFragmentStarts:    make([]frontend.Variable, MaxDepth),
		NodePathPrefixLength: make([]frontend.Variable, MaxDepth-1),
		NodeTypes:            make([]frontend.Variable, MaxDepth-1),
	}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
