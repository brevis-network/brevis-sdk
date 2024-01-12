package mpt

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

type MPTLeafCheckCircuit struct {
	KeyNibbleLen         frontend.Variable
	KeyNibbles           []frontend.Variable
	Values               []frontend.Variable
	LeafRlp              []frontend.Variable
	LeafPathPrefixLength frontend.Variable
	Output               frontend.Variable
}

func (c *MPTLeafCheckCircuit) Define(api frontend.API) error {
	leafCheck := NewMPTLeafCheck(len(c.KeyNibbles), len(c.Values))
	result := leafCheck.CheckLeaf(api, c.KeyNibbleLen, c.KeyNibbles[:], c.Values[:], c.LeafRlp[:], c.LeafPathPrefixLength)
	api.AssertIsEqual(result.result.output, c.Output)
	return nil
}

const TransactionMaxKeyHexLen = 6

const StorageLeafMaxHexLen = 140
const StorageLeafArrayPrefixMaxHexLen = 2
const StorageLeafMaxKeyHexLen = 64
const StorageLeafMaxValueHexLen = 66

const AccountLeafMaxHexLen = 302
const AccountLeafArrayPrefixMaxHexLen = 2
const AccountLeafMaxKeyHexLen = 64
const AccountLeafMaxValueHexLen = 228

const TransactionLeafMaxHexLen = 8000
const TransactionLeafMaxKeyHexLen = 64
const TransactionLeafMaxValueHexLen = 7800

func Test_STORAGE_MPT_LEAF_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	leafHexString := "f7a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594bc50cbd395314a43302e3bf56677755e5a543a8c"
	leafHexLen := len(leafHexString)

	var storageLeafRlpHex [StorageLeafMaxHexLen]frontend.Variable
	for i := 0; i < StorageLeafMaxHexLen; i++ {
		if i < leafHexLen {
			intValue, _ := strconv.ParseInt(string(leafHexString[i]), 16, 64)
			storageLeafRlpHex[i] = intValue
		} else {
			storageLeafRlpHex[i] = 0
		}
	}

	keyNibblesHexString := "0decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
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

	valueHexString := "94bc50cbd395314a43302e3bf56677755e5a543a8c"
	valueHexLen := len(valueHexString)
	var values [StorageLeafMaxValueHexLen]frontend.Variable
	for i := 0; i < StorageLeafMaxValueHexLen; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueHexString[i]), 16, 64)
			values[i] = intValue
		} else {
			values[i] = 0
		}
	}

	/// Account proof leaf check
	witness := &MPTLeafCheckCircuit{
		KeyNibbleLen:         keyNibblesLen,
		KeyNibbles:           keyNibbles[:],
		Values:               values[:],
		LeafRlp:              storageLeafRlpHex[:],
		LeafPathPrefixLength: StorageLeafArrayPrefixMaxHexLen,
		Output:               4,
	}

	err := test.IsSolved(&MPTLeafCheckCircuit{
		KeyNibbles: make([]frontend.Variable, StorageLeafMaxKeyHexLen),
		Values:     make([]frontend.Variable, StorageLeafMaxValueHexLen),
		LeafRlp:    make([]frontend.Variable, StorageLeafMaxHexLen)}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Test_STORAGE_MPT_PADDED_LEAF_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	leafHexString := "f7a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594bc50cbd395314a43302e3bf56677755e5a543a8c"

	leafBytes, _ := hexutil.Decode(leafHexString)
	paddedLeafBytes := keccak.Pad101Bytes(leafBytes)

	// leaf keccak round is 1, so padding size is 1*272 = 272
	var storageLeafRlpHex [272]frontend.Variable
	for i, b := range paddedLeafBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		storageLeafRlpHex[i*2] = n1
		storageLeafRlpHex[i*2+1] = n2
	}

	keyNibblesHexString := "0decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
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

	valueHexString := "94bc50cbd395314a43302e3bf56677755e5a543a8c"
	valueHexLen := len(valueHexString)
	var values [StorageLeafMaxValueHexLen]frontend.Variable
	for i := 0; i < StorageLeafMaxValueHexLen; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueHexString[i]), 16, 64)
			values[i] = intValue
		} else {
			values[i] = 0
		}
	}

	/// Account proof leaf check
	witness := &MPTLeafCheckCircuit{
		KeyNibbleLen:         keyNibblesLen,
		KeyNibbles:           keyNibbles[:],
		Values:               values[:],
		LeafRlp:              storageLeafRlpHex[:],
		LeafPathPrefixLength: StorageLeafArrayPrefixMaxHexLen,
		Output:               4,
	}

	err := test.IsSolved(&MPTLeafCheckCircuit{
		KeyNibbles: make([]frontend.Variable, StorageLeafMaxKeyHexLen),
		Values:     make([]frontend.Variable, StorageLeafMaxValueHexLen),
		LeafRlp:    make([]frontend.Variable, StorageLeafMaxHexLen)}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Test_ACCOUNT_MPT_LEAF_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	leafHexString := "f8669d3fc02dcfd124e531bad562224bed6fce91a548e85fcea1774414965548b846f8440180a0a5a2c8404ccfe404a8a35567b191fa00c3a7a100fae34ca096848f9aa4573cb7a08736329b580cfc0c0c39ee6700515e0bc51652afb614640db9e34a5d784933e8"
	leafHexLen := len(leafHexString)
	var leafRlpHex [AccountLeafMaxHexLen]frontend.Variable
	for i := 0; i < AccountLeafMaxHexLen; i++ {
		if i < leafHexLen {
			intValue, _ := strconv.ParseInt(string(leafHexString[i]), 16, 64)
			leafRlpHex[i] = intValue
		} else {
			leafRlpHex[i] = 0
		}
	}

	keyNibblesHexString := "fc02dcfd124e531bad562224bed6fce91a548e85fcea1774414965548"
	keyNibblesLen := len(keyNibblesHexString)
	var keyNibbles [AccountLeafMaxKeyHexLen]frontend.Variable

	for i := 0; i < AccountLeafMaxKeyHexLen; i++ {
		if i < keyNibblesLen {
			intValue, _ := strconv.ParseInt(string(keyNibblesHexString[i]), 16, 64)
			keyNibbles[i] = intValue
		} else {
			keyNibbles[i] = 0
		}
	}

	valueHexString := "f8440180a0a5a2c8404ccfe404a8a35567b191fa00c3a7a100fae34ca096848f9aa4573cb7a08736329b580cfc0c0c39ee6700515e0bc51652afb614640db9e34a5d784933e8"
	valueHexLen := len(valueHexString)
	var values [AccountLeafMaxValueHexLen]frontend.Variable
	for i := 0; i < AccountLeafMaxValueHexLen; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueHexString[i]), 16, 64)
			values[i] = intValue
		} else {
			values[i] = 0
		}
	}

	/// Account proof leaf check
	witness := &MPTLeafCheckCircuit{
		KeyNibbleLen:         keyNibblesLen,
		KeyNibbles:           keyNibbles[:],
		Values:               values[:],
		LeafRlp:              leafRlpHex[:],
		LeafPathPrefixLength: 1,
		Output:               4,
	}

	err := test.IsSolved(&MPTLeafCheckCircuit{
		KeyNibbles: make([]frontend.Variable, AccountLeafMaxKeyHexLen),
		Values:     make([]frontend.Variable, AccountLeafMaxValueHexLen),
		LeafRlp:    make([]frontend.Variable, AccountLeafMaxHexLen)}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Test_TRANSACTIONS_MPT_LEAF_CHECK(t *testing.T) {
	assert := test.NewAssert(t)

	ec, err := ethclient.Dial("https://ethereum.blockpi.network/v1/rpc/public")
	if err != nil {
		log.Fatal(err)
	}

	//bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17066168))
	//bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17086605)) // 137 transactions, with ext nodes
	//bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17214728)) // test1
	//bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17214727)) // test2
	//bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17214833)) // test3
	bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17228345)) // Failed with 3000. Increase TransactionLeafMaxHexLen to avoid failure
	for index := 5; index <= 5; index++ {
		if err != nil {
			log.Fatal(err)
		}

		nodes, indexBuff, _, err := GetTransactionProof(bk, index)
		//nodes, indexBuff, err := proof.GetTransactionProof(bk, 180)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("indexBuff:", indexBuff)
		leafHexString := fmt.Sprintf("%x", nodes[len(nodes)-1])

		keyRlpHexString := hex.EncodeToString(indexBuff)

		keyHexLen := len(keyRlpHexString)
		var keyRlpHex [TransactionMaxKeyHexLen]frontend.Variable
		for i := 0; i < TransactionMaxKeyHexLen; i++ {
			if i < keyHexLen {
				intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
				keyRlpHex[i] = intValue
			} else {
				keyRlpHex[i] = 0
			}
		}

		//leafHexString := "f901db20b901d702f901d30181b48405f5e100850faf9e23de830962b494c36442b4a4522e871399cd717abdd847ab11fe8880b90164883164560000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000002710fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27660fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9ad400000000000000000000000000000000000000000024c98fcd63f9edd999c2bbe0000000000000000000000000000000000000000000000000000000023c34600000000000000000000000000000000000000000002490b8629cad414ed17c31a0000000000000000000000000000000000000000000000000000000023ac5b490000000000000000000000006880129a290043e85eb6c67c3838d961a85956790000000000000000000000000000000000000000000000000000000064410203c080a0f78c707ba62590c6e4b222ea33c73c585ac7b1179397adf5aa0f80c7c0b63045a01a60736f6bc0effd5005723ae22f65ef92749eebbeed222f7149a8f091ef82bc"
		leafHexLen := len(leafHexString)
		var leafRlpHex [TransactionLeafMaxHexLen]frontend.Variable
		for i := 0; i < TransactionLeafMaxHexLen; i++ {
			if i < leafHexLen {
				intValue, _ := strconv.ParseInt(string(leafHexString[i]), 16, 64)
				leafRlpHex[i] = intValue
			} else {
				leafRlpHex[i] = 0
			}
		}

		// get decodevalue
		input, err := hexutil.Decode("0x" + leafHexString)
		if err != nil {
			log.Error("Failed to decode node rlp", leafHexString, err.Error())
		}
		var decodeValue [][]byte
		err = rlp.Decode(bytes.NewReader(input), &decodeValue)

		if err != nil {
			log.Error("Failed to decode", err)
		}
		prefixKey := hex.EncodeToString(decodeValue[0])

		var keyNibblesHexString string
		if decodeValue[0][0] == 32 {
			keyNibblesHexString = strings.TrimPrefix(prefixKey, "20")
		} else {
			keyNibblesHexString = strings.TrimPrefix(prefixKey, "3")
		}
		fmt.Println(keyNibblesHexString)
		//keyNibblesHexString := ""
		keyNibblesLen := len(keyNibblesHexString)
		var keyNibbles [TransactionLeafMaxKeyHexLen]frontend.Variable

		for i := 0; i < TransactionLeafMaxKeyHexLen; i++ {
			if i < keyNibblesLen {
				intValue, _ := strconv.ParseInt(string(keyNibblesHexString[i]), 16, 64)
				keyNibbles[i] = intValue
			} else {
				keyNibbles[i] = 0
			}
		}

		valueHexString := hex.EncodeToString(decodeValue[1])
		//valueHexString := "02f901d30181b48405f5e100850faf9e23de830962b494c36442b4a4522e871399cd717abdd847ab11fe8880b90164883164560000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000002710fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27660fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9ad400000000000000000000000000000000000000000024c98fcd63f9edd999c2bbe0000000000000000000000000000000000000000000000000000000023c34600000000000000000000000000000000000000000002490b8629cad414ed17c31a0000000000000000000000000000000000000000000000000000000023ac5b490000000000000000000000006880129a290043e85eb6c67c3838d961a85956790000000000000000000000000000000000000000000000000000000064410203c080a0f78c707ba62590c6e4b222ea33c73c585ac7b1179397adf5aa0f80c7c0b63045a01a60736f6bc0effd5005723ae22f65ef92749eebbeed222f7149a8f091ef82bc"
		valueHexLen := len(valueHexString)
		var values [TransactionLeafMaxValueHexLen]frontend.Variable
		for i := 0; i < TransactionLeafMaxValueHexLen; i++ {
			if i < valueHexLen {
				intValue, _ := strconv.ParseInt(string(valueHexString[i]), 16, 64)
				values[i] = intValue
			} else {
				values[i] = 0
			}
		}

		/// Account proof leaf check
		witness := &MPTLeafCheckCircuit{
			KeyNibbleLen:         keyNibblesLen,
			KeyNibbles:           keyNibbles[:],
			Values:               values[:],
			LeafRlp:              leafRlpHex[:],
			LeafPathPrefixLength: 2,
			Output:               4,
		}

		err = test.IsSolved(&MPTLeafCheckCircuit{
			KeyNibbles: make([]frontend.Variable, TransactionLeafMaxKeyHexLen),
			Values:     make([]frontend.Variable, TransactionLeafMaxValueHexLen),
			LeafRlp:    make([]frontend.Variable, TransactionLeafMaxHexLen)}, witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}

type ProofWriter struct {
	Keys   [][]byte
	Values [][]byte
}

func (p *ProofWriter) Put(key []byte, value []byte) error {
	p.Keys = append(p.Keys, key)
	p.Values = append(p.Values, value)
	return nil
}

func (p *ProofWriter) Delete(key []byte) error {
	return nil
}

func GetTransactionProof(bk *types.Block, index int) (nodes [][]byte, keyIndex, leafRlpPrefix []byte, err error) {
	var indexBuf []byte
	keyIndex = rlp.AppendUint64(indexBuf[:0], uint64(index))

	db := trie.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	tt := trie.NewEmpty(db)
	txRootHash := types.DeriveSha(bk.Transactions(), tt)
	if txRootHash != bk.TxHash() {
		log.Errorf("tx root hash mismatch, blk: %d, index: %d, tx root hash: %x != %x", bk.NumberU64(), index, txRootHash, bk.TxHash())
	}
	log.Infof("blk: %d, index: %d, tx root hash: %x", bk.NumberU64(), index, txRootHash)

	proofWriter := &ProofWriter{
		Keys:   [][]byte{},
		Values: [][]byte{},
	}
	err = tt.Prove(keyIndex, proofWriter)
	if err != nil {
		return
	}
	var leafRlp [][]byte
	leafValue := proofWriter.Values[len(proofWriter.Values)-1]
	err = rlp.DecodeBytes(leafValue, &leafRlp)
	if err != nil {
		return
	}
	if len(leafRlp) != 2 {
		err = fmt.Errorf("invalid leaf rlp len:%d, index:%d, bk:%s", len(leafRlp), index, bk.Number().String())
		return
	}
	return proofWriter.Values, keyIndex, leafValue[:len(leafValue)-len(leafRlp[1])], nil
}
