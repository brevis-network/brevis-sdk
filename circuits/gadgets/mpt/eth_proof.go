package mpt

import (
	"math"
	"math/big"

	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak"
	"github.com/celer-network/brevis-sdk/circuits/gadgets/rlp"
	"github.com/consensys/gnark/frontend"
)

const (
	ethBlockHeadMaxRound        = 5
	EthBlockHeadMaxBlockHexSize = ethBlockHeadMaxRound * 272

	StorageMaxValueLength     = 66
	StorageMPTMaxDepth        = 8
	StorageLeafMaxBlockHexLen = 272

	AccountMPTMaxDepth       = 9
	AccountKeyLength         = 64
	MaxValueLengthForAccount = 228 //  228: Account   66: Storage

	MaxDepth                 = 9
	MaxValueLengthForStorage = 66
	BranchNodeMaxRoundSize   = 4
	BranchNodeMaxBlockSize   = BranchNodeMaxRoundSize * 272
)

type EthAccountProofResult struct {
	Output        frontend.Variable
	NonceLength   frontend.Variable
	Nonce         [64]frontend.Variable
	BalanceLength frontend.Variable
	Balance       [24]frontend.Variable
	StorageRoot   [64]frontend.Variable
	CodeHash      [64]frontend.Variable
}

func CheckEthAccountProof(
	api frontend.API,
	maxDepth int,
	stateRoot [64]frontend.Variable,
	addressHash [64]frontend.Variable, // padded address hash
	keyFragmentStarts []frontend.Variable, // [maxDepth]
	addressRlp [228]frontend.Variable,
	leafRlp []frontend.Variable, // [maxLeafRlpLength]
	leafRoundIndex frontend.Variable,
	leafPathPrefixLength frontend.Variable,
	nodeRlp [][]frontend.Variable, // [maxDepth - 1][maxBranchRlpLength]
	nodeRoundIndexs []frontend.Variable,
	nodePathPrefixLength []frontend.Variable, // [maxDepth - 1]
	nodeTypes []frontend.Variable, // [maxDepth - 1]
	depth frontend.Variable,
) EthAccountProofResult {
	addressValueArrayCheck := rlp.ArrayCheck{
		MaxHexLen:            228,
		MaxFields:            4,
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{0, 0, 64, 64},
		FieldMaxHexLen:       []int{64, 24, 64, 64},
	}

	rlpout, _, fieldsLength, fields := addressValueArrayCheck.RlpArrayCheck(api, addressRlp[:])

	nonceLength := fieldsLength[0]
	var nonce [64]frontend.Variable
	var storageRoot [64]frontend.Variable
	var codeHash [64]frontend.Variable
	for i := 0; i < 64; i++ {
		nonce[i] = fields[0][i]
		storageRoot[i] = fields[2][i]
		codeHash[i] = fields[3][i]
	}

	balanceLength := fieldsLength[1]
	var balance [24]frontend.Variable
	for i := 0; i < 24; i++ {
		balance[i] = fields[1][i]
	}

	mptInclusionResult := CheckMPTInclusionFixedKeyLength(
		api,
		maxDepth,
		64,
		228,
		addressHash[:],
		addressRlp[:],
		stateRoot,
		keyFragmentStarts,
		leafRlp,
		leafRoundIndex,
		leafPathPrefixLength,
		nodeRlp,
		nodeRoundIndexs,
		nodePathPrefixLength,
		nodeTypes,
		depth,
	)

	return EthAccountProofResult{
		Output:        api.Mul(rlpout, mptInclusionResult.Output),
		NonceLength:   nonceLength,
		Nonce:         nonce,
		BalanceLength: balanceLength,
		Balance:       balance,
		StorageRoot:   storageRoot,
		CodeHash:      codeHash,
	}
}

type EthStorageProofResult struct {
	Output      frontend.Variable
	SlotValue   [2]frontend.Variable
	ValueLength frontend.Variable
}

func CheckEthStorageProof(
	api frontend.API,
	maxDepth int,
	storageRoot [64]frontend.Variable,
	slotHash [64]frontend.Variable, // padded slotHash
	valueRlp [66]frontend.Variable,
	keyFragmentStarts []frontend.Variable, // [maxDepth]
	leafRlp []frontend.Variable, // [maxLeafRlpLength]
	leafRoundIndex frontend.Variable,
	leafPathPrefixLength frontend.Variable,
	nodeRlp [][]frontend.Variable, // [maxDepth - 1][maxBranchRlpLength]
	nodeRoundIndexs []frontend.Variable,
	nodePathPrefixLength []frontend.Variable, // [maxDepth - 1]
	nodeTypes []frontend.Variable, // [maxDepth - 1]
	depth frontend.Variable,
) EthStorageProofResult {
	keyLength := 64
	maxValueLength := 66
	// maxLeafRlpLength := 4 + (keyLength + 2) + 4 + maxValueLength
	// maxBranchRlpLength := 1064
	// maxExtensionRlpLength := 4 + 2 + keyLength + 2 + 64

	mptInclusionResult := CheckMPTInclusionFixedKeyLength(
		api,
		maxDepth,
		keyLength,
		maxValueLength,
		slotHash[:],
		valueRlp[:],
		storageRoot,
		keyFragmentStarts,
		leafRlp,
		leafRoundIndex,
		leafPathPrefixLength,
		nodeRlp,
		nodeRoundIndexs,
		nodePathPrefixLength,
		nodeTypes,
		depth,
	)

	isBig, isLiteral, prefixOrTotalHexLen, _, _, _, _ := rlp.RlpFieldPrefix(api, [2]frontend.Variable{valueRlp[0], valueRlp[1]})
	//for i := 0; i < 64; i++ {
	//	slotValue[i] = valueRlp[i+2]
	//}

	fieldRlpPrefix1HexLen := api.Mul(isBig, prefixOrTotalHexLen)

	lenPrefixMaxHexs := rlp.LogCeil(66 / 8)
	lenPrefixMaxHexs = (lenPrefixMaxHexs + 1) * 2
	shlToFieldShift := api.Mul(isLiteral, api.Add(2, fieldRlpPrefix1HexLen))
	shlToFieldShift = api.Sub(api.Add(2, fieldRlpPrefix1HexLen), shlToFieldShift)
	shiftOut := rlp.ShiftLeft(api, 66, 0, lenPrefixMaxHexs, valueRlp[:], shlToFieldShift)

	slotValue := rlp.Hex64To2Fr(api, shiftOut, prefixOrTotalHexLen)
	api.Println(slotValue[:])

	return EthStorageProofResult{
		Output:      mptInclusionResult.Output,
		SlotValue:   slotValue,
		ValueLength: api.Sub(mptInclusionResult.ValueLength, 2),
	}
}

type EthBlockHashResult struct {
	Output            frontend.Variable
	BlockHash         [64]frontend.Variable
	BlockNumberLength frontend.Variable
	BlockNumber       [8]frontend.Variable
	BlockTime         [8]frontend.Variable
	StateRoot         [64]frontend.Variable
	TransactionsRoot  [64]frontend.Variable
	ReceiptsRoot      [64]frontend.Variable
}

func CheckEthBlockHash(
	api frontend.API,
	blockRlp [EthBlockHeadMaxBlockHexSize]frontend.Variable, // padded rlp data
	blockFieldsNum frontend.Variable,
	blockRoundIndex frontend.Variable,
) EthBlockHashResult {
	blockHashArrayCheck := rlp.ArrayCheck{
		MaxHexLen:            EthBlockHeadMaxBlockHexSize,
		MaxFields:            17,
		ArrayPrefixMaxHexLen: 4,
		FieldMinHexLen:       []int{64, 64, 40, 64, 64, 64, 512, 0, 0, 0, 0, 0, 0, 64, 16, 0, 64},
		FieldMaxHexLen:       []int{64, 64, 40, 64, 64, 64, 512, 14, 16, 8, 8, 8, 64, 64, 18, 16, 64},
	}
	rlpout, totalRlpLength, fieldsLength, fields := blockHashArrayCheck.BlkHeaderRlpCheck(
		api,
		blockRlp[:],
		blockFieldsNum,
	)

	blocks := keccak.NibblesToU64Array(api, blockRlp[:])

	//keccakRounds := api.Sub(5, rlp.LessThan(api, totalRlpLength, 1089))
	blockHash := rlp.Keccak256AsNibbles(api, totalRlpLength, blocks, blockRoundIndex).Output

	var stateRoot [64]frontend.Variable
	var transactionsRoot [64]frontend.Variable
	var receiptsRoot [64]frontend.Variable
	for i := 0; i < 64; i++ {
		stateRoot[i] = fields[3][i]
		transactionsRoot[i] = fields[4][i]
		receiptsRoot[i] = fields[5][i]
	}

	var blockNumber [8]frontend.Variable
	for i := 0; i < 8; i++ {
		blockNumber[i] = fields[8][i]
	}

	var blockTime [8]frontend.Variable
	for i := 0; i < 8; i++ {
		blockTime[i] = fields[11][i]
	}

	return EthBlockHashResult{
		Output:            rlpout,
		BlockHash:         blockHash,
		BlockNumberLength: fieldsLength[8],
		BlockNumber:       blockNumber,
		BlockTime:         blockTime,
		StateRoot:         stateRoot,
		TransactionsRoot:  transactionsRoot,
		ReceiptsRoot:      receiptsRoot,
	}

}

type EthAddressStorageProofResult struct {
	Output      frontend.Variable
	BlockNumber frontend.Variable
	SlotValue   [2]frontend.Variable
}

func CheckEthAddressStorageProof(
	api frontend.API,
	addressMaxDepth int,
	storageMaxDepth int,
	blockHash [64]frontend.Variable, // big endian 128-bit
	blockFieldsNum frontend.Variable,
	blockRoundIndex frontend.Variable,
	addressHash [64]frontend.Variable, // padded address hash
	slot [64]frontend.Variable, // 128-bit
	blockHashRlp [EthBlockHeadMaxBlockHexSize]frontend.Variable,
	addressKeyFragmentStarts []frontend.Variable, // [addressMaxDepth]
	addressRlp [228]frontend.Variable,
	addressLeafRlp []frontend.Variable, // [addressMaxLeafRlpLength]
	addressLeafRoundIndex frontend.Variable,
	addressLeafPathPrefixLength frontend.Variable,
	addressNodeRlp [][]frontend.Variable, // [addressMaxDepth - 1][addressMaxBranchRlpLength]
	addressNodeRlpRoundIndexes [AccountMPTMaxDepth - 1]frontend.Variable,
	addressNodePathPrefixLength []frontend.Variable, // [addressMaxDepth - 1]
	addressNodeTypes []frontend.Variable, // [addressMaxDepth - 1]
	addressDepth frontend.Variable,
	storageKeyFragmentStarts []frontend.Variable, // [storageMaxDepth]
	slotValueRlp [66]frontend.Variable,
	storageLeafRlp []frontend.Variable, // [storageMaxLeafRlpLength]
	storageLeafRoundIndex frontend.Variable,
	storageLeafPathPrefixLength frontend.Variable,
	storageNodeRlp [][]frontend.Variable, // [storageMaxDepth - 1][storageMaxBranchRlpLength]
	storageNodeRlpRoundIndex []frontend.Variable,
	storageNodePathPrefixLength []frontend.Variable, // [storageMaxDepth - 1]
	storageNodeTypes []frontend.Variable, // [storageMaxDepth - 1]
	storageProofDepth frontend.Variable,
) EthAddressStorageProofResult {
	rlpBlockHashResult := CheckEthBlockHash(api, blockHashRlp, blockFieldsNum, blockRoundIndex)

	// rlpBlockHashResult.
	blockHashEqual := rlp.ArrayEqual(api, blockHash[:], rlpBlockHashResult.BlockHash[:], 64, 64)

	addressProofResult := CheckEthAccountProof(
		api,
		addressMaxDepth,
		rlpBlockHashResult.StateRoot,
		addressHash,
		addressKeyFragmentStarts,
		addressRlp,
		addressLeafRlp,
		addressLeafRoundIndex,
		addressLeafPathPrefixLength,
		addressNodeRlp,
		addressNodeRlpRoundIndexes[:],
		addressNodePathPrefixLength,
		addressNodeTypes,
		addressDepth,
	)

	storageProofResult := CheckEthStorageProof(
		api,
		storageMaxDepth,
		addressProofResult.StorageRoot,
		slot,
		slotValueRlp,
		storageKeyFragmentStarts,
		storageLeafRlp,
		storageLeafRoundIndex,
		storageLeafPathPrefixLength,
		storageNodeRlp,
		storageNodeRlpRoundIndex,
		storageNodePathPrefixLength,
		storageNodeTypes,
		storageProofDepth,
	)

	blockNumberShift := rlp.ShiftRight(api, 8, 3, rlpBlockHashResult.BlockNumber[:], api.Sub(8, rlpBlockHashResult.BlockNumberLength))
	var blockNumber = frontend.Variable(0)
	for i := 0; i < 8; i++ {
		blockNumber = api.Add(blockNumber, api.Mul(blockNumberShift[i], big.NewInt(int64(math.Pow(16, float64(7-i))))))
	}

	return EthAddressStorageProofResult{
		BlockNumber: blockNumber,
		SlotValue:   storageProofResult.SlotValue,
		Output:      rlp.Equal(api, api.Add(blockHashEqual, addressProofResult.Output, storageProofResult.Output), 3),
	}
}
