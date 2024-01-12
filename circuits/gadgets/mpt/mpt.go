package mpt

import (
	"github.com/celer-network/brevis-sdk/circuits/gadgets/keccak"
	"github.com/celer-network/brevis-sdk/circuits/gadgets/rlp"
	"github.com/celer-network/brevis-sdk/common/utils"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
)

type CheckMPTInclusionFixedKeyLengthResult struct {
	Output      frontend.Variable
	ValueLength frontend.Variable
}

func CheckMPTInclusionFixedKeyLength(
	api frontend.API,
	maxDepth int,
	keyLength int,
	maxValueLength int,
	key []frontend.Variable, // [keyLength]
	value []frontend.Variable, // [maxValueLength]
	rootHash [64]frontend.Variable, // Root hash should be 32-bytes long value. Divide it by 4-bits ===> 0xcf78 will be [c, f, 7, 8]
	keyFragmentStarts []frontend.Variable, // [maxDepth]
	leafRlp []frontend.Variable,
	leafRoundIndex frontend.Variable,
	leafPathPrefixLength frontend.Variable,
	nodeRlp [][]frontend.Variable, // [maxDepth - 1][maxBranchRlpHexLen]
	nodeRoundIndexes []frontend.Variable,
	nodePathPrefixLength []frontend.Variable, // [maxDepth - 1]
	nodeTypes []frontend.Variable, // [maxDepth - 1]
	depth frontend.Variable,
) CheckMPTInclusionFixedKeyLengthResult {
	api.AssertIsLessOrEqual(maxDepth, 10)

	//maxLeafRLPLength := 4 + (keyLength + 2) + 4 + maxValueLength
	maxBranchRlpHexLen := 1064
	maxExtensionRlpHexLen := 4 + 2 + keyLength + 2 + 64

	// KEY_BITS := LogCeil(keyLength)
	// api.AssertIsEqual(KEY_BITS, 6)

	var keyFragmentValidBranch []frontend.Variable // [maxDepth - 1]
	var isSingleKeyFragment []frontend.Variable    // [maxDepth - 1]
	var isMonotoneStart []frontend.Variable        // [maxDepth - 1]
	var isStartRange []frontend.Variable           // [maxDepth]

	for index := 0; index < maxDepth-1; index++ {
		isSingleKeyFragment = append(isSingleKeyFragment, rlp.Equal(api, api.Add(keyFragmentStarts[index], 1), keyFragmentStarts[index+1]))
		isMonotoneStart = append(isMonotoneStart, rlp.LessThan(api, keyFragmentStarts[index], keyFragmentStarts[index+1]))
		keyFragmentValidBranch = append(keyFragmentValidBranch, api.Or(isSingleKeyFragment[index], api.Sub(1, nodeTypes[index])))
		isStartRange = append(isStartRange, rlp.LessThan(api, keyFragmentStarts[index], keyLength))
	}

	isStartRange = append(isStartRange, rlp.LessThan(api, keyFragmentStarts[maxDepth-1], keyLength))

	var allFragmentsInput [][]frontend.Variable
	var tmp frontend.Variable = 0
	for i := 0; i < maxDepth-1; i++ {
		if len(allFragmentsInput) == 0 {
			allFragmentsInput = append(allFragmentsInput, []frontend.Variable{})
		}
		tmp = api.Add(tmp, keyFragmentValidBranch[i], isMonotoneStart[i], isStartRange[i])
		allFragmentsInput[0] = append(allFragmentsInput[0], tmp)
	}

	tmp = api.Add(tmp, 2, isStartRange[maxDepth-1])
	allFragmentsInput[0] = append(allFragmentsInput[0], tmp)

	allFragmentsValidMultiplexer := rlp.Multiplexer(api, api.Sub(depth, 1), 1, maxDepth, allFragmentsInput)
	allFragmentsValid := rlp.Equal(api, allFragmentsValidMultiplexer[0], api.Mul(3, depth))

	var leafStartInput [][]frontend.Variable
	for i := 0; i < maxDepth; i++ {
		if len(leafStartInput) == 0 {
			leafStartInput = append(leafStartInput, []frontend.Variable{})
		}
		leafStartInput[0] = append(leafStartInput[0], keyFragmentStarts[i])
	}
	leafStartMultiplexer := rlp.Multiplexer(api, api.Sub(depth, 1), 1, maxDepth, leafStartInput)

	var leafSubArrayInput [64]frontend.Variable
	for i := 0; i < 64; i++ {
		leafSubArrayInput[i] = key[i]
	}

	log.Debug(leafSubArrayInput, leafStartMultiplexer[0], keyLength)

	subArray := rlp.NewSubArray(64, 64, 7)
	leafSelector, leafSelectorLength := subArray.SubArray(api, leafSubArrayInput[:], leafStartMultiplexer[0], keyLength)

	leafCheck := NewMPTLeafCheck(keyLength, maxValueLength)
	leafCheckResult := leafCheck.CheckLeaf(api, leafSelectorLength, leafSelector, value, leafRlp, leafPathPrefixLength)

	leafRlpBlock := keccak.NibblesToU64Array(api, leafRlp[:])
	leafHash := rlp.Keccak256AsNibbles(api, len(leafRlp), leafRlpBlock, leafRoundIndex)

	log.Debug("leafHash:", leafHash.Output)

	log.Debug(leafHash.Output, leafHash.OutputLength)

	var depthEqual []frontend.Variable
	var depthLessThan []frontend.Variable
	for i := 0; i < maxDepth; i++ {
		depthEqual = append(depthEqual, rlp.Equal(api, depth, i+1))
		depthLessThan = append(depthLessThan, rlp.LessThan(api, i, depth))
	}

	//maxNodeRLPLength := 1064
	// maxRounds := (maxNodeRLPLength + 272) / 272

	var extensionCheckResults []MPTCheckResult // [maxDepth - 1]
	var branchCheckResults []MPTCheckResult    // [maxDepth - 1]
	var nodeHashes []rlp.KeccakOrLiteralHex    // [maxDepth - 1]
	for i := 0; i < maxDepth-1; i++ {
		extensionCheckResults = append(extensionCheckResults, MPTCheckResult{})
		branchCheckResults = append(branchCheckResults, MPTCheckResult{})
		nodeHashes = append(nodeHashes, rlp.KeccakOrLiteralHex{})
	}

	for layer := maxDepth - 2; layer >= 0; layer-- {
		var keySubArrayInput [64]frontend.Variable
		for i := 0; i < 64; i++ {
			keySubArrayInput[i] = key[i]
		}

		keySelector, _ := subArray.SubArray(api, keySubArrayInput[:], keyFragmentStarts[layer], keyFragmentStarts[layer+1])

		extensionCheck := NewMPTExtensionCheck(keyLength, 64)

		/// Extension and Branch check uses the same nodeRefLength and nodeRefs
		var nodeRefLength frontend.Variable
		var nodeRefs []frontend.Variable
		if layer == maxDepth-2 {
			nodeRefLength = api.Mul(depthEqual[layer+1], leafHash.OutputLength)
			for i := 0; i < 64; i++ {
				nodeRefs = append(nodeRefs, api.Mul(depthEqual[layer+1], leafHash.Output[i]))
			}
		} else {
			nodeRefLength = api.Add(api.Mul(depthEqual[layer+1], api.Sub(leafHash.OutputLength, nodeHashes[layer+1].OutputLength)), nodeHashes[layer+1].OutputLength)
			for i := 0; i < 64; i++ {
				value := api.Mul(depthEqual[layer+1], api.Sub(leafHash.Output[i], nodeHashes[layer+1].Output[i]))
				nodeRefs = append(nodeRefs, api.Add(value, nodeHashes[layer+1].Output[i]))
			}
		}

		var extesionCheckNodeRlpAtCurrentLayer []frontend.Variable

		for i := 0; i < maxExtensionRlpHexLen; i++ {
			rlpAtI := api.Mul(nodeTypes[layer], nodeRlp[layer][i])
			extesionCheckNodeRlpAtCurrentLayer = append(extesionCheckNodeRlpAtCurrentLayer, rlpAtI)
		}

		extensionCheckResults[layer] = extensionCheck.CheckExtension(
			api,
			api.Sub(keyFragmentStarts[layer+1], keyFragmentStarts[layer]),
			keySelector,
			nodeRefLength,
			nodeRefs,
			extesionCheckNodeRlpAtCurrentLayer,
			nodePathPrefixLength[layer],
		)

		var nibbleSelectorInput [][]frontend.Variable
		for i := 0; i < keyLength; i++ {
			if len(nibbleSelectorInput) == 0 {
				nibbleSelectorInput = append(nibbleSelectorInput, []frontend.Variable{})
			}
			nibbleSelectorInput[0] = append(nibbleSelectorInput[0], key[i])
		}
		nibbleSelector := rlp.Multiplexer(api, api.Mul(depthLessThan[layer], keyFragmentStarts[layer]), 1, keyLength, nibbleSelectorInput)

		branchCheck := NewMPTBranchCheck(64)

		var branchCheckNodeRlpAtCurrentLayer []frontend.Variable

		for i := 0; i < maxBranchRlpHexLen; i++ {
			rlpAtI := api.Mul(nodeTypes[layer], nodeRlp[layer][i])
			extesionCheckNodeRlpAtCurrentLayer = append(extesionCheckNodeRlpAtCurrentLayer, rlpAtI)
			branchCheckNodeRlpAtCurrentLayer = append(branchCheckNodeRlpAtCurrentLayer, api.Sub(nodeRlp[layer][i], rlpAtI))
		}

		branchCheckResults[layer] = branchCheck.CheckBranch(
			api,
			nibbleSelector[0],
			nodeRefLength,
			nodeRefs,
			branchCheckNodeRlpAtCurrentLayer,
		)

		nodeHashInputLengthAtCurrentLayer :=
			api.Add(
				api.Mul(
					nodeTypes[layer],
					api.Sub(
						extensionCheckResults[layer].rlpTotalLength,
						branchCheckResults[layer].rlpTotalLength,
					),
				),
				branchCheckResults[layer].rlpTotalLength,
			)

		nodeRlpBlock := keccak.NibblesToU64Array(api, nodeRlp[layer][:])
		nodeHashes[layer] = *rlp.Keccak256AsNibbles(api, nodeHashInputLengthAtCurrentLayer, nodeRlpBlock, nodeRoundIndexes[layer])
	}

	rootHashCheck := rlp.ArrayEqual(api, rootHash[:], nodeHashes[0].Output[:], 64, 64)
	log.Debug(rootHashCheck, leafCheckResult.result.output, allFragmentsValid, extensionCheckResults, branchCheckResults)

	var allCheckMultiplexerInput [][]frontend.Variable
	allCheckMultiplexerInput = append(allCheckMultiplexerInput, []frontend.Variable{api.Add(rootHashCheck, leafCheckResult.result.output, allFragmentsValid)})

	for layer := 0; layer < maxDepth-1; layer++ {
		currentLayerValue :=
			api.Add(
				allCheckMultiplexerInput[0][layer],
				branchCheckResults[layer].output,
				api.Mul(
					nodeTypes[layer],
					api.Sub(
						extensionCheckResults[layer].output,
						branchCheckResults[layer].output,
					),
				),
			)
		if len(allCheckMultiplexerInput) == 0 {
			allCheckMultiplexerInput = append(allCheckMultiplexerInput, []frontend.Variable{})
		}
		allCheckMultiplexerInput[0] = append(allCheckMultiplexerInput[0], currentLayerValue)
	}

	allCheckMultiplexer := rlp.Multiplexer(api, api.Sub(depth, 1), 1, maxDepth, allCheckMultiplexerInput)

	return CheckMPTInclusionFixedKeyLengthResult{
		Output:      rlp.Equal(api, allCheckMultiplexer[0], api.Add(api.Mul(depth, 4), 2)),
		ValueLength: leafCheckResult.valueLength,
	}
}

func CheckMPTInclusionNoBranchTermination(
	api frontend.API,
	maxDepth int,
	maxKeyHexLen int,
	key []frontend.Variable, // [keyLength]
	keyLength frontend.Variable,
	rootHash [64]frontend.Variable, // Root hash should be 32-bytes long value. Divide it by 4-bits ===> 0xcf78 will be [c, f, 7, 8]
	keyFragmentStarts []frontend.Variable, // [maxDepth]
	publicLeafHash [2]frontend.Variable,
	nodeRlp [][]frontend.Variable, // [maxDepth - 1][maxBranchRlpHexLen]
	nodeRoundIndexes []frontend.Variable,
	nodePathPrefixLength []frontend.Variable, // [maxDepth - 1]
	nodeTypes []frontend.Variable, // [maxDepth - 1]
	depth frontend.Variable,
) CheckMPTInclusionFixedKeyLengthResult {
	api.AssertIsLessOrEqual(maxDepth, 10)

	maxBranchRlpHexLen := 1064
	maxExtensionRlpHexLen := 4 + 2 + maxKeyHexLen + 2 + 64

	var keyFragmentValidBranch []frontend.Variable // [maxDepth - 1]
	var isSingleKeyFragment []frontend.Variable    // [maxDepth - 1]
	var isMonotoneStart []frontend.Variable        // [maxDepth - 1]
	var isStartRange []frontend.Variable           // [maxDepth]

	for index := 0; index < maxDepth-1; index++ {
		isSingleKeyFragment = append(isSingleKeyFragment, rlp.Equal(api, api.Add(keyFragmentStarts[index], 1), keyFragmentStarts[index+1]))
		isMonotoneStart = append(isMonotoneStart, rlp.LessThan(api, keyFragmentStarts[index], keyFragmentStarts[index+1]))
		keyFragmentValidBranch = append(keyFragmentValidBranch, api.Or(isSingleKeyFragment[index], api.Sub(1, nodeTypes[index])))
		isStartRange = append(isStartRange, rlp.LessThan(api, keyFragmentStarts[index], keyLength))
	}

	isStartRange = append(isStartRange, rlp.LessThan(api, keyFragmentStarts[maxDepth-1], keyLength))

	var allFragmentsInput [][]frontend.Variable
	var tmp frontend.Variable = 0
	for i := 0; i < maxDepth-1; i++ {
		if len(allFragmentsInput) == 0 {
			allFragmentsInput = append(allFragmentsInput, []frontend.Variable{})
		}
		tmp = api.Add(tmp, keyFragmentValidBranch[i], isMonotoneStart[i], isStartRange[i])
		allFragmentsInput[0] = append(allFragmentsInput[0], tmp)
	}

	tmp = api.Add(tmp, 2, isStartRange[maxDepth-1])
	allFragmentsInput[0] = append(allFragmentsInput[0], tmp)

	allFragmentsValidMultiplexer := rlp.Multiplexer(api, api.Sub(depth, 1), 1, maxDepth, allFragmentsInput)
	allFragmentsValid := rlp.Equal(api, allFragmentsValidMultiplexer[0], api.Mul(3, depth))

	var leafStartInput [][]frontend.Variable
	for i := 0; i < maxDepth; i++ {
		if len(leafStartInput) == 0 {
			leafStartInput = append(leafStartInput, []frontend.Variable{})
		}
		leafStartInput[0] = append(leafStartInput[0], keyFragmentStarts[i])
	}
	leafStartMultiplexer := rlp.Multiplexer(api, api.Sub(depth, 1), 1, maxDepth, leafStartInput)

	var leafSubArrayInput [6]frontend.Variable
	for i := 0; i < 6; i++ {
		leafSubArrayInput[i] = key[i]
	}

	log.Debug(leafSubArrayInput, leafStartMultiplexer[0], keyLength)

	subArray := rlp.NewSubArray(maxKeyHexLen, maxKeyHexLen, rlp.LogCeil(maxKeyHexLen))

	leafHash := utils.Recompose32ByteToNibbles(api, publicLeafHash[:])

	//log.Info(leafHash.Output, leafHash.OutputLength)

	var depthEqual []frontend.Variable
	var depthLessThan []frontend.Variable
	for i := 0; i < maxDepth; i++ {
		depthEqual = append(depthEqual, rlp.Equal(api, depth, i+1))
		depthLessThan = append(depthLessThan, rlp.LessThan(api, i, depth))
	}

	//maxNodeRLPLength := 1064
	// maxRounds := (maxNodeRLPLength + 272) / 272

	var extensionCheckResults []MPTCheckResult // [maxDepth - 1]
	var branchCheckResults []MPTCheckResult    // [maxDepth - 1]
	var nodeHashes []rlp.KeccakOrLiteralHex    // [maxDepth - 1]
	for i := 0; i < maxDepth-1; i++ {
		extensionCheckResults = append(extensionCheckResults, MPTCheckResult{})
		branchCheckResults = append(branchCheckResults, MPTCheckResult{})
		nodeHashes = append(nodeHashes, rlp.KeccakOrLiteralHex{})
	}

	for layer := maxDepth - 2; layer >= 0; layer-- {
		var keySubArrayInput [6]frontend.Variable
		for i := 0; i < 6; i++ {
			keySubArrayInput[i] = key[i]
		}

		keySelector, _ := subArray.SubArray(api, keySubArrayInput[:], keyFragmentStarts[layer], keyFragmentStarts[layer+1])

		extensionCheck := NewMPTExtensionCheck(maxKeyHexLen, 64)

		/// Extension and Branch check uses the same nodeRefLength and nodeRefs
		var nodeRefLength frontend.Variable
		var nodeRefs []frontend.Variable
		if layer == maxDepth-2 {
			nodeRefLength = api.Mul(depthEqual[layer+1], 64)
			for i := 0; i < 64; i++ {
				nodeRefs = append(nodeRefs, api.Mul(depthEqual[layer+1], leafHash[i]))
			}
		} else {
			nodeRefLength = api.Add(api.Mul(depthEqual[layer+1], api.Sub(64, nodeHashes[layer+1].OutputLength)), nodeHashes[layer+1].OutputLength)
			for i := 0; i < 64; i++ {
				value := api.Mul(depthEqual[layer+1], api.Sub(leafHash[i], nodeHashes[layer+1].Output[i]))
				nodeRefs = append(nodeRefs, api.Add(value, nodeHashes[layer+1].Output[i]))
			}
		}

		var extesionCheckNodeRlpAtCurrentLayer []frontend.Variable

		for i := 0; i < maxExtensionRlpHexLen; i++ {
			rlpAtI := api.Mul(nodeTypes[layer], nodeRlp[layer][i])
			extesionCheckNodeRlpAtCurrentLayer = append(extesionCheckNodeRlpAtCurrentLayer, rlpAtI)
		}

		extensionCheckResults[layer] = extensionCheck.CheckExtension(
			api,
			api.Sub(keyFragmentStarts[layer+1], keyFragmentStarts[layer]),
			keySelector,
			nodeRefLength,
			nodeRefs,
			extesionCheckNodeRlpAtCurrentLayer,
			nodePathPrefixLength[layer],
		)

		var nibbleSelectorInput [][]frontend.Variable
		for i := 0; i < maxKeyHexLen; i++ {
			if len(nibbleSelectorInput) == 0 {
				nibbleSelectorInput = append(nibbleSelectorInput, []frontend.Variable{})
			}
			nibbleSelectorInput[0] = append(nibbleSelectorInput[0], key[i])
		}
		nibbleSelector := rlp.Multiplexer(api, api.Mul(depthLessThan[layer], keyFragmentStarts[layer]), 1, maxKeyHexLen, nibbleSelectorInput)

		branchCheck := NewMPTBranchCheck(64)

		var branchCheckNodeRlpAtCurrentLayer []frontend.Variable

		for i := 0; i < maxBranchRlpHexLen; i++ {
			rlpAtI := api.Mul(nodeTypes[layer], nodeRlp[layer][i])
			extesionCheckNodeRlpAtCurrentLayer = append(extesionCheckNodeRlpAtCurrentLayer, rlpAtI)
			branchCheckNodeRlpAtCurrentLayer = append(branchCheckNodeRlpAtCurrentLayer, api.Sub(nodeRlp[layer][i], rlpAtI))
		}

		branchCheckResults[layer] = branchCheck.CheckBranch(
			api,
			nibbleSelector[0],
			nodeRefLength,
			nodeRefs,
			branchCheckNodeRlpAtCurrentLayer,
		)

		nodeHashInputLengthAtCurrentLayer :=
			api.Add(
				api.Mul(
					nodeTypes[layer],
					api.Sub(
						extensionCheckResults[layer].rlpTotalLength,
						branchCheckResults[layer].rlpTotalLength,
					),
				),
				branchCheckResults[layer].rlpTotalLength,
			)

		nodeRlpBlock := keccak.NibblesToU64Array(api, nodeRlp[layer][:])
		nodeHashes[layer] = *rlp.Keccak256AsNibbles(api, nodeHashInputLengthAtCurrentLayer, nodeRlpBlock, nodeRoundIndexes[layer])
	}

	rootHashCheck := rlp.ArrayEqual(api, rootHash[:], nodeHashes[0].Output[:], 64, 64)
	log.Debug("Inclusion Check:", rootHashCheck, allFragmentsValid, extensionCheckResults, branchCheckResults)

	var allCheckMultiplexerInput [][]frontend.Variable
	allCheckMultiplexerInput = append(allCheckMultiplexerInput, []frontend.Variable{api.Add(rootHashCheck, 4, allFragmentsValid)})

	for layer := 0; layer < maxDepth-1; layer++ {
		currentLayerValue :=
			api.Add(
				allCheckMultiplexerInput[0][layer],
				branchCheckResults[layer].output,
				api.Mul(
					nodeTypes[layer],
					api.Sub(
						extensionCheckResults[layer].output,
						branchCheckResults[layer].output,
					),
				),
			)
		if len(allCheckMultiplexerInput) == 0 {
			allCheckMultiplexerInput = append(allCheckMultiplexerInput, []frontend.Variable{})
		}
		allCheckMultiplexerInput[0] = append(allCheckMultiplexerInput[0], currentLayerValue)
	}

	allCheckMultiplexer := rlp.Multiplexer(api, api.Sub(depth, 1), 1, maxDepth, allCheckMultiplexerInput)

	return CheckMPTInclusionFixedKeyLengthResult{
		Output:      rlp.Equal(api, allCheckMultiplexer[0], api.Add(api.Mul(depth, 4), 1)),
		ValueLength: 0,
	}
}
