package sdk

import (
	"fmt"
	"log"
	"math/big"

	brevisCommon "github.com/brevis-network/brevis-sdk/common"
	"github.com/brevis-network/zk-hash/utils"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Deprecated, please use BuildCircuitInputV2
func (q *BrevisApp) BuildCircuitInput(app AppCircuit) (CircuitInput, error) {
	return q.BuildCircuitInputV2(&AppCircuitWrapper{V1: app})
}

// BuildCircuitInputV2 executes all added queries and package the query results
// into circuit assignment (the DataInput struct) The provided ctx is used
// when performing network calls to the provided blockchain RPC.
func (q *BrevisApp) BuildCircuitInputV2(app AppCircuitV2) (CircuitInput, error) {
	// 1. mimc hash data at each position to generate and assign input commitments and toggles commitment
	// 2. dry-run user circuit to generate output and output commitment

	info := app.Allocate()
	q.maxReceipts = info.MaxReceipts
	q.maxStorage = info.MaxSlots
	q.maxTxs = info.MaxTxs
	q.maxBlockHeader = info.MaxBlockHeaders

	err := q.checkAllocations(app)
	if err != nil {
		return CircuitInput{}, err
	}

	q.dataPoints = DataPointsNextPowerOf2(q.maxReceipts + q.maxStorage + q.maxTxs)
	in := defaultCircuitInput(q.maxReceipts, q.maxStorage, q.maxTxs, q.maxBlockHeader, q.dataPoints)

	// blockHeader
	err = q.assignBlockHeaders(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from receipt queries", err)
	}

	// receipt
	err = q.assignReceipts(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from receipt queries", err)
	}

	// storage
	err = q.assignStorageSlots(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from storage queries", err)
	}

	// transaction
	err = q.assignTransactions(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from transaction queries", err)
	}

	q.writeDataIntoLocalStorage()

	if q.realDataLength() > 0 && q.mockDataLength() > 0 {
		return CircuitInput{}, fmt.Errorf("you cannot add real data and mock data at the same time")
	}
	err = q.assignMockReceipts(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from receipt queries", err)
	}

	// storage
	err = q.assignMockStorageSlots(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from storage queries", err)
	}

	// transaction
	err = q.assignMockTransactions(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from transaction queries", err)
	}

	// commitment
	q.assignInputCommitment(&in)
	q.assignToggleCommitment(&in)

	// dry run without assigning the output commitment first to compute the output commitment using the user circuit
	outputCommit, output, err := dryRun(in, app)
	if err != nil {
		return buildCircuitInputErr("failed to generate output commitment", err)
	}
	in.OutputCommitment = outputCommit
	// cache dry-run output to be used in building gateway request later
	in.dryRunOutput = output

	q.circuitInput = in // cache the generated circuit input for later use in building gateway request
	q.buildInputCalled = true
	fmt.Printf("output %x\n", output)

	return in, nil
}

func buildCircuitInputErr(m string, err error) (CircuitInput, error) {
	return CircuitInput{}, fmt.Errorf("%s: %s", m, err.Error())
}

func allocationMultipleErr(name string, queryCount int) error {
	return fmt.Errorf("# of %s max queries (%d) must be an integral multiple of 32, check your AppCircuit.Allocate() method",
		name, queryCount)
}

func allocationLenErr(name string, queryCount, maxCount int) error {
	return fmt.Errorf("# of %s queries (%d) must not exceed the allocated max %s (%d), check your AppCircuit.Allocate() method",
		name, queryCount, name, maxCount)
}

func (q *BrevisApp) checkAllocations(cb AppCircuitV2) error {
	info := cb.Allocate()
	maxReceipts := info.MaxReceipts
	maxSlots := info.MaxSlots
	maxTxs := info.MaxTxs
	maxBlockHeaders := info.MaxBlockHeaders

	numBlockHeaders := len(q.blockHeaders.special) + len(q.blockHeaders.ordered)
	if maxBlockHeaders%32 != 0 {
		return allocationMultipleErr("block header", maxBlockHeaders)
	}
	for index := range q.receipts.special {
		if index >= maxBlockHeaders {
			return allocationIndexErr("block header", index, maxBlockHeaders)
		}
	}
	if numBlockHeaders > maxBlockHeaders {
		return allocationLenErr("block header", numBlockHeaders, maxBlockHeaders)
	}

	numReceipts := len(q.receipts.special) + len(q.receipts.ordered)
	if maxReceipts%32 != 0 {
		return allocationMultipleErr("receipt", maxReceipts)
	}
	for index := range q.receipts.special {
		if index >= maxReceipts {
			return allocationIndexErr("receipt", index, maxReceipts)
		}
	}
	if numReceipts > maxReceipts {
		return allocationLenErr("receipt", numReceipts, maxReceipts)
	}
	numStorages := len(q.storageVals.special) + len(q.storageVals.ordered)
	if maxSlots%32 != 0 {
		return allocationMultipleErr("storage", maxSlots)
	}
	for index := range q.storageVals.special {
		if index >= maxSlots {
			return allocationIndexErr("storage", index, maxSlots)
		}
	}
	if numStorages > maxSlots {
		return allocationLenErr("storage", numStorages, maxSlots)
	}
	numTxs := len(q.txs.special) + len(q.txs.ordered)
	if maxTxs%32 != 0 {
		return allocationMultipleErr("transaction", maxTxs)
	}
	for index := range q.txs.special {
		if index >= maxTxs {
			return allocationIndexErr("transaction", index, maxTxs)
		}
	}
	if numTxs > maxTxs {
		return allocationLenErr("transaction", numTxs, maxTxs)
	}

	if maxReceipts == 0 && maxSlots == 0 && maxTxs == 0 && maxBlockHeaders == 0 {
		return fmt.Errorf("no receipts, slots, txs and blocks used in circuit")
	}
	return nil
}

func (q *BrevisApp) assignInputCommitment(w *CircuitInput) {
	leafs := make([]*big.Int, q.dataPoints)
	hasher := utils.NewPoseidonBn254()

	j := 0
	hic := brevisCommon.DummyBlockHeaderInputCommitment[q.srcChainId]
	if len(hic) == 0 {
		panic(fmt.Sprintf("cannot find dummy receipt info for chain %d", q.srcChainId))
	}
	hicData, err := hexutil.Decode(hic)
	if err != nil {
		panic(err.Error())
	}
	if len(hicData) == 0 {
		panic(fmt.Sprintf("cannot decode dummy receipt info for chain %d", q.srcChainId))
	}
	w.DummyReceiptInputCommitment = hicData
	for i, blockHeader := range w.BlockHeaders.Raw {
		if fromInterface(w.BlockHeaders.Toggles[i]).Sign() != 0 {
			result, err := doHash(hasher, blockHeader.goPack())
			if err != nil {
				panic(fmt.Sprintf("failed to hash receipt: %s", err.Error()))
			}
			w.InputCommitments[j] = result
			leafs[j] = result
		} else {
			w.InputCommitments[j] = hicData
			leafs[j] = new(big.Int).SetBytes(hicData)
		}
		j++
	}

	ric := brevisCommon.DummyReceiptInputCommitment[q.srcChainId]
	if len(ric) == 0 {
		panic(fmt.Sprintf("cannot find dummy receipt info for chain %d", q.srcChainId))
	}
	ricData, err := hexutil.Decode(ric)
	if err != nil {
		panic(err.Error())
	}
	if len(ricData) == 0 {
		panic(fmt.Sprintf("cannot decode dummy receipt info for chain %d", q.srcChainId))
	}
	w.DummyReceiptInputCommitment = ricData

	for i, receipt := range w.Receipts.Raw {
		if fromInterface(w.Receipts.Toggles[i]).Sign() != 0 {
			result, err := doHash(hasher, receipt.goPack())
			if err != nil {
				panic(fmt.Sprintf("failed to hash receipt: %s", err.Error()))
			}
			w.InputCommitments[j] = result
			leafs[j] = result
		} else {
			w.InputCommitments[j] = ricData
			leafs[j] = new(big.Int).SetBytes(ricData)
		}
		j++
	}

	sic := brevisCommon.DummyStorageInputCommitment[q.srcChainId]
	if len(sic) == 0 {
		panic(fmt.Sprintf("cannot find dummy receipt info for chain %d", q.srcChainId))
	}
	sicData, err := hexutil.Decode(sic)
	if err != nil {
		panic(err.Error())
	}
	if len(sicData) == 0 {
		panic(fmt.Sprintf("cannot decode dummy receipt info for chain %d", q.srcChainId))
	}
	w.DummyStorageInputCommitment = sicData

	for i, slot := range w.StorageSlots.Raw {
		if fromInterface(w.StorageSlots.Toggles[i]).Sign() != 0 {
			result, err := doHash(hasher, slot.goPack())
			if err != nil {
				panic(fmt.Sprintf("failed to hash receipt: %s", err.Error()))
			}
			w.InputCommitments[j] = result
			leafs[j] = result
		} else {
			w.InputCommitments[j] = sicData
			leafs[j] = new(big.Int).SetBytes(sicData)
		}
		j++
	}

	tic := brevisCommon.DummyTransactionInputCommitment[q.srcChainId]
	if len(tic) == 0 {
		panic(fmt.Sprintf("cannot find dummy receipt info for chain %d", q.srcChainId))
	}
	ticData, err := hexutil.Decode(tic)
	if err != nil {
		panic(err.Error())
	}
	if len(ticData) == 0 {
		panic(fmt.Sprintf("cannot decode dummy receipt info for chain %d", q.srcChainId))
	}
	w.DummyTransactionInputCommitment = ticData

	for i, tx := range w.Transactions.Raw {
		if fromInterface(w.Transactions.Toggles[i]).Sign() != 0 {
			result, err := doHash(hasher, tx.goPack())
			if err != nil {
				panic(fmt.Sprintf("failed to hash receipt: %s", err.Error()))
			}
			w.InputCommitments[j] = result
			leafs[j] = result
		} else {

			w.InputCommitments[j] = ticData
			leafs[j] = new(big.Int).SetBytes(ticData)
		}
		j++
	}

	for i := j; i < q.dataPoints; i++ {
		w.InputCommitments[i] = ticData
		leafs[i] = new(big.Int).SetBytes(ticData)
	}

	w.InputCommitmentsRoot, err = CalPoseidonBn254MerkleTree(leafs)
	if err != nil {
		panic(fmt.Sprintf("failed to dp sub hash merkel with poseidon bn254: %s", err.Error()))
	}
}

func DoHashWithPoseidonBn254(packed []*big.Int) (*big.Int, error) {
	hasher := utils.NewPoseidonBn254()
	return DoHash(hasher, packed)
}

func DoHash(hasher *utils.PoseidonBn254Hasher, packed []*big.Int) (*big.Int, error) {
	return doHash(hasher, packed)
}

func doHash(hasher *utils.PoseidonBn254Hasher, packed []*big.Int) (*big.Int, error) {
	for _, v := range packed {
		hasher.Write(new(big.Int).SetBytes(common.LeftPadBytes(v.Bytes(), 32)))
	}
	ret, err := hasher.Sum()
	if err != nil {
		return nil, err
	}
	hasher.Reset()
	return ret, nil
}

// To reduce toggles commitment constraint comsumption,
// hash 32 toggles into one value which is used as merkle tree leaf.
func (q *BrevisApp) assignToggleCommitment(in *CircuitInput) {
	var err error
	in.TogglesCommitment, err = q.calTogglesHashRoot(in.Toggles())
	if err != nil {
		log.Panicf("fail to CalTogglesHashRoot, err: %v", err)
	}
}

func (q *BrevisApp) calTogglesHashRoot(toggles []frontend.Variable) (*big.Int, error) {
	leafs := make([]*big.Int, q.dataPoints/32)
	if len(toggles)%32 != 0 {
		return nil, fmt.Errorf("invalid toggles length %d", len(toggles))
	}

	hasher := utils.NewPoseidonBn254()

	for i := range leafs {
		var toggleBits []uint
		for _, t := range toggles[i*32 : i*32+32] {
			toggleBits = append(toggleBits, uint(fromInterface(t).Uint64()))
		}
		packed := packBitsToInt(toggleBits, bn254_fr.Bits-1)
		hasher.Reset()
		for _, v := range packed {
			hasher.Write(v)
		}
		result, err := hasher.Sum()
		if err != nil {
			return nil, err
		}
		leafs[i] = result
	}

	togglesHashRoot, err := CalPoseidonBn254MerkleTree(leafs)
	if err != nil {
		panic(fmt.Sprintf("fail to cal toggles hash root %v", err))
	}
	return togglesHashRoot, nil
}
