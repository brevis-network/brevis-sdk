package sdk

import (
	"fmt"
	"math/big"

	"github.com/brevis-network/zk-hash/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type ReceiptData struct {
	TxHash       common.Hash    `json:"tx_hash,omitempty"`        // Required value
	BlockNum     *big.Int       `json:"block_num,omitempty"`      // Optional value
	BlockBaseFee *big.Int       `json:"block_base_fee,omitempty"` // Optional value
	MptKeyPath   *big.Int       `json:"mpt_key_path,omitempty"`   // Optional value
	Fields       []LogFieldData `json:"fields,omitempty"`         // required value
}

type LogFieldData struct {
	// The contract from which the event is emitted
	// Optional value
	Contract common.Address `json:"contract,omitempty"`
	// The event ID of the event to which the field belong (aka topics[0])
	// Optional value
	EventID common.Hash `json:"event_id,omitempty"`
	// the log's position in the receipt
	// Required value
	LogPos uint `json:"log_index,omitempty"`
	// Whether the field is a topic (aka "indexed" as in solidity events)
	// Required value
	IsTopic bool `json:"is_topic,omitempty"`
	// The index of the field in either a log's topics or data. For example, if a
	// field is the second topic of a log, then FieldIndex is 1; if a field is the
	// third field in the RLP decoded data, then FieldIndex is 2.
	// Required value
	FieldIndex uint `json:"field_index,omitempty"`
	// The value of the field in event, aka the actual thing we care about, only
	// 32-byte fixed length values are supported.
	// Optional value
	Value common.Hash `json:"value,omitempty"`
}

type StorageData struct {
	BlockNum     *big.Int       `json:"block_num,omitempty"`      // Required value
	BlockBaseFee *big.Int       `json:"block_base_fee,omitempty"` // Optional value
	Address      common.Address `json:"address,omitempty"`        // Required value
	Slot         common.Hash    `json:"slot,omitempty"`           // Required value
	Value        common.Hash    `json:"value,omitempty"`          // Optional value
}

type TransactionData struct {
	Hash         common.Hash `json:"hash,omitempty"`           // Required value
	BlockNum     *big.Int    `json:"block_num,omitempty"`      // Optional value
	BlockBaseFee *big.Int    `json:"block_base_fee,omitempty"` // Optional value
	MptKeyPath   *big.Int    `json:"mpt_key_path,omitempty"`   // Optional value
	LeafHash     common.Hash `json:"leaf_hash,omitempty"`      // Optional value
}

type BlockHeaderData struct {
	BlockNum *big.Int      `json:"block_num,omitempty"` // Required value
	Header   *types.Header `json:"header,omitempty"`    // Optional value
}

type rawData[T ReceiptData | StorageData | TransactionData | BlockHeaderData] struct {
	ordered []T
	special map[int]T
}

func (q *rawData[T]) add(data T, index ...int) {
	if len(index) > 1 {
		panic("no more than one index should be supplied")
	}
	if q.special == nil {
		q.special = make(map[int]T)
	}
	if len(index) == 1 {
		if _, ok := q.special[index[0]]; ok {
			panic(fmt.Sprintf("an element already pinned at index %d", index[0]))
		}
		q.special[index[0]] = data
	} else {
		q.ordered = append(q.ordered, data)
	}
}

func (q *rawData[T]) list(max int) []T {
	var l []T
	ordered := q.ordered
	for i := 0; i < max; i++ {
		if e, ok := q.special[i]; ok {
			l = append(l, e)
		} else if len(ordered) > 0 {
			l = append(l, ordered[0])
			ordered = ordered[1:]
		}
	}
	return l
}

// AddReceipt adds the ReceiptData to be queried. If an index is specified, the
// data will be assigned to the specified index of DataInput.Receipts.
func (q *BrevisApp) AddReceipt(data ReceiptData, index ...int) {
	if len(data.Fields) > NumMaxLogFields {
		panic(fmt.Sprintf("maximum number of log fields in one receipt is %d", NumMaxLogFields))
	}
	q.receipts.add(data, index...)
}

// AddMockReceipt adds the MockReceipt to be queried. If an index is specified, the
// data will be assigned to the specified index of DataInput.Receipts.
// It should be used ONLY for circuit implementation and testing.
func (q *BrevisApp) AddMockReceipt(data ReceiptData, index ...int) {
	if len(data.Fields) > NumMaxLogFields {
		panic(fmt.Sprintf("maximum number of log fields in one receipt is %d", NumMaxLogFields))
	}
	q.mockReceipts.add(data, index...)
}

// AddStorage adds the StorageData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.StorageSlots.
func (q *BrevisApp) AddStorage(data StorageData, index ...int) {
	if data.BlockNum == nil {
		panic(fmt.Sprintf("storage data block num missing: %+v", data))
	}
	q.storageVals.add(data, index...)
}

// AddMockStorage adds the MockStorage to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.StorageSlots.
// It should be used ONLY for circuit implementation and testing.
func (q *BrevisApp) AddMockStorage(data StorageData, index ...int) {
	q.mockStorage.add(data, index...)
}

// AddTransaction adds the TransactionData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.Transactions.
func (q *BrevisApp) AddTransaction(data TransactionData, index ...int) {
	q.txs.add(data, index...)
}

// AddMockTransaction adds the MockTransaction to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.Transactions.
// It should be used ONLY for circuit implementation and testing.
func (q *BrevisApp) AddMockTransaction(data TransactionData, index ...int) {
	q.mockTxs.add(data, index...)
}

// AddBlockHeader adds the BlockHeaderData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.BlockHeaders.
func (q *BrevisApp) AddBlockHeader(data BlockHeaderData, index ...int) {
	q.blockHeaders.add(data, index...)
}

// AddBlockHeader adds the BlockHeaderData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.BlockHeaders.
// It should be used ONLY for circuit implementation and testing.
func (q *BrevisApp) AddMockBlockHeader(data BlockHeaderData, index ...int) {
	q.mockBlockHeaders.add(data, index...)
}

func (q *BrevisApp) assignReceipts(in *CircuitInput) error {
	// assigning user appointed receipts at specific indices
	for i, r := range q.receipts.special {
		receipt, err := q.buildReceipt(r)
		if err != nil {
			return err
		}
		in.Receipts.Raw[i] = receipt
		in.Receipts.Toggles[i] = 1
	}

	// distribute other receipts in order to the rest of the unassigned spaces
	j := 0
	for _, r := range q.receipts.ordered {
		for in.Receipts.Toggles[j] == 1 {
			j++
		}
		receipt, err := q.buildReceipt(r)
		if err != nil {
			return err
		}
		in.Receipts.Raw[j] = receipt
		in.Receipts.Toggles[j] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) BuildReceipt(t ReceiptData) (Receipt, error) {
	return q.buildReceipt(t)
}

func (q *BrevisApp) buildReceipt(r ReceiptData) (Receipt, error) {
	key := generateReceiptKey(r, q.srcChainId)
	data := q.localInputData.Receipts[key]
	if data == nil {
		if r.isReadyToSave() {
			fmt.Println("adding manual input receipt data")
			data = &r
		} else {
			receiptInfo, mptKey, blockNum, blockBaseFee, err := q.getReceiptInfos(r.TxHash)
			if err != nil {
				return Receipt{}, err
			}
			fields, err := buildLogFieldsData(r.Fields, receiptInfo)
			if err != nil {
				return Receipt{}, err
			}

			data = &ReceiptData{
				TxHash:       r.TxHash,
				BlockNum:     blockNum,
				BlockBaseFee: blockBaseFee,
				MptKeyPath:   mptKey,
				Fields:       fields,
			}
		}
		q.localInputData.Receipts[key] = data
	}
	return convertReceiptDataToReceipt(data), nil
}

func (q *BrevisApp) assignStorageSlots(in *CircuitInput) (err error) {
	// assigning user appointed data at specific indices
	for i, val := range q.storageVals.special {
		s, err := q.buildStorageSlot(val)
		if err != nil {
			return err
		}
		in.StorageSlots.Raw[i] = s
		in.StorageSlots.Toggles[i] = 1
	}

	// distribute other data in order to the rest of the unassigned spaces
	j := 0
	for _, val := range q.storageVals.ordered {
		for in.StorageSlots.Toggles[j] == 1 {
			j++
		}
		s, err := q.buildStorageSlot(val)
		if err != nil {
			return err
		}
		in.StorageSlots.Raw[j] = s
		in.StorageSlots.Toggles[j] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) BuildStorageSlot(s StorageData) (StorageSlot, error) {
	return q.buildStorageSlot(s)
}

func (q *BrevisApp) buildStorageSlot(s StorageData) (StorageSlot, error) {
	key := generateStorageKey(s, q.srcChainId)
	data := q.localInputData.Storages[key]
	if data == nil {
		if s.isReadyToSave() {
			fmt.Println("adding manual input storage data")
			data = &s
		} else {
			blockBaseFee, err := q.getBlockBaseFee(s.BlockNum)
			if err != nil {
				return StorageSlot{}, nil
			}

			value, err := q.getStorageValue(s.BlockNum, s.Address, s.Slot)
			if err != nil {
				return StorageSlot{}, nil
			}

			data = &StorageData{
				BlockNum:     s.BlockNum,
				BlockBaseFee: blockBaseFee,
				Address:      s.Address,
				Slot:         s.Slot,
				Value:        value,
			}
		}
		q.localInputData.Storages[key] = data
	}

	return convertStorageDataToStorage(data), nil
}

func (q *BrevisApp) assignTransactions(in *CircuitInput) (err error) {
	// assigning user appointed data at specific indices
	for i, t := range q.txs.special {
		tx, err := q.buildTx(t)
		if err != nil {
			return err
		}
		in.Transactions.Raw[i] = tx
		in.Transactions.Toggles[i] = 1
	}

	j := 0
	for i, t := range q.txs.ordered {
		for in.Transactions.Toggles[j] == 1 {
			j++
		}
		tx, err := q.buildTx(t)
		if err != nil {
			return err
		}
		in.Transactions.Raw[i] = tx
		in.Transactions.Toggles[i] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) BuildTx(t TransactionData) (Transaction, error) {
	return q.buildTx(t)
}

func (q *BrevisApp) buildTx(t TransactionData) (Transaction, error) {
	key := generateTxKey(t, q.srcChainId)
	data := q.localInputData.Txs[key]
	if data == nil {
		if t.isReadyToSave() {
			data = &t
		} else {
			leafHash, mptKey, blockNumber, baseFee, err := q.calculateTxLeafHashBlockBaseFeeAndMPTKey(t.Hash)
			if err != nil {
				return Transaction{}, err
			}

			data = &TransactionData{
				Hash:         t.Hash,
				BlockNum:     blockNumber,
				BlockBaseFee: baseFee,
				MptKeyPath:   mptKey,
				LeafHash:     leafHash,
			}
		}
		q.localInputData.Txs[key] = data
	}

	return convertTxDataToTransaction(data), nil
}

func (q *BrevisApp) assignBlockHeaders(in *CircuitInput) (err error) {
	// assigning user appointed data at specific indices
	for i, val := range q.blockHeaders.special {
		s, err := q.buildBlockHeader(val)
		if err != nil {
			return err
		}
		in.BlockHeaders.Raw[i] = s
		in.BlockHeaders.Toggles[i] = 1
	}

	// distribute other data in order to the rest of the unassigned spaces
	j := 0
	for _, val := range q.blockHeaders.ordered {
		for in.BlockHeaders.Toggles[j] == 1 {
			j++
		}
		s, err := q.buildBlockHeader(val)
		if err != nil {
			return err
		}
		in.BlockHeaders.Raw[j] = s
		in.BlockHeaders.Toggles[j] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) BuildBlockHeader(s BlockHeaderData) (BlockHeader, error) {
	return q.buildBlockHeader(s)
}

func (q *BrevisApp) buildBlockHeader(s BlockHeaderData) (BlockHeader, error) {
	key := generateBlockHeaderKey(s, q.srcChainId)
	data := q.localInputData.BlockHeaders[key]
	if data == nil {
		if s.isReadyToSave() {
			fmt.Println("adding manual input storage data")
			data = &s
		} else {
			blockHeader, err := q.getBlockHeader(s.BlockNum)
			if err != nil {
				return BlockHeader{}, nil
			}

			data = &BlockHeaderData{
				BlockNum: s.BlockNum,
				Header:   blockHeader,
			}
		}
		q.localInputData.BlockHeaders[key] = data
	}

	return convertBlockHeaderDataToBlockHeader(data), nil
}

func (q *BrevisApp) realDataLength() int {
	return len(q.receipts.ordered) + len(q.receipts.special) + len(q.storageVals.ordered) + len(q.storageVals.special) + len(q.txs.ordered) + len(q.txs.special)
}

func (q *BrevisApp) mockDataLength() int {
	return len(q.mockReceipts.ordered) + len(q.mockReceipts.special) + len(q.mockStorage.ordered) + len(q.mockStorage.special) + len(q.mockTxs.ordered) + len(q.mockTxs.special)
}

func allocationIndexErr(name string, pinnedIndex, maxCount int) error {
	return fmt.Errorf("# of pinned entry index (%d) must not exceed the allocated max %s (%d), check your AppCircuit.Allocate() method",
		pinnedIndex, name, maxCount)
}

// Reset app input, used for prover server
func (q *BrevisApp) ResetInput() {
	q.receipts = rawData[ReceiptData]{}
	q.storageVals = rawData[StorageData]{}
	q.txs = rawData[TransactionData]{}
}

func CalPoseidonBn254MerkleTree(leafs []*big.Int) (*big.Int, error) {
	if !CheckNumberPowerOfTwo(len(leafs)) {
		return nil, fmt.Errorf("not pow of 2, %d", len(leafs))
	}
	hasher := utils.NewPoseidonBn254()
	elementCount := len(leafs)
	for {
		if elementCount == 1 {
			return leafs[0], nil
		}
		for i := 0; i < elementCount/2; i++ {
			hasher.Reset()
			hasher.Write(leafs[2*i])
			hasher.Write(leafs[2*i+1])
			result, err := hasher.Sum()
			if err != nil {
				return nil, fmt.Errorf("fail to hash in CalPoseidonBn254MerkleTree, err: %v", err)
			}
			leafs[i] = result
		}
		elementCount = elementCount / 2
	}
}
