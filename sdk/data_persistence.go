package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// To reduce rpc requests for developers, save data into local storage for future reference
type DataPersistence struct {
	Receipts map[string]*ReceiptPersistence     `json:"receipts,omitempty"`
	Storages map[string]*StoragePersistence     `json:"storage_slots,omitempty"`
	Txs      map[string]*TransactionPersistence `json:"txs,omitempty"`
}

// Used for data persistence only
type ReceiptPersistence struct {
	TxHash       common.Hash            `json:"tx_hash,omitempty"`
	BlockNum     *big.Int               `json:"block_num,omitempty"`
	BlockBaseFee *big.Int               `json:"block_base_fee,omitempty"`
	MptKeyPath   *big.Int               `json:"mpt_key_path,omitempty"`
	Fields       []*LogFieldPersistence `json:"fields,omitempty"`
}

// Used for data persistence only
type LogFieldPersistence struct {
	// The contract from which the event is emitted
	Contract common.Address `json:"contract,omitempty"`
	// The event ID of the event to which the field belong (aka topics[0])
	EventID common.Hash `json:"event_id,omitempty"`
	// the log's position in the receipt
	LogPos uint `json:"log_index,omitempty"`
	// Whether the field is a topic (aka "indexed" as in solidity events)
	IsTopic bool `json:"is_topic,omitempty"`
	// The index of the field in either a log's topics or data. For example, if a
	// field is the second topic of a log, then FieldIndex is 1; if a field is the
	// third field in the RLP decoded data, then FieldIndex is 2.
	FieldIndex uint `json:"field_index,omitempty"`
	// The value of the field in event, aka the actual thing we care about, only
	// 32-byte fixed length values are supported.
	Value common.Hash `json:"value,omitempty"`
}

// Used for data persistence only
type StoragePersistence struct {
	BlockNum     *big.Int       `json:"block_num,omitempty"`
	BlockBaseFee *big.Int       `json:"block_base_fee,omitempty"`
	Address      common.Address `json:"address,omitempty"`
	Slot         common.Hash    `json:"slot,omitempty"`
	Value        common.Hash    `json:"value,omitempty"`
}

// Used for data persistence only
type TransactionPersistence struct {
	Hash         common.Hash `json:"hash,omitempty"`
	BlockNum     *big.Int    `json:"block_num,omitempty"`
	BlockBaseFee *big.Int    `json:"block_base_fee,omitempty"`
	MptKeyPath   *big.Int    `json:"mpt_key_path,omitempty"`
	LeafHash     common.Hash `json:"leaf_hash,omitempty"`
}

func generateReceiptKey(receipt ReceiptData, srcChainId uint64) string {
	data, err := json.Marshal(receipt)
	data = append(data, new(big.Int).SetUint64(srcChainId).Bytes()...)
	if err != nil {
		panic("failed to generate receipt data persistence key")
	}
	return crypto.Keccak256Hash(data).Hex()
}

func generateStorageKey(storage StorageData, srcChainId uint64) string {
	data, err := json.Marshal(storage)
	data = append(data, new(big.Int).SetUint64(srcChainId).Bytes()...)
	if err != nil {
		panic("failed to generate receipt data persistence key")
	}
	return crypto.Keccak256Hash(data).Hex()
}

func generateTxKey(tx TransactionData, srcChainId uint64) string {
	data, err := json.Marshal(tx)
	data = append(data, new(big.Int).SetUint64(srcChainId).Bytes()...)
	if err != nil {
		panic("failed to generate receipt data persistence key")
	}
	return crypto.Keccak256Hash(data).Hex()
}

func readDataFromLocalStorage(path string) *DataPersistence {
	fmt.Printf(">> scan local storage: %s\n", path)
	empty := &DataPersistence{
		Receipts: map[string]*ReceiptPersistence{},
		Storages: map[string]*StoragePersistence{},
		Txs:      map[string]*TransactionPersistence{},
	}
	path = os.ExpandEnv(path)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf(">> no local storage record: %s", err.Error())
		return empty
	}
	result := DataPersistence{
		Receipts: map[string]*ReceiptPersistence{},
		Storages: map[string]*StoragePersistence{},
		Txs:      map[string]*TransactionPersistence{},
	}
	err = json.Unmarshal(data, &result)
	if err != nil {
		fmt.Printf(">> no local storage record: %s", err.Error())
		return empty
	}
	fmt.Printf(">> finish scan local storage: %s\n", path)
	return &result
}

func (q *BrevisApp) writeDataIntoLocalStorage() {
	fmt.Printf(">> write input data into local storage: %s\n", q.localInputDataPath)

	data, err := json.Marshal(q.localInputData)
	if err != nil {
		fmt.Printf(">> write input data into local storage failed: %s\n", err.Error())
	}

	buf := new(bytes.Buffer)
	_, err = buf.Write(data)
	if err != nil {
		fmt.Printf(">> write input data into local storage failed: %s\n", err.Error())
	}
	writer := io.WriterTo(buf)
	err = WriteTo(writer, q.localInputDataPath)
	if err != nil {
		fmt.Printf(">> write input data into local storage failed: %s\n", err.Error())
	}
	fmt.Printf(">>finish write\n")
}

func buildLogFieldsPersistence(fs []LogFieldData, receipt *types.Receipt) (fields []*LogFieldPersistence, err error) {
	if len(fs) > 4 {
		return nil, fmt.Errorf("each receipt can use up to 4 fields")
	}

	if len(fs) == 0 {
		return nil, fmt.Errorf("empty log field data for receipts: %s", receipt.TxHash.Hex())
	}

	for _, f := range fs {
		if len(receipt.Logs) <= int(f.LogPos) {
			return nil, fmt.Errorf("invalid log pos %d for receipt %s", f.LogPos, receipt.TxHash.Hex())
		}

		log := receipt.Logs[f.LogPos]

		var logValue common.Hash

		if f.IsTopic {
			if int(f.FieldIndex) >= len(log.Topics) {
				err = fmt.Errorf("invalid field index %d for receipt %s log %d, which topics length is %d", f.FieldIndex, receipt.TxHash.Hex(), f.LogPos, len(log.Topics))
				return
			}
			logValue = log.Topics[f.FieldIndex]
		} else {
			if int(f.FieldIndex)*32+32 > len(log.Data) {
				err = fmt.Errorf("invalid field index %d (try to find data range from %d to %d) for receipt %s log %d, which data length is %d", f.FieldIndex, f.FieldIndex*32, f.FieldIndex*32+32, receipt.TxHash.Hex(), f.LogPos, len(log.Data))
				return
			}
			logValue = common.BytesToHash(log.Data[f.FieldIndex*32 : f.FieldIndex*32+32])
		}

		fields = append(fields, &LogFieldPersistence{
			Contract:   log.Address,
			LogPos:     f.LogPos,
			EventID:    log.Topics[0],
			IsTopic:    f.IsTopic,
			FieldIndex: f.FieldIndex,
			Value:      logValue,
		})
	}
	return
}

// Send rpc request to query receipt related information
func (q *BrevisApp) getReceiptInfos(txHash common.Hash) (receipt *types.Receipt, mptKey *big.Int, blockNumber *big.Int, baseFee *big.Int, err error) {
	receipt, err = q.ec.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot get mpt key with wrong tx hash %s: %s", txHash.Hex(), err.Error())
	}
	mptKey = q.calculateMPTKeyWithIndex(int(receipt.TransactionIndex))
	blockNumber = receipt.BlockNumber

	block, err := q.ec.BlockByNumber(context.Background(), receipt.BlockNumber)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cannot calculate tx leaf hash with wrong tx hash %s: %s", txHash.Hex(), err.Error())
	}
	baseFee = block.BaseFee()
	return
}

func convertReceiptPersistenceToReceipt(r *ReceiptPersistence) Receipt {
	var fields [NumMaxLogFields]LogField
	for i, log := range r.Fields {
		fields[i] = convertFieldPersistenceToField(log)
	}
	for i := len(r.Fields); i < NumMaxLogFields; i++ {
		fields[i] = fields[len(r.Fields)-1]
	}
	return Receipt{
		BlockNum:     newU32(r.BlockNum),
		BlockBaseFee: newU248(r.BlockBaseFee),
		MptKeyPath:   newU32(r.MptKeyPath),
		Fields:       fields,
	}
}

func convertFieldPersistenceToField(f *LogFieldPersistence) LogField {
	return LogField{
		Contract: ConstUint248(f.Contract),
		LogPos:   ConstUint32(f.LogPos),
		// we only constrain the first 6 bytes of EventID in circuit for performance reasons
		// 6 bytes give us 1/2^48 chance of two logs of different IDs clashing per contract.
		EventID: ConstUint248(f.EventID.Bytes()[0:6]),
		IsTopic: ConstUint248(f.IsTopic),
		Index:   ConstUint248(f.FieldIndex),
		Value:   ConstBytes32(f.Value[:]),
	}
}

func (q *BrevisApp) getBlockBaseFee(blkNum *big.Int) (baseFee *big.Int, err error) {
	block, err := q.ec.BlockByNumber(context.Background(), blkNum)
	if err != nil {
		return nil, fmt.Errorf("cannot get blk base fee with wrong blkNum %d: %s", blkNum, err.Error())
	}
	baseFee = block.BaseFee()
	return
}

func (q *BrevisApp) getStorageValue(blkNum *big.Int, account common.Address, slot common.Hash) (result common.Hash, err error) {
	value, err := q.ec.StorageAt(context.Background(), account, slot, blkNum)
	if err != nil {
		return common.Hash{}, fmt.Errorf("cannot get storage value for account 0x%x with slot 0x%x blkNum %d: %s", account.Bytes(), slot, blkNum, err.Error())
	}
	return common.BytesToHash(value), nil
}

func convertStoragePersistenceToStorage(data *StoragePersistence) StorageSlot {
	return StorageSlot{
		BlockNum:     newU32(data.BlockNum),
		BlockBaseFee: newU248(data.BlockBaseFee),
		Contract:     ConstUint248(data.Address),
		Slot:         ConstBytes32(data.Slot[:]),
		Value:        ConstBytes32(data.Value[:]),
	}
}

func (q *BrevisApp) calculateTxLeafHashBlockBaseFeeAndMPTKey(txHash common.Hash) (leafHash common.Hash, mptKey *big.Int, blockNumber *big.Int, baseFee *big.Int, err error) {
	receipt, err := q.ec.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		return common.Hash{}, nil, nil, nil, fmt.Errorf("cannot calculate tx leaf hash with wrong tx hash %s: %s", txHash.Hex(), err.Error())
	}
	mptKey = q.calculateMPTKeyWithIndex(int(receipt.TransactionIndex))
	blockNumber = receipt.BlockNumber

	block, err := q.ec.BlockByNumber(context.Background(), receipt.BlockNumber)
	if err != nil {
		return common.Hash{}, nil, nil, nil, fmt.Errorf("cannot calculate tx leaf hash with wrong tx hash %s: %s", txHash.Hex(), err.Error())
	}
	baseFee = block.BaseFee()

	proofs, _, _, err := getTransactionProof(block, int(receipt.TransactionIndex))
	if err != nil {
		return common.Hash{}, nil, nil, nil, fmt.Errorf("cannot calculate tx leaf hash with wrong tx hash %s: %s", txHash.Hex(), err.Error())
	}

	leafHash = common.BytesToHash(crypto.Keccak256(proofs[len(proofs)-1]))

	return
}

func convertTxPersistenceToTransaction(data *TransactionPersistence) Transaction {
	return Transaction{
		BlockNum:     ConstUint32(data.BlockNum),
		BlockBaseFee: newU248(data.BlockBaseFee),
		MptKeyPath:   newU32(data.MptKeyPath),
		LeafHash:     ConstBytes32(data.LeafHash.Bytes()),
	}
}
