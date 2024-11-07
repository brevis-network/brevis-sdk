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
	Receipts map[string]*ReceiptData     `json:"receipts,omitempty"`
	Storages map[string]*StorageData     `json:"storage_slots,omitempty"`
	Txs      map[string]*TransactionData `json:"txs,omitempty"`
}

type ReceiptPos struct {
	TxHash common.Hash   `json:"tx_hash,omitempty"`
	Fields []LogFieldPos `json:"fields,omitempty"`
}

// LogFieldPos represents a single field of an event.
type LogFieldPos struct {
	// the log's position in the receipt
	LogPos uint `json:"log_index,omitempty"`
	// Whether the field is a topic (aka "indexed" as in solidity events)
	IsTopic bool `json:"is_topic,omitempty"`
	// The index of the field in either a log's topics or data. For example, if a
	// field is the second topic of a log, then FieldIndex is 1; if a field is the
	// third field in the RLP decoded data, then FieldIndex is 2.
	FieldIndex uint `json:"field_index,omitempty"`
}

type StoragePos struct {
	BlockNum *big.Int       `json:"block_num,omitempty"`
	Address  common.Address `json:"address,omitempty"`
	Slot     common.Hash    `json:"slot,omitempty"`
}

type TransactionPos struct {
	Hash common.Hash `json:"hash,omitempty"`
}

func (q *ReceiptData) isReadyToSave() bool {
	return q.BlockBaseFee != nil && q.BlockNum != nil && q.MptKeyPath != nil && q.BlockBaseFee.Sign() == 1 && q.BlockNum.Sign() == 1 && q.MptKeyPath.Sign() == 1
}

func (q *StorageData) isReadyToSave() bool {
	return q.BlockBaseFee != nil && q.BlockBaseFee.Sign() == 1
}

func (q *TransactionData) isReadyToSave() bool {
	return q.BlockBaseFee != nil && q.BlockNum != nil && q.MptKeyPath != nil && q.BlockBaseFee.Sign() == 1 && q.BlockNum.Sign() == 1 && q.MptKeyPath.Sign() == 1
}

func generateReceiptKey(receipt ReceiptData, srcChainId uint64) string {
	data, err := json.Marshal(convertReceiptDataToReceiptPos(receipt))
	data = append(data, new(big.Int).SetUint64(srcChainId).Bytes()...)
	if err != nil {
		panic("failed to generate receipt data persistence key")
	}
	return crypto.Keccak256Hash(data).Hex()
}

func generateStorageKey(storage StorageData, srcChainId uint64) string {
	data, err := json.Marshal(convertStorageDataToStoragePos(storage))
	data = append(data, new(big.Int).SetUint64(srcChainId).Bytes()...)
	if err != nil {
		panic("failed to generate storage data persistence key")
	}
	return crypto.Keccak256Hash(data).Hex()
}

func generateTxKey(tx TransactionData, srcChainId uint64) string {
	data, err := json.Marshal(convertTxDataToTxPos(tx))
	data = append(data, new(big.Int).SetUint64(srcChainId).Bytes()...)
	if err != nil {
		panic("failed to generate tx data persistence key")
	}
	return crypto.Keccak256Hash(data).Hex()
}

func readDataFromLocalStorage(path string) *DataPersistence {
	fmt.Printf(">> scan local storage: %s\n", path)
	empty := &DataPersistence{
		Receipts: map[string]*ReceiptData{},
		Storages: map[string]*StorageData{},
		Txs:      map[string]*TransactionData{},
	}
	path = os.ExpandEnv(path)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf(">> no local storage record: %s", err.Error())
		return empty
	}
	result := DataPersistence{
		Receipts: map[string]*ReceiptData{},
		Storages: map[string]*StorageData{},
		Txs:      map[string]*TransactionData{},
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

func buildLogFieldsData(fs []LogFieldData, receipt *types.Receipt) (fields []LogFieldData, err error) {
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

		fields = append(fields, LogFieldData{
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

func convertReceiptDataToReceipt(r *ReceiptData) Receipt {
	var fields [NumMaxLogFields]LogField
	for i, log := range r.Fields {
		fields[i] = convertFieldDataToField(log)
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

func convertFieldDataToField(f LogFieldData) LogField {
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

func convertStorageDataToStorage(data *StorageData) StorageSlot {
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

func convertTxDataToTransaction(data *TransactionData) Transaction {
	return Transaction{
		BlockNum:     ConstUint32(data.BlockNum),
		BlockBaseFee: newU248(data.BlockBaseFee),
		MptKeyPath:   newU32(data.MptKeyPath),
		LeafHash:     ConstBytes32(data.LeafHash.Bytes()),
	}
}

func convertReceiptDataToReceiptPos(data ReceiptData) ReceiptPos {
	fields := make([]LogFieldPos, len(data.Fields))
	for i, fieldData := range data.Fields {
		fields[i] = convertLogFieldDataToLogFieldPos(fieldData)
	}
	return ReceiptPos{
		TxHash: data.TxHash,
		Fields: fields,
	}
}

func convertLogFieldDataToLogFieldPos(data LogFieldData) LogFieldPos {
	return LogFieldPos{
		LogPos:     data.LogPos,
		IsTopic:    data.IsTopic,
		FieldIndex: data.FieldIndex,
	}
}

func convertStorageDataToStoragePos(data StorageData) StoragePos {
	return StoragePos{
		BlockNum: data.BlockNum,
		Address:  data.Address,
		Slot:     data.Slot,
	}
}

func convertTxDataToTxPos(data TransactionData) TransactionPos {
	return TransactionPos{
		Hash: data.Hash,
	}
}
