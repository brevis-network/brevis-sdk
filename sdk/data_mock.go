package sdk

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Mock Data should be used only for application circuit testing
type MockReceipt struct {
	BlockNum     *big.Int        `json:"block_num,omitempty"`
	BlockBaseFee *big.Int        `json:"block_base_fee,omitempty"`
	MptKeyPath   *big.Int        `json:"mpt_key_path,omitempty"`
	Fields       []*MockLogField `json:"fields,omitempty"`
}

type MockLogField struct {
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

type MockStorage struct {
	BlockNum     *big.Int       `json:"block_num,omitempty"`
	BlockBaseFee *big.Int       `json:"block_base_fee,omitempty"`
	Address      common.Address `json:"address,omitempty"`
	Slot         common.Hash    `json:"slot,omitempty"`
	Value        common.Hash    `json:"value,omitempty"`
}

type MockTransaction struct {
	Hash         common.Hash `json:"hash,omitempty"`
	BlockNum     *big.Int    `json:"block_num,omitempty"`
	BlockBaseFee *big.Int    `json:"block_base_fee,omitempty"`
	MptKeyPath   *big.Int    `json:"mpt_key_path,omitempty"`
	LeafHash     common.Hash `json:"leaf_hash,omitempty"`
}

func (q *BrevisApp) assignMockReceipts(in *CircuitInput) error {
	// assigning user appointed receipts at specific indices
	for i, r := range q.mockReceipts.special {
		receipt, err := q.buildMockReceipt(r)
		if err != nil {
			return err
		}
		in.Receipts.Raw[i] = receipt
		in.Receipts.Toggles[i] = 1
	}

	// distribute other receipts in order to the rest of the unassigned spaces
	j := 0
	for _, r := range q.mockReceipts.ordered {
		for in.Receipts.Toggles[j] == 1 {
			j++
		}
		receipt, err := q.buildMockReceipt(r)
		if err != nil {
			return err
		}
		in.Receipts.Raw[j] = receipt
		in.Receipts.Toggles[j] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) buildMockReceipt(r MockReceipt) (Receipt, error) {
	var fields [NumMaxLogFields]LogField
	for i, log := range r.Fields {
		fields[i] = LogField{
			Contract: ConstUint248(log.Contract),
			LogPos:   ConstUint32(log.LogPos),
			// we only constrain the first 6 bytes of EventID in circuit for performance reasons
			// 6 bytes give us 1/2^48 chance of two logs of different IDs clashing per contract.
			EventID: ConstUint248(log.EventID.Bytes()[0:6]),
			IsTopic: ConstUint248(log.IsTopic),
			Index:   ConstUint248(log.FieldIndex),
			Value:   ConstBytes32(log.Value[:]),
		}
	}
	if len(r.Fields) == 0 {
		fields[0] = LogField{
			Contract: ConstUint248(0),
			LogPos:   ConstUint32(0),
			EventID:  ConstUint248(0),
			IsTopic:  ConstUint248(0),
			Index:    ConstUint248(0),
			Value:    ConstBytes32([]byte{}),
		}
		fields[1] = fields[0]
		fields[2] = fields[0]
		fields[3] = fields[0]
	} else {
		for i := len(r.Fields); i < NumMaxLogFields; i++ {
			fields[i] = fields[len(r.Fields)-1]
		}
	}
	return Receipt{
		BlockNum:     newU32(r.BlockNum),
		BlockBaseFee: newU248(r.BlockBaseFee),
		MptKeyPath:   newU32(r.MptKeyPath),
		Fields:       fields,
	}, nil
}

func (q *BrevisApp) assignMockStorageSlots(in *CircuitInput) (err error) {
	// assigning user appointed data at specific indices
	for i, val := range q.mockStorage.special {
		s, err := q.buildMockStorageSlot(val)
		if err != nil {
			return err
		}
		in.StorageSlots.Raw[i] = s
		in.StorageSlots.Toggles[i] = 1
	}

	// distribute other data in order to the rest of the unassigned spaces
	j := 0
	for _, val := range q.mockStorage.ordered {
		for in.StorageSlots.Toggles[j] == 1 {
			j++
		}
		s, err := q.buildMockStorageSlot(val)
		if err != nil {
			return err
		}
		in.StorageSlots.Raw[j] = s
		in.StorageSlots.Toggles[j] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) buildMockStorageSlot(s MockStorage) (StorageSlot, error) {
	return StorageSlot{
		BlockNum:     newU32(s.BlockNum),
		BlockBaseFee: newU248(s.BlockBaseFee),
		Contract:     ConstUint248(s.Address),
		Slot:         ConstBytes32(s.Slot[:]),
		Value:        ConstBytes32(s.Value[:]),
	}, nil
}

func (q *BrevisApp) assignMockTransactions(in *CircuitInput) (err error) {
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

func (q *BrevisApp) buildMockTx(t MockTransaction) (Transaction, error) {
	return Transaction{
		BlockNum:     ConstUint32(t.BlockNum),
		BlockBaseFee: newU248(t.BlockBaseFee),
		MptKeyPath:   newU32(t.MptKeyPath),
		LeafHash:     ConstBytes32(t.LeafHash.Bytes()),
	}, nil
}
