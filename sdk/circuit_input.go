package sdk

import (
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/ethereum/go-ethereum/common"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type DataInput struct {
	Receipts     DataPoints[Receipt]
	StorageSlots DataPoints[StorageSlot]
	Transactions DataPoints[Transaction]
}

func (d DataInput) Toggles() List[Variable] {
	var toggles []Variable
	toggles = append(toggles, d.Receipts.Toggles...)
	toggles = append(toggles, d.StorageSlots.Toggles...)
	toggles = append(toggles, d.Transactions.Toggles...)
	// pad the reset (the dummy part) with off toggles
	for i := len(toggles); i < NumMaxDataPoints; i++ {
		toggles = append(toggles, newV(0))
	}
	return toggles
}

type CircuitInput struct {
	// InputCommitments is a list of hash commitment to each value of Raw. These
	// commitments must match sub-prover circuit's commitment to its rlp decoded
	// values
	InputCommitments  []frontend.Variable `gnark:",public"`
	TogglesCommitment frontend.Variable   `gnark:",public"`
	// OutputCommitment is a keccak256 commitment to the computation results of the
	// developer's circuit. The output of this commitment is revealed by the
	// developer in their application contract.
	OutputCommitment OutputCommitment `gnark:",public"`

	Data DataInput

	dryRunOutput []byte `gnark:"-"`
}

func (in CircuitInput) Clone() CircuitInput {
	inputCommits := make([]frontend.Variable, len(in.InputCommitments))
	copy(inputCommits, in.InputCommitments)

	return CircuitInput{
		InputCommitments:  inputCommits,
		TogglesCommitment: in.TogglesCommitment,
		OutputCommitment:  in.OutputCommitment,
		Data: DataInput{
			Receipts:     in.Data.Receipts.Clone(),
			StorageSlots: in.Data.StorageSlots.Clone(),
			Transactions: in.Data.Transactions.Clone(),
		},
	}
}

func (in CircuitInput) Toggles() List[Variable] {
	return in.Data.Toggles()
}

func (in CircuitInput) GetAbiPackedOutput() []byte {
	ret := make([]byte, len(dryRunOutput))
	copy(ret, dryRunOutput)
	return ret
}

// OutputCommitment represents the value of a keccak256 hash H in the form of {H[:16], H[16:]}
type OutputCommitment [2]frontend.Variable

// Hash returns the go hash representation of the commitment
func (c OutputCommitment) Hash() common.Hash {
	hi := c[0].(*big.Int)
	lo := c[1].(*big.Int)
	h := new(big.Int)
	h.Lsh(hi, 128).Add(h, lo)
	return common.BytesToHash(h.Bytes())
}

type DataPoints[T any] struct {
	// Raw is the structured input data (receiptQueries, txs, and slots).
	Raw []T
	// Toggles is a bitmap that toggles the effectiveness of each position of Raw.
	// len(Toggles) must equal len(Raw)
	Toggles List[Variable]
}

func NewDataPoints[T any](maxCount int, newEmpty func() T) DataPoints[T] {
	dp := DataPoints[T]{
		Raw:     make([]T, maxCount),
		Toggles: make([]Variable, maxCount),
	}
	for i := range dp.Raw {
		dp.Raw[i] = newEmpty()
		dp.Toggles[i] = newV(0)
	}
	return dp
}

func (dp DataPoints[T]) Clone() DataPoints[T] {
	raw := make([]T, len(dp.Raw))
	copy(raw, dp.Raw)

	toggles := make([]Variable, len(dp.Toggles))
	copy(toggles, dp.Toggles)

	return DataPoints[T]{
		Raw:     raw,
		Toggles: toggles,
	}
}

// NumMaxDataPoints is the max amount of data points this circuit can handle at
// once. This couples tightly to the batch size of the aggregation circuit on
// Brevis' side
const NumMaxDataPoints = 100

// NumMaxLogFields is the max amount of log fields each Receipt can have. This
// couples tightly to the decoding capacity of the receipt decoder circuit on
// Brevis' side
const NumMaxLogFields = 3

// Receipt is a collection of LogField.
type Receipt struct {
	BlockNum Variable
	Fields   [NumMaxLogFields]LogField
}

func NewReceipt() Receipt {
	return Receipt{
		BlockNum: newV(0),
		Fields:   [3]LogField{NewLogField(), NewLogField(), NewLogField()},
	}
}

// LogField represents a single field of an event.
type LogField struct {
	// The contract from which the event is emitted
	Contract Variable
	// The event ID of the event to which the field belong (aka topics[0])
	EventID Variable
	// Whether the field is a topic (aka "indexed" as in solidity events)
	IsTopic Variable
	// The index of the field. For example, if a field is the second topic of a log, then Index is 1; if a field is the
	// third field in the RLP decoded data, then Index is 2.
	Index Variable
	// The value of the field in event, aka the actual thing we care about, only 32-byte fixed length values are supported.
	Value Bytes32
}

func NewLogField() LogField {
	return LogField{
		Contract: newV(0),
		EventID:  newV(0),
		IsTopic:  newV(0),
		Index:    newV(0),
		Value:    ParseBytes32([]byte{}),
	}
}

// pack packs the log fields into BLS12377 scalars
// 4 + 3 * 59 = 181 bytes, fits into 6 fr vars
// 59 bytes for each log field:
//   - 20 bytes for contract address
//   - 6 bytes for topic (topics are 32-byte long, but we are only using the first 6 bytes distinguish them.
//     6 bytes gives a per-contract 1/2^48 chance of two different events having the same topic)
//   - 1 bit for whether the field is a topic
//   - 7 bits for field index
//   - 32 bytes for value
func (r Receipt) pack(api frontend.API) []frontend.Variable {
	var bits []frontend.Variable
	bits = append(bits, api.ToBinary(r.BlockNum, 8*4)...)

	for _, field := range r.Fields {
		bits = append(bits, api.ToBinary(field.Contract, 8*20)...)
		bits = append(bits, api.ToBinary(field.EventID, 8*6)...)
		bits = append(bits, api.ToBinary(field.IsTopic, 1)...)
		bits = append(bits, api.ToBinary(field.Index, 7)...)
		bits = append(bits, field.Value.toBinaryVars(api)...)
	}
	return packBitsToFr(api, bits)
}

func (r Receipt) goPack() []*big.Int {
	var bits []uint
	bits = append(bits, decomposeBits(var2BigInt(r.BlockNum), 8*4)...)
	for _, field := range r.Fields {
		bits = append(bits, decomposeBits(var2BigInt(field.Contract), 8*20)...)
		bits = append(bits, decomposeBits(var2BigInt(field.EventID), 8*6)...)
		bits = append(bits, decomposeBits(var2BigInt(field.IsTopic), 1)...)
		bits = append(bits, decomposeBits(var2BigInt(field.Index), 7)...)
		bits = append(bits, field.Value.toBinary()...)
	}
	return packBitsToInt(bits, bls12377_fr.Bits-1) // pack to ints of bit size of BLS12377Fr - 1, which is 252 bits
}

func packBitsToFr(api frontend.API, bits []frontend.Variable) []frontend.Variable {
	bitSize := api.Compiler().FieldBitLen() - 1
	var r []frontend.Variable
	for i := 0; i < len(bits); i += bitSize {
		end := i + bitSize
		if end > len(bits) {
			end = len(bits)
		}
		z := api.FromBinary(bits[i:end]...)
		r = append(r, z)
	}
	return r
}

type StorageSlot struct {
	BlockNum Variable
	// The contract to which the storage slot belong
	Contract Variable
	// The key of the slot
	Key Bytes32
	// The storage slot value
	Value Bytes32
}

func NewStorageSlot() StorageSlot {
	return StorageSlot{
		BlockNum: newV(0),
		Contract: newV(0),
		Key:      ParseBytes32([]byte{}),
		Value:    ParseBytes32([]byte{}),
	}
}

// pack packs the storage slots into BLS12377 scalars
// 4 bytes for block num + 84 bytes for each slot = 672 bits, fits into 3 BLS12377 fr vars:
// - 20 bytes for contract address
// - 32 bytes for slot key
// - 32 bytes for slot value
func (s StorageSlot) pack(api frontend.API) []frontend.Variable {
	var bits []frontend.Variable
	bits = append(bits, api.ToBinary(s.BlockNum, 8*4)...)
	bits = append(bits, api.ToBinary(s.Contract, 8*20)...)
	bits = append(bits, s.Key.toBinaryVars(api)...)
	bits = append(bits, s.Value.toBinaryVars(api)...)
	return packBitsToFr(api, bits)
}

func (s StorageSlot) goPack() []*big.Int {
	var bits []uint
	bits = append(bits, decomposeBits(var2BigInt(s.BlockNum), 8*4)...)
	bits = append(bits, decomposeBits(var2BigInt(s.Contract), 8*20)...)
	bits = append(bits, s.Key.toBinary()...)
	bits = append(bits, s.Value.toBinary()...)
	return packBitsToInt(bits, bls12377_fr.Bits-1)
}

type Transaction struct {
	ChainId              Variable
	BlockNum             Variable
	Nonce                Variable
	MaxPriorityFeePerGas Variable
	MaxFeePerGas         Variable
	GasLimit             Variable
	From                 Variable
	To                   Variable
	Value                Bytes32
}

func NewTransaction() Transaction {
	return Transaction{
		ChainId:              newV(0),
		BlockNum:             newV(0),
		Nonce:                newV(0),
		MaxPriorityFeePerGas: newV(0),
		MaxFeePerGas:         newV(0),
		GasLimit:             newV(0),
		From:                 newV(0),
		To:                   newV(0),
		Value:                ParseBytes32([]byte{}),
	}
}

// pack packs the transactions into BLS12377 scalars
// chain_id - 4 bytes
// nonce - 4 bytes
// max_priority_fee_per_gas, in Gwei - 8 bytes
// max_fee_per_gas, in Gwei - 8 bytes
// gas_limit - 4 bytes
// to - 20 bytes
// from - 20 bytes
// value - 32 bytes
func (t Transaction) pack(api frontend.API) []frontend.Variable {
	var bits []frontend.Variable
	bits = append(bits, api.ToBinary(t.BlockNum, 8*4)...)
	bits = append(bits, api.ToBinary(t.ChainId, 8*4)...)
	bits = append(bits, api.ToBinary(t.Nonce, 8*4)...)
	bits = append(bits, api.ToBinary(t.MaxPriorityFeePerGas, 8*8)...)
	bits = append(bits, api.ToBinary(t.MaxFeePerGas, 8*8)...)
	bits = append(bits, api.ToBinary(t.GasLimit, 8*4)...)
	bits = append(bits, api.ToBinary(t.From, 8*20)...)
	bits = append(bits, api.ToBinary(t.To, 8*20)...)
	bits = append(bits, t.Value.toBinaryVars(api)...)
	return packBitsToFr(api, bits)
}

func (t Transaction) goPack() []*big.Int {
	var bits []uint
	bits = append(bits, decomposeBits(var2BigInt(t.BlockNum), 8*4)...)
	bits = append(bits, decomposeBits(var2BigInt(t.ChainId), 8*4)...)
	bits = append(bits, decomposeBits(var2BigInt(t.Nonce), 8*4)...)
	bits = append(bits, decomposeBits(var2BigInt(t.MaxPriorityFeePerGas), 8*8)...)
	bits = append(bits, decomposeBits(var2BigInt(t.MaxFeePerGas), 8*8)...)
	bits = append(bits, decomposeBits(var2BigInt(t.GasLimit), 8*4)...)
	bits = append(bits, decomposeBits(var2BigInt(t.From), 8*20)...)
	bits = append(bits, decomposeBits(var2BigInt(t.To), 8*20)...)
	bits = append(bits, t.Value.toBinary()...)
	return packBitsToInt(bits, bls12377_fr.Bits-1)
}
