package sdk

import (
	"math/big"

	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/common"

	"github.com/consensys/gnark/frontend"
)

type DataInput struct {
	Receipts     DataPoints[Receipt]
	StorageSlots DataPoints[StorageSlot]
	Transactions DataPoints[Transaction]
	BlockHeaders DataPoints[BlockHeader]
}

func defaultDataInput(maxReceipts, maxStorage, maxTxs, maxBlockHeaders int) DataInput {
	return DataInput{
		Receipts:     NewDataPoints(maxReceipts, defaultReceipt),
		StorageSlots: NewDataPoints(maxStorage, defaultStorageSlot),
		Transactions: NewDataPoints(maxTxs, defaultTransaction),
		BlockHeaders: NewDataPoints(maxBlockHeaders, defaultBlockHeader),
	}
}

func (d DataInput) Toggles() []frontend.Variable {
	var toggles []frontend.Variable
	toggles = append(toggles, d.Receipts.Toggles...)
	toggles = append(toggles, d.StorageSlots.Toggles...)
	toggles = append(toggles, d.Transactions.Toggles...)
	dataPoints := DataPointsNextPowerOf2(len(d.Receipts.Toggles) + len(d.StorageSlots.Toggles) + len(d.Transactions.Toggles))
	// pad the reset (the dummy part) with off toggles
	for i := len(toggles); i < dataPoints; i++ {
		toggles = append(toggles, 0)
	}
	return toggles
}

type CircuitInput struct {
	DataInput

	// InputCommitments is a list of hash commitment to each value of Raw. These
	// commitments must match sub-prover circuit's commitment to its rlp decoded
	// values
	InputCommitmentsRoot frontend.Variable `gnark:",public"`
	InputCommitments     []frontend.Variable
	TogglesCommitment    frontend.Variable
	// OutputCommitment is a keccak256 commitment to the computation results of the
	// developer's circuit. The output of this commitment is revealed by the
	// developer in their application contract.
	OutputCommitment                OutputCommitment  `gnark:",public"`
	DummyReceiptInputCommitment     frontend.Variable `gnark:",public"`
	DummyStorageInputCommitment     frontend.Variable `gnark:",public"`
	DummyTransactionInputCommitment frontend.Variable `gnark:",public"`
	DummyBlockHeaderInputCommitment frontend.Variable `gnark:",public"`

	dryRunOutput []byte `gnark:"-"`
}

func defaultCircuitInput(maxReceipts, maxStorage, maxTxs, maxBlockHeaders, dataPoints int) CircuitInput {
	var inputCommits = make([]frontend.Variable, dataPoints)
	for i := 0; i < dataPoints; i++ {
		inputCommits[i] = 0
	}
	return CircuitInput{
		DataInput:                       defaultDataInput(maxReceipts, maxStorage, maxTxs, maxBlockHeaders),
		InputCommitmentsRoot:            0,
		InputCommitments:                inputCommits,
		TogglesCommitment:               0,
		OutputCommitment:                OutputCommitment{0, 0},
		DummyReceiptInputCommitment:     0,
		DummyStorageInputCommitment:     0,
		DummyTransactionInputCommitment: 0,
		DummyBlockHeaderInputCommitment: 0,
	}
}

func (in CircuitInput) Clone() CircuitInput {
	inputCommits := make([]frontend.Variable, len(in.InputCommitments))
	copy(inputCommits, in.InputCommitments)

	return CircuitInput{
		InputCommitmentsRoot:            in.InputCommitmentsRoot,
		InputCommitments:                inputCommits,
		TogglesCommitment:               in.TogglesCommitment,
		OutputCommitment:                in.OutputCommitment,
		DummyReceiptInputCommitment:     in.DummyReceiptInputCommitment,
		DummyStorageInputCommitment:     in.DummyStorageInputCommitment,
		DummyTransactionInputCommitment: in.DummyTransactionInputCommitment,
		DummyBlockHeaderInputCommitment: in.DummyBlockHeaderInputCommitment,
		DataInput: DataInput{
			Receipts:     in.Receipts.Clone(),
			StorageSlots: in.StorageSlots.Clone(),
			Transactions: in.Transactions.Clone(),
			BlockHeaders: in.BlockHeaders.Clone(),
		},
	}
}

func (in CircuitInput) GetAbiPackedOutput() []byte {
	ret := make([]byte, len(in.dryRunOutput))
	copy(ret, in.dryRunOutput)
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
	// Raw is the structured input data (receipts, txs, and slots).
	Raw []T
	// Toggles is a bitmap that toggles the effectiveness of each position of Raw.
	// len(Toggles) must equal len(Raw)
	Toggles []frontend.Variable
}

func NewDataPoints[T any](maxCount int, newEmpty func() T) DataPoints[T] {
	dp := DataPoints[T]{
		Raw:     make([]T, maxCount),
		Toggles: make([]frontend.Variable, maxCount),
	}
	for i := range dp.Raw {
		dp.Raw[i] = newEmpty()
		dp.Toggles[i] = 0
	}
	return dp
}

func (dp DataPoints[T]) Clone() DataPoints[T] {
	raw := make([]T, len(dp.Raw))
	copy(raw, dp.Raw)

	toggles := make([]frontend.Variable, len(dp.Toggles))
	copy(toggles, dp.Toggles)

	return DataPoints[T]{
		Raw:     raw,
		Toggles: toggles,
	}
}

// NumMaxLogFields is the max amount of log fields each Receipt can have. This
// couples tightly to the decoding capacity of the receipt decoder circuit on
// Brevis' side
const NumMaxLogFields = 4

// Receipt is a collection of LogField.
type Receipt struct {
	BlockNum     Uint32
	BlockBaseFee Uint248
	MptKeyPath   Uint32
	Fields       [NumMaxLogFields]LogField
}

func DefaultReceipt() Receipt {
	return defaultReceipt()
}

func defaultReceipt() Receipt {
	r := Receipt{
		BlockNum:     newU32(0),
		BlockBaseFee: newU248(0),
		MptKeyPath:   newU32(0),
		Fields:       [NumMaxLogFields]LogField{},
	}
	for i := range r.Fields {
		r.Fields[i] = defaultLogField()
	}
	return r
}

var _ CircuitVariable = Receipt{}

func (r Receipt) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, r.BlockNum.Values()...)
	ret = append(ret, r.BlockBaseFee.Values()...)
	ret = append(ret, r.MptKeyPath.Values()...)
	for _, field := range r.Fields {
		ret = append(ret, field.Values()...)
	}
	return ret
}

func (r Receipt) FromValues(vs ...frontend.Variable) CircuitVariable {
	nr := Receipt{}

	start, end := uint32(0), r.BlockNum.NumVars()
	nr.BlockNum = r.BlockNum.FromValues(vs[start:end]...).(Uint32)

	start, end = end, end+r.BlockBaseFee.NumVars()
	nr.BlockBaseFee = r.BlockBaseFee.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+r.MptKeyPath.NumVars()
	nr.MptKeyPath = r.MptKeyPath.FromValues(vs[start:end]...).(Uint32)

	for i, f := range r.Fields {
		start, end = end, end+f.NumVars()
		nr.Fields[i] = f.FromValues(vs[start:end]...).(LogField)
	}
	return nr
}

func (r Receipt) NumVars() uint32 {
	sum := r.BlockNum.NumVars()
	sum += r.BlockBaseFee.NumVars()
	for _, field := range r.Fields {
		sum += field.NumVars()
	}
	return sum
}

func (r Receipt) String() string { return "Receipt" }

// LogField represents a single field of an event.
type LogField struct {
	// The contract from which the event is emitted
	Contract Uint248
	// the log position in the receipt
	LogPos Uint32
	// The event ID of the event to which the field belong (aka topics[0])
	EventID Uint248
	// Whether the field is a topic (aka "indexed" as in solidity events)
	IsTopic Uint248
	// The index of the field. For example, if a field is the second topic of a log, then Index is 1; if a field is the
	// third field in the RLP decoded data, then Index is 2.
	Index Uint248
	// The value of the field in event, aka the actual thing we care about, only 32-byte fixed length values are supported.
	Value Bytes32
}

func defaultLogField() LogField {
	return LogField{
		Contract: newU248(0),
		LogPos:   newU32(0),
		EventID:  newU248(0),
		IsTopic:  newU248(0),
		Index:    newU248(0),
		Value:    ConstFromBigEndianBytes([]byte{}),
	}
}

var _ CircuitVariable = LogField{}

func (f LogField) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, f.Contract.Values()...)
	ret = append(ret, f.LogPos.Values()...)
	ret = append(ret, f.EventID.Values()...)
	ret = append(ret, f.IsTopic.Values()...)
	ret = append(ret, f.Index.Values()...)
	ret = append(ret, f.Value.Values()...)
	return ret
}

func (f LogField) FromValues(vs ...frontend.Variable) CircuitVariable {
	nf := LogField{}

	start, end := uint32(0), f.Contract.NumVars()
	nf.Contract = f.Contract.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+f.LogPos.NumVars()
	nf.LogPos = f.LogPos.FromValues(vs[start:end]...).(Uint32)

	start, end = end, end+f.EventID.NumVars()
	nf.EventID = f.EventID.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+f.IsTopic.NumVars()
	nf.IsTopic = f.IsTopic.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+f.Index.NumVars()
	nf.Index = f.Index.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+f.Value.NumVars()
	nf.Value = f.Value.FromValues(vs[start:end]...).(Bytes32)

	return nf
}

func (f LogField) String() string { return "LogField" }

func (f LogField) NumVars() uint32 {
	return f.Contract.NumVars() +
		f.LogPos.NumVars() +
		f.EventID.NumVars() +
		f.IsTopic.NumVars() +
		f.Index.NumVars() +
		f.Value.NumVars()
}

// pack packs the log fields into Bn254 scalars
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
	bits = append(bits, api.ToBinary(r.BlockNum.Val, 8*4)...)
	bits = append(bits, api.ToBinary(r.BlockBaseFee.Val, 8*16)...)
	bits = append(bits, api.ToBinary(r.MptKeyPath.Val, 4*8)...)
	for _, field := range r.Fields {
		bits = append(bits, api.ToBinary(field.Contract.Val, 8*20)...)
		bits = append(bits, api.ToBinary(field.LogPos.Val, 8*2)...)
		bits = append(bits, api.ToBinary(field.EventID.Val, 8*6)...)
		bits = append(bits, api.ToBinary(field.IsTopic.Val, 1)...)
		bits = append(bits, api.ToBinary(field.Index.Val, 7)...)
		bits = append(bits, field.Value.toBinaryVars(api)...)
	}
	return packBitsToFr(api, bits)
}

func (r Receipt) Pack(api frontend.API) []frontend.Variable {
	return r.pack(api)
}

func (r Receipt) GoPack() []*big.Int {
	return r.goPack()
}

func (r Receipt) goPack() []*big.Int {
	var bits []uint
	bits = append(bits, decomposeBits(fromInterface(r.BlockNum.Val), 8*4)...)
	bits = append(bits, decomposeBits(fromInterface(r.BlockBaseFee.Val), 8*16)...)
	bits = append(bits, decomposeBits(fromInterface(r.MptKeyPath.Val), 8*4)...)
	for _, field := range r.Fields {
		bits = append(bits, decomposeBits(fromInterface(field.Contract.Val), 8*20)...)
		bits = append(bits, decomposeBits(fromInterface(field.LogPos.Val), 8*2)...)
		bits = append(bits, decomposeBits(fromInterface(field.EventID.Val), 8*6)...)
		bits = append(bits, decomposeBits(fromInterface(field.IsTopic.Val), 1)...)
		bits = append(bits, decomposeBits(fromInterface(field.Index.Val), 7)...)
		bits = append(bits, field.Value.toBinary()...)
	}
	return packBitsToInt(bits, bn254_fr.Bits-1) // pack to ints of bit size of Bn254Fr - 1, which is 252 bits
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
	BlockNum     Uint32
	BlockBaseFee Uint248

	// The contract to which the storage slot belong
	Contract Uint248
	// The storage slot
	Slot Bytes32
	// The storage slot value
	Value Bytes32
}

func defaultStorageSlot() StorageSlot {
	return StorageSlot{
		BlockNum:     newU32(0),
		BlockBaseFee: newU248(0),
		Contract:     newU248(0),
		Slot:         ConstFromBigEndianBytes([]byte{}),
		Value:        ConstFromBigEndianBytes([]byte{}),
	}
}

var _ CircuitVariable = StorageSlot{}

func (s StorageSlot) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, s.BlockNum.Values()...)
	ret = append(ret, s.BlockBaseFee.Values()...)
	ret = append(ret, s.Contract.Values()...)
	ret = append(ret, s.Slot.Values()...)
	ret = append(ret, s.Value.Values()...)
	return ret
}

func (s StorageSlot) FromValues(vs ...frontend.Variable) CircuitVariable {
	nr := StorageSlot{}

	start, end := uint32(0), s.BlockNum.NumVars()
	nr.BlockNum = s.BlockNum.FromValues(vs[start:end]...).(Uint32)

	start, end = end, end+s.BlockBaseFee.NumVars()
	nr.BlockBaseFee = s.BlockBaseFee.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+s.Contract.NumVars()
	nr.Contract = s.Contract.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+s.Slot.NumVars()
	nr.Slot = s.Slot.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+s.Value.NumVars()
	nr.Value = s.Value.FromValues(vs[start:end]...).(Bytes32)

	return nr
}

func (s StorageSlot) NumVars() uint32 {
	return s.BlockNum.NumVars() + s.BlockBaseFee.NumVars() + s.Contract.NumVars() + s.Slot.NumVars() + s.Value.NumVars()
}

func (s StorageSlot) String() string { return "StorageSlot" }

func (s StorageSlot) Pack(api frontend.API) []frontend.Variable {
	return s.pack(api)
}

// pack packs the storage slots into Bn254 scalars
// 4 bytes for block num + 84 bytes for each slot = 672 bits, fits into 3 Bn254 fr vars:
// - 20 bytes for contract address
// - 32 bytes for slot key
// - 32 bytes for slot value
func (s StorageSlot) pack(api frontend.API) []frontend.Variable {
	var bits []frontend.Variable
	bits = append(bits, api.ToBinary(s.BlockNum.Val, 8*4)...)
	bits = append(bits, api.ToBinary(s.BlockBaseFee.Val, 8*16)...)
	bits = append(bits, api.ToBinary(s.Contract.Val, 8*20)...)
	bits = append(bits, s.Slot.toBinaryVars(api)...)
	bits = append(bits, s.Value.toBinaryVars(api)...)
	return packBitsToFr(api, bits)
}

func (s StorageSlot) GoPack() []*big.Int {
	return s.goPack()
}

func (s StorageSlot) goPack() []*big.Int {
	var bits []uint
	bits = append(bits, decomposeBits(fromInterface(s.BlockNum.Val), 8*4)...)
	bits = append(bits, decomposeBits(fromInterface(s.BlockBaseFee.Val), 8*16)...)
	bits = append(bits, decomposeBits(fromInterface(s.Contract.Val), 8*20)...)
	bits = append(bits, s.Slot.toBinary()...)
	bits = append(bits, s.Value.toBinary()...)
	return packBitsToInt(bits, bn254_fr.Bits-1)
}

// TODO: Bring back detailed information when subproof expose corresponding data
// LeafHash: unsigned tx rlp keccak result
type Transaction struct {
	// ChainId  Uint248
	BlockNum     Uint32
	BlockBaseFee Uint248
	MptKeyPath   Uint32
	// Nonce    Uint248
	// GasTipCapOrGasPrice is GasPrice for legacy tx (type 0) and GasTipCapOap for
	// dynamic-fee tx (type 2)
	// GasTipCapOrGasPrice Uint248
	// GasFeeCap is always 0 for legacy tx
	// GasFeeCap Uint248
	// GasLimit  Uint248
	// From      Uint248
	// To        Uint248
	// Value     Bytes32
	LeafHash Bytes32
}

func defaultTransaction() Transaction {
	return Transaction{
		// ChainId:             newU248(0),
		BlockNum:     newU32(0),
		BlockBaseFee: newU248(0),
		MptKeyPath:   newU32(0),
		// Nonce:               newU248(0),
		// GasTipCapOrGasPrice: newU248(0),
		// GasFeeCap:           newU248(0),
		// GasLimit:            newU248(0),
		// From:                newU248(0),
		// To:                  newU248(0),
		// Value:               ConstBytes32([]byte{}),
		LeafHash: ConstFromBigEndianBytes([]byte{}),
	}
}

var _ CircuitVariable = Transaction{}

func (t Transaction) Values() []frontend.Variable {
	var ret []frontend.Variable
	// ret = append(ret, t.ChainId.Values()...)
	ret = append(ret, t.BlockNum.Values()...)
	// ret = append(ret, t.Nonce.Values()...)
	// ret = append(ret, t.GasTipCapOrGasPrice.Values()...)
	// ret = append(ret, t.GasFeeCap.Values()...)
	// ret = append(ret, t.GasLimit.Values()...)
	// ret = append(ret, t.From.Values()...)
	// ret = append(ret, t.To.Values()...)
	// ret = append(ret, t.Value.Values()...)
	ret = append(ret, t.BlockBaseFee.Values()...)
	ret = append(ret, t.MptKeyPath.Values()...)
	ret = append(ret, t.LeafHash.Values()...)
	return ret
}

func (t Transaction) FromValues(vs ...frontend.Variable) CircuitVariable {
	nr := Transaction{}

	end := uint32(0)
	// start, end := uint32(0), t.ChainId.NumVars()
	// nr.ChainId = t.ChainId.FromValues(vs[start:end]...).(Uint248)

	start, end := end, end+t.BlockNum.NumVars()
	nr.BlockNum = t.BlockNum.FromValues(vs[start:end]...).(Uint32)

	start, end = end, end+t.MptKeyPath.NumVars()
	nr.MptKeyPath = t.MptKeyPath.FromValues(vs[start:end]...).(Uint32)

	// start, end = end, end+t.Nonce.NumVars()
	// nr.Nonce = t.Nonce.FromValues(vs[start:end]...).(Uint248)

	// start, end = end, end+t.GasTipCapOrGasPrice.NumVars()
	// nr.GasTipCapOrGasPrice = t.GasTipCapOrGasPrice.FromValues(vs[start:end]...).(Uint248)

	// start, end = end, end+t.GasFeeCap.NumVars()
	// nr.GasFeeCap = t.GasFeeCap.FromValues(vs[start:end]...).(Uint248)

	// start, end = end, end+t.GasLimit.NumVars()
	// nr.GasLimit = t.GasLimit.FromValues(vs[start:end]...).(Uint248)

	// start, end = end, end+t.From.NumVars()
	// nr.From = t.From.FromValues(vs[start:end]...).(Uint248)

	// start, end = end, end+t.To.NumVars()
	// nr.To = t.To.FromValues(vs[start:end]...).(Uint248)

	// start, end = end, end+t.Value.NumVars()
	// nr.Value = t.Value.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+t.BlockBaseFee.NumVars()
	nr.BlockBaseFee = t.BlockBaseFee.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+t.LeafHash.NumVars()
	nr.LeafHash = t.LeafHash.FromValues(vs[start:end]...).(Bytes32)

	return nr
}

func (t Transaction) NumVars() uint32 {
	fields := []CircuitVariable{
		// t.ChainId,  t.Nonce, t.GasTipCapOrGasPrice,
		// t.GasFeeCap, t.GasLimit, t.From, t.To, t.Value,
		t.BlockNum,
		t.BlockBaseFee,
		t.MptKeyPath,
		t.LeafHash,
	}
	sum := uint32(0)
	for _, f := range fields {
		sum += f.NumVars()
	}
	return sum
}

func (t Transaction) String() string { return "Transaction" }

func (t Transaction) Pack(api frontend.API) []frontend.Variable {
	return t.pack(api)
}

// pack packs the transactions into Bn254 scalars
// chain_id - 4 bytes
// nonce - 4 bytes
// max_priority_fee_per_gas, in Gwei - 8 bytes
// max_fee_per_gas, in Gwei - 8 bytes
// gas_limit - 4 bytes
// to - 20 bytes
// from - 20 bytes
// value - 32 bytes
func (t Transaction) pack(api frontend.API) []variable {
	var bits []variable
	bits = append(bits, api.ToBinary(t.BlockNum.Val, 8*4)...)
	bits = append(bits, api.ToBinary(t.BlockBaseFee.Val, 8*16)...)
	bits = append(bits, api.ToBinary(t.MptKeyPath.Val, 8*4)...)
	// bits = append(bits, api.ToBinary(t.ChainId.Val, 8*4)...)
	// bits = append(bits, api.ToBinary(t.Nonce.Val, 8*4)...)
	// bits = append(bits, api.ToBinary(t.GasTipCapOrGasPrice.Val, 8*8)...)
	// bits = append(bits, api.ToBinary(t.GasFeeCap.Val, 8*8)...)
	// bits = append(bits, api.ToBinary(t.GasLimit.Val, 8*4)...)
	// bits = append(bits, api.ToBinary(t.From.Val, 8*20)...)
	// bits = append(bits, api.ToBinary(t.To.Val, 8*20)...)
	// bits = append(bits, t.Value.toBinaryVars(api)...)
	bits = append(bits, t.LeafHash.toBinaryVars(api)...)
	return packBitsToFr(api, bits)
}

func (t Transaction) GoPack() []*big.Int {
	return t.goPack()
}

func (t Transaction) goPack() []*big.Int {
	var bits []uint
	bits = append(bits, decomposeBits(fromInterface(t.BlockNum.Val), 8*4)...)
	bits = append(bits, decomposeBits(fromInterface(t.BlockBaseFee.Val), 8*16)...)
	bits = append(bits, decomposeBits(fromInterface(t.MptKeyPath.Val), 8*4)...)
	// bits = append(bits, decomposeBits(fromInterface(t.ChainId.Val), 8*4)...)
	// bits = append(bits, decomposeBits(fromInterface(t.Nonce.Val), 8*4)...)
	// bits = append(bits, decomposeBits(fromInterface(t.GasTipCapOrGasPrice.Val), 8*8)...)
	// bits = append(bits, decomposeBits(fromInterface(t.GasFeeCap.Val), 8*8)...)
	// bits = append(bits, decomposeBits(fromInterface(t.GasLimit.Val), 8*4)...)
	// bits = append(bits, decomposeBits(fromInterface(t.From.Val), 8*20)...)
	// bits = append(bits, decomposeBits(fromInterface(t.To.Val), 8*20)...)
	// bits = append(bits, t.Value.toBinary()...)
	bits = append(bits, t.LeafHash.toBinary()...)
	return packBitsToInt(bits, bn254_fr.Bits-1)
}

type BlockHeader struct {
	ParentHash       Bytes32
	UncleHash        Bytes32
	Coinbase         Uint248
	StateRoot        Bytes32
	TransactionsRoot Bytes32
	ReceiptsRoot     Bytes32
	LogsBloom        [8]Bytes32
	Difficulty       Uint248
	BlockNumber      Uint32
	GasLimit         Uint64
	GasUsed          Uint64
	TimeStamp        Uint64
	ExtraData        Bytes32 // Only 32-bytes extra data is supported
	MixDigest        Bytes32
	Nonce            Uint64
	BaseFee          Uint248
	WithdrawalsHash  Bytes32
	BlobGasUsed      Uint64
	ExcessBlobGas    Uint64
	ParentBeaconRoot Bytes32
}

func defaultBlockHeader() BlockHeader {
	var logsBloom [8]Bytes32
	for i := range logsBloom {
		logsBloom[i] = ConstFromBigEndianBytes([]byte{})
	}
	return BlockHeader{
		ParentHash:       ConstFromBigEndianBytes([]byte{}),
		UncleHash:        ConstFromBigEndianBytes([]byte{}),
		Coinbase:         newU248(0),
		StateRoot:        ConstFromBigEndianBytes([]byte{}),
		TransactionsRoot: ConstFromBigEndianBytes([]byte{}),
		ReceiptsRoot:     ConstFromBigEndianBytes([]byte{}),
		LogsBloom:        logsBloom,
		Difficulty:       newU248(0),
		BlockNumber:      newU32(0),
		GasLimit:         newU64(0),
		GasUsed:          newU64(0),
		TimeStamp:        newU64(0),
		ExtraData:        ConstFromBigEndianBytes([]byte{}),
		MixDigest:        ConstFromBigEndianBytes([]byte{}),
		Nonce:            newU64(0),
		BaseFee:          newU248(0),
		WithdrawalsHash:  ConstFromBigEndianBytes([]byte{}),
		BlobGasUsed:      newU64(0),
		ExcessBlobGas:    newU64(0),
		ParentBeaconRoot: ConstFromBigEndianBytes([]byte{}),
	}
}

var _ CircuitVariable = BlockHeader{}

func (h BlockHeader) Values() []frontend.Variable {
	var ret []frontend.Variable
	ret = append(ret, h.ParentHash.Values()...)
	ret = append(ret, h.UncleHash.Values()...)
	ret = append(ret, h.Coinbase.Values()...)
	ret = append(ret, h.StateRoot.Values()...)
	ret = append(ret, h.TransactionsRoot.Values()...)
	ret = append(ret, h.ReceiptsRoot.Values()...)
	for _, logBloom := range h.LogsBloom {
		ret = append(ret, logBloom.Values()...)
	}
	ret = append(ret, h.Difficulty.Values()...)
	ret = append(ret, h.BlockNumber.Values()...)
	ret = append(ret, h.GasLimit.Values()...)
	ret = append(ret, h.GasUsed.Values()...)
	ret = append(ret, h.TimeStamp.Values()...)
	ret = append(ret, h.ExtraData.Values()...)
	ret = append(ret, h.MixDigest.Values()...)
	ret = append(ret, h.Nonce.Values()...)
	ret = append(ret, h.BaseFee.Values()...)
	ret = append(ret, h.WithdrawalsHash.Values()...)
	ret = append(ret, h.BlobGasUsed.Values()...)
	ret = append(ret, h.ExcessBlobGas.Values()...)
	ret = append(ret, h.ParentBeaconRoot.Values()...)
	return ret
}

func (h BlockHeader) FromValues(vs ...frontend.Variable) CircuitVariable {
	nh := BlockHeader{}

	start, end := uint32(0), h.ParentHash.NumVars()
	nh.ParentHash = h.ParentHash.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+h.UncleHash.NumVars()
	nh.UncleHash = h.UncleHash.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+h.Coinbase.NumVars()
	nh.Coinbase = h.Coinbase.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+h.StateRoot.NumVars()
	nh.StateRoot = h.StateRoot.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+h.TransactionsRoot.NumVars()
	nh.TransactionsRoot = h.TransactionsRoot.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+h.ReceiptsRoot.NumVars()
	nh.ReceiptsRoot = h.ReceiptsRoot.FromValues(vs[start:end]...).(Bytes32)

	for i := 0; i < 8; i++ {
		start, end = end, end+h.LogsBloom[i].NumVars()
		nh.LogsBloom[i] = h.LogsBloom[i].FromValues(vs[start:end]...).(Bytes32)
	}

	start, end = end, end+h.Difficulty.NumVars()
	nh.Difficulty = h.Difficulty.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+h.BlockNumber.NumVars()
	nh.BlockNumber = h.BlockNumber.FromValues(vs[start:end]...).(Uint32)

	start, end = end, end+h.GasLimit.NumVars()
	nh.GasLimit = h.GasLimit.FromValues(vs[start:end]...).(Uint64)

	start, end = end, end+h.GasUsed.NumVars()
	nh.GasUsed = h.GasUsed.FromValues(vs[start:end]...).(Uint64)

	start, end = end, end+h.TimeStamp.NumVars()
	nh.TimeStamp = h.TimeStamp.FromValues(vs[start:end]...).(Uint64)

	start, end = end, end+h.ExtraData.NumVars()
	nh.ExtraData = h.ExtraData.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+h.MixDigest.NumVars()
	nh.MixDigest = h.MixDigest.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+h.Nonce.NumVars()
	nh.Nonce = h.Nonce.FromValues(vs[start:end]...).(Uint64)

	start, end = end, end+h.BaseFee.NumVars()
	nh.BaseFee = h.BaseFee.FromValues(vs[start:end]...).(Uint248)

	start, end = end, end+h.WithdrawalsHash.NumVars()
	nh.WithdrawalsHash = h.WithdrawalsHash.FromValues(vs[start:end]...).(Bytes32)

	start, end = end, end+h.BlobGasUsed.NumVars()
	nh.BlobGasUsed = h.BlobGasUsed.FromValues(vs[start:end]...).(Uint64)

	start, end = end, end+h.ExcessBlobGas.NumVars()
	nh.ExcessBlobGas = h.ExcessBlobGas.FromValues(vs[start:end]...).(Uint64)

	start, end = end, end+h.ParentBeaconRoot.NumVars()
	nh.ParentBeaconRoot = h.ParentBeaconRoot.FromValues(vs[start:end]...).(Bytes32)

	return nh
}

func (h BlockHeader) NumVars() uint32 {
	logsBloomNumVars := uint32(0)
	for _, logBloom := range h.LogsBloom {
		logsBloomNumVars += logBloom.NumVars()
	}

	return h.ParentHash.NumVars() + h.UncleHash.NumVars() + h.Coinbase.NumVars() +
		h.StateRoot.NumVars() + h.TransactionsRoot.NumVars() + h.ReceiptsRoot.NumVars() +
		logsBloomNumVars + h.Difficulty.NumVars() + h.BlockNumber.NumVars() +
		h.GasLimit.NumVars() + h.GasUsed.NumVars() + h.TimeStamp.NumVars() + h.ExtraData.NumVars() +
		h.MixDigest.NumVars() + h.Nonce.NumVars() + h.BaseFee.NumVars() + h.WithdrawalsHash.NumVars() +
		h.BlobGasUsed.NumVars() + h.ExcessBlobGas.NumVars() + h.ParentBeaconRoot.NumVars()
}

func (s BlockHeader) String() string { return "BlockHeader" }

func (s BlockHeader) Pack(api frontend.API) []frontend.Variable {
	return s.pack(api)
}

func (h BlockHeader) pack(api frontend.API) []frontend.Variable {
	var bits []frontend.Variable
	bits = append(bits, h.ParentHash.toBinaryVars(api)...)
	bits = append(bits, h.UncleHash.toBinaryVars(api)...)
	bits = append(bits, api.ToBinary(h.Coinbase.Val, 8*31)...)
	bits = append(bits, h.StateRoot.toBinaryVars(api)...)
	bits = append(bits, h.TransactionsRoot.toBinaryVars(api)...)
	bits = append(bits, h.ReceiptsRoot.toBinaryVars(api)...)
	for _, logBloom := range h.LogsBloom {
		bits = append(bits, logBloom.toBinaryVars(api)...)
	}
	bits = append(bits, api.ToBinary(h.Difficulty.Val, 8*31)...)
	bits = append(bits, api.ToBinary(h.BlockNumber.Val, 8*4)...)
	bits = append(bits, api.ToBinary(h.GasLimit.Val, 8*8)...)
	bits = append(bits, api.ToBinary(h.GasUsed.Val, 8*8)...)
	bits = append(bits, api.ToBinary(h.TimeStamp.Val, 8*8)...)
	bits = append(bits, h.ExtraData.toBinaryVars(api)...)
	bits = append(bits, h.MixDigest.toBinaryVars(api)...)
	bits = append(bits, api.ToBinary(h.Nonce.Val, 8*8)...)
	bits = append(bits, api.ToBinary(h.BaseFee.Val, 8*16)...)
	bits = append(bits, h.WithdrawalsHash.toBinaryVars(api)...)
	bits = append(bits, api.ToBinary(h.BlobGasUsed.Val, 8*8)...)
	bits = append(bits, api.ToBinary(h.ExcessBlobGas.Val, 8*8)...)
	bits = append(bits, h.ParentBeaconRoot.toBinaryVars(api)...)

	return packBitsToFr(api, bits)
}

func (s BlockHeader) GoPack() []*big.Int {
	return s.goPack()
}

func (h BlockHeader) goPack() []*big.Int {
	var bits []uint
	bits = append(bits, h.ParentHash.toBinary()...)
	bits = append(bits, h.UncleHash.toBinary()...)
	bits = append(bits, decomposeBits(fromInterface(h.Coinbase.Val), 8*31)...)
	bits = append(bits, h.StateRoot.toBinary()...)
	bits = append(bits, h.TransactionsRoot.toBinary()...)
	bits = append(bits, h.ReceiptsRoot.toBinary()...)
	for _, logBloom := range h.LogsBloom {
		bits = append(bits, logBloom.toBinary()...)
	}
	bits = append(bits, decomposeBits(fromInterface(h.Difficulty.Val), 8*31)...)
	bits = append(bits, decomposeBits(fromInterface(h.BlockNumber.Val), 8*4)...)
	bits = append(bits, decomposeBits(fromInterface(h.BlockNumber.Val), 8*8)...)
	bits = append(bits, decomposeBits(fromInterface(h.BlockNumber.Val), 8*8)...)
	bits = append(bits, decomposeBits(fromInterface(h.BlockNumber.Val), 8*8)...)
	bits = append(bits, h.ExtraData.toBinary()...)
	bits = append(bits, h.MixDigest.toBinary()...)
	bits = append(bits, decomposeBits(fromInterface(h.Nonce.Val), 8*8)...)
	bits = append(bits, decomposeBits(fromInterface(h.BaseFee.Val), 8*16)...)
	bits = append(bits, h.WithdrawalsHash.toBinary()...)
	bits = append(bits, decomposeBits(fromInterface(h.BlobGasUsed.Val), 8*8)...)
	bits = append(bits, decomposeBits(fromInterface(h.ExcessBlobGas.Val), 8*8)...)
	bits = append(bits, h.ParentBeaconRoot.toBinary()...)
	return packBitsToInt(bits, bn254_fr.Bits-1)
}
