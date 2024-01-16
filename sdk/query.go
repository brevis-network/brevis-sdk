package sdk

import (
	"context"
	"fmt"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/ethereum/go-ethereum/crypto"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type LogFieldQuery struct {
	// The index of the log (event)
	LogIndex int
	// Whether the field is a topic (aka "indexed" as in solidity events)
	IsTopic bool
	// The index of the field. For example, if a field is the second topic of a log, then FieldIndex is 1; if a field is the
	// third field in the RLP decoded data, then FieldIndex is 2.
	FieldIndex int
}

type ReceiptQuery struct {
	TxHash     common.Hash
	SubQueries [NumMaxLogFields]LogFieldQuery
}

type StorageSlotQuery struct {
	BlockNum int
	Address  common.Address
	Slot     common.Hash
}

type TransactionQuery struct {
	TxHash common.Hash
}

type Querier struct {
	ec *ethclient.Client

	receiptQueries queries[ReceiptQuery]
	storageQueries queries[StorageSlotQuery]
	txQueries      queries[TransactionQuery]
}

type queries[T any] struct {
	ordered []T
	special map[int]T
}

func (q *queries[T]) add(query T, index ...int) {
	if len(index) > 1 {
		panic("no more than one index should be supplied")
	}
	if q.special == nil {
		q.special = make(map[int]T)
	}
	if len(index) == 1 {
		q.special[index[0]] = query
	} else {
		q.ordered = append(q.ordered, query)
	}
}

func NewQuerier(rpcUrl string) (*Querier, error) {
	ec, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, err
	}
	return &Querier{
		ec:             ec,
		receiptQueries: queries[ReceiptQuery]{},
		storageQueries: queries[StorageSlotQuery]{},
		txQueries:      queries[TransactionQuery]{},
	}, nil
}

// AddReceipt adds the ReceiptQuery to be queried. If an index is specified, the
// query result will be assigned to the specified index of Witness.Receipts.
func (q *Querier) AddReceipt(query ReceiptQuery, index ...int) {
	q.receiptQueries.add(query, index...)
}

// AddStorageSlot adds the StorageSlotQuery to be queried. If an index is
// specified, the query result will be assigned to the specified index of
// Witness.StorageSlots.
func (q *Querier) AddStorageSlot(query StorageSlotQuery, index ...int) {
	q.storageQueries.add(query, index...)
}

// AddTransaction adds the TransactionQuery to be queried. If an index is
// specified, the query result will be assigned to the specified index of
// Witness.Transactions.
func (q *Querier) AddTransaction(query TransactionQuery, index ...int) {
	q.txQueries.add(query, index...)
}

// BuildWitness executes all added queries and package the query results into circuit assignment (the Witness struct)
// The provided ctx is used when performing network calls to the provided blockchain RPC.
func (q *Querier) BuildWitness(
	ctx context.Context,
	guestCircuit GuestCircuit,
) (witness Witness, abiEncodedOutput []byte, err error) {

	// 1. call rpc to fetch data for each query type, then assign the corresponding witness fields
	// 2. mimc hash data at each position to generate and assign input commitments and toggles commitment
	// 3. dry-run user circuit to generate output and output commitment

	w := &Witness{}
	maxReceipts, maxSlots, maxTxs := guestCircuit.Allocate()
	err = q.checkAllocations(guestCircuit)
	if err != nil {
		return
	}

	// initialize
	w.Receipts = NewDataPoints[Receipt](maxReceipts, NewReceipt)
	w.StorageSlots = NewDataPoints[StorageSlot](maxSlots, NewStorageSlot)
	w.Transactions = NewDataPoints[Transaction](maxTxs, NewTransaction)
	w.OutputCommitment = OutputCommitment{0, 0}
	w.InputCommitments = make([]Variable, NumMaxDataPoints)
	for i := range w.InputCommitments {
		w.InputCommitments[i] = 0
	}

	// receipt
	ro, rs, err := q.executeReceiptQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute receipt queries", err)
	}
	err = q.assignReceipts(w, ro, rs)
	if err != nil {
		return buildWitnessErr("failed to assign witness from receipt queries", err)
	}

	// storage
	vo, vs, err := q.executeStorageQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute storage queries", err)
	}
	err = q.assignStorageSlots(w, vo, vs)
	if err != nil {
		return buildWitnessErr("failed to assign witness from storage queries", err)
	}

	// transaction
	to, ts, err := q.executeTransactionQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute transaction queries", err)
	}
	err = q.assignTransactions(w, to, ts)
	if err != nil {
		return buildWitnessErr("failed to assign witness from transaction queries", err)
	}

	// commitment
	q.assignInputCommitment(w)
	q.assignToggleCommitment(w)

	fmt.Printf("input commits: %d\n", w.InputCommitments)

	// dry run without assigning the output commitment first to compute the output commitment using the user circuit
	outputCommit, output, err := dryRun(*w, guestCircuit)
	if err != nil {
		return buildWitnessErr("failed to generate output commitment", err)
	}
	w.OutputCommitment = outputCommit

	return *w, output, nil
}

func (q *Querier) checkAllocations(cb GuestCircuit) error {
	maxReceipts, maxSlots, maxTxs := cb.Allocate()

	if len(q.receiptQueries.special) > maxReceipts {
		return allocationLenErr("receipt", len(q.receiptQueries.special), maxReceipts)
	}
	if len(q.storageQueries.special) > maxSlots {
		return allocationLenErr("storage", len(q.storageQueries.special), maxSlots)
	}
	if len(q.txQueries.special) > maxTxs {
		return allocationLenErr("transaction", len(q.txQueries.special), maxTxs)
	}
	total := maxReceipts + maxSlots + maxTxs
	if total > NumMaxDataPoints {
		return allocationLenErr("total", total, NumMaxDataPoints)
	}
	return nil
}

func (q *Querier) assignInputCommitment(w *Witness) {
	hasher := mimc.NewMiMC()
	// assign 0 to input commit for dummy slots and actual data hash for non-dummies
	j := 0
	for i, receipt := range w.Receipts.Raw {
		if var2BigInt(w.Receipts.Toggles[i]).Sign() != 0 {
			w.InputCommitments[j] = doHash(hasher, receipt.goPack())
		}
		j++
	}
	for i, slot := range w.StorageSlots.Raw {
		if var2BigInt(w.StorageSlots.Toggles[i]).Sign() != 0 {
			w.InputCommitments[j] = doHash(hasher, slot.goPack())
		}
		j++
	}
	for i, tx := range w.Transactions.Raw {
		if var2BigInt(w.Transactions.Toggles[i]).Sign() != 0 {
			w.InputCommitments[j] = doHash(hasher, tx.goPack())
		}
		j++
	}
}

func doHash(hasher hash.Hash, packed []*big.Int) *big.Int {
	for _, v := range packed {
		hasher.Write(common.LeftPadBytes(v.Bytes(), 32))
	}
	ret := new(big.Int).SetBytes(hasher.Sum(nil))
	hasher.Reset()
	return ret
}

func (q *Querier) assignToggleCommitment(w *Witness) {
	var toggles []Variable
	toggles = append(toggles, w.Receipts.Toggles...)
	toggles = append(toggles, w.StorageSlots.Toggles...)
	toggles = append(toggles, w.Transactions.Toggles...)

	var toggleBits []uint
	for _, t := range toggles {
		toggleBits = append(toggleBits, uint(var2BigInt(t).Uint64()))
	}
	packed := packBitsToInt(toggleBits, bls12377_fr.Bits-1)
	hasher := mimc.NewMiMC()
	for _, v := range packed {
		hasher.Write(common.LeftPadBytes(v.Bytes(), 32))
	}
	w.TogglesCommitment = new(big.Int).SetBytes(hasher.Sum(nil))
}

func (q *Querier) executeReceiptQueries(ctx context.Context) ([]*types.Receipt, map[int]*types.Receipt, error) {
	var ordered []*types.Receipt
	special := make(map[int]*types.Receipt)
	// TODO: parallelize this
	for _, query := range q.receiptQueries.ordered {
		receipt, err := q.ec.TransactionReceipt(ctx, query.TxHash)
		if err != nil {
			return nil, nil, err
		}
		ordered = append(ordered, receipt)
	}
	for i, query := range q.receiptQueries.special {
		receipt, err := q.ec.TransactionReceipt(ctx, query.TxHash)
		if err != nil {
			return nil, nil, err
		}
		special[i] = receipt
	}
	return ordered, special, nil
}

func (q *Querier) executeStorageQueries(ctx context.Context) ([][]byte, map[int][]byte, error) {
	var ordered [][]byte
	special := make(map[int][]byte)
	for _, query := range q.storageQueries.ordered {
		val, err := q.ec.StorageAt(ctx, query.Address, query.Slot, big.NewInt(int64(query.BlockNum)))
		if err != nil {
			return nil, nil, err
		}
		ordered = append(ordered, val)
	}
	for i, query := range q.storageQueries.special {
		val, err := q.ec.StorageAt(ctx, query.Address, query.Slot, big.NewInt(int64(query.BlockNum)))
		if err != nil {
			return nil, nil, err
		}
		special[i] = val
	}
	return ordered, special, nil
}

type txResult struct {
	*types.Transaction
	blockNum *big.Int
}

func (q *Querier) executeTransactionQueries(ctx context.Context) ([]*txResult, map[int]*txResult, error) {
	var ordered []*txResult
	special := make(map[int]*txResult)

	// TODO: parallelize this
	for _, query := range q.txQueries.ordered {
		res, err := q.getTx(ctx, query.TxHash)
		if err != nil {
			return nil, nil, err
		}
		ordered = append(ordered, res)
	}

	for i, query := range q.txQueries.special {
		var err error
		special[i], err = q.getTx(ctx, query.TxHash)
		if err != nil {
			return nil, nil, err
		}
	}
	return ordered, special, nil
}

func (q *Querier) getTx(ctx context.Context, txHash common.Hash) (*txResult, error) {
	tx, pending, err := q.ec.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, fmt.Errorf("tx %s is pending", txHash)
	}
	r, err := q.ec.TransactionReceipt(ctx, txHash)
	if err != nil {
		return nil, err
	}
	return &txResult{
		Transaction: tx,
		blockNum:    r.BlockNumber,
	}, nil
}

func (q *Querier) assignReceipts(w *Witness, ordered []*types.Receipt, special map[int]*types.Receipt) error {
	// assigning user appointed receipts at specific indices
	for i, receipt := range special {
		w.Receipts.Raw[i] = Receipt{
			BlockNum: receipt.BlockNumber,
			Fields:   buildLogFields(receipt, q.receiptQueries.special[i]),
		}
		w.Receipts.Toggles[i] = 1
	}

	// distribute other receipts in order to the rest of the unassigned spaces
	j := 0
	for i, receipt := range ordered {
		for w.Receipts.Toggles[j] == 1 {
			j++
		}
		w.Receipts.Raw[j] = Receipt{
			BlockNum: receipt.BlockNumber,
			Fields:   buildLogFields(receipt, q.receiptQueries.ordered[i]),
		}
		w.Receipts.Toggles[j] = 1
		j++
	}
	return nil
}

func buildLogFields(receipt *types.Receipt, query ReceiptQuery) (fields [NumMaxLogFields]LogField) {
	for j, subQuery := range query.SubQueries {
		log := receipt.Logs[subQuery.LogIndex]

		var value Bytes32
		if subQuery.IsTopic {
			value = ParseBytes32(log.Topics[subQuery.FieldIndex][:])
		} else {
			value = ParseBytes32(log.Data[subQuery.FieldIndex*32 : subQuery.FieldIndex*32+32])
		}

		fields[j] = LogField{
			Contract: ParseAddress(log.Address),
			// we only constrain the first 6 bytes of EventID in circuit for performance reasons
			// 6 bytes give us 1/2^48 chance of two logs of different IDs clashing per contract.
			EventID: ParseBytes(log.Topics[0][:6]),
			IsTopic: ParseBool(subQuery.IsTopic),
			Index:   subQuery.FieldIndex,
			Value:   value,
		}
	}
	return
}

func (q *Querier) assignStorageSlots(w *Witness, ordered [][]byte, special map[int][]byte) (err error) {
	// assigning user appointed data at specific indices
	for i, val := range special {
		query := q.storageQueries.special[i]
		w.StorageSlots.Raw[i], err = buildStorageSlot(val, query)
		if err != nil {
			return
		}
		w.StorageSlots.Toggles[i] = 1
	}

	// distribute other data in order to the rest of the unassigned spaces
	j := 0
	for i, val := range ordered {
		for w.StorageSlots.Toggles[j] != 0 {
			j++
		}
		query := q.storageQueries.ordered[i]
		w.StorageSlots.Raw[i], err = buildStorageSlot(val, query)
		if err != nil {
			return
		}
		w.StorageSlots.Toggles[i] = 1
		j++
	}
	return nil
}

func buildStorageSlot(val []byte, query StorageSlotQuery) (StorageSlot, error) {
	if len(val) > 32 {
		return StorageSlot{}, fmt.Errorf("value of address %s slot key %s is %d bytes. only values less than 32 bytes are supported",
			query.Address, query.Slot, len(val))
	}
	slotMptKey := crypto.Keccak256(query.Slot[:])
	return StorageSlot{
		BlockNum: query.BlockNum,
		Contract: ParseAddress(query.Address),
		Key:      ParseBytes32(slotMptKey),
		Value:    ParseBytes32(val),
	}, nil
}

func (q *Querier) assignTransactions(w *Witness, ordered []*txResult, special map[int]*txResult) (err error) {
	// assigning user appointed data at specific indices
	for i, t := range special {
		w.Transactions.Raw[i], err = buildTx(t)
		if err != nil {
			return
		}
		w.Transactions.Toggles[i] = 1
	}

	j := 0
	for i, t := range ordered {
		for w.Transactions.Toggles[j] == 1 {
			j++
		}
		w.Transactions.Raw[i], err = buildTx(t)
		if err != nil {
			return
		}
		w.Transactions.Toggles[i] = 1
		j++
	}
	return nil
}

func buildTx(t *txResult) (Transaction, error) {
	from, err := types.Sender(types.NewLondonSigner(t.ChainId()), t.Transaction)
	if err != nil {
		return Transaction{}, err
	}
	return Transaction{
		ChainId:              t.ChainId(),
		BlockNum:             t.blockNum,
		Nonce:                t.Nonce(),
		MaxPriorityFeePerGas: t.GasTipCap(),
		MaxFeePerGas:         t.GasFeeCap(),
		GasLimit:             t.Gas(),
		From:                 ParseAddress(from),
		To:                   ParseAddress(*t.To()),
		Value:                ParseBytes32(t.Value().Bytes()),
	}, nil
}

func buildWitnessErr(m string, err error) (Witness, []byte, error) {
	return Witness{}, nil, fmt.Errorf("%s: %s", m, err.Error())
}

func allocationLenErr(name string, queryCount, maxCount int) error {
	return fmt.Errorf("# of %s queries (%d) must not exceed the allocated max %s (%d), check your GuestCircuit.Allocate() method",
		name, queryCount, name, maxCount)
}
