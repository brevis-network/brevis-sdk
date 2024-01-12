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

	receiptQueries []ReceiptQuery
	storageQueries []StorageSlotQuery
	txQueries      []TransactionQuery
}

func NewQuerier(rpcUrl string) (*Querier, error) {
	ec, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, err
	}
	return &Querier{ec: ec}, nil
}

func (q *Querier) AddReceipt(query ReceiptQuery) {
	q.receiptQueries = append(q.receiptQueries, query)
}

func (q *Querier) AddStorageSlot(query StorageSlotQuery) {
	q.storageQueries = append(q.storageQueries, query)
}

func (q *Querier) AddTransaction(query TransactionQuery) {
	q.txQueries = append(q.txQueries, query)
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
	w.Receipts = NewDataPoints[Receipt](maxReceipts)
	w.StorageSlots = NewDataPoints[StorageSlot](maxSlots)
	w.Transactions = NewDataPoints[Transaction](maxTxs)
	w.OutputCommitment = OutputCommitment{0, 0}
	w.InputCommitments = make([]Variable, NumMaxDataPoints)
	for i := range w.InputCommitments {
		w.InputCommitments[i] = 0
	}

	// receipt
	receipts, err := q.executeReceiptQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute receipt queries", err)
	}
	err = q.assignReceipts(w, receipts)
	if err != nil {
		return buildWitnessErr("failed to assign witness from receipt queries", err)
	}

	// storage
	vals, err := q.executeStorageQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute storage queries", err)
	}
	err = q.assignStorageSlots(w, vals)
	if err != nil {
		return buildWitnessErr("failed to assign witness from storage queries", err)
	}

	// transaction
	txs, blockNums, err := q.executeTransactionQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute transaction queries", err)
	}
	err = q.assignTransactions(w, txs, blockNums)
	if err != nil {
		return buildWitnessErr("failed to assign witness from transaction queries", err)
	}

	// commitment
	q.assignInputCommitment(w)
	q.assignToggleCommitment(w)

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

	if len(q.receiptQueries) > maxReceipts {
		return allocationLenErr("receipt", len(q.receiptQueries), maxReceipts)
	}
	if len(q.storageQueries) > maxSlots {
		return allocationLenErr("storage", len(q.storageQueries), maxSlots)
	}
	if len(q.txQueries) > maxTxs {
		return allocationLenErr("transaction", len(q.txQueries), maxTxs)
	}
	total := maxReceipts + maxSlots + maxTxs
	if total > NumMaxDataPoints {
		return allocationLenErr("total", total, NumMaxDataPoints)
	}
	return nil
}

var zero Variable = 0

func (q *Querier) assignInputCommitment(w *Witness) {
	hasher := mimc.NewMiMC()
	// assign 0 to input commit for dummy slots and actual data hash for non-dummies
	var i = 0
	for j, receipt := range w.Receipts.Raw {
		if j >= len(q.receiptQueries) {
			w.InputCommitments[i] = big.NewInt(0)
		} else {
			w.InputCommitments[i] = doHash(hasher, receipt.goPack())
		}
		i++
	}
	for j, slot := range w.StorageSlots.Raw {
		if j >= len(q.storageQueries) {
			w.InputCommitments[i] = big.NewInt(0)
		} else {
			w.InputCommitments[i] = doHash(hasher, slot.goPack())
		}
		i++
	}
	for j, tx := range w.Transactions.Raw {
		if j >= len(q.txQueries) {
			w.InputCommitments[i] = big.NewInt(0)
		} else {
			w.InputCommitments[i] = doHash(hasher, tx.goPack())
		}
		i++
	}
	// fill the unallocated positions with zeros
	for ; i < NumMaxDataPoints; i++ {
		w.InputCommitments[i] = zero
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

func (q *Querier) executeReceiptQueries(ctx context.Context) ([]*types.Receipt, error) {
	var rs []*types.Receipt
	// TODO: parallelize this
	for _, query := range q.receiptQueries {
		receipt, err := q.ec.TransactionReceipt(ctx, query.TxHash)
		if err != nil {
			return nil, err
		}
		rs = append(rs, receipt)
	}
	return rs, nil
}

func (q *Querier) executeStorageQueries(ctx context.Context) ([][]byte, error) {
	var ret [][]byte
	for _, query := range q.storageQueries {
		val, err := q.ec.StorageAt(ctx, query.Address, query.Slot, big.NewInt(int64(query.BlockNum)))
		if err != nil {
			return nil, err
		}
		ret = append(ret, val)
	}
	return ret, nil
}

func (q *Querier) executeTransactionQueries(ctx context.Context) ([]*types.Transaction, []*big.Int, error) {
	var txs []*types.Transaction
	var blockNums []*big.Int
	// TODO: parallelize this
	for _, query := range q.txQueries {
		tx, pending, err := q.ec.TransactionByHash(ctx, query.TxHash)
		if err != nil {
			return nil, nil, err
		}
		if pending {
			return nil, nil, fmt.Errorf("tx %s is pending", query.TxHash)
		}
		txs = append(txs, tx)

		r, err := q.ec.TransactionReceipt(ctx, query.TxHash)
		blockNums = append(blockNums, r.BlockNumber)
	}
	return txs, blockNums, nil
}

func (q *Querier) assignReceipts(w *Witness, receipts []*types.Receipt) error {
	for i := range w.Receipts.Raw {
		if i < len(q.receiptQueries) {
			query := q.receiptQueries[i]
			var fields [NumMaxLogFields]LogField
			receipt := receipts[i]
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
			w.Receipts.Raw[i] = Receipt{
				BlockNum: receipt.BlockNumber,
				Fields:   fields,
			}
			w.Receipts.Toggles[i] = 1
		} else {
			w.Receipts.Raw[i] = NewReceipt()
			w.Receipts.Toggles[i] = 0
		}
	}
	return nil
}

func (q *Querier) assignStorageSlots(w *Witness, vals [][]byte) error {
	for i := range w.StorageSlots.Raw {
		if i < len(q.storageQueries) {
			query := q.storageQueries[i]
			val := vals[i]
			if len(val) > 32 {
				return fmt.Errorf("value of address %s slot key %s is %d bytes. only values less than 32 bytes are supported",
					query.Address, query.Slot, len(val))
			}
			slotMptKey := crypto.Keccak256(query.Slot[:])
			slot := StorageSlot{
				BlockNum: query.BlockNum,
				Contract: ParseAddress(query.Address),
				Key:      ParseBytes32(slotMptKey),
				Value:    ParseBytes32(val),
			}
			w.StorageSlots.Raw[i] = slot
			w.StorageSlots.Toggles[i] = 1
		} else {
			w.StorageSlots.Raw[i] = NewStorageSlot()
			w.StorageSlots.Toggles[i] = 0
		}
	}
	return nil
}

func (q *Querier) assignTransactions(w *Witness, txs []*types.Transaction, blockNums []*big.Int) error {
	for i := range w.Transactions.Raw {
		if i < len(q.txQueries) {
			t := txs[i]
			from, err := types.Sender(types.NewLondonSigner(t.ChainId()), t)
			if err != nil {
				return err
			}
			tx := Transaction{
				ChainId:              t.ChainId(),
				BlockNum:             blockNums[i],
				Nonce:                t.Nonce(),
				MaxPriorityFeePerGas: t.GasTipCap(),
				MaxFeePerGas:         t.GasFeeCap(),
				GasLimit:             t.Gas(),
				From:                 ParseAddress(from),
				To:                   ParseAddress(*t.To()),
				Value:                ParseBytes32(t.Value().Bytes()),
			}
			w.Transactions.Raw[i] = tx
			w.Transactions.Toggles[i] = 1
		} else {
			w.Transactions.Raw[i] = NewTransaction()
			w.Transactions.Toggles[i] = 0
		}
	}
	return nil
}

func buildWitnessErr(m string, err error) (Witness, []byte, error) {
	return Witness{}, nil, fmt.Errorf("%s: %s", m, err.Error())
}

func allocationLenErr(name string, queryCount, maxCount int) error {
	return fmt.Errorf("# of %s queries (%d) must not exceed the allocated max %s (%d), check your GuestCircuit.Allocate() method",
		name, queryCount, name, maxCount)
}
