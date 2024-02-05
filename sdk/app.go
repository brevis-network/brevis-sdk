package sdk

import (
	"bytes"
	"context"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/celer-network/brevis-sdk/sdk/proto"
	"github.com/celer-network/zk-utils/common/eth"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
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

type StorageQuery struct {
	BlockNum int
	Address  common.Address
	Slot     common.Hash
}

type TransactionQuery struct {
	TxHash common.Hash
}

type queries[T ReceiptQuery | StorageQuery | TransactionQuery] struct {
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

func (q *queries[T]) list() []T {
	indexed := map[int]T{}
	// copy the map
	for i, v := range q.special {
		indexed[i] = v
	}

	var empty T
	j := 0
	for _, v := range q.ordered {
		for indexed[j] != empty {
			j++
		}
		indexed[j] = v
	}

	l := make([]T, len(indexed))
	for i, v := range indexed {
		l[i] = v
	}

	return l
}

type BrevisApp struct {
	ec            *ethclient.Client
	gc            *GatewayClient
	brevisRequest *abi.ABI

	receiptQueries queries[ReceiptQuery]
	storageQueries queries[StorageQuery]
	txQueries      queries[TransactionQuery]

	// cache fields
	circuitInput           CircuitInput
	buildInputCalled       bool
	queryId                []byte
	srcChainId, dstChainId uint64
}

func NewBrevisApp(rpcUrl string, gatewayUrlOverride ...string) (*BrevisApp, error) {
	ec, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, err
	}
	gc, err := NewGatewayClient(gatewayUrlOverride...)
	if err != nil {
		return nil, err
	}
	br, err := eth.BrevisRequestMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return &BrevisApp{
		ec:             ec,
		gc:             gc,
		brevisRequest:  br,
		receiptQueries: queries[ReceiptQuery]{},
		storageQueries: queries[StorageQuery]{},
		txQueries:      queries[TransactionQuery]{},
	}, nil
}

// AddReceipt adds the ReceiptQuery to be queried. If an index is specified, the
// query result will be assigned to the specified index of CircuitInput.Receipts.
func (q *BrevisApp) AddReceipt(query ReceiptQuery, index ...int) {
	q.receiptQueries.add(query, index...)
}

// AddStorage adds the StorageQuery to be queried. If an index is
// specified, the query result will be assigned to the specified index of
// CircuitInput.StorageSlots.
func (q *BrevisApp) AddStorage(query StorageQuery, index ...int) {
	q.storageQueries.add(query, index...)
}

// AddTransaction adds the TransactionQuery to be queried. If an index is
// specified, the query result will be assigned to the specified index of
// CircuitInput.Transactions.
func (q *BrevisApp) AddTransaction(query TransactionQuery, index ...int) {
	q.txQueries.add(query, index...)
}

// BuildCircuitInput executes all added queries and package the query results
// into circuit assignment (the CircuitInput struct) The provided ctx is used
// when performing network calls to the provided blockchain RPC.
func (q *BrevisApp) BuildCircuitInput(ctx context.Context, guestCircuit AppCircuit) (in CircuitInput, err error) {

	// 1. call rpc to fetch data for each query type, then assign the corresponding input fields
	// 2. mimc hash data at each position to generate and assign input commitments and toggles commitment
	// 3. dry-run user circuit to generate output and output commitment

	v := &CircuitInput{}
	maxReceipts, maxSlots, maxTxs := guestCircuit.Allocate()
	err = q.checkAllocations(guestCircuit)
	if err != nil {
		return
	}

	// initialize
	v.Receipts = NewDataPoints[Receipt](maxReceipts, NewReceipt)
	v.StorageSlots = NewDataPoints[StorageSlot](maxSlots, NewStorageSlot)
	v.Transactions = NewDataPoints[Transaction](maxTxs, NewTransaction)
	v.OutputCommitment = OutputCommitment{0, 0}
	v.InputCommitments = make([]Variable, NumMaxDataPoints)
	for i := range v.InputCommitments {
		v.InputCommitments[i] = 0
	}

	// receipt
	ro, rs, err := q.executeReceiptQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute receipt queries", err)
	}
	err = q.assignReceipts(v, ro, rs)
	if err != nil {
		return buildWitnessErr("failed to assign in from receipt queries", err)
	}

	// storage
	vo, vs, err := q.executeStorageQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute storage queries", err)
	}
	err = q.assignStorageSlots(v, vo, vs)
	if err != nil {
		return buildWitnessErr("failed to assign in from storage queries", err)
	}

	// transaction
	to, ts, err := q.executeTransactionQueries(ctx)
	if err != nil {
		return buildWitnessErr("failed to execute transaction queries", err)
	}
	err = q.assignTransactions(v, to, ts)
	if err != nil {
		return buildWitnessErr("failed to assign in from transaction queries", err)
	}

	// commitment
	q.assignInputCommitment(v)
	q.assignToggleCommitment(v)

	fmt.Printf("input commits: %d\n", v.InputCommitments)

	// dry run without assigning the output commitment first to compute the output commitment using the user circuit
	outputCommit, output, err := dryRun(*v, guestCircuit)
	if err != nil {
		return buildWitnessErr("failed to generate output commitment", err)
	}
	v.OutputCommitment = outputCommit
	// cache dry-run output to be used in building gateway request later
	v.dryRunOutput = output

	q.circuitInput = *v // cache the generated circuit input for later use in building gateway request
	q.buildInputCalled = true
	fmt.Printf("output %x\n", output)

	return *v, nil
}

func (q *BrevisApp) PrepareRequest(
	vk plonk.VerifyingKey,
	srcChainId, dstChainId uint64,
	refundee, appContract common.Address,
) (calldata []byte, requestId common.Hash, feeValue *big.Int, err error) {
	if !q.buildInputCalled {
		panic("must call BuildCircuitInput before PrepareRequest")
	}
	q.srcChainId = srcChainId
	q.dstChainId = dstChainId

	req := &proto.PrepareQueryRequest{
		ChainId:           srcChainId,
		TargetChainId:     dstChainId,
		ReceiptInfos:      buildReceiptInfos(q.receiptQueries),
		StorageQueryInfos: buildStorageQueryInfos(q.storageQueries),
		TransactionInfos:  buildTxInfos(q.txQueries),
		AppCircuitInfo:    buildAppCircuitInfo(q.circuitInput, vk),
		UseAppCircuitInfo: true,
	}

	fmt.Println("Calling Brevis gateway PrepareRequest...")
	res, err := q.gc.PrepareQuery(req)
	if err != nil {
		return
	}
	queryId, err := hexutil.Decode(res.QueryHash)
	if err != nil {
		return
	}
	q.queryId = queryId

	feeValue, ok := new(big.Int).SetString(res.GetFee(), 10)
	if !ok {
		err = fmt.Errorf("cannot parse fee value of %s", res.GetFee())
		return
	}

	fmt.Printf("Brevis gateway responded with requestId %x, feeValue %d\n", queryId, feeValue)

	calldata, err = q.buildSendRequestCalldata(common.BytesToHash(queryId), refundee, appContract)
	return calldata, common.BytesToHash(queryId), feeValue, err
}

func (q *BrevisApp) buildSendRequestCalldata(args ...interface{}) ([]byte, error) {
	sendRequest, ok := q.brevisRequest.Methods["sendRequest"]
	if !ok {
		return nil, fmt.Errorf("method sendRequest not fonud in abi")
	}
	inputs, err := sendRequest.Inputs.Pack(args...)
	if err != nil {
		return nil, err
	}
	return append(sendRequest.ID, inputs...), nil
}

type submitProofOptions struct {
	onSubmitted func(txHash common.Hash)
	onError     func(err error)
	ctx         context.Context
}
type SubmitProofOption func(option submitProofOptions)

func WithFinalProofSubmittedCallback(onSubmitted func(txHash common.Hash), onError func(err error)) SubmitProofOption {
	return func(option submitProofOptions) {
		option.onSubmitted = onSubmitted
		option.onError = onError
	}
}

func WithContext(ctx context.Context) SubmitProofOption {
	return func(option submitProofOptions) { option.ctx = ctx }
}

func (q *BrevisApp) SubmitProof(proof plonk.Proof, options ...SubmitProofOption) error {
	opts := submitProofOptions{}
	for _, apply := range options {
		apply(opts)
	}

	buf := bytes.NewBuffer([]byte{})
	_, err := proof.WriteTo(buf)
	if err != nil {
		return fmt.Errorf("error writing proof to bytes: %s", err.Error())
	}
	res, err := q.gc.SubmitProof(&proto.SubmitAppCircuitProofRequest{
		QueryHash:     hexutil.Encode(q.queryId),
		TargetChainId: q.dstChainId,
		Proof:         hexutil.Encode(buf.Bytes()),
	})
	if err != nil {
		return fmt.Errorf("error calling brevis gateway SubmitProof: %s", err.Error())
	}
	if !res.GetSuccess() {
		return fmt.Errorf("error calling brevis gateway SubmitProof: cdoe %s, msg %s",
			res.GetErr().GetCode(), res.GetErr().GetMsg())
	}

	if opts.onSubmitted != nil {
		var cancel <-chan struct{}
		if opts.ctx != nil {
			cancel = opts.ctx.Done()
		}
		go func() {
			tx, err := q.waitFinalProofSubmitted(cancel)
			if err != nil {
				fmt.Println(err.Error())
				opts.onError(err)
			}
			opts.onSubmitted(tx)
		}()
	}

	return nil
}

func (q *BrevisApp) WaitFinalProofSubmitted(ctx context.Context) (tx common.Hash, err error) {
	return q.waitFinalProofSubmitted(ctx.Done())
}

func (q *BrevisApp) waitFinalProofSubmitted(cancel <-chan struct{}) (common.Hash, error) {
	t := time.NewTicker(12 * time.Second)
	for {
		select {
		case <-t.C:
			res, err := q.gc.GetQueryStatus(&proto.GetQueryStatusRequest{
				QueryHash:     hexutil.Encode(q.queryId),
				TargetChainId: q.dstChainId,
			})
			if err != nil {
				return common.Hash{}, fmt.Errorf("error querying proof status: %s", err.Error())
			}
			if res.Status == proto.QueryStatus_QS_COMPLETE {
				fmt.Printf("final proof for query %x submitted: tx %s\n", q.queryId, res.TxHash)
				return common.HexToHash(res.TxHash), nil
			} else if res.Status == proto.QueryStatus_QS_FAILED {
				return common.Hash{}, fmt.Errorf("proof submission status Failure")
			} else {
				fmt.Printf("polling for final proof submission: status %s\n", res.Status)
			}
		case <-cancel:
			fmt.Println("stop waiting for final proof submission: context cancelled")
			return common.Hash{}, nil
		}
	}
}

func (q *BrevisApp) checkAllocations(cb AppCircuit) error {
	maxReceipts, maxSlots, maxTxs := cb.Allocate()

	numReceipts := len(q.receiptQueries.special) + len(q.receiptQueries.ordered)
	if numReceipts > maxReceipts {
		return allocationLenErr("receipt", numReceipts, maxReceipts)
	}
	numStorages := len(q.storageQueries.special) + len(q.storageQueries.ordered)
	if numStorages > maxSlots {
		return allocationLenErr("storage", numStorages, maxSlots)
	}
	numTxs := len(q.txQueries.special) + len(q.txQueries.ordered)
	if numTxs > maxTxs {
		return allocationLenErr("transaction", numTxs, maxTxs)
	}
	total := maxReceipts + maxSlots + maxTxs
	if total > NumMaxDataPoints {
		return allocationLenErr("total", total, NumMaxDataPoints)
	}
	return nil
}

func (q *BrevisApp) assignInputCommitment(w *CircuitInput) {
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

func (q *BrevisApp) assignToggleCommitment(in *CircuitInput) {
	var toggles []Variable
	toggles = append(toggles, in.Receipts.Toggles...)
	toggles = append(toggles, in.StorageSlots.Toggles...)
	toggles = append(toggles, in.Transactions.Toggles...)

	var toggleBits []uint
	for _, t := range toggles {
		toggleBits = append(toggleBits, uint(var2BigInt(t).Uint64()))
	}
	packed := packBitsToInt(toggleBits, bls12377_fr.Bits-1)
	hasher := mimc.NewMiMC()
	for _, v := range packed {
		hasher.Write(common.LeftPadBytes(v.Bytes(), 32))
	}
	in.TogglesCommitment = new(big.Int).SetBytes(hasher.Sum(nil))
}

func (q *BrevisApp) executeReceiptQueries(ctx context.Context) ([]*types.Receipt, map[int]*types.Receipt, error) {
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

func (q *BrevisApp) executeStorageQueries(ctx context.Context) ([][]byte, map[int][]byte, error) {
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

func (q *BrevisApp) executeTransactionQueries(ctx context.Context) ([]*txResult, map[int]*txResult, error) {
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

func (q *BrevisApp) getTx(ctx context.Context, txHash common.Hash) (*txResult, error) {
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

func (q *BrevisApp) assignReceipts(in *CircuitInput, ordered []*types.Receipt, special map[int]*types.Receipt) error {
	// assigning user appointed receipts at specific indices
	for i, receipt := range special {
		in.Receipts.Raw[i] = Receipt{
			BlockNum: receipt.BlockNumber,
			Fields:   buildLogFields(receipt, q.receiptQueries.special[i]),
		}
		in.Receipts.Toggles[i] = 1
	}

	// distribute other receipts in order to the rest of the unassigned spaces
	j := 0
	for i, receipt := range ordered {
		for in.Receipts.Toggles[j] == 1 {
			j++
		}
		in.Receipts.Raw[j] = Receipt{
			BlockNum: receipt.BlockNumber,
			Fields:   buildLogFields(receipt, q.receiptQueries.ordered[i]),
		}
		in.Receipts.Toggles[j] = 1
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

func (q *BrevisApp) assignStorageSlots(in *CircuitInput, ordered [][]byte, special map[int][]byte) (err error) {
	// assigning user appointed data at specific indices
	for i, val := range special {
		query := q.storageQueries.special[i]
		in.StorageSlots.Raw[i], err = buildStorageSlot(val, query)
		if err != nil {
			return
		}
		in.StorageSlots.Toggles[i] = 1
	}

	// distribute other data in order to the rest of the unassigned spaces
	j := 0
	for i, val := range ordered {
		for in.StorageSlots.Toggles[j] != 0 {
			j++
		}
		query := q.storageQueries.ordered[i]
		in.StorageSlots.Raw[i], err = buildStorageSlot(val, query)
		if err != nil {
			return
		}
		in.StorageSlots.Toggles[i] = 1
		j++
	}
	return nil
}

func buildStorageSlot(val []byte, query StorageQuery) (StorageSlot, error) {
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

func (q *BrevisApp) assignTransactions(in *CircuitInput, ordered []*txResult, special map[int]*txResult) (err error) {
	// assigning user appointed data at specific indices
	for i, t := range special {
		in.Transactions.Raw[i], err = buildTx(t)
		if err != nil {
			return
		}
		in.Transactions.Toggles[i] = 1
	}

	j := 0
	for i, t := range ordered {
		for in.Transactions.Toggles[j] == 1 {
			j++
		}
		in.Transactions.Raw[i], err = buildTx(t)
		if err != nil {
			return
		}
		in.Transactions.Toggles[i] = 1
		j++
	}
	return nil
}

func buildTx(t *txResult) (Transaction, error) {
	from, err := types.Sender(types.NewLondonSigner(t.ChainId()), t.Transaction)
	if err != nil {
		return Transaction{}, err
	}

	var maxPriorityFeePerGas = new(big.Int)
	var gasPriceOrCap = new(big.Int)

	txType := t.Transaction.Type()
	if txType == types.LegacyTxType || txType == types.AccessListTxType {
		maxPriorityFeePerGas.SetUint64(0)
		gasPriceOrCap.SetBytes(t.GasPrice().Bytes())
	} else {
		maxPriorityFeePerGas.SetBytes(t.GasTipCap().Bytes())
		gasPriceOrCap.SetBytes(t.GasFeeCap().Bytes())
	}

	return Transaction{
		ChainId:              t.ChainId(),
		BlockNum:             t.blockNum,
		Nonce:                t.Nonce(),
		MaxPriorityFeePerGas: maxPriorityFeePerGas,
		GasPriceOrFeeCap:     gasPriceOrCap,
		GasLimit:             t.Gas(),
		From:                 ParseAddress(from),
		To:                   ParseAddress(*t.To()),
		Value:                ParseBytes32(t.Value().Bytes()),
	}, nil
}

func buildWitnessErr(m string, err error) (CircuitInput, error) {
	return CircuitInput{}, fmt.Errorf("%s: %s", m, err.Error())
}

func allocationLenErr(name string, queryCount, maxCount int) error {
	return fmt.Errorf("# of %s queries (%d) must not exceed the allocated max %s (%d), check your AppCircuit.Allocate() method",
		name, queryCount, name, maxCount)
}
