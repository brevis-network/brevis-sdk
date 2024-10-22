package sdk

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/consensys/gnark/frontend"

	brevisCommon "github.com/brevis-network/brevis-sdk/common"

	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"

	"github.com/brevis-network/brevis-sdk/sdk/eth"
	"github.com/brevis-network/zk-hash/utils"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

type ReceiptData struct {
	TxHash common.Hash                   `json:"tx_hash,omitempty"`
	Fields [NumMaxLogFields]LogFieldData `json:"fields,omitempty"`
}

// LogFieldData represents a single field of an event.
type LogFieldData struct {
	// the log's position in the receipt
	LogPos uint `json:"log_index,omitempty"`
	// Whether the field is a topic (aka "indexed" as in solidity events)
	IsTopic bool `json:"is_topic,omitempty"`
	// The index of the field in either a log's topics or data. For example, if a
	// field is the second topic of a log, then FieldIndex is 1; if a field is the
	// third field in the RLP decoded data, then FieldIndex is 2.
	FieldIndex uint `json:"field_index,omitempty"`
}

type StorageData struct {
	BlockNum *big.Int       `json:"block_num,omitempty"`
	Address  common.Address `json:"address,omitempty"`
	Slot     common.Hash    `json:"slot,omitempty"`
}

type TransactionData struct {
	Hash common.Hash `json:"hash,omitempty"`
}

type rawData[T ReceiptData | StorageData | TransactionData] struct {
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
		q.special[index[0]] = data
	} else {
		q.ordered = append(q.ordered, data)
	}
}

func (q *rawData[T]) list(max int) []T {
	var empty T
	var l []T
	ordered := q.ordered
	for i := 0; i < max; i++ {
		if q.special[i] != empty {
			l = append(l, q.special[i])
		} else if len(ordered) > 0 {
			l = append(l, ordered[0])
			ordered = ordered[1:]
		}
	}
	return l
}

type BrevisApp struct {
	gc            *GatewayClient
	ec            *ethclient.Client
	brevisRequest *abi.ABI

	receipts    rawData[ReceiptData]
	storageVals rawData[StorageData]
	txs         rawData[TransactionData]

	// cache fields
	circuitInput                                      CircuitInput
	buildInputCalled                                  bool
	queryId                                           []byte
	nonce                                             uint64
	srcChainId, dstChainId                            uint64
	maxReceipts, maxStorage, maxTxs, numMaxDataPoints int
}

func NewBrevisApp(
	srcChainId uint64,
	numMaxDataPoints int,
	rpcUrl string,
	gatewayUrlOverride ...string,
) (*BrevisApp, error) {
	ec, err := ethclient.Dial(rpcUrl)
	if err != nil {
		fmt.Printf("dialing invalid rpc url %s: %s\n", rpcUrl, err.Error())
		return nil, err
	}

	chainId, err := ec.ChainID(context.Background())
	if err != nil {
		return nil, err
	}

	if srcChainId != chainId.Uint64() {
		return nil, fmt.Errorf("invalid src chain id %d rpcUrl %s pair", srcChainId, rpcUrl)
	}
	gc, err := NewGatewayClient(gatewayUrlOverride...)
	if err != nil {
		return nil, err
	}

	br, err := eth.BrevisRequestMetaData.GetAbi()
	if err != nil {
		return nil, err
	}

	if numMaxDataPoints < 64 {
		return nil, fmt.Errorf("the minimum numMaxDataPoints is 64")
	}

	if numMaxDataPoints%64 != 0 {
		return nil, fmt.Errorf("numMaxDataPoints %d should be integral multiple of 64", numMaxDataPoints)
	}

	if !CheckNumberPowerOfTwo(numMaxDataPoints / 64) {
		return nil, fmt.Errorf("numMaxDataPoints / 32 %d should be a power of 2", numMaxDataPoints)
	}
	return &BrevisApp{
		gc:               gc,
		ec:               ec,
		brevisRequest:    br,
		srcChainId:       srcChainId,
		receipts:         rawData[ReceiptData]{},
		storageVals:      rawData[StorageData]{},
		txs:              rawData[TransactionData]{},
		numMaxDataPoints: numMaxDataPoints,
	}, nil
}

// AddReceipt adds the ReceiptData to be queried. If an index is specified, the
// data will be assigned to the specified index of DataInput.Receipts.
func (q *BrevisApp) AddReceipt(data ReceiptData, index ...int) {
	q.receipts.add(data, index...)
}

// AddStorage adds the StorageData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.StorageSlots.
func (q *BrevisApp) AddStorage(data StorageData, index ...int) {
	q.storageVals.add(data, index...)
}

// AddTransaction adds the TransactionData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.Transactions.
func (q *BrevisApp) AddTransaction(data TransactionData, index ...int) {
	q.txs.add(data, index...)
}

// BuildCircuitInput executes all added queries and package the query results
// into circuit assignment (the DataInput struct) The provided ctx is used
// when performing network calls to the provided blockchain RPC.
func (q *BrevisApp) BuildCircuitInput(app AppCircuit) (CircuitInput, error) {

	// 1. mimc hash data at each position to generate and assign input commitments and toggles commitment
	// 2. dry-run user circuit to generate output and output commitment

	q.maxReceipts, q.maxStorage, q.maxTxs = app.Allocate()
	err := q.checkAllocations(app)
	if err != nil {
		return CircuitInput{}, err
	}

	in := defaultCircuitInput(q.maxReceipts, q.maxStorage, q.maxTxs, q.numMaxDataPoints)

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

func (q *BrevisApp) PrepareRequest(
	vk plonk.VerifyingKey,
	witness witness.Witness,
	srcChainId, dstChainId uint64,
	refundee, appContract common.Address,
	callbackGasLimit uint64,
	option *gwproto.QueryOption,
	apiKey string, // used for brevis partner flow
	vkHash []byte,
) (calldata []byte, requestId common.Hash, nonce uint64, feeValue *big.Int, err error) {
	if !q.buildInputCalled {
		panic("must call BuildCircuitInput before PrepareRequest")
	}
	if len(apiKey) > 0 {
		fmt.Println("Use Brevis Partner Flow to PrepareRequest...")
		return q.prepareQueryForBrevisPartnerFlow(
			vk, witness, srcChainId, dstChainId, appContract, option, apiKey, vkHash,
		)
	}

	q.srcChainId = srcChainId
	q.dstChainId = dstChainId

	appCircuitInfo, err := buildAppCircuitInfo(q.circuitInput, q.maxReceipts, q.maxStorage, q.maxTxs, q.numMaxDataPoints, vk, witness)
	if err != nil {
		return
	}

	req := &gwproto.PrepareQueryRequest{
		ChainId:           srcChainId,
		TargetChainId:     dstChainId,
		ReceiptInfos:      buildReceiptInfos(q.receipts, q.maxReceipts),
		StorageQueryInfos: buildStorageQueryInfos(q.storageVals, q.maxStorage),
		TransactionInfos:  buildTxInfos(q.txs, q.maxTxs),
		AppCircuitInfo:    appCircuitInfo,
		Option:            *option,
	}

	fmt.Println("Calling Brevis gateway PrepareRequest...")
	res, err := q.gc.PrepareQuery(req)
	if err != nil {
		return
	}
	queryId, err := hexutil.Decode(res.QueryKey.QueryHash)
	if err != nil {
		return
	}
	q.queryId = queryId
	q.nonce = res.QueryKey.Nonce

	feeValue, ok := new(big.Int).SetString(res.GetFee(), 10)
	if !ok {
		err = fmt.Errorf("cannot parse fee value of %s", res.GetFee())
		return
	}

	fmt.Printf("Brevis gateway responded with proofId %x, nonce %d, feeValue %d\n", queryId, q.nonce, feeValue)

	calldata, err = q.buildSendRequestCalldata(common.BytesToHash(queryId), res.QueryKey.Nonce, refundee, eth.IBrevisTypesCallback{
		Target: appContract,
		Gas:    callbackGasLimit,
	}, uint8(0))
	return calldata, common.BytesToHash(queryId), q.nonce, feeValue, err
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

// WithFinalProofSubmittedCallback sets an async callback for final proof submission result
func WithFinalProofSubmittedCallback(onSubmitted func(txHash common.Hash), onError func(err error)) SubmitProofOption {
	return func(option submitProofOptions) {
		option.onSubmitted = onSubmitted
		option.onError = onError
	}
}

// WithContext uses the input context as the context for waiting for final proof submission
func WithContext(ctx context.Context) SubmitProofOption {
	return func(option submitProofOptions) { option.ctx = ctx }
}

func (q *BrevisApp) SubmitProofWithQueryId(queryId string, nonce uint64, dstChainId uint64, proof []byte) error {
	res, err := q.gc.SubmitProof(&gwproto.SubmitAppCircuitProofRequest{
		QueryKey: &gwproto.QueryKey{
			QueryHash: queryId,
			Nonce:     nonce,
		},
		TargetChainId: dstChainId,
		Proof:         hexutil.Encode(proof),
	})
	if err != nil {
		return fmt.Errorf("error calling brevis gateway SubmitProof: %s", err.Error())
	}
	if !res.GetSuccess() {
		return fmt.Errorf("error calling brevis gateway SubmitProof: cdoe %s, msg %s",
			res.GetErr().GetCode(), res.GetErr().GetMsg())
	}
	return nil
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
	res, err := q.gc.SubmitProof(&gwproto.SubmitAppCircuitProofRequest{
		QueryKey: &gwproto.QueryKey{
			QueryHash: hexutil.Encode(q.queryId),
			Nonce:     q.nonce,
		},
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
			res, err := q.gc.GetQueryStatus(&gwproto.GetQueryStatusRequest{
				QueryKey: &gwproto.QueryKey{
					QueryHash: hexutil.Encode(q.queryId),
					Nonce:     q.nonce,
				},
				TargetChainId: q.dstChainId,
			})
			if err != nil {
				return common.Hash{}, fmt.Errorf("error querying proof status: %s", err.Error())
			}
			if res.Status == gwproto.QueryStatus_QS_COMPLETE {
				fmt.Printf("final proof for query %x submitted: tx %s\n", q.queryId, res.TxHash)
				return common.HexToHash(res.TxHash), nil
			} else if res.Status == gwproto.QueryStatus_QS_FAILED {
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

func (q *BrevisApp) prepareQueryForBrevisPartnerFlow(
	vk plonk.VerifyingKey,
	witness witness.Witness,
	srcChainId, dstChainId uint64,
	appContract common.Address,
	option *gwproto.QueryOption,
	apiKey string, // used for brevis partner flow
	vkHash []byte,
) (calldata []byte, requestId common.Hash, nonce uint64, feeValue *big.Int, err error) {
	if !q.buildInputCalled {
		panic("must call BuildCircuitInput before PrepareRequest")
	}
	q.srcChainId = srcChainId
	q.dstChainId = dstChainId

	appCircuitInfo, err := buildAppCircuitInfo(q.circuitInput, q.maxReceipts, q.maxStorage, q.maxTxs, q.numMaxDataPoints, vk, witness)
	if err != nil {
		err = fmt.Errorf("failed to build app circuit info: %s", err.Error())
		return
	}

	req := &gwproto.SendBatchQueriesRequest{
		ChainId: srcChainId,
		Queries: []*gwproto.Query{
			{
				ReceiptInfos:      buildReceiptInfos(q.receipts, q.maxReceipts),
				StorageQueryInfos: buildStorageQueryInfos(q.storageVals, q.maxStorage),
				TransactionInfos:  buildTxInfos(q.txs, q.maxTxs),
				AppCircuitInfo: &commonproto.AppCircuitInfoWithProof{
					OutputCommitment:     appCircuitInfo.OutputCommitment,
					VkHash:               hexutil.Encode(vkHash),
					InputCommitments:     appCircuitInfo.InputCommitments,
					Toggles:              appCircuitInfo.Toggles,
					Output:               appCircuitInfo.Output,
					CallbackAddr:         hexutil.Encode(appContract[:]),
					InputCommitmentsRoot: appCircuitInfo.InputCommitmentsRoot,
					MaxReceipts:          appCircuitInfo.MaxReceipts,
					MaxStorage:           appCircuitInfo.MaxStorage,
					MaxTx:                appCircuitInfo.MaxTx,
				},
			},
		},
		TargetChainId: dstChainId,
		Option:        *option,
		ApiKey:        apiKey,
	}
	fmt.Println("Calling Brevis gateway PrepareRequest...")
	res, err := q.gc.SendBatchQueries(req)
	if err != nil {
		return
	}

	if len(res.QueryKeys) == 0 {
		err = fmt.Errorf("empty query info from brevis gateway")
		return
	}

	queryKey := res.QueryKeys[0]
	queryId, err := hexutil.Decode(queryKey.QueryHash)
	if err != nil {
		return
	}
	q.queryId = queryId
	q.nonce = queryKey.Nonce

	feeValue, ok := new(big.Int).SetString(res.GetFee(), 10)
	if !ok {
		err = fmt.Errorf("cannot parse fee value of %s", res.GetFee())
		return
	}

	fmt.Printf("Brevis gateway responded with proofId %x, nonce %d, feeValue %d\n", queryId, q.nonce, feeValue)
	fmt.Println("No need to submit on-chain tx for brevis partner flow")
	return nil, common.BytesToHash(queryId), q.nonce, feeValue, err
}

func (q *BrevisApp) checkAllocations(cb AppCircuit) error {
	maxReceipts, maxSlots, maxTxs := cb.Allocate()

	numReceipts := len(q.receipts.special) + len(q.receipts.ordered)
	if maxReceipts%32 != 0 {
		return allocationMultipleErr("receipt", maxReceipts)
	}
	if numReceipts > maxReceipts {
		return allocationLenErr("receipt", numReceipts, maxReceipts)
	}
	numStorages := len(q.storageVals.special) + len(q.storageVals.ordered)
	if maxSlots%32 != 0 {
		return allocationMultipleErr("storage", maxSlots)
	}
	if numStorages > maxSlots {
		return allocationLenErr("storage", numStorages, maxSlots)
	}
	numTxs := len(q.txs.special) + len(q.txs.ordered)
	if maxTxs%32 != 0 {
		return allocationMultipleErr("transaction", maxTxs)
	}
	if numTxs > maxTxs {
		return allocationLenErr("transaction", numTxs, maxTxs)
	}
	total := maxReceipts + maxSlots + maxTxs
	if total > q.numMaxDataPoints {
		return allocationLenErr("total", total, q.numMaxDataPoints)
	}
	return nil
}

func (q *BrevisApp) assignInputCommitment(w *CircuitInput) {
	leafs := make([]*big.Int, q.numMaxDataPoints)
	hasher := utils.NewPoseidonBn254()
	// assign 0 to input commit for dummy and actual data hash for non-dummies
	j := 0

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

	for i := j; i < q.numMaxDataPoints; i++ {
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
	leafs := make([]*big.Int, q.numMaxDataPoints/32)
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
			return nil, fmt.Errorf("invalid toggles length %d", len(toggles))
		}
		leafs[i] = result
	}

	togglesHashRoot, err := CalPoseidonBn254MerkleTree(leafs)
	if err != nil {
		panic(fmt.Sprintf("fail to cal toggles hash root %v", err))
	}
	return togglesHashRoot, nil
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

func (q *BrevisApp) assignReceipts(in *CircuitInput) error {
	// assigning user appointed receipts at specific indices
	for i, receipt := range q.receipts.special {
		receiptInfo, mptKey, blockNum, blockBaseFee, err := q.getReceiptInfos(receipt.TxHash)
		if err != nil {
			return err
		}
		fields, err := buildLogFields(receipt.Fields, receiptInfo)
		if err != nil {
			return err
		}
		in.Receipts.Raw[i] = Receipt{
			BlockNum:     newU32(blockNum),
			BlockBaseFee: newU248(blockBaseFee),
			MptKeyPath:   newU32(mptKey),
			Fields:       fields,
		}
		in.Receipts.Toggles[i] = 1
	}

	// distribute other receipts in order to the rest of the unassigned spaces
	j := 0
	for _, receipt := range q.receipts.ordered {
		receiptInfo, mptKey, blockNum, blockBaseFee, err := q.getReceiptInfos(receipt.TxHash)
		if err != nil {
			return err
		}
		for in.Receipts.Toggles[j] == 1 {
			j++
		}
		fields, err := buildLogFields(receipt.Fields, receiptInfo)
		if err != nil {
			return err
		}
		in.Receipts.Raw[j] = Receipt{
			BlockNum:     newU32(blockNum),
			BlockBaseFee: newU248(blockBaseFee),
			MptKeyPath:   newU32(mptKey),
			Fields:       fields,
		}
		in.Receipts.Toggles[j] = 1
		j++
	}

	return nil
}

func BuildLogFields(fs [NumMaxLogFields]LogFieldData, receipt *types.Receipt) (fields [NumMaxLogFields]LogField, err error) {
	return buildLogFields(fs, receipt)
}

func buildLogFields(fs [NumMaxLogFields]LogFieldData, receipt *types.Receipt) (fields [NumMaxLogFields]LogField, err error) {
	empty := LogFieldData{}

	lastNonEmpty := fs[0]
	for i := 0; i < NumMaxLogFields; i++ {
		// Due to backend circuit's limitations, we must fill []LogField with valid data
		// up to NumMaxLogFields. If the user actually only wants less NumMaxLogFields
		// log fields, then we simply copy the previous log field in the list to fill the
		// empty spots.
		f := fs[i]
		if i > 0 && f == empty {
			f = lastNonEmpty
		} else {
			lastNonEmpty = f
		}

		if len(receipt.Logs) <= int(f.LogPos) {
			return [NumMaxLogFields]LogField{}, fmt.Errorf("invalid log pos %d for receipt %s", f.LogPos, receipt.TxHash.Hex())
		}

		log := receipt.Logs[f.LogPos]

		value := common.Hash{}

		if f.IsTopic {
			if int(f.FieldIndex) >= len(log.Topics) {
				return [NumMaxLogFields]LogField{}, fmt.Errorf("invalid field index %d for receipt %s log %d, which topics length is %d", f.FieldIndex, receipt.TxHash.Hex(), f.LogPos, len(log.Topics))
			}
			value = log.Topics[f.FieldIndex]
		} else {
			if int(f.FieldIndex)*32+32 > len(log.Data) {
				return [NumMaxLogFields]LogField{}, fmt.Errorf("invalid field index %d (try to find data range from %d to %d) for receipt %s log %d, which data length is %d", f.FieldIndex, f.FieldIndex*32, f.FieldIndex*32+32, receipt.TxHash.Hex(), f.LogPos, len(log.Data))
			}
			value = common.BytesToHash(log.Data[f.FieldIndex*32 : f.FieldIndex*32+32])
		}

		fields[i] = LogField{
			Contract: ConstUint248(log.Address),
			LogPos:   ConstUint32(f.LogPos),
			// we only constrain the first 6 bytes of EventID in circuit for performance reasons
			// 6 bytes give us 1/2^48 chance of two logs of different IDs clashing per contract.
			EventID: ConstUint248(log.Topics[0].Bytes()[0:6]),
			IsTopic: ConstUint248(f.IsTopic),
			Index:   ConstUint248(f.FieldIndex),
			Value:   ConstBytes32(value[:]),
		}
	}
	return
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
	blockBaseFee, err := q.getBlockBaseFee(s.BlockNum)
	if err != nil {
		return StorageSlot{}, nil
	}

	value, err := q.getStorageValue(s.BlockNum, s.Address, s.Slot)
	if err != nil {
		return StorageSlot{}, nil
	}

	return StorageSlot{
		BlockNum:     newU32(s.BlockNum),
		BlockBaseFee: newU248(blockBaseFee),
		Contract:     ConstUint248(s.Address),
		Slot:         ConstBytes32(s.Slot[:]),
		Value:        ConstBytes32(value[:]),
	}, nil
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
	leafHash, mptKey, blockNumber, baseFee, err := q.calculateTxLeafHashBlockBaseFeeAndMPTKey(t.Hash)
	if err != nil {
		return Transaction{}, err
	}

	return Transaction{
		BlockNum:     ConstUint32(blockNumber),
		BlockBaseFee: newU248(baseFee),
		MptKeyPath:   newU32(mptKey),
		LeafHash:     ConstBytes32(leafHash.Bytes()),
	}, nil
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

func (q *BrevisApp) calculateMPTKeyWithIndex(index int) *big.Int {
	var indexBuf []byte
	keyIndex := rlp.AppendUint64(indexBuf[:0], uint64(index))
	return new(big.Int).SetBytes(keyIndex)
}

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
