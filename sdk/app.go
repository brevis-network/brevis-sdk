package sdk

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/big"
	"path/filepath"
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
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

type ReceiptData struct {
	TxHash common.Hash    `json:"tx_hash,omitempty"`
	Fields []LogFieldData `json:"fields,omitempty"`
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

type BrevisApp struct {
	gc            *GatewayClient
	ec            *ethclient.Client
	brevisRequest *abi.ABI

	receipts    rawData[ReceiptData]
	storageVals rawData[StorageData]
	txs         rawData[TransactionData]

	localInputDataPath string
	localInputData     *DataPersistence

	// cache fields
	circuitInput                    CircuitInput
	buildInputCalled                bool
	queryId                         []byte
	nonce                           uint64
	srcChainId, dstChainId          uint64
	maxReceipts, maxStorage, maxTxs int
	dataPoints                      int
}

func NewBrevisApp(
	srcChainId uint64,
	numMaxDataPoints int,
	rpcUrl string,
	localStoragePath string,
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

	localInputDataPath := filepath.Join(localStoragePath, "data.json")
	localInputData := readDataFromLocalStorage(localInputDataPath)
	if localInputData == nil {
		localInputData = &DataPersistence{
			Receipts: map[string]*ReceiptPersistence{},
			Storages: map[string]*StoragePersistence{},
			Txs:      map[string]*TransactionPersistence{},
		}
	}

	return &BrevisApp{
		gc:                 gc,
		ec:                 ec,
		brevisRequest:      br,
		srcChainId:         srcChainId,
		receipts:           rawData[ReceiptData]{},
		storageVals:        rawData[StorageData]{},
		txs:                rawData[TransactionData]{},
		numMaxDataPoints:   numMaxDataPoints,
		localInputData:     localInputData,
		localInputDataPath: localInputDataPath,
	}, nil
}

// AddReceipt adds the ReceiptData to be queried. If an index is specified, the
// data will be assigned to the specified index of DataInput.Receipts.
func (q *BrevisApp) AddReceipt(data ReceiptData, index ...int) {
	if len(data.Fields) > NumMaxLogFields {
		panic(fmt.Sprintf("maximum number of log fields in one receipt is %d", NumMaxLogFields))
	}
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

	q.dataPoints = DataPointsNextPowerOf2(q.maxReceipts + q.maxStorage + q.maxTxs)
	in := defaultCircuitInput(q.maxReceipts, q.maxStorage, q.maxTxs, q.dataPoints)

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

	q.writeDataIntoLocalStorage()

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

	appCircuitInfo, err := buildAppCircuitInfo(q.circuitInput, q.maxReceipts, q.maxStorage, q.maxTxs, vk, witness)
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

	appCircuitInfo, err := buildAppCircuitInfo(q.circuitInput, q.maxReceipts, q.maxStorage, q.maxTxs, vk, witness)
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

	if maxReceipts == 0 && maxSlots == 0 && maxTxs == 0 {
		return fmt.Errorf("no receipts, slots and txs used in circuit")
	}
	return nil
}

func (q *BrevisApp) assignInputCommitment(w *CircuitInput) {
	leafs := make([]*big.Int, q.dataPoints)
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

	for i := j; i < q.dataPoints; i++ {
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
	in.TogglesCommitment, err = CalTogglesHashRoot(in.Toggles(), q.dataPoints)
	if err != nil {
		log.Panicf("fail to CalTogglesHashRoot, err: %v", err)
	}
}

func (q *BrevisApp) calTogglesHashRoot(toggles []frontend.Variable) (*big.Int, error) {
	leafs := make([]*big.Int, dataPoints/32)
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
		receiptInfo, mptKey, blockNum, blockBaseFee, err := q.getReceiptInfos(r.TxHash)
		if err != nil {
			return Receipt{}, err
		}
		fields, err := buildLogFieldsPersistence(r.Fields, receiptInfo)
		if err != nil {
			return Receipt{}, err
		}

		data = &ReceiptPersistence{
			TxHash:       r.TxHash,
			BlockNum:     blockNum,
			BlockBaseFee: blockBaseFee,
			MptKeyPath:   mptKey,
			Fields:       fields,
		}
		q.localInputData.Receipts[key] = data
	}
	return convertReceiptPersistenceToReceipt(data), nil
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
		blockBaseFee, err := q.getBlockBaseFee(s.BlockNum)
		if err != nil {
			return StorageSlot{}, nil
		}

		value, err := q.getStorageValue(s.BlockNum, s.Address, s.Slot)
		if err != nil {
			return StorageSlot{}, nil
		}

		data = &StoragePersistence{
			BlockNum:     s.BlockNum,
			BlockBaseFee: blockBaseFee,
			Address:      s.Address,
			Slot:         s.Slot,
			Value:        value,
		}
		q.localInputData.Storages[key] = data
	}

	return convertStoragePersistenceToStorage(data), nil
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
		leafHash, mptKey, blockNumber, baseFee, err := q.calculateTxLeafHashBlockBaseFeeAndMPTKey(t.Hash)
		if err != nil {
			return Transaction{}, err
		}

		data = &TransactionPersistence{
			Hash:         t.Hash,
			BlockNum:     blockNumber,
			BlockBaseFee: baseFee,
			MptKeyPath:   mptKey,
			LeafHash:     leafHash,
		}
		q.localInputData.Txs[key] = data
	}

	return convertTxPersistenceToTransaction(data), nil
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
