package sdk

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/big"
	"path/filepath"
	"time"

	pgoldilocks "github.com/OpenAssetStandards/poseidon-goldilocks-go"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/sync/errgroup"

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
	TxHash         common.Hash    `json:"tx_hash,omitempty"`         // Required value
	BlockNum       *big.Int       `json:"block_num,omitempty"`       // Optional value
	BlockBaseFee   *big.Int       `json:"block_base_fee,omitempty"`  // Optional value
	MptKeyPath     *big.Int       `json:"mpt_key_path,omitempty"`    // Optional value
	Fields         []LogFieldData `json:"fields,omitempty"`          // required value
	BlockTimestamp uint64         `json:"block_timestamp,omitempty"` // Optional value
}

type LogFieldData struct {
	// The contract from which the event is emitted
	// Optional value
	Contract common.Address `json:"contract,omitempty"`
	// The event ID of the event to which the field belong (aka topics[0])
	// Optional value
	EventID common.Hash `json:"event_id,omitempty"`
	// the log's position in the receipt
	// Required value
	LogPos uint `json:"log_index,omitempty"`
	// Whether the field is a topic (aka "indexed" as in solidity events)
	// Required value
	IsTopic bool `json:"is_topic,omitempty"`
	// The index of the field in either a log's topics or data. For example, if a
	// field is the second topic of a log, then FieldIndex is 1; if a field is the
	// third field in the RLP decoded data, then FieldIndex is 2.
	// Required value
	FieldIndex uint `json:"field_index,omitempty"`
	// The value of the field in event, aka the actual thing we care about, only
	// 32-byte fixed length values are supported.
	// Optional value
	Value common.Hash `json:"value,omitempty"`
}

type StorageData struct {
	BlockNum       *big.Int       `json:"block_num,omitempty"`       // Required value
	BlockBaseFee   *big.Int       `json:"block_base_fee,omitempty"`  // Optional value
	Address        common.Address `json:"address,omitempty"`         // Required value
	Slot           common.Hash    `json:"slot,omitempty"`            // Required value
	Value          common.Hash    `json:"value,omitempty"`           // Optional value
	BlockTimestamp uint64         `json:"block_timestamp,omitempty"` // Optional value
}

type TransactionData struct {
	Hash           common.Hash `json:"hash,omitempty"`            // Required value
	BlockNum       *big.Int    `json:"block_num,omitempty"`       // Optional value
	BlockBaseFee   *big.Int    `json:"block_base_fee,omitempty"`  // Optional value
	MptKeyPath     *big.Int    `json:"mpt_key_path,omitempty"`    // Optional value
	LeafHash       common.Hash `json:"leaf_hash,omitempty"`       // Optional value
	BlockTimestamp uint64      `json:"block_timestamp,omitempty"` // Optional value
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
		if _, ok := q.special[index[0]]; ok {
			panic(fmt.Sprintf("an element already pinned at index %d", index[0]))
		}
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

	mockReceipts rawData[ReceiptData]
	mockStorage  rawData[StorageData]
	mockTxs      rawData[TransactionData]

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

	receiptCircuitDigestHash *pgoldilocks.HashOut256
	storageCircuitDigestHash *pgoldilocks.HashOut256
	txCircuitDigestHash      *pgoldilocks.HashOut256
}

func NewBrevisApp(
	srcChainId uint64,
	rpcUrl string,
	outDir string,
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

	localInputDataPath := filepath.Join(outDir, "input", "data.json")
	localInputData, _ := readDataFromLocalStorage(localInputDataPath)
	if localInputData == nil {
		localInputData = &DataPersistence{}
	}

	resp, err := gc.c.GetCircuitDigest(context.Background(), &gwproto.CircuitDigestRequest{})
	if err != nil {
		panic(err)
	}
	if resp.Err != nil {
		panic(resp.Err)
	}
	if len(resp.HashesLimbs) != 12 {
		panic("invalid circuit digest hashes limbs")
	}

	return &BrevisApp{
		gc:                       gc,
		ec:                       ec,
		brevisRequest:            br,
		srcChainId:               srcChainId,
		receipts:                 rawData[ReceiptData]{},
		storageVals:              rawData[StorageData]{},
		txs:                      rawData[TransactionData]{},
		localInputData:           localInputData,
		localInputDataPath:       localInputDataPath,
		receiptCircuitDigestHash: &pgoldilocks.HashOut256{resp.HashesLimbs[0], resp.HashesLimbs[1], resp.HashesLimbs[2], resp.HashesLimbs[3]},
		storageCircuitDigestHash: &pgoldilocks.HashOut256{resp.HashesLimbs[4], resp.HashesLimbs[5], resp.HashesLimbs[6], resp.HashesLimbs[7]},
		txCircuitDigestHash:      &pgoldilocks.HashOut256{resp.HashesLimbs[8], resp.HashesLimbs[9], resp.HashesLimbs[10], resp.HashesLimbs[11]},
	}, nil
}

// set digests directly
func NewBrevisAppWithDigestsSetOnly(receiptCircuitDigestHash, storageCircuitDigestHash, txCircuitDigestHash *pgoldilocks.HashOut256) *BrevisApp {
	return &BrevisApp{
		receiptCircuitDigestHash: receiptCircuitDigestHash,
		storageCircuitDigestHash: storageCircuitDigestHash,
		txCircuitDigestHash:      txCircuitDigestHash,
	}
}

// retrieve digests from gateway
func NewBrevisAppWithDigestsSetOnlyFromRemote(gatewayUrlOverride ...string) *BrevisApp {
	gc, err := NewGatewayClient(gatewayUrlOverride...)
	if err != nil {
		panic(err)
	}

	resp, err := gc.c.GetCircuitDigest(context.Background(), &gwproto.CircuitDigestRequest{})
	if err != nil {
		panic(err)
	}
	if resp.Err != nil {
		panic(resp.Err)
	}
	if len(resp.HashesLimbs) != 12 {
		panic("invalid circuit digest hashes limbs")
	}

	return &BrevisApp{
		gc:                       gc,
		receiptCircuitDigestHash: &pgoldilocks.HashOut256{resp.HashesLimbs[0], resp.HashesLimbs[1], resp.HashesLimbs[2], resp.HashesLimbs[3]},
		storageCircuitDigestHash: &pgoldilocks.HashOut256{resp.HashesLimbs[4], resp.HashesLimbs[5], resp.HashesLimbs[6], resp.HashesLimbs[7]},
		txCircuitDigestHash:      &pgoldilocks.HashOut256{resp.HashesLimbs[8], resp.HashesLimbs[9], resp.HashesLimbs[10], resp.HashesLimbs[11]},
	}
}

// AddReceipt adds the ReceiptData to be queried. If an index is specified, the
// data will be assigned to the specified index of DataInput.Receipts.
func (q *BrevisApp) AddReceipt(data ReceiptData, index ...int) {
	if len(data.Fields) > NumMaxLogFields {
		panic(fmt.Sprintf("maximum number of log fields in one receipt is %d", NumMaxLogFields))
	}
	q.receipts.add(data, index...)
}

// AddMockReceipt adds the MockReceipt to be queried. If an index is specified, the
// data will be assigned to the specified index of DataInput.Receipts.
// It should be used ONLY for circuit implementation and testing.
func (q *BrevisApp) AddMockReceipt(data ReceiptData, index ...int) {
	if len(data.Fields) > NumMaxLogFields {
		panic(fmt.Sprintf("maximum number of log fields in one receipt is %d", NumMaxLogFields))
	}
	q.mockReceipts.add(data, index...)
}

// AddStorage adds the StorageData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.StorageSlots.
func (q *BrevisApp) AddStorage(data StorageData, index ...int) {
	if data.BlockNum == nil {
		panic(fmt.Sprintf("storage data block num missing: %+v", data))
	}
	q.storageVals.add(data, index...)
}

// AddMockStorage adds the MockStorage to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.StorageSlots.
// It should be used ONLY for circuit implementation and testing.
func (q *BrevisApp) AddMockStorage(data StorageData, index ...int) {
	q.mockStorage.add(data, index...)
}

// AddTransaction adds the TransactionData to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.Transactions.
func (q *BrevisApp) AddTransaction(data TransactionData, index ...int) {
	q.txs.add(data, index...)
}

// AddMockTransaction adds the MockTransaction to be queried. If an index is
// specified, the data will be assigned to the specified index of
// DataInput.Transactions.
// It should be used ONLY for circuit implementation and testing.
func (q *BrevisApp) AddMockTransaction(data TransactionData, index ...int) {
	q.mockTxs.add(data, index...)
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

	var errG errgroup.Group
	// receipt
	errG.Go(func() error {
		err := q.assignReceipts(&in)
		if err != nil {
			return fmt.Errorf("failed to assign in from receipt queries: %w", err)
		}
		return nil
	})

	// storage
	errG.Go(func() error {
		err := q.assignStorageSlots(&in)
		if err != nil {
			return fmt.Errorf("failed to assign in from storage queries: %w", err)
		}
		return nil
	})

	// transaction
	errG.Go(func() error {
		err = q.assignTransactions(&in)
		if err != nil {
			return fmt.Errorf("failed to assign in from transaction queries: %w", err)
		}
		return nil
	})

	err = errG.Wait()
	if err != nil {
		return buildCircuitInputErr("failed to build input", err)
	}

	q.writeDataIntoLocalStorage()

	if q.realDataLength() > 0 && q.mockDataLength() > 0 {
		return CircuitInput{}, fmt.Errorf("you cannot add real data and mock data at the same time")
	}
	err = q.assignMockReceipts(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from receipt queries", err)
	}

	// storage
	err = q.assignMockStorageSlots(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from storage queries", err)
	}

	// transaction
	err = q.assignMockTransactions(&in)
	if err != nil {
		return buildCircuitInputErr("failed to assign in from transaction queries", err)
	}

	dummyResponse, err := q.gc.GetCircuitDummyInput(&gwproto.CircuitDummyInputRequest{
		ChainId: q.srcChainId,
	})
	if err != nil || dummyResponse == nil {
		return buildCircuitInputErr("failed to get dummy information from brevis gateway", err)
	}
	if dummyResponse.Err != nil || len(dummyResponse.Receipt) == 0 ||
		len(dummyResponse.Storage) == 0 || len(dummyResponse.Tx) == 0 {
		return CircuitInput{}, fmt.Errorf("failed to get dummy information from brevis gateway: %s", dummyResponse.Err.Msg)
	}

	// commitment
	q.assignInputCommitment(&in, dummyResponse)
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
) (calldata []byte, requestId common.Hash, nonce uint64, feeValue *big.Int, err error) {
	if q.mockDataLength() > 0 {
		panic("you cannot use mock data to send PrepareRequest")
	}
	if !q.buildInputCalled {
		panic("must call BuildCircuitInput before PrepareRequest")
	}
	if len(apiKey) > 0 {
		fmt.Println("Use Brevis Partner Flow to PrepareRequest...")
		return q.prepareQueryForBrevisPartnerFlow(
			vk, witness, srcChainId, dstChainId, appContract, option, apiKey)
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

		errChan := make(chan error, 1)

		go func() {
			tx, err := q.waitFinalProofSubmitted(cancel)
			if err != nil {
				fmt.Println(err.Error())
				opts.onError(err)
				errChan <- err
				return
			}
			opts.onSubmitted(tx)
			errChan <- nil
		}()
		return <-errChan
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

	vkHashInBigInt, err := CalBrevisCircuitDigest(q.maxReceipts, q.maxStorage, q.dataPoints-q.maxReceipts-q.maxStorage, vk, q)
	if err != nil {
		fmt.Printf("error computing vk hash: %s", err.Error())
		return
	}

	// Make sure vk hash is 32-bytes
	vkHash := common.BytesToHash(vkHashInBigInt.Bytes()).Bytes()

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
					Witness:              appCircuitInfo.Witness,
					MaxReceipts:          appCircuitInfo.MaxReceipts,
					MaxStorage:           appCircuitInfo.MaxStorage,
					MaxTx:                appCircuitInfo.MaxTx,
					MaxNumDataPoints:     appCircuitInfo.MaxNumDataPoints,
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

func (q *BrevisApp) GenerateProtoQuery(
	vk plonk.VerifyingKey,
	witness witness.Witness,
	proof []byte,
	callbackAddr common.Address,
) (*gwproto.Query, error) {
	if q.mockDataLength() > 0 {
		panic("you cannot use mock data to generate proto query")
	}
	appCircuitInfo, err := buildAppCircuitInfo(q.circuitInput, q.maxReceipts, q.maxStorage, q.maxTxs, vk, witness)
	if err != nil {
		return nil, err
	}

	vkHashInBigInt, err := CalBrevisCircuitDigest(q.maxReceipts, q.maxStorage, q.dataPoints-q.maxReceipts-q.maxStorage, vk, q)
	if err != nil {
		fmt.Printf("error computing vk hash: %s", err.Error())
		return nil, err
	}

	// Make sure vk hash is 32-bytes
	vkHash := common.BytesToHash(vkHashInBigInt.Bytes()).Bytes()

	return &gwproto.Query{
		ReceiptInfos:      buildReceiptInfos(q.receipts, q.maxReceipts),
		StorageQueryInfos: buildStorageQueryInfos(q.storageVals, q.maxStorage),
		TransactionInfos:  buildTxInfos(q.txs, q.maxTxs),
		AppCircuitInfo: &commonproto.AppCircuitInfoWithProof{
			OutputCommitment:     appCircuitInfo.OutputCommitment,
			VkHash:               hexutil.Encode(vkHash),
			InputCommitments:     appCircuitInfo.InputCommitments,
			Toggles:              appCircuitInfo.Toggles,
			Output:               appCircuitInfo.Output,
			CallbackAddr:         hexutil.Encode(callbackAddr[:]),
			InputCommitmentsRoot: appCircuitInfo.InputCommitmentsRoot,
			MaxReceipts:          appCircuitInfo.MaxReceipts,
			MaxStorage:           appCircuitInfo.MaxStorage,
			MaxTx:                appCircuitInfo.MaxTx,
		},
	}, nil
}

func (q *BrevisApp) SendBatchQuery(
	queries []*gwproto.Query,
	batchAPIKey string,
	queryOption *gwproto.QueryOption,
) (queryKeys []*gwproto.QueryKey, fee string, err error) {
	req := &gwproto.SendBatchQueriesRequest{
		ChainId:       q.srcChainId,
		TargetChainId: q.dstChainId,
		Queries:       queries,
		Option:        *queryOption,
		ApiKey:        batchAPIKey,
	}
	res, err := q.gc.SendBatchQueries(req)
	if err != nil {
		return nil, "", fmt.Errorf("error calling brevis gateway SendBatchQuery: %s", err.Error())
	}
	queryKeys = res.QueryKeys
	fee = res.Fee
	return
}

func (q *BrevisApp) checkAllocations(cb AppCircuit) error {
	maxReceipts, maxSlots, maxTxs := cb.Allocate()

	numReceipts := len(q.receipts.special) + len(q.receipts.ordered)
	if maxReceipts%32 != 0 {
		return allocationMultipleErr("receipt", maxReceipts)
	}
	for index := range q.receipts.special {
		if index >= maxReceipts {
			return allocationIndexErr("receipt", index, maxReceipts)
		}
	}
	if numReceipts > maxReceipts {
		return allocationLenErr("receipt", numReceipts, maxReceipts)
	}
	numStorages := len(q.storageVals.special) + len(q.storageVals.ordered)
	if maxSlots%32 != 0 {
		return allocationMultipleErr("storage", maxSlots)
	}
	for index := range q.storageVals.special {
		if index >= maxSlots {
			return allocationIndexErr("storage", index, maxSlots)
		}
	}
	if numStorages > maxSlots {
		return allocationLenErr("storage", numStorages, maxSlots)
	}
	numTxs := len(q.txs.special) + len(q.txs.ordered)
	if maxTxs%32 != 0 {
		return allocationMultipleErr("transaction", maxTxs)
	}
	for index := range q.txs.special {
		if index >= maxTxs {
			return allocationIndexErr("transaction", index, maxTxs)
		}
	}
	if numTxs > maxTxs {
		return allocationLenErr("transaction", numTxs, maxTxs)
	}

	if maxReceipts == 0 && maxSlots == 0 && maxTxs == 0 {
		return fmt.Errorf("no receipts, slots and txs used in circuit")
	}
	return nil
}

func (q *BrevisApp) assignInputCommitment(w *CircuitInput, dummyInputCommitment *gwproto.CircuitDummyInputResponse) {
	leafs := make([]*big.Int, q.dataPoints)
	hasher := utils.NewPoseidonBn254()

	j := 0
	ric := dummyInputCommitment.Receipt
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

	sic := dummyInputCommitment.Storage
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

	tic := dummyInputCommitment.Tx
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
	in.TogglesCommitment, err = q.calTogglesHashRoot(in.Toggles())
	if err != nil {
		log.Panicf("fail to CalTogglesHashRoot, err: %v", err)
	}
}

func (q *BrevisApp) calTogglesHashRoot(toggles []frontend.Variable) (*big.Int, error) {
	leafs := make([]*big.Int, q.dataPoints/32)
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
			return nil, err
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
	var errG errgroup.Group
	// assigning user appointed receipts at specific indices
	for i, r := range q.receipts.special {
		index := i
		receiptData := r
		in.Receipts.Toggles[index] = 1
		errG.Go(func() error {
			receipt, err := q.buildReceipt(receiptData)
			if err != nil {
				return err
			}
			in.Receipts.Raw[index] = receipt
			return nil
		})
	}

	// distribute other receipts in order to the rest of the unassigned spaces
	j := 0
	for _, r := range q.receipts.ordered {
		receiptData := r
		for in.Receipts.Toggles[j] == 1 {
			j++
		}
		in.Receipts.Toggles[j] = 1
		errG.Go(func() error {
			receipt, err := q.buildReceipt(receiptData)
			if err != nil {
				return err
			}
			in.Receipts.Raw[j] = receipt
			return nil
		})
		j++
	}

	return errG.Wait()
}

func (q *BrevisApp) BuildReceipt(t ReceiptData) (Receipt, error) {
	return q.buildReceipt(t)
}

func (q *BrevisApp) buildReceipt(r ReceiptData) (Receipt, error) {
	key := generateReceiptKey(r, q.srcChainId)
	data, ok := q.localInputData.Receipts.Load(key)
	if !ok {
		if r.isReadyToSave() {
			fmt.Println("adding manual input receipt data")
			data = &r
		} else {
			receiptInfo, mptKey, blockNum, baseFee, time, err := q.getReceiptInfos(r.TxHash)
			if err != nil {
				return Receipt{}, err
			}
			fields, err := buildLogFieldsData(r.Fields, receiptInfo)
			if err != nil {
				return Receipt{}, err
			}

			data = &ReceiptData{
				TxHash:         r.TxHash,
				BlockNum:       blockNum,
				BlockBaseFee:   baseFee,
				MptKeyPath:     mptKey,
				Fields:         fields,
				BlockTimestamp: time,
			}
		}
		q.localInputData.Receipts.Store(key, data)
	}
	return convertReceiptDataToReceipt(data.(*ReceiptData)), nil
}

func (q *BrevisApp) assignStorageSlots(in *CircuitInput) (err error) {
	var errG errgroup.Group
	// assigning user appointed data at specific indices
	for i, s := range q.storageVals.special {
		index := i
		storageData := s
		in.StorageSlots.Toggles[index] = 1

		errG.Go(func() error {
			storage, err := q.buildStorageSlot(storageData)
			if err != nil {
				return err
			}
			in.StorageSlots.Raw[index] = storage
			return nil
		})
	}

	// distribute other data in order to the rest of the unassigned spaces
	j := 0
	for _, s := range q.storageVals.ordered {
		storageData := s
		for in.StorageSlots.Toggles[j] == 1 {
			j++
		}
		in.StorageSlots.Toggles[j] = 1

		errG.Go(func() error {
			storage, err := q.buildStorageSlot(storageData)
			if err != nil {
				return err
			}
			in.StorageSlots.Raw[j] = storage
			return nil
		})
		j++
	}

	return errG.Wait()
}

func (q *BrevisApp) BuildStorageSlot(s StorageData) (StorageSlot, error) {
	return q.buildStorageSlot(s)
}

func (q *BrevisApp) buildStorageSlot(s StorageData) (StorageSlot, error) {
	key := generateStorageKey(s, q.srcChainId)
	data, ok := q.localInputData.Storages.Load(key)
	if !ok {
		if s.isReadyToSave() {
			fmt.Println("adding manual input storage data")
			data = &s
		} else {
			baseFee, time, err := q.getBlockInfo(s.BlockNum)
			if err != nil {
				return StorageSlot{}, err
			}

			value, err := q.getStorageValue(s.BlockNum, s.Address, s.Slot)
			if err != nil {
				return StorageSlot{}, err
			}

			data = &StorageData{
				BlockNum:       s.BlockNum,
				BlockBaseFee:   baseFee,
				Address:        s.Address,
				Slot:           s.Slot,
				Value:          value,
				BlockTimestamp: time,
			}
		}
		q.localInputData.Storages.Store(key, data)
	}

	return convertStorageDataToStorage(data.(*StorageData)), nil
}

func (q *BrevisApp) assignTransactions(in *CircuitInput) (err error) {
	var errG errgroup.Group
	// assigning user appointed data at specific indices
	for i, t := range q.txs.special {
		index := i
		txData := t
		in.Transactions.Toggles[index] = 1
		errG.Go(func() error {
			tx, err := q.buildTx(txData)
			if err != nil {
				return err
			}
			in.Transactions.Raw[index] = tx
			return nil
		})
	}

	j := 0
	for _, t := range q.txs.ordered {
		txData := t
		for in.Transactions.Toggles[j] == 1 {
			j++
		}
		in.Transactions.Toggles[j] = 1
		errG.Go(func() error {
			tx, err := q.buildTx(txData)
			if err != nil {
				return err
			}
			in.Transactions.Raw[j] = tx
			return nil
		})
		j++
	}

	return nil
}

func (q *BrevisApp) BuildTx(t TransactionData) (Transaction, error) {
	return q.buildTx(t)
}

func (q *BrevisApp) buildTx(t TransactionData) (Transaction, error) {
	key := generateTxKey(t, q.srcChainId)
	data, ok := q.localInputData.Txs.Load(key)
	if !ok {
		if t.isReadyToSave() {
			data = &t
		} else {
			leafHash, mptKey, blockNumber, baseFee, time, err := q.calculateTxLeafHashBlockBaseFeeAndMPTKey(t.Hash)
			if err != nil {
				return Transaction{}, err
			}

			data = &TransactionData{
				Hash:           t.Hash,
				BlockNum:       blockNumber,
				BlockBaseFee:   baseFee,
				MptKeyPath:     mptKey,
				LeafHash:       leafHash,
				BlockTimestamp: time,
			}
		}
		q.localInputData.Txs.Store(key, data)
	}

	return convertTxDataToTransaction(data.(*TransactionData)), nil
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

func (q *BrevisApp) realDataLength() int {
	return len(q.receipts.ordered) + len(q.receipts.special) + len(q.storageVals.ordered) + len(q.storageVals.special) + len(q.txs.ordered) + len(q.txs.special)
}

func (q *BrevisApp) mockDataLength() int {
	return len(q.mockReceipts.ordered) + len(q.mockReceipts.special) + len(q.mockStorage.ordered) + len(q.mockStorage.special) + len(q.mockTxs.ordered) + len(q.mockTxs.special)
}

func allocationIndexErr(name string, pinnedIndex, maxCount int) error {
	return fmt.Errorf("# of pinned entry index (%d) must not exceed the allocated max %s (%d), check your AppCircuit.Allocate() method",
		pinnedIndex, name, maxCount)
}

// Reset app input, used for prover server
func (q *BrevisApp) ResetInput() {
	q.receipts = rawData[ReceiptData]{}
	q.storageVals = rawData[StorageData]{}
	q.txs = rawData[TransactionData]{}
}
