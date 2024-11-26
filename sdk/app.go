package sdk

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"

	"github.com/brevis-network/brevis-sdk/sdk/eth"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
)

type BrevisApp struct {
	gc            *GatewayClient
	ec            *ethclient.Client
	brevisRequest *abi.ABI

	receipts     rawData[ReceiptData]
	storageVals  rawData[StorageData]
	txs          rawData[TransactionData]
	blockHeaders rawData[BlockHeaderData]

	mockReceipts     rawData[ReceiptData]
	mockStorage      rawData[StorageData]
	mockTxs          rawData[TransactionData]
	mockBlockHeaders rawData[BlockHeaderData]

	localInputDataPath string
	localInputData     *DataPersistence

	// cache fields
	circuitInput           CircuitInput
	buildInputCalled       bool
	queryId                []byte
	nonce                  uint64
	srcChainId, dstChainId uint64

	maxReceipts    int
	maxStorage     int
	maxTxs         int
	maxBlockHeader int
	dataPoints     int
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
	localInputData := readDataFromLocalStorage(localInputDataPath)
	if localInputData == nil {
		localInputData = &DataPersistence{
			Receipts:     map[string]*ReceiptData{},
			Storages:     map[string]*StorageData{},
			Txs:          map[string]*TransactionData{},
			BlockHeaders: map[string]*BlockHeaderData{},
		}
	} else {
		if localInputData.Receipts == nil {
			localInputData.Receipts = map[string]*ReceiptData{}
		}
		if localInputData.Storages == nil {
			localInputData.Storages = map[string]*StorageData{}
		}
		if localInputData.Txs == nil {
			localInputData.Txs = map[string]*TransactionData{}
		}
		if localInputData.BlockHeaders == nil {
			localInputData.BlockHeaders = map[string]*BlockHeaderData{}
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
		blockHeaders:       rawData[BlockHeaderData]{},
		mockReceipts:       rawData[ReceiptData]{},
		mockStorage:        rawData[StorageData]{},
		mockTxs:            rawData[TransactionData]{},
		mockBlockHeaders:   rawData[BlockHeaderData]{},
		localInputData:     localInputData,
		localInputDataPath: localInputDataPath,
	}, nil
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

	vkHashInBigInt, err := CalBrevisCircuitDigest(q.maxReceipts, q.maxStorage, q.dataPoints-q.maxReceipts-q.maxStorage-q.maxBlockHeader, q.maxBlockHeader, vk)
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

	vkHashInBigInt, err := CalBrevisCircuitDigest(q.maxReceipts, q.maxStorage, q.dataPoints-q.maxReceipts-q.maxStorage-q.maxBlockHeader, q.maxBlockHeader, vk)
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
