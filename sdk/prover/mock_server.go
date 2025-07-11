package prover

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/brevis-network/brevis-kafka-utils/brevis_data"
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/brevis-network/brevis-sdk/store"
	"github.com/celer-network/goutils/log"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/philippgille/gokv"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type MockService struct {
	svr *mockServer
}

type mockServer struct {
	sdkproto.UnimplementedProverServer

	// A unique identifier for this server, defaults to hostname
	proverId string

	appCircuits []sdk.AppCircuit
	// chain ID => *BrevisApp
	// Placeholder for common dependencies shared by all BrevisApp instances
	appTemplates map[uint64]*sdk.BrevisApp

	vkString string
	vkHash   string

	grpcServer *grpc.Server
	proofStore gokv.Store

	kafkaUrl string
}

// NewService creates a new prover server instance that automatically manages
// compilation & setup, and serves as a GRPC server that interoperates with
// brevis sdk in other languages.
func NewMockService(
	appCircuits []sdk.AppCircuit, config ServiceConfig, srcChainConfigs SourceChainConfigs) (*MockService, error) {
	log.Debugf("New MockService called with %d app circuits", len(appCircuits))
	svr, err := newMockServer(appCircuits, config, srcChainConfigs)
	if err != nil {
		return nil, fmt.Errorf("newServer err: %w", err)
	}
	return &MockService{svr: svr}, nil
}

func newMockServer(appCircuits []sdk.AppCircuit, config ServiceConfig, srcChainConfigs SourceChainConfigs) (*mockServer, error) {
	var err error
	proverId := config.ProverId
	if proverId == "" {
		proverId, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("os.Hostname err: %w", err)
		}
	}
	// Enfore mock use file type to store proofs
	proofStore, err := store.InitStore("file", config.ProofPersistenceOptions)
	if err != nil {
		return nil, fmt.Errorf("InitStore error: %w", err)
	}

	// Create BrevisApp templates for each source chain
	appTemplates := make(map[uint64]*sdk.BrevisApp)
	for _, srcChainConfig := range srcChainConfigs {
		srcChainId := srcChainConfig.ChainId
		appConfig := &sdk.BrevisAppConfig{
			SrcChainId:           srcChainId,
			RpcUrl:               srcChainConfig.RpcUrl,
			GatewayUrl:           config.GatewayUrl,
			PersistenceType:      "file",
			PersistenceOptions:   config.DataPersistenceOptions,
			ConcurrentFetchLimit: config.ConcurrentFetchLimit,
		}
		template, err := sdk.NewBrevisAppWithConfig(appConfig)
		if err != nil {
			return nil, fmt.Errorf("NewBrevisAppWithConfig err: %w", err)
		}
		appTemplates[srcChainId] = template
	}

	concurrentProveLimit := config.ConcurrentProveLimit
	if concurrentProveLimit <= 0 {
		concurrentProveLimit = defaultConcurrentProveLimit
	}

	return &mockServer{
		proverId:     proverId,
		appCircuits:  appCircuits,
		appTemplates: appTemplates,
		vkString:     config.MockVkHash,
		vkHash:       config.MockVkHash,
		proofStore:   proofStore,
		kafkaUrl:     config.KafkaUrl,
	}, nil
}

func (s *mockServer) setProveRequest(id string, req *ProveRequest) error {
	log.Debugf("set prove request, ID: %s\n", id)
	setErr := s.proofStore.Set(id, *req)
	if setErr != nil {
		return fmt.Errorf("store.Set err: %w", setErr)
	}
	return nil
}

func (s *mockServer) getProveRequest(id string) (bool, *ProveRequest, error) {
	log.Debugf("get prove request, ID: %s\n", id)
	var req ProveRequest
	found, err := s.proofStore.Get(id, &req)
	if err != nil {
		return false, nil, fmt.Errorf("store.Get err: %w", err)
	}
	return found, &req, nil
}

func (s *mockServer) buildInputStage2AndProve(brevisApp *sdk.BrevisApp, appCircuit sdk.AppCircuit, proveRequest *ProveRequest, requestProto *sdkproto.ProveRequest, inputStage1 *sdk.CircuitInput) (*string, error) {
	defer func() {
		err := brevisApp.CloseDataStore()
		if err != nil {
			log.Errorf("failed to close dataStore: %s", err.Error())
		}
	}()

	input, guest, witnessStr, err := buildInputStage2(appCircuit, brevisApp, requestProto, inputStage1)
	if err != nil {
		return nil, err
	}
	witness, _, err := genWitness(input, guest)
	if err != nil {
		return nil, err
	}
	witnessBytes, err := witness.MarshalBinary()
	if err != nil {
		return nil, err
	}
	proveRequest.Witness = witnessBytes
	appCircuitInfo := buildFullAppCircuitInfo(appCircuit, *input, s.vkString, s.vkHash, witnessStr)
	appCircuitInfoBytes, err := proto.Marshal(appCircuitInfo)
	if err != nil {
		return nil, fmt.Errorf("proto.Marshal for circuit info err: %w", err)
	}
	// Transition to ProveStatusInProgress once we have complete AppCircuitInfo
	proveRequest.Status = ProveStatusInProgress
	proveRequest.AppCircuitInfo = appCircuitInfoBytes
	proveRequest.Status = ProveStatusSuccess

	proofBytes, err := s.getProof(proveRequest)
	if err != nil {
		log.Errorf("failed to get proof: %s", err.Error())
		return nil, fmt.Errorf("failed to get proof: %w", err)
	}
	proof := common.Bytes2Hex(proofBytes)
	proveRequest.Proof = proof
	proofId := crypto.Keccak256Hash(proofBytes).Hex()

	setProofErr := s.setProveRequest(proofId, proveRequest)
	if setProofErr != nil {
		log.Errorln("failed to set proof:", setProofErr.Error())
		return nil, fmt.Errorf("failed to set proof: %w", setProofErr)
	}
	return &proofId, nil
}

func (s *mockServer) newBrevisApp(srcChainId uint64) (*sdk.BrevisApp, error) {
	appTemplate, ok := s.appTemplates[srcChainId]
	if !ok {
		return nil, fmt.Errorf("unsupported chain ID: %d", srcChainId)
	}
	brevisApp, err := sdk.NewBrevisAppFromExisting(appTemplate)
	if err != nil {
		return nil, fmt.Errorf("NewBrevisAppFromExisting err: %w", err)
	}
	return brevisApp, nil
}

func (s *mockServer) getProof(proveRequest *ProveRequest) ([]byte, error) {
	appCircuitInfo := &commonproto.AppCircuitInfo{}
	err := proto.Unmarshal(proveRequest.AppCircuitInfo, appCircuitInfo)
	if err != nil {
		log.Errorf("failed to unmarshal app circuit info: %s", err)
		return nil, err
	}

	ty, _ := abi.NewType("bytes32", "", nil)
	args := abi.Arguments{
		{Type: ty},
		{Type: ty},
	}
	appCommitHash := common.HexToHash(appCircuitInfo.OutputCommitment)
	appVkHash := common.HexToHash(s.vkHash)
	proofBytes, err := args.Pack(appCommitHash, appVkHash)
	if err != nil {
		log.Errorf("failed to pack mock proof: %s", err)
		return nil, err
	}
	return proofBytes, nil
}

func (s *mockServer) SendProveReqState() error {
	if s.kafkaUrl == "" {
		log.Warnln("Skipping sending mock ProveReq to Kafka, kafkaUrl is empty")
		return nil
	}
	reqStateWriter := brevis_data.NewProveReqWriterClient(s.kafkaUrl)
	err := reqStateWriter.WriteEv(context.Background(), brevis_data.ProveReqMsg{
		QueryPath:        fmt.Sprintf("mockdata-%d", time.Now().UnixMilli()),
		VkHash:           s.vkHash,
		LeafCount:        2,
		ReceiptLeafCount: 2,
		StorageLeafCount: 0,
		TxLeafCount:      0,
		Complete:         true,
		Ts:               uint64(time.Now().Unix()),
	})
	if err != nil {
		log.Errorf("failed to send mock ProveReq to Kafka: %s", err.Error())
		return fmt.Errorf("failed to send mock ProveReq to Kafka: %w", err)
	}
	log.Debugf("Sent mock ProveReq to Kafka at %s, vkHash: %s", s.kafkaUrl, s.vkHash)
	return nil
}

// Prove synchronously proves an app and returns the proof. This can be a long blocking call so use with caution.
// ProveAsync should be used in most cases.
func (s *mockServer) Prove(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveResponse, error) {
	log.Debugln("received synchronous prove request", req.String())

	errRes := func(protoErr *sdkproto.Err) (*sdkproto.ProveResponse, error) {
		return &sdkproto.ProveResponse{Err: protoErr, CircuitInfo: nil}, nil
	}

	brevisApp, err := s.newBrevisApp(req.SrcChainId)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to create BrevisApp: %s", err.Error()))
	}
	defer func() {
		err := brevisApp.CloseDataStore()
		if err != nil {
			log.Errorf("failed to close dataStore: %s", err.Error())
		}
	}()

	var appCircuit sdk.AppCircuit
	for _, ac := range s.appCircuits {
		log.Debugf("checking circuit: %s", sdk.GetCircuitName(ac))
		if sdk.GetCircuitName(ac) == req.CircuitName {
			appCircuit = ac
			break
		}
	}

	if appCircuit == nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "unknown circuit: %s", req.CircuitName))
	}

	input, _, witnessStr, protoErr := buildInput(appCircuit, brevisApp, req)
	if protoErr != nil {
		return errRes(protoErr)
	}

	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proto.Marshal err: %s", err.Error()))
	}
	appCircuitInfo := buildPartialAppCircuitInfoForGatewayRequest(appCircuit, input, s.vkHash)
	appCircuitInfoBytes, err := proto.Marshal(appCircuitInfo)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proto.Marshal for circuit info err: %s", err.Error()))
	}

	proveRequest := &ProveRequest{
		Status:         ProveStatusInProgress,
		SrcChainId:     req.SrcChainId,
		Request:        reqBytes,
		AppCircuitInfo: appCircuitInfoBytes,
	}

	proof, err := s.getProof(proveRequest)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE, "failed to prove: %s", err.Error()))
	}

	proofHex := hexutil.Encode(proof)
	return &sdkproto.ProveResponse{
		Proof:       proofHex,
		CircuitInfo: buildFullAppCircuitInfo(appCircuit, *input, s.vkString, s.vkHash, witnessStr),
	}, nil
}

// ProveAsync returns a proof ID and triggers a prove action asynchronously. The status, app circuit info and proof can be
// queried with subsequent GetProof calls.
func (s *mockServer) ProveAsync(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveAsyncResponse, error) {
	errRes := func(protoErr *sdkproto.Err) (*sdkproto.ProveAsyncResponse, error) {
		return &sdkproto.ProveAsyncResponse{Err: protoErr, ProofId: ""}, nil
	}
	var resp sdkproto.ProveAsyncResponse = sdkproto.ProveAsyncResponse{}
	brevisApp, err := s.newBrevisApp(req.SrcChainId)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to build circuit input stage 1: %s", err.Error()))
	}
	log.Debugf("appCircuits length: %d", len(s.appCircuits))
	var appCircuit sdk.AppCircuit
	for _, ac := range s.appCircuits {
		log.Debugf("checking circuit: %s", sdk.GetCircuitName(ac))
		if sdk.GetCircuitName(ac) == req.CircuitName {
			appCircuit = ac
			break
		}
	}

	if appCircuit == nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "unknown circuit: %s", req.CircuitName))
	}

	inputStage1, err := buildInputStage1(appCircuit, brevisApp, req)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to build circuit input stage 1: %s", err.Error()))
	}
	appCircuitInfo := buildPartialAppCircuitInfoForGatewayRequest(appCircuit, inputStage1, s.vkHash)
	resp.CircuitInfo = appCircuitInfo

	requestBytes, err := proto.Marshal(req)
	if err != nil {
		return &sdkproto.ProveAsyncResponse{
			Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proto.Marshal err: %s", err.Error()),
		}, nil
	}

	appCircuitInfoBytes, err := proto.Marshal(appCircuitInfo)
	if err != nil {
		return &sdkproto.ProveAsyncResponse{
			Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proto.Marshal for circuit info err: %s", err.Error()),
		}, nil
	}

	proveRequest := &ProveRequest{
		Status:         ProveStatusInit,
		SrcChainId:     req.SrcChainId,
		Request:        requestBytes,
		AppCircuitInfo: appCircuitInfoBytes,
	}

	proofId, err := s.buildInputStage2AndProve(brevisApp, appCircuit, proveRequest, req, inputStage1)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to build input stage 2 and prove: %s", err.Error()))
	}

	log.Debug("ProveAsync completed successfully, proof ID:", *proofId)
	resp.ProofId = *proofId
	return &resp, nil
}

// GetProofs returns the status, app circuit info and proof associated with a proof ID
func (s *mockServer) GetProof(ctx context.Context, req *sdkproto.GetProofRequest) (res *sdkproto.GetProofResponse, err error) {
	proofId := req.ProofId
	found, proveRequest, err := s.getProveRequest(proofId)
	if err != nil {
		return &sdkproto.GetProofResponse{
			Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to get proof request %s: internal err %s", proofId, err.Error()),
		}, nil
	}
	if !found {
		return &sdkproto.GetProofResponse{}, nil
	}
	switch proveRequest.Status {
	case ProveStatusInit:
		return &sdkproto.GetProofResponse{}, nil
	case ProveStatusInProgress:
		appCircuitInfo := &commonproto.AppCircuitInfo{}
		err = proto.Unmarshal(proveRequest.AppCircuitInfo, appCircuitInfo)
		if err != nil {
			return &sdkproto.GetProofResponse{
				Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to unmarshal app circuit info, proof ID %s: internal err %s", proofId, err.Error()),
			}, nil
		}
		return &sdkproto.GetProofResponse{CircuitInfo: appCircuitInfo}, nil
	case ProveStatusSuccess:
		appCircuitInfo := &commonproto.AppCircuitInfo{}
		err = proto.Unmarshal(proveRequest.AppCircuitInfo, appCircuitInfo)
		if err != nil {
			return &sdkproto.GetProofResponse{
				Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to unmarshal app circuit info, proof ID %s: internal err %s", proofId, err.Error()),
			}, nil
		}
		// If proof is empty, it means the proof was not generated successfully,send the state update to Kafka
		if len(proveRequest.Proof) > 0 {
			err := s.SendProveReqState()
			if err != nil {
				log.Warnf("failed to send ProveReq state to Kafka: %s", err.Error())
			}
		}
		return &sdkproto.GetProofResponse{
			Proof:       proveRequest.Proof,
			CircuitInfo: appCircuitInfo,
		}, nil
	case ProveStatusFailed:
		return &sdkproto.GetProofResponse{
			Err: newErr(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE, "failed to prove %s: %s", proofId, proveRequest.Err),
		}, nil
	default:
		panic("Unknown prove status")
	}
}

func (s *mockServer) Health(context.Context, *sdkproto.HealthRequest) (*sdkproto.HealthResponse, error) {
	return &sdkproto.HealthResponse{}, nil
}

func (s *mockServer) DeleteProof(ctx context.Context, req *sdkproto.DeleteProofRequest) (res *sdkproto.DeleteProofResponse, err error) {
	id := req.ProofId
	err = s.deleteProveRequest(id)
	if err != nil {
		return &sdkproto.DeleteProofResponse{Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to delete proof request: %s", err.Error())}, nil
	}
	return &sdkproto.DeleteProofResponse{}, nil
}

func (s *mockServer) deleteProveRequest(id string) error {
	log.Debugf("delete prove request, ID: %s\n", id)

	err := s.proofStore.Delete(id)
	if err != nil {
		return fmt.Errorf("store.Delete err: %w", err)
	}
	return nil
}

func (s *MockService) Serve(bind string, grpcPort, restPort uint) error {
	stopCtx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()
	errG, errGCtx := errgroup.WithContext(context.Background())

	errG.Go(func() error { return s.serveGrpc(bind, grpcPort) })
	errG.Go(func() error { return serveGrpcGateway(bind, grpcPort, restPort) })

	var err error
	select {
	case <-errGCtx.Done():
		err = errGCtx.Err()
	case <-stopCtx.Done():
	}

	log.Infoln("Shutting down...")
	s.svr.grpcServer.GracefulStop()
	proofStoreCloseErr := s.svr.proofStore.Close()
	return errors.Join(err, proofStoreCloseErr)
}

func (s *MockService) serveGrpc(bind string, port uint) error {
	size := 1024 * 1024 * 100
	s.svr.grpcServer = grpc.NewServer(grpc.MaxSendMsgSize(size),
		grpc.MaxRecvMsgSize(size))
	sdkproto.RegisterProverServer(s.svr.grpcServer, s.svr)
	address := fmt.Sprintf("%s:%d", bind, port)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to start prover server: %w", err)
	}
	log.Infoln(">> serving prover gRPC at port", port)
	if err = s.svr.grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("grpc server crashed: %w", err)
	}
	return nil
}
