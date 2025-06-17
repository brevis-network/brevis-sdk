package prover

import (
	"context"
	"fmt"
	"os"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/brevis-network/brevis-sdk/store"
	"github.com/celer-network/goutils/log"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/philippgille/gokv"
	"golang.org/x/sync/singleflight"
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

	appCircuit sdk.AppCircuit
	// chain ID => *BrevisApp
	// Placeholder for common dependencies shared by all BrevisApp instances
	appTemplates map[uint64]*sdk.BrevisApp

	vkString string
	vkHash   string

	proveAsyncSingleFlight singleflight.Group

	grpcServer *grpc.Server

	proofStore gokv.Store
}

// NewService creates a new prover server instance that automatically manages
// compilation & setup, and serves as a GRPC server that interoperates with
// brevis sdk in other languages.
func NewMockService(
	app sdk.AppCircuit, config ServiceConfig, srcChainConfigs SourceChainConfigs) (*MockService, error) {
	svr, err := newMockServer(app, config, srcChainConfigs)
	if err != nil {
		return nil, fmt.Errorf("newServer err: %w", err)
	}
	return &MockService{svr: svr}, nil
}

func newMockServer(appCircuit sdk.AppCircuit, config ServiceConfig, srcChainConfigs SourceChainConfigs) (*mockServer, error) {
	var err error
	proverId := config.ProverId
	if proverId == "" {
		proverId, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("os.Hostname err: %w", err)
		}
	}
	persistenceType := config.ProofPersistenceType
	if persistenceType == "" {
		persistenceType = "syncmap"
	}
	proofStore, err := store.InitStore(persistenceType, config.ProofPersistenceOptions)
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
			OutDir:               config.SetupDir,
			PersistenceType:      config.DataPersistenceType,
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
		proverId:               proverId,
		appCircuit:             appCircuit,
		appTemplates:           appTemplates,
		vkString:               "0x0000000000000000000000000000000000000000000000000000000000000000",
		vkHash:                 "0x0000000000000000000000000000000000000000000000000000000000000000", // hardcode mock vk hash
		proveAsyncSingleFlight: singleflight.Group{},
		proofStore:             proofStore,
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

func (s *mockServer) buildInputStage2AndProve(brevisApp *sdk.BrevisApp, proveRequest *ProveRequest, requestProto *sdkproto.ProveRequest, inputStage1 *sdk.CircuitInput) {
	defer func() {
		err := brevisApp.CloseDataStore()
		if err != nil {
			log.Errorf("failed to close dataStore: %s", err.Error())
		}
	}()

	input, guest, witnessStr, err := buildInputStage2(s.appCircuit, brevisApp, requestProto, inputStage1)
	if err != nil {
		return
	}
	witness, _, err := genWitness(input, guest)
	if err != nil {
		return
	}
	witnessBytes, err := witness.MarshalBinary()
	if err != nil {
		return
	}
	proveRequest.Witness = witnessBytes
	appCircuitInfo := buildFullAppCircuitInfo(s.appCircuit, *input, s.vkString, s.vkHash, witnessStr)
	appCircuitInfoBytes, err := proto.Marshal(appCircuitInfo)
	if err != nil {
		return
	}
	// Transition to ProveStatusInProgress once we have complete AppCircuitInfo
	proveRequest.Status = ProveStatusInProgress
	proveRequest.AppCircuitInfo = appCircuitInfoBytes
	proveRequest.Status = ProveStatusSuccess

	proofBytes, err := s.getProof(proveRequest)
	if err != nil {
		log.Errorf("failed to get proof: %s", err.Error())
		return
	}
	proof := common.Bytes2Hex(proofBytes)
	proveRequest.Proof = proof
	proofId := crypto.Keccak256Hash(proofBytes).Hex()

	setProofErr := s.setProveRequest(proofId, proveRequest)
	if setProofErr != nil {
		log.Errorln("failed to set proof:", setProofErr.Error())
	}
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

// Prove synchronously proves an app and returns the proof. This can be a long blocking call so use with caution.
// ProveAsync should be used in most cases.
func (s *mockServer) Prove(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveResponse, error) {
	return nil, nil
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
	inputStage1, err := buildInputStage1(s.appCircuit, brevisApp, req)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to build circuit input stage 1: %s", err.Error()))
	}
	appCircuitInfo := buildPartialAppCircuitInfoForGatewayRequest(s.appCircuit, inputStage1, s.vkHash)
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

	go s.buildInputStage2AndProve(brevisApp, proveRequest, req, inputStage1)

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

	if err != nil {
		return fmt.Errorf("removeJob err: %w", err)
	}

	return nil
}
