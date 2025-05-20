package prover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	goruntime "runtime"
	"sync"
	"syscall"

	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/brevis-network/brevis-sdk/store"
	"github.com/celer-network/goutils/log"
	"github.com/gowebpki/jcs"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/brevis-network/brevis-sdk/sdk"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/philippgille/gokv"
	"google.golang.org/grpc"
)

const (
	ProveStatusInit = iota
	ProveStatusInProgress
	ProveStatusSuccess
	ProveStatusFailed

	jobsKeyPrefix               = "j"
	defaultConcurrentProveLimit = 1
)

type Service struct {
	svr *server
}

type ProveRequest struct {
	Status         int    `json:"status"`
	SrcChainId     uint64 `json:"src_chain_id"`
	Request        []byte `json:"request"`
	Witness        []byte `json:"witness"`
	Proof          string `json:"proof"`
	AppCircuitInfo []byte `json:"app_circuit_info"`
	Err            string `json:"err"`
}

type server struct {
	sdkproto.UnimplementedProverServer

	// A unique identifier for this server, defaults to hostname
	proverId string

	appCircuit sdk.AppCircuit
	// chain ID => *BrevisApp
	// Placeholder for common dependencies shared by all BrevisApp instances
	appTemplates map[uint64]*sdk.BrevisApp

	pk  plonk.ProvingKey
	vk  plonk.VerifyingKey
	ccs constraint.ConstraintSystem

	vkString string
	vkHash   string

	grpcServer *grpc.Server

	proofStore gokv.Store

	proveAsyncSingleFlight singleflight.Group
	jobsLock               sync.Mutex

	// rate limiter to ensure only a limited number of prove actions can run at a time
	proveRateLimiter chan struct{}
}

// NewService creates a new prover server instance that automatically manages
// compilation & setup, and serves as a GRPC server that interoperates with
// brevis sdk in other languages.
func NewService(
	app sdk.AppCircuit, config ServiceConfig, srcChainConfigs SourceChainConfigs) (*Service, error) {
	svr, err := newServer(app, config, srcChainConfigs)
	if err != nil {
		return nil, fmt.Errorf("newServer err: %w", err)
	}
	return &Service{svr: svr}, nil
}

func (s *Service) Serve(bind string, grpcPort, restPort uint) error {
	// resume jobs first
	err := s.svr.resumeJobs()
	if err != nil {
		return fmt.Errorf("resumeJobs err: %w", err)
	}

	stopCtx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()
	errG, errGCtx := errgroup.WithContext(context.Background())

	errG.Go(func() error { return s.serveGrpc(bind, grpcPort) })
	errG.Go(func() error { return serveGrpcGateway(bind, grpcPort, restPort) })

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

func (s *Service) serveGrpc(bind string, port uint) error {
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

func serveGrpcGateway(bind string, grpcPort, restPort uint) error {
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	endpoint := fmt.Sprintf("%s:%d", bind, grpcPort)

	err := sdkproto.RegisterProverHandlerFromEndpoint(context.Background(), mux, endpoint, opts)
	if err != nil {
		return fmt.Errorf("failed to start prover server: %w", err)
	}

	handler := cors.New(cors.Options{
		AllowedHeaders:   []string{"*"},
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	}).Handler(mux)

	log.Infoln(">> serving prover REST API at port", restPort)
	if err = http.ListenAndServe(fmt.Sprintf(":%d", restPort), handler); err != nil {
		return fmt.Errorf("REST server crashed: %w", err)
	}
	return nil
}

func newServer(appCircuit sdk.AppCircuit, config ServiceConfig, srcChainConfigs SourceChainConfigs) (*server, error) {
	var err error
	proverId := config.ProverId
	if proverId == "" {
		proverId, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("os.Hostname err: %w", err)
		}
	}

	hashInfo, err := sdk.NewBrevisHashInfo(config.GatewayUrl)
	if err != nil {
		return nil, fmt.Errorf("NewBrevisHashInfo err: %w", err)
	}
	var pk plonk.ProvingKey
	var vk plonk.VerifyingKey
	var ccs constraint.ConstraintSystem
	var vkHash []byte
	if config.DirectLoad {
		pk, vk, ccs, vkHash, err = readOnly(appCircuit, config.GetSetupDir(), hashInfo)
	} else {
		pk, vk, ccs, vkHash, err = readOrSetup(appCircuit, config.GetSetupDir(), config.GetSrsDir(), hashInfo)
	}
	if err != nil {
		return nil, fmt.Errorf("readOrSetup err: %w", err)
	}

	var buf bytes.Buffer
	_, err = vk.WriteRawTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("vk.WriteTo err: %w", err)
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

	return &server{
		proverId:               proverId,
		appCircuit:             appCircuit,
		appTemplates:           appTemplates,
		pk:                     pk,
		vk:                     vk,
		ccs:                    ccs,
		vkString:               hexutil.Encode(buf.Bytes()),
		vkHash:                 hexutil.Encode(vkHash),
		proofStore:             proofStore,
		proveAsyncSingleFlight: singleflight.Group{},
		jobsLock:               sync.Mutex{},
		proveRateLimiter:       make(chan struct{}, concurrentProveLimit),
	}, nil
}

// Prove synchronously proves an app and returns the proof. This can be a long blocking call so use with caution.
// ProveAsync should be used in most cases.
func (s *server) Prove(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveResponse, error) {
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
	input, guest, witnessStr, protoErr := s.buildInput(brevisApp, req)
	if protoErr != nil {
		return errRes(protoErr)
	}

	witness, _, err := s.genWitness(input, guest)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "failed to generate witness: %s", err.Error()))
	}

	proof, err := s.prove(witness)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE, "failed to prove: %s", err.Error()))
	}

	return &sdkproto.ProveResponse{
		Proof:       proof,
		CircuitInfo: buildFullAppCircuitInfo(s.appCircuit, *input, s.vkString, s.vkHash, witnessStr),
	}, nil
}

// ProveAsync returns a proof ID and triggers a prove action asynchronously. The status, app circuit info and proof can be
// queried with subsequent GetProof calls.
func (s *server) ProveAsync(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveAsyncResponse, error) {
	errRes := func(protoErr *sdkproto.Err) (*sdkproto.ProveAsyncResponse, error) {
		return &sdkproto.ProveAsyncResponse{Err: protoErr, ProofId: ""}, nil
	}
	proofId, err := s.getProofId(req)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to generate proof ID: %s", err.Error()))
	}
	log.Infof("start do proofId %s", proofId)
	res, err, _ := s.proveAsyncSingleFlight.Do(proofId, func() (interface{}, error) {
		found, proveRequest, err := s.getProveRequest(proofId)
		if err != nil {
			return &sdkproto.ProveAsyncResponse{
				Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, failed to get proof request: internal err %s", proofId, err.Error()),
			}, nil
		}
		resp := &sdkproto.ProveAsyncResponse{
			Err:     nil,
			ProofId: proofId,
		}
		if found {
			log.Infof("found proof id %s", proofId)
			appCircuitInfo := &commonproto.AppCircuitInfo{}
			err := proto.Unmarshal(proveRequest.AppCircuitInfo, appCircuitInfo)
			if err != nil {
				return &sdkproto.ProveAsyncResponse{
					Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, failed to unmarshal app circuit info: internal err %s", proofId, err.Error()),
				}, nil
			}
			resp.CircuitInfo = appCircuitInfo
			log.Infof("reuse circuit info on store, circuit info: %+v", appCircuitInfo)
			return resp, nil
		}
		// Build partial AppCircuitInfo
		brevisApp, err := s.newBrevisApp(req.SrcChainId)
		if err != nil {
			return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to build circuit input stage 1: %s", err.Error()))
		}
		inputStage1, err := s.buildInputStage1(brevisApp, req)
		if err != nil {
			return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to build circuit input stage 1: %s", err.Error()))
		}
		appCircuitInfo := buildPartialAppCircuitInfoForGatewayRequest(s.appCircuit, inputStage1, s.vkHash)
		resp.CircuitInfo = appCircuitInfo

		requestBytes, err := proto.Marshal(req)
		if err != nil {
			return &sdkproto.ProveAsyncResponse{
				Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, proto.Marshal err: %s", proofId, err.Error()),
			}, nil
		}
		appCircuitInfoBytes, err := proto.Marshal(appCircuitInfo)
		if err != nil {
			return &sdkproto.ProveAsyncResponse{
				Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, proto.Marshal for circuit info err: %s", proofId, err.Error()),
			}, nil
		}
		proveRequest = &ProveRequest{
			Status:         ProveStatusInit,
			SrcChainId:     req.SrcChainId,
			Request:        requestBytes,
			AppCircuitInfo: appCircuitInfoBytes,
		}
		err = s.setProveRequest(proofId, proveRequest)
		if err != nil {
			return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, failed to save proof request: %s", proofId, err.Error()))
		}
		err = s.addJob(proofId)
		if err != nil {
			return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, failed to add proof job: %s", proofId, err.Error()))
		}

		go s.buildInputStage2AndProve(proofId, brevisApp, proveRequest, req, inputStage1)

		log.Infof("accepted job proof ID: %s", proofId)
		return resp, nil
	})
	finalResp := res.(*sdkproto.ProveAsyncResponse)
	if err != nil {
		log.Errorf("fail to asyc prove this resp finalResp: %+v, err; %v", finalResp, err)
		finalResp.Err = newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, err: %s", proofId, err.Error())
		return finalResp, nil
	}
	return finalResp, nil
}

// GetProofs returns the status, app circuit info and proof associated with a proof ID
func (s *server) GetProof(ctx context.Context, req *sdkproto.GetProofRequest) (res *sdkproto.GetProofResponse, err error) {
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

func (s *server) Health(context.Context, *sdkproto.HealthRequest) (*sdkproto.HealthResponse, error) {
	return &sdkproto.HealthResponse{}, nil
}

func (s *server) DeleteProof(ctx context.Context, req *sdkproto.DeleteProofRequest) (res *sdkproto.DeleteProofResponse, err error) {
	id := req.ProofId
	err = s.deleteProveRequest(id)
	if err != nil {
		return &sdkproto.DeleteProofResponse{Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to delete proof request: %s", err.Error())}, nil
	}
	return &sdkproto.DeleteProofResponse{}, nil
}

func (s *server) buildInputStage1(brevisApp *sdk.BrevisApp, req *sdkproto.ProveRequest) (input *sdk.CircuitInput, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic, recovered value: %v", r)
		}
	}()

	// Add data
	for _, receipt := range req.Receipts {
		sdkReceipt, err := convertProtoReceiptToSdkReceipt(receipt.Data)
		if err != nil {
			return nil, fmt.Errorf("convertProtoReceiptToSdkReceipt err: %w", err)
		}
		brevisApp.AddReceipt(sdkReceipt, int(receipt.Index))
	}
	for _, storage := range req.Storages {
		sdkStorage, err := convertProtoStorageToSdkStorage(storage.Data)
		if err != nil {
			return nil, fmt.Errorf("convertProtoReceiptToSdkReceipt err: %w", err)
		}
		brevisApp.AddStorage(sdkStorage, int(storage.Index))
	}
	for _, transaction := range req.Transactions {
		sdkTx, err := convertProtoTxToSdkTx(transaction.Data)
		if err != nil {
			return nil, fmt.Errorf("convertProtoTxToSdkTx err: %w", err)
		}
		brevisApp.AddTransaction(sdkTx, int(transaction.Index))
	}
	inputStage1, err := brevisApp.BuildCircuitInputStage1(s.appCircuit)
	if err != nil {
		return nil, fmt.Errorf("BuildCircuitInputStage1 err: %w", err)
	}
	return &inputStage1, nil
}

func (s *server) buildInputStage2(brevisApp *sdk.BrevisApp, req *sdkproto.ProveRequest, inputStage1 *sdk.CircuitInput) (*sdk.CircuitInput, sdk.AppCircuit, string, error) {
	guest, err := assignCustomInput(s.appCircuit, req.CustomInput)
	if err != nil {
		return nil, nil, "", fmt.Errorf("assignCustomInput err: %w", err)
	}

	input, err := brevisApp.BuildCircuitInputStage2(guest, *inputStage1)
	if err != nil {
		return nil, nil, "", fmt.Errorf("BuildCircuitInputStage2 err: %w", err)
	}

	_, publicWitness, err := sdk.NewFullWitness(guest, input)
	if err != nil {
		return nil, nil, "", fmt.Errorf("NewFullWitness err: %w", err)
	}

	var witnessBuffer bytes.Buffer
	witnessData := io.Writer(&witnessBuffer)
	_, err = publicWitness.WriteTo(witnessData)
	if err != nil {
		return nil, nil, "", fmt.Errorf("publicWitness.WriteTo err: %w", err)
	}
	witness := fmt.Sprintf("0x%x", witnessBuffer.Bytes())

	return &input, guest, witness, nil
}

func (s *server) buildInput(brevisApp *sdk.BrevisApp, req *sdkproto.ProveRequest) (*sdk.CircuitInput, sdk.AppCircuit, string, *sdkproto.Err) {
	makeErr := func(code sdkproto.ErrCode, format string, args ...any) (*sdk.CircuitInput, sdk.AppCircuit, string, *sdkproto.Err) {
		log.Errorf(format, args...)
		log.Errorln()
		return nil, nil, "", newErr(code, format, args...)
	}

	inputStage1, err := s.buildInputStage1(brevisApp, req)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "buildInputStage1 err: %s", err.Error())
	}
	input, appCircuit, witness, err := s.buildInputStage2(brevisApp, req, inputStage1)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "buildInputStage2 err: %s", err.Error())
	}
	return input, appCircuit, witness, nil
}

func (s *server) genWitness(input *sdk.CircuitInput, guest sdk.AppCircuit) (witness.Witness, witness.Witness, error) {
	witness, publicWitness, err := sdk.NewFullWitness(guest, *input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get full witness: %w", err)
	}
	return witness, publicWitness, nil
}

func (s *server) prove(witness witness.Witness) (string, error) {
	s.proveRateLimiter <- struct{}{}
	proof, err := sdk.Prove(s.ccs, s.pk, witness)
	goruntime.GC()
	<-s.proveRateLimiter
	if err != nil {
		return "", fmt.Errorf("failed to prove: %w", err)
	}
	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		return "", fmt.Errorf("failed to write proof bytes: %w", err)
	}

	return hexutil.Encode(buf.Bytes()), nil
}

func (s *server) buildInputAndProve(proofId string, proveRequest *ProveRequest, requestProto *sdkproto.ProveRequest) {
	brevisApp, err := s.newBrevisApp(proveRequest.SrcChainId)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	inputStage1, err := s.buildInputStage1(brevisApp, requestProto)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	s.buildInputStage2AndProve(proofId, brevisApp, proveRequest, requestProto, inputStage1)
}

func (s *server) buildInputStage2AndProve(proofId string, brevisApp *sdk.BrevisApp, proveRequest *ProveRequest, requestProto *sdkproto.ProveRequest, inputStage1 *sdk.CircuitInput) {
	defer func() {
		err := brevisApp.CloseDataStore()
		if err != nil {
			log.Errorf("failed to close dataStore: %s", err.Error())
		}
	}()

	input, guest, witnessStr, err := s.buildInputStage2(brevisApp, requestProto, inputStage1)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	witness, _, err := s.genWitness(input, guest)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	witnessBytes, err := witness.MarshalBinary()
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	proveRequest.Witness = witnessBytes
	appCircuitInfo := buildFullAppCircuitInfo(s.appCircuit, *input, s.vkString, s.vkHash, witnessStr)
	appCircuitInfoBytes, err := proto.Marshal(appCircuitInfo)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	// Transition to ProveStatusInProgress once we have complete AppCircuitInfo
	proveRequest.Status = ProveStatusInProgress
	proveRequest.AppCircuitInfo = appCircuitInfoBytes
	setProofErr := s.setProveRequest(proofId, proveRequest)
	if setProofErr != nil {
		log.Errorln("failed to set proof:", setProofErr.Error())
	}
	s.doProveHelper(proofId, proveRequest, witness)
}

func (s *server) continueProve(proofId string, proveRequest *ProveRequest) {
	brevisApp, err := s.newBrevisApp(proveRequest.SrcChainId)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, fmt.Errorf("newBrevisApp err: %w", err))
		return
	}
	defer func() {
		err := brevisApp.CloseDataStore()
		if err != nil {
			log.Errorf("failed to close dataStore: %s", err.Error())
		}
	}()

	// Unmarshal witnesses
	witness, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	err = witness.UnmarshalBinary(proveRequest.Witness)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}

	s.doProveHelper(proofId, proveRequest, witness)
}

func (s *server) doProveHelper(proofId string, proveRequest *ProveRequest, witness witness.Witness) {
	proof, err := s.prove(witness)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	proveRequest.Status = ProveStatusSuccess
	proveRequest.Proof = proof
	err = s.setProveRequest(proofId, proveRequest)
	if err != nil {
		log.Errorln("failed to set proof:", err.Error())
	}
	err = s.removeJob(proofId)
	if err != nil {
		log.Errorln("removeJob err:", err.Error())
	}
	log.Infof("prove success, proof ID: %s\n", proofId)
}

func (s *server) newBrevisApp(srcChainId uint64) (*sdk.BrevisApp, error) {
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

func (s *server) resumeJobs() error {
	var jobs []string
	ok, err := s.proofStore.Get(s.getJobsKey(), &jobs)
	if err != nil {
		return fmt.Errorf("store.Get err: %w", err)
	}
	if !ok {
		return nil
	}
	for _, proofId := range jobs {
		found, proveRequest, err := s.getProveRequest(proofId)
		if err != nil {
			return fmt.Errorf("getProveRequest err: %w", err)
		}
		if !found {
			return fmt.Errorf("proof request not found for proof ID: %s", proofId)
		}
		switch proveRequest.Status {
		case ProveStatusInit:
			requestProto := &sdkproto.ProveRequest{}
			err = proto.Unmarshal(proveRequest.Request, requestProto)
			if err != nil {
				return fmt.Errorf("proto.Unmarshal err: %w", err)
			}
			go s.buildInputAndProve(proofId, proveRequest, requestProto)
		case ProveStatusInProgress:
			go s.continueProve(proofId, proveRequest)
		case ProveStatusSuccess, ProveStatusFailed:
			// Cleanup
			err = s.removeJob(proofId)
			if err != nil {
				return fmt.Errorf("removeJob err: %w", err)
			}
		default:
			panic("Unknown prove status")
		}
	}
	return nil
}

// addJob adds a proof job
func (s *server) addJob(proofId string) error {
	s.jobsLock.Lock()
	defer s.jobsLock.Unlock()

	jobsKey := s.getJobsKey()
	var jobs []string
	_, err := s.proofStore.Get(jobsKey, &jobs)
	if err != nil {
		return fmt.Errorf("store.Get err: %w", err)
	}
	jobs = append(jobs, proofId)
	err = s.proofStore.Set(jobsKey, jobs)
	if err != nil {
		return fmt.Errorf("store.Set err: %w", err)
	}
	return nil
}

// removeJob removes a proof job, no-op if nonexistent
func (s *server) removeJob(proofId string) error {
	s.jobsLock.Lock()
	defer s.jobsLock.Unlock()

	jobsKey := s.getJobsKey()
	var jobs []string
	ok, err := s.proofStore.Get(jobsKey, &jobs)
	if err != nil {
		return fmt.Errorf("store.Get err: %w", err)
	}
	if !ok {
		// No-op
		return nil
	}
	var newJobs []string
	for _, currId := range jobs {
		if currId != proofId {
			newJobs = append(newJobs, currId)
		}
	}
	err = s.proofStore.Set(jobsKey, newJobs)
	if err != nil {
		return fmt.Errorf("store.Set err: %w", err)
	}
	return nil
}

func (s *server) setProveRequest(id string, req *ProveRequest) error {
	log.Debugf("set prove request, ID: %s\n", id)
	setErr := s.proofStore.Set(id, *req)
	if setErr != nil {
		return fmt.Errorf("store.Set err: %w", setErr)
	}
	return nil
}

func (s *server) getProveRequest(id string) (bool, *ProveRequest, error) {
	log.Debugf("get prove request, ID: %s\n", id)
	var req ProveRequest
	found, err := s.proofStore.Get(id, &req)
	if err != nil {
		return false, nil, fmt.Errorf("store.Get err: %w", err)
	}
	return found, &req, nil
}

func (s *server) deleteProveRequest(id string) error {
	log.Debugf("delete prove request, ID: %s\n", id)

	err := s.proofStore.Delete(id)
	if err != nil {
		return fmt.Errorf("store.Delete err: %w", err)
	}

	err = s.removeJob(id)
	if err != nil {
		return fmt.Errorf("removeJob err: %w", err)
	}

	return nil
}

func (s *server) markProofFailed(proofId string, request *ProveRequest, err error) {
	request.Status = ProveStatusFailed
	errStr := err.Error()
	request.Err = errStr
	log.Errorf("markProofFailed, proof ID: %s, err: %s\n", proofId, errStr)
	setProofErr := s.setProveRequest(proofId, request)
	if setProofErr != nil {
		log.Errorf("failed to set proof, err: %s, original err: %s", setProofErr.Error(), errStr)
	}

	removeJobErr := s.removeJob(proofId)
	if removeJobErr != nil {
		log.Errorf("removeJob err: %s", removeJobErr.Error())
	}
}

func (s *server) getProofId(req *sdkproto.ProveRequest) (string, error) {
	jsonBytes, err := protojson.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("protojson.Marshal err: %w", err)
	}
	canonJsonBytes, err := jcs.Transform(jsonBytes)
	if err != nil {
		return "", fmt.Errorf("jcs.Transform err: %w", err)
	}
	return crypto.Keccak256Hash(append([]byte(s.vkHash), canonJsonBytes...)).Hex(), nil
}

func (s *server) getJobsKey() string {
	return fmt.Sprintf("%s-%s-%s", jobsKeyPrefix, s.proverId, s.vkHash)
}
