package prover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/signal"
	goruntime "runtime"
	"sync"
	"syscall"

	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/celer-network/goutils/log"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/rs/cors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/ethereum/go-ethereum/common/hexutil"

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
)

type Service struct {
	svr *server
}

type proveRequest struct {
	Status         int
	Request        []byte
	Witness        []byte
	Proof          string
	AppCircuitInfo []byte
	Err            string
}

type server struct {
	sdkproto.UnimplementedProverServer

	appCircuit sdk.AppCircuit
	brevisApp  *sdk.BrevisApp

	pk  plonk.ProvingKey
	vk  plonk.VerifyingKey
	ccs constraint.ConstraintSystem

	vkString string
	vkHash   string

	grpcServer *grpc.Server

	store      gokv.Store
	activeJobs sync.Map
}

// package level singleton to ensure only one prove process is running at a time
var proveProcessorLock sync.Mutex

// NewService creates a new prover server instance that automatically manages
// compilation & setup, and serves as a GRPC server that interoperates with
// brevis sdk in other languages.
func NewService(
	app sdk.AppCircuit, config ServiceConfig) (*Service, error) {
	brevisApp, err := sdk.NewBrevisApp(uint64(config.ChainId), config.RpcURL, config.GetSetupDir())
	if err != nil {
		return nil, fmt.Errorf("failed to initiate brevis app %w", err)
	}

	var pk plonk.ProvingKey
	var vk plonk.VerifyingKey
	var ccs constraint.ConstraintSystem
	var vkHash []byte
	if config.DirectLoad {
		pk, vk, ccs, vkHash, err = readOnly(app, config.GetSetupDir(), brevisApp)
	} else {
		pk, vk, ccs, vkHash, err = readOrSetup(app, config.GetSetupDir(), config.GetSrsDir(), brevisApp)
	}
	if err != nil {
		return nil, fmt.Errorf("readOrSetup err: %w", err)
	}
	svr, err := newServer(brevisApp, app, pk, vk, ccs, vkHash, config.PersistenceType, config.PersistenceOptions)
	if err != nil {
		return nil, fmt.Errorf("newServer err: %w", err)
	}
	return &Service{svr: svr}, nil
}

func (s *Service) Serve(bind string, grpcPort, restPort uint) error {
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
	storeCloseErr := s.svr.store.Close()
	return errors.Join(err, storeCloseErr)
}

func (s *Service) serveGrpc(bind string, port uint) error {
	s.svr.grpcServer = grpc.NewServer()
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

func initStore(persistenceType string, persistenceOptions string) (gokv.Store, error) {
	switch persistenceType {
	case "", "syncmap":
		return newSyncMapStore(persistenceOptions)
	case "s3":
		return newS3Store(persistenceOptions)
	case "badgerdb":
		return newBadgerDBStore(persistenceOptions)
	default:
		return nil, fmt.Errorf("unsupported persistence type %s", persistenceType)
	}
}

func newServer(
	brevisApp *sdk.BrevisApp,
	appCircuit sdk.AppCircuit,
	pk plonk.ProvingKey,
	vk plonk.VerifyingKey,
	ccs constraint.ConstraintSystem,
	vkHash []byte,
	persistenceType string,
	persistenceOptions string,
) (*server, error) {
	var buf bytes.Buffer
	_, err := vk.WriteRawTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("vk.WriteTo err: %w", err)
	}
	store, err := initStore(persistenceType, persistenceOptions)
	if err != nil {
		return nil, fmt.Errorf("initStore error: %w", err)
	}
	return &server{
		appCircuit: appCircuit,
		brevisApp:  brevisApp,
		pk:         pk,
		vk:         vk,
		ccs:        ccs,
		vkString:   hexutil.Encode(buf.Bytes()),
		vkHash:     hexutil.Encode(vkHash),
		store:      store,
		activeJobs: sync.Map{},
	}, nil
}

func (s *server) Prove(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveResponse, error) {
	log.Debugln("received synchronous prove request", req.String())

	errRes := func(protoErr *sdkproto.Err) (*sdkproto.ProveResponse, error) {
		return &sdkproto.ProveResponse{Err: protoErr, CircuitInfo: nil}, nil
	}

	input, guest, witnessStr, protoErr := s.buildInput(req)
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
		CircuitInfo: buildAppCircuitInfo(s.appCircuit, *input, s.vkString, s.vkHash, witnessStr),
	}, nil
}

func (s *server) ProveAsync(ctx context.Context, req *sdkproto.ProveRequest) (res *sdkproto.ProveAsyncResponse, err error) {
	errRes := func(protoErr *sdkproto.Err) (*sdkproto.ProveAsyncResponse, error) {
		return &sdkproto.ProveAsyncResponse{Err: protoErr, ProofId: ""}, nil
	}
	proofId, err := getProofId(s.vkHash, req)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to generate proof ID: %s", err.Error()))
	}
	found, _, err := s.getProveRequest(proofId)
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
		return resp, nil
	}
	requestBytes, err := proto.Marshal(req)
	if err != nil {
		return &sdkproto.ProveAsyncResponse{
			Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, proto.Marshal err: %s", proofId, err.Error()),
		}, nil
	}
	proveRequest := &proveRequest{
		Status:  ProveStatusInit,
		Request: requestBytes,
	}
	err = s.setProveRequest(proofId, proveRequest)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "proof ID %s, failed to save proof request: %s", proofId, err.Error()))
	}

	go s.buildInputAndProve(proofId, proveRequest, req)

	return resp, nil
}

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
	// Lazily re-spawn an interrupted job
	switch proveRequest.Status {
	case ProveStatusInit:
		requestProto := &sdkproto.ProveRequest{}
		err = proto.Unmarshal(proveRequest.Request, requestProto)
		if err != nil {
			return &sdkproto.GetProofResponse{
				Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to unmarshal request, proof ID %s: internal err %s", proofId, err.Error()),
			}, nil
		}
		_, ok := s.activeJobs.Load(proofId)
		if !ok {
			go s.buildInputAndProve(proofId, proveRequest, requestProto)
		}
		return &sdkproto.GetProofResponse{}, nil
	case ProveStatusInProgress:
		appCircuitInfo := &commonproto.AppCircuitInfo{}
		err = proto.Unmarshal(proveRequest.AppCircuitInfo, appCircuitInfo)
		if err != nil {
			return &sdkproto.GetProofResponse{
				Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to unmarshal app circuit info, proof ID %s: internal err %s", proofId, err.Error()),
			}, nil
		}
		_, ok := s.activeJobs.Load(proofId)
		if !ok {
			go s.continueProve(proofId, proveRequest)
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

func (s *server) DeleteProof(ctx context.Context, req *sdkproto.DeleteProofRequest) (res *sdkproto.DeleteProofResponse, err error) {
	id := req.ProofId
	err = s.deleteProveRequest(id)
	if err != nil {
		return &sdkproto.DeleteProofResponse{Err: newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to delete proof request: %s", err.Error())}, nil
	}
	return &sdkproto.DeleteProofResponse{}, nil
}

func (s *server) buildInput(req *sdkproto.ProveRequest) (*sdk.CircuitInput, sdk.AppCircuit, string, *sdkproto.Err) {
	makeErr := func(code sdkproto.ErrCode, format string, args ...any) (*sdk.CircuitInput, sdk.AppCircuit, string, *sdkproto.Err) {
		log.Errorf(format, args...)
		log.Errorln()
		return nil, nil, "", newErr(code, format, args...)
	}

	s.brevisApp.ResetInput()

	for _, receipt := range req.Receipts {
		sdkReceipt, err := convertProtoReceiptToSdkReceipt(receipt.Data)
		if err != nil {
			return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "invalid sdk receipt: %+v, %s", receipt.Data, err.Error())
		}
		s.brevisApp.AddReceipt(sdkReceipt, int(receipt.Index))
	}

	for _, storage := range req.Storages {
		sdkStorage, err := convertProtoStorageToSdkStorage(storage.Data)
		if err != nil {
			return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "invalid sdk storage: %+v, %s", storage.Data, err.Error())
		}
		s.brevisApp.AddStorage(sdkStorage, int(storage.Index))
	}

	for _, transaction := range req.Transactions {
		sdkTx, err := convertProtoTxToSdkTx(transaction.Data)
		if err != nil {
			return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "invalid sdk transaction: %+v, %s", transaction.Data, err.Error())
		}

		s.brevisApp.AddTransaction(sdkTx, int(transaction.Index))
	}

	guest, err := assignCustomInput(s.appCircuit, req.CustomInput)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_INVALID_CUSTOM_INPUT, "invalid custom input %s\n", err.Error())
	}

	input, err := s.brevisApp.BuildCircuitInput(guest)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE, "failed to build circuit input: %+v, %s", req, err.Error())
	}

	_, publicWitness, err := sdk.NewFullWitness(guest, input)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to prepare witness %s\n", err.Error())
	}

	var witnessBuffer bytes.Buffer
	witnessData := io.Writer(&witnessBuffer)
	_, err = publicWitness.WriteTo(witnessData)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to convert witness %s\n", err.Error())
	}
	witness := fmt.Sprintf("0x%x", witnessBuffer.Bytes())

	return &input, guest, witness, nil
}

func (s *server) genWitness(input *sdk.CircuitInput, guest sdk.AppCircuit) (witness.Witness, witness.Witness, error) {
	witness, publicWitness, err := sdk.NewFullWitness(guest, *input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get full witness: %w", err)
	}
	return witness, publicWitness, nil
}

func (s *server) prove(witness witness.Witness) (string, error) {
	proveProcessorLock.Lock()
	proof, err := sdk.Prove(s.ccs, s.pk, witness)
	goruntime.GC()
	proveProcessorLock.Unlock()
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

func (s *server) buildInputAndProve(proofId string, proveRequest *proveRequest, proveRequestProto *sdkproto.ProveRequest) {
	s.activeJobs.Store(proofId, true)
	defer s.activeJobs.Delete(proofId)

	input, guest, witnessStr, protoErr := s.buildInput(proveRequestProto)
	if protoErr != nil {
		s.markProofFailed(proofId, proveRequest, errors.New(protoErr.String()))
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
	appCircuitInfo := buildAppCircuitInfo(s.appCircuit, *input, s.vkString, s.vkHash, witnessStr)
	appCircuitInfoBytes, err := proto.Marshal(appCircuitInfo)
	if err != nil {
		s.markProofFailed(proofId, proveRequest, err)
		return
	}
	proveRequest.Status = ProveStatusInProgress
	proveRequest.AppCircuitInfo = appCircuitInfoBytes
	setProofErr := s.setProveRequest(proofId, proveRequest)
	if setProofErr != nil {
		log.Errorln("failed to set proof:", setProofErr.Error())
	}
	s.doProveHelper(proofId, proveRequest, witness)
}

func (s *server) continueProve(proofId string, proveRequest *proveRequest) {
	s.activeJobs.Store(proofId, true)
	defer s.activeJobs.Delete(proofId)

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

func (s *server) doProveHelper(proofId string, proveRequest *proveRequest, witness witness.Witness) {
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
	log.Infof("prove success, proof ID: %s\n", proofId)
}

func (s *server) setProveRequest(id string, req *proveRequest) error {
	log.Debugf("set prove request, ID: %s\n", id)
	setErr := s.store.Set(id, *req)
	if setErr != nil {
		return fmt.Errorf("store.Set err: %w", setErr)
	}
	return nil
}

func (s *server) getProveRequest(id string) (bool, *proveRequest, error) {
	log.Debugf("get prove request, ID: %s\n", id)
	var req proveRequest
	found, err := s.store.Get(id, &req)
	if err != nil {
		return false, nil, fmt.Errorf("store.Get err: %w", err)
	}
	return found, &req, nil
}

func (s *server) deleteProveRequest(id string) error {
	log.Debugf("delete prove request, ID: %s\n", id)
	s.activeJobs.Delete(id)
	err := s.store.Delete(id)
	if err != nil {
		return fmt.Errorf("store.Delete err: %w", err)
	}
	return nil
}

func (s *server) markProofFailed(proofId string, request *proveRequest, err error) {
	request.Status = ProveStatusFailed
	request.Err = err.Error()
	setProofErr := s.setProveRequest(proofId, request)
	if setProofErr != nil {
		log.Errorf("failed to set proof, err: %s, original err: %s", setProofErr.Error(), err.Error())
	}
}

func newErr(code sdkproto.ErrCode, format string, args ...any) *sdkproto.Err {
	return &sdkproto.Err{
		Code: code,
		Msg:  fmt.Sprintf(format, args...),
	}
}
