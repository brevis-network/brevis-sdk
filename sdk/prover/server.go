package prover

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/hashicorp/go-uuid"
	"github.com/rs/cors"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/brevis-network/brevis-sdk/sdk"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"google.golang.org/grpc"
)

type Service struct {
	svr *server
}

// NewService creates a new prover server instance that automatically manages
// compilation & setup, and serves as a GRPC server that interoperates with
// brevis sdk in other languages.
func NewService(app sdk.AppCircuit, config ServiceConfig) (*Service, error) {
	pk, vk, ccs, err := readOrSetup(app, config.SetupDir, config.GetSrsDir())
	if err != nil {
		return nil, err
	}
	return &Service{
		svr: newServer(app, pk, vk, ccs),
	}, nil
}

func (s *Service) Serve(bind string, port uint) {
	go s.serveGrpc(bind, port)
	s.serveGrpcGateway(bind, port, port+10)
}

func (s *Service) serveGrpc(bind string, port uint) {
	grpcServer := grpc.NewServer()
	sdkproto.RegisterProverServer(grpcServer, s.svr)
	address := fmt.Sprintf("%s:%d", bind, port)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("failed to start prover server:", err)
		os.Exit(1)
	}
	fmt.Println(">> serving prover GRPC at port", port)
	if err = grpcServer.Serve(lis); err != nil {
		fmt.Println("grpc server crashed", err)
		os.Exit(1)
	}
}

func (s *Service) serveGrpcGateway(bind string, grpcPort, restPort uint) {
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	endpoint := fmt.Sprintf("%s:%d", bind, grpcPort)

	err := sdkproto.RegisterProverHandlerFromEndpoint(context.Background(), mux, endpoint, opts)
	if err != nil {
		fmt.Println("failed to start prover server:", err)
		os.Exit(1)
	}

	handler := cors.New(cors.Options{
		AllowedHeaders:   []string{"*"},
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	}).Handler(mux)

	fmt.Println(">> serving prover REST API at port", restPort)
	if err = http.ListenAndServe(fmt.Sprintf(":%d", restPort), handler); err != nil {
		fmt.Println("REST server crashed", err)
		os.Exit(1)
	}
}

type proofRes struct {
	proof string
	err   string
}

type server struct {
	sdkproto.UnimplementedProverServer

	app sdk.AppCircuit

	pk  plonk.ProvingKey
	vk  plonk.VerifyingKey
	ccs constraint.ConstraintSystem

	vkBytes string

	proofs map[string]proofRes
	lock   sync.RWMutex
}

func newServer(
	app sdk.AppCircuit,
	pk plonk.ProvingKey,
	vk plonk.VerifyingKey,
	ccs constraint.ConstraintSystem,
) *server {
	var buf bytes.Buffer
	_, err := vk.WriteRawTo(&buf)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return &server{
		app:     app,
		pk:      pk,
		vk:      vk,
		ccs:     ccs,
		vkBytes: hexutil.Encode(buf.Bytes()),
		proofs:  make(map[string]proofRes),
	}
}

func (s *server) Prove(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveResponse, error) {
	fmt.Println(req.String())

	errRes := func(protoErr *sdkproto.Err) (*sdkproto.ProveResponse, error) {
		return &sdkproto.ProveResponse{Err: protoErr, CircuitInfo: nil}, nil
	}

	input, guest, protoErr := s.buildInput(req)
	if protoErr != nil {
		return errRes(protoErr)
	}

	proof, err := s.prove(input, guest)
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE, "failed to prove: %s", err.Error()))
	}

	return &sdkproto.ProveResponse{
		Proof:       proof,
		CircuitInfo: buildAppCircuitInfo(*input, s.vkBytes),
	}, nil
}

func (s *server) ProveAsync(ctx context.Context, req *sdkproto.ProveRequest) (res *sdkproto.ProveAsyncResponse, err error) {
	errRes := func(protoErr *sdkproto.Err) (*sdkproto.ProveAsyncResponse, error) {
		return &sdkproto.ProveAsyncResponse{Err: protoErr, ProofId: "", CircuitInfo: nil}, nil
	}

	uid, err := uuid.GenerateUUID()
	if err != nil {
		return errRes(newErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to generate uuid %s", err.Error()))
	}

	input, guest, protoErr := s.buildInput(req)
	if protoErr != nil {
		return errRes(protoErr)
	}

	go func() {
		proof, err := s.prove(input, guest)
		if err != nil {
			fmt.Println("failed to prove:", err.Error())
			s.setProof(uid, "", err.Error())
			return
		}
		s.setProof(uid, proof, "")
	}()

	return &sdkproto.ProveAsyncResponse{
		Err:         nil,
		ProofId:     uid,
		CircuitInfo: buildAppCircuitInfo(*input, s.vkBytes),
	}, nil
}

func (s *server) GetProof(ctx context.Context, req *sdkproto.GetProofRequest) (res *sdkproto.GetProofResponse, err error) {
	id := req.ProofId
	proof := s.getProof(id)
	if proof.err != "" {
		return &sdkproto.GetProofResponse{
			Err:   newErr(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE, "failed to prove: %s", err.Error()),
			Proof: "",
		}, nil
	}

	if len(proof.proof) > 0 {
		s.deleteProof(id)
	}
	return &sdkproto.GetProofResponse{
		Proof: proof.proof,
	}, nil
}

func (s *server) buildInput(req *sdkproto.ProveRequest) (*sdk.CircuitInput, sdk.AppCircuit, *sdkproto.Err) {
	makeErr := func(code sdkproto.ErrCode, format string, args ...any) (*sdk.CircuitInput, sdk.AppCircuit, *sdkproto.Err) {
		fmt.Printf(format, args...)
		fmt.Println()
		return nil, nil, newErr(code, format, args...)
	}

	brevisApp, err := sdk.NewBrevisApp()
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_DEFAULT, "failed to new brevis app: %s", err.Error())
	}

	for _, receipt := range req.Receipts {
		sdkReceipt, err := convertProtoReceiptToSdkReceipt(receipt.Data)
		if err != nil {
			return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "invalid sdk receipt: %+v, %s", receipt.Data, err.Error())
		}
		brevisApp.AddReceipt(sdkReceipt, int(receipt.Index))
	}

	for _, storage := range req.Storages {
		sdkStorage, err := convertProtoStorageToSdkStorage(storage.Data)
		if err != nil {
			return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "invalid sdk storage: %+v, %s", storage.Data, err.Error())
		}
		brevisApp.AddStorage(sdkStorage, int(storage.Index))
	}

	for _, transaction := range req.Transactions {
		sdkTx, err := convertProtoTxToSdkTx(transaction.Data)
		if err != nil {
			return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "invalid sdk transaction: %+v, %s", transaction.Data, err.Error())
		}

		brevisApp.AddTransaction(sdkTx, int(transaction.Index))
	}

	guest, err := assignCustomInput(s.app, req.CustomInput)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_INVALID_CUSTOM_INPUT, "invalid custom input %s\n", err.Error())
	}

	input, err := brevisApp.BuildCircuitInput(guest)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE, "failed to build circuit input: %+v, %s", req, err.Error())
	}
	return &input, guest, nil
}

func (s *server) prove(input *sdk.CircuitInput, guest sdk.AppCircuit) (string, error) {
	witness, publicWitness, err := sdk.NewFullWitness(guest, *input)
	if err != nil {
		return "", fmt.Errorf("failed to get full witness: %s", err.Error())
	}

	proof, err := sdk.Prove(s.ccs, s.pk, witness)
	if err != nil {
		return "", fmt.Errorf("failed to prove: %s", err.Error())
	}

	err = sdk.Verify(s.vk, publicWitness, proof)
	if err != nil {
		return "", fmt.Errorf("failed to test verifying after proving: %s", err.Error())
	}

	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		return "", fmt.Errorf("failed to write proof bytes: %s", err.Error())
	}

	return hexutil.Encode(buf.Bytes()), nil
}

func (s *server) setProof(id, proof, err string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.proofs[id] = proofRes{proof, err}
}

func (s *server) getProof(id string) proofRes {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.proofs[id]
}

func (s *server) deleteProof(id string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.proofs, id)
}

func newErr(code sdkproto.ErrCode, format string, args ...any) *sdkproto.Err {
	return &sdkproto.Err{
		Code: code,
		Msg:  fmt.Sprintf(format, args...),
	}
}
