package prover

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
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

func (s *Service) Serve(port uint) error {
	grpcServer := grpc.NewServer()
	sdkproto.RegisterProverServer(grpcServer, s.svr)
	address := fmt.Sprintf("localhost:%d", port)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to start prover server: %v", err)
	}
	fmt.Println("\n>> serving prover at", address)
	err = grpcServer.Serve(lis)
	if err != nil {
		return err
	}
	return nil
}

type server struct {
	sdkproto.UnimplementedProverServer

	app sdk.AppCircuit

	pk  plonk.ProvingKey
	vk  plonk.VerifyingKey
	ccs constraint.ConstraintSystem

	vkBytes string
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
		log.Fatal(err)
	}
	return &server{
		app:     app,
		pk:      pk,
		vk:      vk,
		ccs:     ccs,
		vkBytes: hexutil.Encode(buf.Bytes()),
	}
}

func (s *server) Prove(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveResponse, error) {
	brevisApp, err := sdk.NewBrevisApp()

	if err != nil {
		fmt.Println("failed to new brevis app: ", err.Error())
		return prepareErrorResponse(sdkproto.ErrCode_ERROR_DEFAULT), nil
	}

	for _, receipt := range req.Receipts {
		sdkReceipt, err := convertProtoReceiptToSdkReceipt(receipt.Data)
		if err != nil {
			fmt.Println("invalid sdk receipt: ", receipt.Data, err.Error())
			return prepareErrorResponse(sdkproto.ErrCode_ERROR_INVALID_INPUT), nil
		}
		brevisApp.AddReceipt(sdkReceipt, int(receipt.Index))
	}

	for _, storage := range req.Storages {
		sdkStorage, err := convertProtoStorageToSdkStorage(storage.Data)
		if err != nil {
			fmt.Println("invalid sdk storage: ", storage.Data, err.Error())
			return prepareErrorResponse(sdkproto.ErrCode_ERROR_INVALID_INPUT), nil
		}

		brevisApp.AddStorage(sdkStorage, int(storage.Index))
	}

	for _, transaction := range req.Transactions {
		sdkTx, err := convertProtoTxToSdkTx(transaction.Data)
		if err != nil {
			fmt.Println("invalid sdk transaction: ", transaction.Data, err.Error())
			return prepareErrorResponse(sdkproto.ErrCode_ERROR_INVALID_INPUT), nil
		}

		brevisApp.AddTransaction(sdkTx, int(transaction.Index))
	}

	guest, err := assignCustomInput(s.app, req.CustomInput)
	if err != nil {
		fmt.Println("invalid sdk custom input: ", req.CustomInput, err.Error())
		return prepareErrorResponse(sdkproto.ErrCode_ERROR_INVALID_CUSTOM_INPUT), nil
	}

	input, err := brevisApp.BuildCircuitInput(guest)
	if err != nil {
		fmt.Println("failed to build circuit input: ", req, err.Error())
		return prepareErrorResponse(sdkproto.ErrCode_ERROR_CIRCUIT_INPUT_FAILURE), nil
	}

	witness, publicWitness, err := sdk.NewFullWitness(guest, input)
	if err != nil {
		fmt.Println("failed to get full witness: ", req, err.Error())
		return prepareErrorResponse(sdkproto.ErrCode_ERROR_INVALID_WITNESS), nil
	}

	proof, err := sdk.Prove(s.ccs, s.pk, witness)
	if err != nil {
		fmt.Println("failed to prove: ", req, err.Error())
		return prepareErrorResponse(sdkproto.ErrCode_ERROR_FAILED_TO_PROVE), nil
	}

	err = sdk.Verify(s.vk, publicWitness, proof)
	if err != nil {
		fmt.Println("failed to verify: ", req, err.Error())
		return prepareErrorResponse(sdkproto.ErrCode_ERROR_FAILED_TO_VERIFY), nil
	}

	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		fmt.Println("failed to write proof bytes: ", req, err.Error())
		return prepareErrorResponse(sdkproto.ErrCode_ERROR_FAILED_TO_WRITE_PROOF), nil
	}

	return &sdkproto.ProveResponse{
		Proof:       hexutil.Encode(buf.Bytes()),
		CircuitInfo: buildAppCircuitInfo(input, s.vkBytes),
	}, nil
}

func prepareErrorResponse(code sdkproto.ErrCode) *sdkproto.ProveResponse {
	msg := ""
	switch code {
	case sdkproto.ErrCode_ERROR_UNDEFINED:
		msg = "unknown error"
	case sdkproto.ErrCode_ERROR_DEFAULT:
		msg = "internal server error"
	case sdkproto.ErrCode_ERROR_INVALID_INPUT:
		msg = "invalid input"
	case sdkproto.ErrCode_ERROR_INVALID_CUSTOM_INPUT:
		msg = "invalid custom input"
	case sdkproto.ErrCode_ERROR_CIRCUIT_INPUT_FAILURE:
		msg = "cannot generate brevis circuit input"
	case sdkproto.ErrCode_ERROR_INVALID_WITNESS:
		msg = "cannot generate circuit witness"
	case sdkproto.ErrCode_ERROR_FAILED_TO_PROVE:
		msg = "failed to prove"
	case sdkproto.ErrCode_ERROR_FAILED_TO_VERIFY:
		msg = "failed to verify proof"
	case sdkproto.ErrCode_ERROR_FAILED_TO_WRITE_PROOF:
		msg = "failed to serialize proof"
	default:
		fmt.Sprintln("found unknown code usage", code)
		msg = "unknown error"
	}

	return &sdkproto.ProveResponse{
		Err: &sdkproto.Err{
			Code: code,
			Msg:  msg,
		},
	}
}
