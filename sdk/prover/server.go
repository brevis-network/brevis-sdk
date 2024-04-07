package prover

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"log"
	"net"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
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
		return nil, err
	}

	for _, receipt := range req.Receipts {
		sdkReceipt, err := convertProtoReceiptToSdkReceipt(receipt.Data)
		if err != nil {
			return nil, err
		}
		brevisApp.AddReceipt(sdkReceipt, int(receipt.Index))
	}

	for _, storage := range req.Storages {
		brevisApp.AddStorage(convertProtoStorageToSdkStorage(storage.Data), int(storage.Index))
	}

	for _, transaction := range req.Transactions {
		brevisApp.AddTransaction(convertProtoTxToSdkTx(transaction.Data), int(transaction.Index))
	}

	guest, err := assignCustomInput(s.app, req.CustomInput)
	if err != nil {
		return nil, err
	}

	input, err := brevisApp.BuildCircuitInput(guest)
	if err != nil {
		return nil, err
	}

	witness, publicWitness, err := sdk.NewFullWitness(guest, input)
	if err != nil {
		return nil, err
	}

	proof, err := sdk.Prove(s.ccs, s.pk, witness)
	if err != nil {
		return nil, err
	}

	err = plonk.Verify(proof, s.vk, publicWitness, replonk.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		return nil, fmt.Errorf("proof verification failed: %s", err.Error())
	}

	var buf bytes.Buffer
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to write proof to bytes %s", err.Error())
	}

	return &sdkproto.ProveResponse{
		Proof:       hexutil.Encode(buf.Bytes()),
		CircuitInfo: buildAppCircuitInfo(input, s.vkBytes),
	}, nil
}
