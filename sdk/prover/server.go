package prover

import (
	"bytes"
	"context"
	"fmt"
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
	*server
}

// NewService creates a new prover server instance that automatically manages
// compilation & setup, and serves as a GRPC server that interoperates with
// brevis sdk in other languages
func NewService(app sdk.AppCircuit, config ServiceConfig) (*Service, error) {
	setupMan := newSetupManager(config.SetupDir, config.SrsDir)
	pk, vk, ccs, err := setupMan.readOrSetup(app)
	if err != nil {
		return nil, err
	}
	vkBytes, err := GetVKBytes(vk)
	if err != nil {
		return nil, err
	}
	return &Service{server: newServer(app, pk, vk, ccs, fmt.Sprintf("0x%x", vkBytes))}, nil
}

func (s *Service) Serve(port uint) error {
	grpcServer := grpc.NewServer()
	sdkproto.RegisterProverServer(grpcServer, s.server)
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to start prover server: %v", err)
	}
	err = grpcServer.Serve(lis)
	if err != nil {
		return err
	}
	return nil
}

type server struct {
	sdkproto.UnimplementedProverServer

	app sdk.AppCircuit

	pk      plonk.ProvingKey
	vk      plonk.VerifyingKey
	ccs     constraint.ConstraintSystem
	vkBytes string
}

func newServer(
	app sdk.AppCircuit,
	pk plonk.ProvingKey,
	vk plonk.VerifyingKey,
	ccs constraint.ConstraintSystem,
	vkBytes string,
) *server {
	return &server{
		app:     app,
		pk:      pk,
		vk:      vk,
		ccs:     ccs,
		vkBytes: vkBytes,
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
		Proof:       fmt.Sprintf("0x%x", buf.Bytes()),
		CircuitInfo: buildAppCircuitInfo(input, s.vkBytes),
	}, nil
}
