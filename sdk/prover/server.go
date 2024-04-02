package prover

import (
	"context"
	"fmt"
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"google.golang.org/grpc"
	"log"
	"net"
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
	return &Service{server: newServer(app, pk, vk, ccs)}, nil
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

	pk  plonk.ProvingKey
	vk  plonk.VerifyingKey
	ccs constraint.ConstraintSystem
}

func newServer(
	app sdk.AppCircuit,
	pk plonk.ProvingKey,
	vk plonk.VerifyingKey,
	ccs constraint.ConstraintSystem,
) *server {
	return &server{
		app: app,
		pk:  pk,
		vk:  vk,
		ccs: ccs,
	}
}

func (s *server) Prove(ctx context.Context, req *sdkproto.ProveRequest) (*sdkproto.ProveResponse, error) {
	req.CustomInput
	sdk.NewBrevisApp()

	sdk.NewFullWitness()
	sdk.Prove(s.ccs, s.pk)
}
