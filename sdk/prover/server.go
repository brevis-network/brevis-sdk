package prover

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/celer-network/goutils/big"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	replonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
		sdkReceipt, err := ConvertProtoReceiptToSdkReceipt(receipt.Data)
		if err != nil {
			return nil, err
		}
		brevisApp.AddReceipt(sdkReceipt, int(receipt.Index))
	}

	for _, storage := range req.Storages {
		brevisApp.AddStorage(ConvertProtoStorageToSdkStorage(storage.Data), int(storage.Index))
	}

	for _, transaction := range req.Transactions {
		brevisApp.AddTransaction(ConvertProtoTxToSdkTx(transaction.Data), int(transaction.Index))
	}

	/// TODO: Use actual data to build input
	guest := s.app
	input, err := brevisApp.BuildCircuitInput(guest)
	if err != nil {
		return nil, err
	}

	assignment := sdk.NewHostCircuit(input.Clone(), guest)

	witness, err := frontend.NewWitness(assignment, ecc.BLS12_377.ScalarField())

	if err != nil {
		return nil, err
	}

	proof, err := plonk.Prove(s.ccs, s.pk, witness, replonk.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		return nil, err
	}

	witnessPublic, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public witness %s", err.Error())
	}

	err = plonk.Verify(proof, s.vk, witnessPublic, replonk.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
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
		CircuitInfo: BuildAppCircuitInfo(input, s.vkBytes),
	}, nil
}

func BuildAppCircuitInfo(in sdk.CircuitInput, vk string) *commonproto.AppCircuitInfo {
	inputCommitments := make([]string, len(in.InputCommitments))
	for i, value := range in.InputCommitments {
		inputCommitments[i] = fmt.Sprintf("0x%x", value)
	}

	toggles := make([]bool, len(in.Toggles()))
	for i, value := range in.Toggles() {
		toggles[i] = fmt.Sprintf("%x", value) == "1"
	}

	return &proto.AppCircuitInfo{
		OutputCommitment:  hexutil.Encode(in.OutputCommitment.Hash().Bytes()),
		Vk:                vk,
		InputCommitments:  inputCommitments,
		TogglesCommitment: fmt.Sprintf("0x%x", in.TogglesCommitment),
		Toggles:           toggles,
		UseCallback:       true,
		Output:            hexutil.Encode(in.GetAbiPackedOutput()),
	}
}

func ConvertProtoReceiptToSdkReceipt(in *sdkproto.ReceiptData) (sdk.ReceiptData, error) {
	var fields [sdk.NumMaxLogFields]sdk.LogFieldData
	if len(in.Fields) == 0 {
		return sdk.ReceiptData{}, fmt.Errorf("invalid log field")
	}

	for i := range fields {
		if i < len(in.Fields) {
			fields[i] = ConvertProtoFieldToSdkLog(in.Fields[i])
		} else {
			fields[i] = fields[len(in.Fields)-1]
		}
	}

	return sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(in.BlockNum),
		TxHash:   Hex2Hash(in.TxHash),
		Fields:   fields,
	}, nil
}

func ConvertProtoFieldToSdkLog(in *sdkproto.Field) sdk.LogFieldData {
	return sdk.LogFieldData{
		Contract:   Hex2Addr(in.Contract),
		LogIndex:   uint(in.LogIndex),
		EventID:    Hex2Hash(in.EventId),
		IsTopic:    in.IsTopic,
		FieldIndex: uint(in.FieldIndex),
		Value:      Hex2Hash(in.Value),
	}
}

func ConvertProtoStorageToSdkStorage(in *sdkproto.StorageData) sdk.StorageData {
	return sdk.StorageData{
		BlockNum: new(big.Int).SetUint64(in.BlockNum),
		Address:  Hex2Addr(in.Address),
		Slot:     Hex2Hash(in.Slot),
		Value:    Hex2Hash(in.Value),
	}
}

func ConvertProtoTxToSdkTx(in *sdkproto.TransactionData) sdk.TransactionData {
	return sdk.TransactionData{
		Hash:                Hex2Hash(in.Hash),
		ChainId:             new(big.Int).SetUint64(in.ChainId),
		BlockNum:            new(big.Int).SetUint64(in.BlockNum),
		Nonce:               in.Nonce,
		GasTipCapOrGasPrice: new(big.Int).SetBytes(Hex2Bytes(in.GasTipCapOrGasPrice)),
		GasFeeCap:           new(big.Int).SetBytes(Hex2Bytes(in.GasFeeCap)),
		GasLimit:            in.GasLimit,
		From:                Hex2Addr(in.From),
		To:                  Hex2Addr(in.To),
		Value:               new(big.Int).SetBytes(Hex2Bytes(in.Value)),
	}
}
