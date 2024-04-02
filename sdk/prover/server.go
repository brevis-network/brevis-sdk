package prover

import "github.com/brevis-network/brevis-sdk/sdk"

type Server struct {
}

// NewServer creates a new prover server instance that automatically manages
// compilation & setup, and serves as a GRPC server that interoperates with
// brevis sdk in other languages
func NewServer(circuit sdk.AppCircuit) {

}

func (s *Server) Serve(port uint) {

}
