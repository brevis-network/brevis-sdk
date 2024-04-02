package prover

type ServiceConfig struct {
	// Required. Dir to save the circuit compilation outputs (proving key, verifying
	// key, verifying key hash)
	SetupDir string

	// Optional. Dir to save the srs (structured reference string) file. Default to
	// use the same dir as SetupDir
	SrsDir string

	// The port on localhost to host the prover service on
	Port string
}
