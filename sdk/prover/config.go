package prover

import "os"

type ServiceConfig struct {
	// SetupDir saves the circuit compilation outputs (proving key, verifying key,
	// verifying key hash)
	SetupDir string

	// SrsDir saves the SRS files that will be automatically downloaded. These files
	// can be shared across different circuits. So the best practice is to have them
	// in a shared directory for all projects. Default to use the same dir as
	// SetupDir if not specified
	SrsDir string

	// RpcURL will be used to query on-chain data by sending rpc call.
	RpcURL string

	// On-chain query data will be stored in LocalStoragePath/data.json. It will
	// save rpc usage for developers.
	LocalStoragePath string

	// Source chain id.
	ChainId int
}

func (c ServiceConfig) GetSetupDir() string {
	return os.ExpandEnv(c.SetupDir)
}

func (c ServiceConfig) GetSrsDir() string {
	if len(c.SrsDir) == 0 {
		return c.GetSetupDir()
	}
	return os.ExpandEnv(c.SrsDir)
}

func (c ServiceConfig) GetLocalStoragePath() string {
	return os.ExpandEnv(c.LocalStoragePath)
}
