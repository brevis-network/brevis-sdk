package prover

import "os"

type ServiceConfig struct {
	// Required. Dir to save the circuit compilation outputs (proving key, verifying
	// key, verifying key hash)
	SetupDir string

	// Optional. Dir to save the srs (structured reference string) file. Default to
	// use the same dir as SetupDir
	SrsDir string
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
