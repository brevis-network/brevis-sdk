package prover

import "os"

type ServiceConfig struct {
	// ProverId is a unique identifier for this prover, defaults to hostname
	ProverId string `mapstructure:"prover_id" json:"prover_id"`

	// SetupDir saves the circuit compilation outputs (proving key, verifying key,
	// verifying key hash)
	SetupDir string `mapstructure:"setup_dir" json:"setup_dir"`

	// SrsDir saves the SRS files that will be automatically downloaded. These files
	// can be shared across different circuits. So the best practice is to have them
	// in a shared directory for all projects. Default to use the same dir as
	// SetupDir if not specified
	SrsDir string `mapstructure:"srs_dir" json:"srs_dir"`

	// GatewayUrl is the Brevis gateway URL, defaults to appsdkv3.brevis.network:443
	GatewayUrl string `mapstructure:"gateway_url" json:"gateway_url"`

	// DirectLoad indicates whether the setup process will parallel compile ccs and load pk vk, without digest check
	DirectLoad bool `mapstructure:"direct_load" json:"direct_load"`

	// ProofPersistenceType currently supporting "syncmap", "file", "badgerdb" and "s3".
	// Defaults to "syncmap".
	ProofPersistenceType string `mapstructure:"proof_persistence_type" json:"proof_persistence_type"`

	// ProofPersistenceOptions as JSON string. See implementations for details.
	ProofPersistenceOptions string `mapstructure:"proof_persistence_options" json:"proof_persistence_options"`

	// PersistenceType currently supporting "syncmap", "file", "badgerdb" and "s3".
	// Defaults to "file" under {setupDir}/input.
	DataPersistenceType string `mapstructure:"data_persistence_type" json:"data_persistence_type"`

	// DataPersistenceOptions as JSON string. See implementations for details.
	DataPersistenceOptions string `mapstructure:"data_persistence_options" json:"data_persistence_options"`

	// ConcurrentFetchLimit limits the number of concurrent on-chain fetches, defaults to 20
	ConcurrentFetchLimit int `mapstructure:"concurrent_fetch_limit" json:"concurrent_fetch_limit"`

	// ConcurrentProveLimit limits the number of concurrent prove actions, defaults to 1
	ConcurrentProveLimit int `mapstructure:"concurrent_prove_limit" json:"concurrent_prove_limit"`

	// UseMockProof indicates whether to use mock proof for testing purposes.
	UseMockProof bool `mapstructure:"use_mock_proof" json:"use_mock_proof"`
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

type SourceChainConfig struct {
	// ChainId the chain ID
	ChainId uint64 `mapstructure:"chain_id" json:"chain_id"`
	// RpcUrl will be used to query on-chain data by sending rpc call.
	RpcUrl string `mapstructure:"rpc_url" json:"rpc_url"`
}

type SourceChainConfigs []*SourceChainConfig
