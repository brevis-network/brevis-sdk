// Implements an in-memory kv store using sync.Map
package prover

import (
	"encoding/json"
	"fmt"

	"github.com/philippgille/gokv"
	"github.com/philippgille/gokv/syncmap"
)

type syncMapStoreOptions struct {
	Codec string `json:"codec"`
}

func newSyncMapStore(optionsJSON string) (gokv.Store, error) {
	if optionsJSON == "" {
		return syncmap.NewStore(syncmap.DefaultOptions), nil
	}
	var options syncMapStoreOptions
	err := json.Unmarshal([]byte(optionsJSON), &options)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal err: %w", err)
	}
	codec, err := getStoreCodec(options.Codec)
	if err != nil {
		return nil, fmt.Errorf("getStoreCodec err: %w", err)
	}
	return syncmap.NewStore(syncmap.Options{Codec: codec}), nil
}
