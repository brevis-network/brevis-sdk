// Implements a local kv store using an embedded BadgerDB
package store

import (
	"encoding/json"
	"fmt"

	"github.com/philippgille/gokv"
	"github.com/philippgille/gokv/badgerdb"
)

type BadgerDbStoreOptions struct {
	Dir   string `json:"dir"`
	Codec string `json:"codec"`
}

func NewBadgerDBStore(optionsJSON string) (gokv.Store, error) {
	if optionsJSON == "" {
		return createBadgerDBStore(badgerdb.DefaultOptions)
	}
	var options BadgerDbStoreOptions
	err := json.Unmarshal([]byte(optionsJSON), &options)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal err: %w", err)
	}
	codec, err := getStoreCodec(options.Codec)
	if err != nil {
		return nil, fmt.Errorf("getStoreCodec err: %w", err)
	}
	return createBadgerDBStore(badgerdb.Options{Dir: options.Dir, Codec: codec})
}

func createBadgerDBStore(options badgerdb.Options) (gokv.Store, error) {
	store, err := badgerdb.NewStore(options)
	if err != nil {
		return nil, fmt.Errorf("badgerdb.NewStore err: %w", err)
	}
	return store, nil
}
