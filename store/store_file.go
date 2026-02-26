// Implements a local kv store using an embedded BadgerDB
package store

import (
	"encoding/json"
	"fmt"

	"github.com/philippgille/gokv"
	"github.com/philippgille/gokv/file"
)

type FileStoreOptions struct {
	Directory         string `json:"dir"`
	FilenameExtension string `json:"file_name_extension"`
	Codec             string `json:"codec"`
}

func NewFileStore(optionsJSON string) (gokv.Store, error) {
	if optionsJSON == "" {
		return createFileStore(file.DefaultOptions)
	}
	var options FileStoreOptions
	err := json.Unmarshal([]byte(optionsJSON), &options)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal err: %w", err)
	}
	codec, err := getStoreCodec(options.Codec)
	if err != nil {
		return nil, fmt.Errorf("getStoreCodec err: %w", err)
	}
	var filenameExtension *string
	if options.FilenameExtension != "" {
		filenameExtension = &options.FilenameExtension
	}
	return createFileStore(file.Options{Directory: options.Directory, FilenameExtension: filenameExtension, Codec: codec})
}

func createFileStore(options file.Options) (gokv.Store, error) {
	store, err := file.NewStore(options)
	if err != nil {
		return nil, fmt.Errorf("file.NewStore err: %w", err)
	}
	return store, nil
}
