// Implements a remote kv store using an AWS s3 bucket
package prover

import (
	"encoding/json"
	"fmt"

	"github.com/philippgille/gokv"
	"github.com/philippgille/gokv/s3"
)

type s3StoreOptions struct {
	BucketName             string `json:"bucket_name"`
	Region                 string `json:"region"`
	AWSAccessKeyID         string `json:"aws_access_key_id"`
	AWSSecretAccessKey     string `json:"aws_secret_access_key"`
	CustomEndpoint         string `json:"custom_endpoint"`
	UsePathStyleAddressing bool   `json:"use_path_style_addressing"`
	Codec                  string `json:"codec"`
}

func newS3Store(optionsJSON string) (gokv.Store, error) {
	if optionsJSON == "" {
		return nil, fmt.Errorf("options cannot be empty, need at least BucketName")
	}
	var options s3StoreOptions
	err := json.Unmarshal([]byte(optionsJSON), &options)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal err: %w", err)
	}
	codec, err := getStoreCodec(options.Codec)
	if err != nil {
		return nil, fmt.Errorf("getStoreCodec err: %w", err)
	}
	store, err := s3.NewClient(s3.Options{
		BucketName:             options.BucketName,
		Region:                 options.Region,
		AWSaccessKeyID:         options.AWSAccessKeyID,
		AWSsecretAccessKey:     options.AWSSecretAccessKey,
		CustomEndpoint:         options.CustomEndpoint,
		UsePathStyleAddressing: options.UsePathStyleAddressing,
		Codec:                  codec,
	})
	if err != nil {
		return nil, fmt.Errorf("s3.NewClient err: %w", err)
	}
	return store, nil
}
