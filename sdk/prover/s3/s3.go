package s3

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	awss3 "github.com/aws/aws-sdk-go/service/s3"

	"github.com/philippgille/gokv/encoding"
	"github.com/philippgille/gokv/util"
)

// Client is a gokv.Store implementation for S3.
type Client struct {
	c          *awss3.S3
	bucketName string
	keyPrefix  string
	codec      encoding.Codec
}

// Set stores the given value for the given key.
// Values are automatically marshalled to JSON or gob (depending on the configuration).
// The key must not be "" and the value must not be nil.
func (c Client) Set(k string, v any) error {
	if err := util.CheckKeyAndValue(k, v); err != nil {
		return err
	}

	// First turn the passed object into something that S3 can handle.
	data, err := c.codec.Marshal(v)
	if err != nil {
		return err
	}

	fullKey := strings.Join([]string{c.keyPrefix, k}, "")
	pubObjectInput := awss3.PutObjectInput{
		Body:   bytes.NewReader(data),
		Bucket: &c.bucketName,
		Key:    &fullKey,
	}
	_, err = c.c.PutObject(&pubObjectInput)
	if err != nil {
		return err
	}

	return nil
}

// Get retrieves the stored value for the given key.
// You need to pass a pointer to the value, so in case of a struct
// the automatic unmarshaling can populate the fields of the object
// that v points to with the values of the retrieved object's values.
// If no value is found it returns (false, nil).
// The key must not be "" and the pointer must not be nil.
func (c Client) Get(k string, v any) (found bool, err error) {
	if err := util.CheckKeyAndValue(k, v); err != nil {
		return false, err
	}

	fullKey := strings.Join([]string{c.keyPrefix, k}, "")
	getObjectInput := awss3.GetObjectInput{
		Bucket: &c.bucketName,
		Key:    &fullKey,
	}
	getObjectOutput, err := c.c.GetObject(&getObjectInput)
	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == awss3.ErrCodeNoSuchKey {
			return false, nil
		}
		return false, err
	}
	if getObjectOutput.Body == nil {
		// Return false if there's no value
		// TODO: Maybe return an error? Behavior should be consistent across all implementations.
		return false, nil
	}
	data, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		return true, err
	}

	return true, c.codec.Unmarshal(data, v)
}

// Delete deletes the stored value for the given key.
// Deleting a non-existing key-value pair does NOT lead to an error.
// The key must not be "".
func (c Client) Delete(k string) error {
	if err := util.CheckKey(k); err != nil {
		return err
	}

	fullKey := strings.Join([]string{c.keyPrefix, k}, "")
	deleteObjectInput := awss3.DeleteObjectInput{
		Bucket: &c.bucketName,
		Key:    &fullKey,
	}
	_, err := c.c.DeleteObject(&deleteObjectInput)
	return err
}

// Close closes the client.
// In the S3 implementation this doesn't have any effect.
func (c Client) Close() error {
	return nil
}

// Options are the options for the S3 client.
type Options struct {
	// Name of the S3 bucket.
	// The bucket is automatically created if it doesn't exist yet.
	BucketName string
	// Prefix for all keys, eg. "{your-folder-name}/".
	KeyPrefix string
	// Region of the S3 service you want to use.
	// Valid values: https://docs.aws.amazon.com/general/latest/gr/rande.html#ddb_region.
	// E.g. "us-west-2".
	// Optional (read from shared config file or environment variable if not set).
	// Environment variable: "AWS_REGION".
	//
	// Note: A region is also required when using an S3-compatible cloud service and even when using a self-hosted solution.
	// Example for Google Cloud Storage: "EUROPE-WEST3".
	// Example for Alibaba Cloud Object Storage Service (OSS): "oss-ap-southeast-1".
	// Example for Scaleway Object Storage: "nl-ams".
	// Example for a locally running Minio server: "foo" (any value works).
	Region string
	// AWS access key ID (part of the credentials).
	// Optional (read from shared credentials file or environment variable if not set).
	// Environment variable: "AWS_ACCESS_KEY_ID".
	AWSAccessKeyID string
	// AWS secret access key (part of the credentials).
	// Optional (read from shared credentials file or environment variable if not set).
	// Environment variable: "AWS_SECRET_ACCESS_KEY".
	AWSSecretAccessKey string
	// S3 differentiates between "virtual hosted bucket addressing" and "path-style addressing".
	// Example URL for the virtual host style: http://BUCKET.s3.amazonaws.com/KEY.
	// Example UL for the path style: http://s3.amazonaws.com/BUCKET/KEY.
	// Most S3-compatible servers work with both styles,
	// but some work only with the virtual host style (e.g. Alibaba Cloud Object Storage Service (OSS))
	// and some work only with the path style (especially self-hosted services like a Minio server running on localhost).
	// Optional (false by default).
	UsePathStyleAddressing bool
	// Encoding format.
	// Optional (encoding.JSON by default).
	Codec encoding.Codec
}

// DefaultOptions is an Options object with default values.
// Region: "" (use shared config file or environment variable),
// AWSaccessKeyID: "" (use shared credentials file or environment variable),
// AWSsecretAccessKey: "" (use shared credentials file or environment variable),
var DefaultOptions = Options{
	Codec: encoding.JSON,
	// No need to set Region, AWSAccessKeyID, AWSSecretAccessKey
	// or UsePathStyleAddressing because their Go zero values are fine.
}

// NewClient creates a new S3 client.
//
// Credentials can be set in the options, but it's recommended to either use the shared credentials file
// (Linux: "~/.aws/credentials", Windows: "%UserProfile%\.aws\credentials")
// or environment variables (AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY).
// See https://github.com/awsdocs/aws-go-developer-guide/blob/0ae5712d120d43867cf81de875cb7505f62f2d71/doc_source/configuring-sdk.rst#specifying-credentials.
func NewClient(options Options) (Client, error) {
	result := Client{}

	// Precondition check
	if options.BucketName == "" {
		//lint:ignore ST1005 Nit
		return result, errors.New("The BucketName in the options must not be empty")
	}

	// Set default values
	if options.Codec == nil {
		options.Codec = DefaultOptions.Codec
	}

	// Set credentials only if set in the options.
	// If not set, the SDK uses the shared credentials file or environment variables, which is the preferred way.
	// Return an error if only one of the values is set.
	var creds *credentials.Credentials
	if (options.AWSAccessKeyID != "" && options.AWSSecretAccessKey == "") || (options.AWSAccessKeyID == "" && options.AWSSecretAccessKey != "") {
		//lint:ignore ST1005 Nit
		return result, errors.New("When passing credentials via options, you need to set BOTH AWSaccessKeyID AND AWSsecretAccessKey")
	} else if options.AWSAccessKeyID != "" {
		// Due to the previous check we can be sure that in this case AWSsecretAccessKey is not empty as well.
		creds = credentials.NewStaticCredentials(options.AWSAccessKeyID, options.AWSSecretAccessKey, "")
	}

	config := aws.NewConfig()
	if options.Region != "" {
		config = config.WithRegion(options.Region)
	}
	if creds != nil {
		config = config.WithCredentials(creds)
	}
	if options.UsePathStyleAddressing {
		config = config.WithS3ForcePathStyle(true)
	}
	// Use shared config file...
	sessionOpts := session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}
	// ...but allow overwrite of region and credentials if they are set in the options.
	sessionOpts.Config.MergeIn(config)
	session, err := session.NewSessionWithOptions(sessionOpts)
	if err != nil {
		return result, err
	}
	svc := awss3.New(session)

	result.c = svc
	result.bucketName = options.BucketName
	result.keyPrefix = options.KeyPrefix
	result.codec = options.Codec

	return result, nil
}
