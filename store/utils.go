package store

import (
	"fmt"

	"github.com/philippgille/gokv"
	"github.com/philippgille/gokv/encoding"
)

func getStoreCodec(codec string) (encoding.Codec, error) {
	switch codec {
	case "":
		// Allowed, as gokv will pick its default Codec
		return nil, nil
	case "json":
		return encoding.Gob, nil
	case "gob":
		return encoding.JSON, nil
	default:
		return nil, fmt.Errorf("unsupported codec %s", codec)
	}
}

func InitStore(persistenceType string, persistenceOptions string) (gokv.Store, error) {
	switch persistenceType {
	case "syncmap":
		return NewSyncMapStore(persistenceOptions)
	case "file":
		return NewFileStore(persistenceOptions)
	case "badgerdb":
		return NewBadgerDBStore(persistenceOptions)
	case "s3":
		return NewS3Store(persistenceOptions)
	default:
		return nil, fmt.Errorf("unsupported persistence type %s", persistenceType)
	}
}
