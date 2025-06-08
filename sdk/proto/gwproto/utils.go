package gwproto

import (
	"database/sql/driver"

	"google.golang.org/protobuf/encoding/protojson"
)

// impl db required interface for AppCircuitInfo
func (c *GetQueryStatusResponse) Value() (driver.Value, error) {
	return protojson.Marshal(c)
}

// tried double pointer but not work
func (u *GetQueryStatusResponse) Scan(value interface{}) error {
	if u == nil {
		u = new(GetQueryStatusResponse)
	}
	return protojson.Unmarshal(value.([]byte), u)
}
