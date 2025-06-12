package gwproto

import (
	"database/sql/driver"

	"google.golang.org/protobuf/encoding/protojson"
)

// impl db required interface
func (c *GetQueryStatusResponse) Value() (driver.Value, error) {
	return protojson.Marshal(c)
}

func (u *GetQueryStatusResponse) Scan(value any) error {
	if u == nil {
		u = new(GetQueryStatusResponse)
	}
	return protojson.Unmarshal(value.([]byte), u)
}
