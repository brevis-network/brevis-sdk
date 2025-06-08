package commonproto

import (
	"database/sql/driver"

	"google.golang.org/protobuf/encoding/protojson"
)

// helper funcs

// impl db required interface for AppCircuitInfo
func (c *AppCircuitInfo) Value() (driver.Value, error) {
	return protojson.Marshal(c)
}

// tried double pointer but not work
func (u *AppCircuitInfo) Scan(value interface{}) error {
	if u == nil {
		u = new(AppCircuitInfo)
	}
	return protojson.Unmarshal(value.([]byte), u)
}

func (c *AppCircuitInfo) ToInfoWithProof(proof string) *AppCircuitInfoWithProof {
	return &AppCircuitInfoWithProof{
		OutputCommitment:     c.OutputCommitment,
		VkHash:               c.VkHash,
		InputCommitments:     c.InputCommitments,
		Toggles:              c.Toggles,
		Output:               c.Output,
		InputCommitmentsRoot: c.InputCommitmentsRoot,
		Witness:              c.Witness,
		MaxReceipts:          c.MaxReceipts,
		MaxStorage:           c.MaxStorage,
		MaxTx:                c.MaxTx,
		MaxNumDataPoints:     c.MaxNumDataPoints,
		Proof:                proof,
	}
}
