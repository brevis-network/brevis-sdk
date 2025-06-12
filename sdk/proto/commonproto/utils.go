package commonproto

import (
	"database/sql/driver"

	"google.golang.org/protobuf/encoding/protojson"
)

// helper funcs

// impl db required interface for AppCircuitInfo. need pointer type b/c protobuf discourage copy value
func (c *AppCircuitInfo) Value() (driver.Value, error) {
	return protojson.Marshal(c)
}

func (u *AppCircuitInfo) Scan(value any) error {
	if u == nil {
		u = new(AppCircuitInfo)
	}
	return protojson.Unmarshal(value.([]byte), u)
}

// callback can be empty string
func (c *AppCircuitInfo) ToInfoWithProof(proof, callback string) *AppCircuitInfoWithProof {
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
		CallbackAddr:         callback,
	}
}
