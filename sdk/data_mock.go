package sdk

func (q *BrevisApp) assignMockReceipts(in *CircuitInput) error {
	// assigning user appointed receipts at specific indices
	for i, r := range q.mockReceipts.special {
		receipt, err := q.buildMockReceipt(r)
		if err != nil {
			return err
		}
		in.Receipts.Raw[i] = receipt
		in.Receipts.Toggles[i] = 1
	}

	// distribute other receipts in order to the rest of the unassigned spaces
	j := 0
	for _, r := range q.mockReceipts.ordered {
		for in.Receipts.Toggles[j] == 1 {
			j++
		}
		receipt, err := q.buildMockReceipt(r)
		if err != nil {
			return err
		}
		in.Receipts.Raw[j] = receipt
		in.Receipts.Toggles[j] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) buildMockReceipt(r ReceiptData) (Receipt, error) {
	var fields [NumMaxLogFields]LogField
	for i, log := range r.Fields {
		fields[i] = LogField{
			Contract: ConstUint248(log.Contract),
			LogPos:   ConstUint32(log.LogPos),
			// we only constrain the first 6 bytes of EventID in circuit for performance reasons
			// 6 bytes give us 1/2^48 chance of two logs of different IDs clashing per contract.
			EventID: ConstUint248(log.EventID.Bytes()[0:6]),
			IsTopic: ConstUint248(log.IsTopic),
			Index:   ConstUint248(log.FieldIndex),
			Value:   ConstFromBigEndianBytes(log.Value[:]),
		}
	}
	if len(r.Fields) == 0 {
		fields[0] = LogField{
			Contract: ConstUint248(0),
			LogPos:   ConstUint32(0),
			EventID:  ConstUint248(0),
			IsTopic:  ConstUint248(0),
			Index:    ConstUint248(0),
			Value:    ConstFromBigEndianBytes([]byte{}),
		}
		fields[1] = fields[0]
		fields[2] = fields[0]
		fields[3] = fields[0]
	} else {
		for i := len(r.Fields); i < NumMaxLogFields; i++ {
			fields[i] = fields[len(r.Fields)-1]
		}
	}
	return Receipt{
		BlockNum:       newU32(r.BlockNum),
		BlockBaseFee:   newU248(r.BlockBaseFee),
		MptKeyPath:     newU32(r.MptKeyPath),
		Fields:         fields,
		BlockTimestamp: newU248(r.BlockTimestamp),
	}, nil
}

func (q *BrevisApp) assignMockStorageSlots(in *CircuitInput) (err error) {
	// assigning user appointed data at specific indices
	for i, val := range q.mockStorage.special {
		s, err := q.buildMockStorageSlot(val)
		if err != nil {
			return err
		}
		in.StorageSlots.Raw[i] = s
		in.StorageSlots.Toggles[i] = 1
	}

	// distribute other data in order to the rest of the unassigned spaces
	j := 0
	for _, val := range q.mockStorage.ordered {
		for in.StorageSlots.Toggles[j] == 1 {
			j++
		}
		s, err := q.buildMockStorageSlot(val)
		if err != nil {
			return err
		}
		in.StorageSlots.Raw[j] = s
		in.StorageSlots.Toggles[j] = 1
		j++
	}

	return nil
}

func (q *BrevisApp) buildMockStorageSlot(s StorageData) (StorageSlot, error) {
	return StorageSlot{
		BlockNum:       newU32(s.BlockNum),
		BlockBaseFee:   newU248(s.BlockBaseFee),
		Contract:       ConstUint248(s.Address),
		Slot:           ConstFromBigEndianBytes(s.Slot[:]),
		Value:          ConstFromBigEndianBytes(s.Value[:]),
		BlockTimestamp: newU248(s.BlockTimestamp),
	}, nil
}

func (q *BrevisApp) assignMockTransactions(in *CircuitInput) (err error) {
	// assigning user appointed data at specific indices
	for i, t := range q.txs.special {
		tx, err := q.buildTx(t)
		if err != nil {
			return err
		}
		in.Transactions.Raw[i] = tx
		in.Transactions.Toggles[i] = 1
	}

	j := 0
	for i, t := range q.txs.ordered {
		for in.Transactions.Toggles[j] == 1 {
			j++
		}
		tx, err := q.buildTx(t)
		if err != nil {
			return err
		}
		in.Transactions.Raw[i] = tx
		in.Transactions.Toggles[i] = 1
		j++
	}

	return nil
}
