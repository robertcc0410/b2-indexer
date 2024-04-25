package model

type WithdrawCheck struct {
	Base
	B2TxHash string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';uniqueIndex;comment:b2 network tx hash"`
}

type WithdrawCheckColumns struct {
	B2TxHash string
}

func (WithdrawCheck) TableName() string {
	return "withdraw_check"
}

func (WithdrawCheck) Column() WithdrawCheckColumns {
	return WithdrawCheckColumns{
		B2TxHash: "b2_tx_hash",
	}
}
