package model

const (
	ResetTypeReset   = 0
	ResetTypeSpeedup = 1
)

type WithdrawReset struct {
	Base
	RequestID string `json:"request_id" gorm:"type:varchar(256);default:'';uniqueIndex;comment:b2 network request id"`
	ResetType int    `json:"reset_type" gorm:"type:SMALLINT;default:0"`
	B2TxHash  string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';comment:b2 network tx hash"`
	Withdraw  string `json:"withdraw" gorm:"type:jsonb;comment:withdraw history"`
	Sinohope  string `json:"sinohope" gorm:"type:jsonb;comment:sinohope history"`
}

type WithdrawResetColumns struct {
	RequestID string
	ResetType string
	B2TxHash  string
	Withdraw  string
	Sinohope  string
}

func (WithdrawReset) TableName() string {
	return "withdraw_reset_history"
}

func (WithdrawReset) Column() WithdrawResetColumns {
	return WithdrawResetColumns{
		RequestID: "request_id",
		ResetType: "reset_type",
		B2TxHash:  "b2_tx_hash",
		Withdraw:  "withdraw",
		Sinohope:  "sinohope",
	}
}
