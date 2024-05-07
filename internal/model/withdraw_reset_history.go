package model

type WithdrawReset struct {
	Base
	RequestID string `json:"request_id" gorm:"type:varchar(256);default:'';uniqueIndex;comment:b2 network request id"`
	B2TxHash  string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';comment:b2 network tx hash"`
	Withdraw  string `json:"withdraw" gorm:"type:varchar;comment:withdraw history"`
}

type WithdrawResetColumns struct {
	RequestID string
	B2TxHash  string
	Withdraw  string
}

func (WithdrawReset) TableName() string {
	return "withdraw_reset_history"
}

func (WithdrawReset) Column() WithdrawResetColumns {
	return WithdrawResetColumns{
		RequestID: "request_id",
		B2TxHash:  "b2_tx_hash",
		Withdraw:  "withdraw",
	}
}
