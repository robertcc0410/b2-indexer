package model

type WithdrawRecord struct {
	Base
	WithdrawID int64  `json:"withdraw_id" gorm:"type:bigint;comment:withdraw id"`
	RequestID  string `json:"request_id" gorm:"type:varchar(256);comment:withdraw request id"`
	B2TxHash   string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';comment:b2 network tx hash"`
	B2TxIndex  uint   `json:"b2_tx_index" gorm:"type:bigint;comment:b2 tx index"`
	B2LogIndex uint   `json:"b2_log_index" gorm:"type:int;comment:b2 log index"`
	BtcFrom    string `json:"btc_from" gorm:"type:varchar(256);default:'';index"`
	BtcTo      string `json:"btc_to" gorm:"type:varchar(256);default:'';index"`
	BtcValue   int64  `json:"btc_value" gorm:"type:bigint;default:0;comment:bitcoin transfer value"`
}

type WithdrawRecordColumns struct {
	WithdrawID string
	RequestID  string
	B2TxHash   string
	B2TxIndex  string
	B2LogIndex string
	BtcFrom    string
	BtcTo      string
	BtcValue   string
}

func (WithdrawRecord) TableName() string {
	return "withdraw_record"
}

func (WithdrawRecord) Column() WithdrawRecordColumns {
	return WithdrawRecordColumns{
		WithdrawID: "withdraw_id",
		RequestID:  "request_id",
		B2TxHash:   "b2_tx_hash",
		B2TxIndex:  "b2_tx_index",
		B2LogIndex: "b2_log_index",
		BtcFrom:    "btc_from",
		BtcTo:      "btc_to",
		BtcValue:   "btc_value",
	}
}
