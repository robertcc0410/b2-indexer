package model

// first audit
const (
	WithdrawAuditStatusPending = iota + 1
	WithdrawAuditStatusApprove
	WithdrawAuditStatusReject
)

// second audit
const (
	WithdrawAuditMPCStatusWait = iota + 1
	WithdrawAuditMPCStatusApprove
	WithdrawAuditMPCStatusReject
)

type WithdrawAudit struct {
	Base
	B2TxHash  string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';comment:b2 network tx hash"`
	BtcFrom   string `json:"btc_from" gorm:"type:varchar(256);default:'';index"`
	BtcTo     string `json:"btc_to" gorm:"type:varchar(256);default:'';index"`
	BtcValue  int64  `json:"btc_value" gorm:"type:bigint;default:0;comment:bitcoin transfer value"`
	BtcTxHash string `json:"btc_tx_hash" gorm:"type:varchar(256);default:'';comment:bitcoin tx hash"`
	Status    int    `json:"status" gorm:"type:smallint;default:1"`
	MPCStatus int    `json:"mpc_status" gorm:"type:smallint;default:1"`
}

type WithdrawAuditColumns struct {
	B2TxHash  string
	BtcFrom   string
	BtcTo     string
	BtcValue  string
	BtcTxHash string
	Status    string
	MPCStatus string
}

func (WithdrawAudit) TableName() string {
	return "withdraw_audit"
}

func (WithdrawAudit) Column() WithdrawAuditColumns {
	return WithdrawAuditColumns{
		B2TxHash:  "b2_tx_hash",
		BtcFrom:   "btc_from",
		BtcTo:     "btc_to",
		BtcValue:  "btc_value",
		BtcTxHash: "btc_tx_hash",
		Status:    "status",
		MPCStatus: "mpc_status",
	}
}
