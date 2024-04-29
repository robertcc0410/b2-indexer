package model

// tx status sequence
// 1.1 BtcTxWithdrawSubmit
// 1.2 BtcTxWithdrawPending
// 1.3 BtcTxWithdrawSuccess/BtcTxWithdrawFailed
const (
	BtcTxWithdrawSubmit          = "submit"
	BtcTxWithdrawPending         = "pending"
	BtcTxWithdrawSinohopeSuccess = "sinohope_success"
	BtcTxWithdrawSuccess         = "success"
	BtcTxWithdrawFailed          = "failed"
)

// btc tx check status sequence
const (
	BtcTxWithdrawSinohopeCallback = iota + 1
	BtcTxWithdrawMPCCallback
)

type Withdraw struct {
	Base
	UUID          string `json:"uuid" gorm:"type:varchar(256);default:'';uniqueIndex;comment:b2 network withdraw_uuid"`
	BtcFrom       string `json:"btc_from" gorm:"type:varchar(256);default:'';index"`
	BtcTo         string `json:"btc_to" gorm:"type:varchar(256);default:'';index"`
	BtcValue      int64  `json:"btc_value" gorm:"type:bigint;default:0;comment:bitcoin transfer value"`
	BtcRealValue  int64  `json:"btc_real_value" gorm:"type:bigint;default:0;comment:bitcoin transfer real value"`
	BtcTxHash     string `json:"btc_tx_hash" gorm:"type:varchar(256);default:'';comment:bitcoin tx hash"`
	B2BlockNumber uint64 `json:"b2_block_number" gorm:"type:bigint;comment:b2 block number"`
	B2BlockHash   string `json:"b2_block_hash" gorm:"type:varchar(256);comment:b2 block hash"`
	B2TxFrom      string `json:"b2_tx_from" gorm:"type:varchar(256);comment:b2 tx from"`
	B2TxHash      string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';uniqueIndex;comment:b2 network tx hash"`
	B2TxIndex     uint   `json:"b2_tx_index" gorm:"type:bigint;comment:b2 tx index"`
	B2LogIndex    uint   `json:"b2_log_index" gorm:"type:int;comment:b2 log index"`
	RefundTxHash  string `json:"refund_tx_hash" gorm:"type:varchar(256);default:'';comment:bitcoin refund tx hash"`
	Status        string `json:"status" gorm:"type:varchar(64);default:1"`
	AuditStatus   string `json:"audit_status" gorm:"type:varchar(64);default:0"`
}

type FeeRates struct {
	FastestFee  int `json:"fastestFee"`
	HalfHourFee int `json:"halfHourFee"`
	HourFee     int `json:"hourFee"`
	EconomyFee  int `json:"economyFee"`
	MinimumFee  int `json:"minimumFee"`
}

type WithdrawColumns struct {
	BtcTxHash     string
	BtcFrom       string
	BtcTo         string
	BtcValue      string
	B2TxHash      string
	B2BlockNumber string
	B2LogIndex    string
	Status        string
	RefundTxHash  string
	AuditStatus   string
	B2TxFrom      string
	BtcRealValue  string
	UUID          string
	B2TxIndex     string
	B2BlockHash   string
}

func (Withdraw) TableName() string {
	return "withdraw_history"
}

func (Withdraw) Column() WithdrawColumns {
	return WithdrawColumns{
		BtcTxHash:     "btc_tx_hash",
		BtcFrom:       "btc_from",
		BtcTo:         "btc_to",
		BtcValue:      "btc_value",
		B2TxHash:      "b2_tx_hash",
		B2BlockNumber: "b2_block_number",
		B2LogIndex:    "b2_log_index",
		Status:        "status",
		AuditStatus:   "audit_status",
		RefundTxHash:  "refund_tx_hash",
		B2TxFrom:      "b2_tx_from",
		BtcRealValue:  "btc_real_value",
		UUID:          "uuid",
		B2TxIndex:     "b2_tx_index",
		B2BlockHash:   "b2_block_hash",
	}
}
