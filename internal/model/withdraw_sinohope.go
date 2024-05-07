package model

type WithdrawSinohope struct {
	Base
	ApiRequestID      string `json:"api_request_id" gorm:"type:varchar(256);comment:withdraw request id"`
	B2TxHash          string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';comment:b2 network tx hash"`
	SinohopeID        string `json:"sinohope_id" gorm:"type:varchar(256)"`
	SinohopeRequestID string `json:"sinohope_request_id" gorm:"type:varchar(256)"`
	FeeRate           string `json:"fee_rate" gorm:"type:varchar(256)"`
	State             int    `json:"state" gorm:"type:smallint"`
}

type WithdrawSinohopeColumns struct {
	ApiRequestID      string
	B2TxHash          string
	SinohopeID        string
	SinohopeRequestID string
	FeeRate           string
	State             string
}

func (WithdrawSinohope) TableName() string {
	return "withdraw_sinohope"
}

func (WithdrawSinohope) Column() WithdrawSinohopeColumns {
	return WithdrawSinohopeColumns{
		ApiRequestID:      "api_request_id",
		B2TxHash:          "b2_tx_hash",
		SinohopeID:        "sinohope_id",
		SinohopeRequestID: "sinohope_request_id",
		FeeRate:           "fee_rate",
		State:             "state",
	}
}
