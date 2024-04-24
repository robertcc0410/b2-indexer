package model

type WithdrawSinohope struct {
	Base
	B2TxHash  string `json:"b2_tx_hash" gorm:"type:varchar(256);default:'';uniqueIndex;comment:b2 network tx hash"`
	SinoId    string `json:"sinoId" gorm:"type:varchar(256)"`
	RequestId string `json:"requestId" gorm:"type:varchar(256)"`
	State     int    `json:"state" gorm:"type:smallint"`
}

type WithdrawSinohopeColumns struct {
	B2TxHash  string
	SinoId    string
	RequestId string
	State     string
}

func (WithdrawSinohope) TableName() string {
	return "withdraw_sinohope"
}

func (WithdrawSinohope) Column() WithdrawSinohopeColumns {
	return WithdrawSinohopeColumns{
		B2TxHash:  "b2_tx_hash",
		SinoId:    "sino_id",
		RequestId: "request_id",
		State:     "state",
	}
}
