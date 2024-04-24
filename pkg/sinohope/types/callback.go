package types

import "encoding/json"

const (
	RequestTypeWithdrawal = 0
	RequestTypeRecharge   = 1
)

const (
	MpcCheckActionApprove = "Approve"
	MpcCheckActionReject  = "Reject"
	MpcCheckActionWait    = "Wait"
)

const (
	WithdrawalActionApprove = "APPROVE"
	WithdrawalActionReject  = "REJECT"
)

type TransactionNotify struct {
	RequestType   int    `json:"requestType"`
	RequestID     string `json:"requestId"`
	RequestDetail any    `json:"requestDetail"`
	ExtraInfo     string `json:"extraInfo"`
}

type RequestDetail struct {
	SinoID          string `json:"sinoId"`
	TxHash          string `json:"txHash"`
	BlockHash       string `json:"blockHash"`
	ConfirmNumber   int    `json:"confirmNumber"`
	WalletID        string `json:"walletId"`
	ChainSymbol     string `json:"chainSymbol"`
	AssetID         string `json:"assetId"`
	TxDirection     int    `json:"txDirection"`
	Note            string `json:"note"`
	Nonce           int    `json:"nonce"`
	From            string `json:"from"`
	To              string `json:"to"`
	ToTag           string `json:"toTag"`
	Amount          string `json:"amount"`
	Decimal         int    `json:"decimal"`
	Fee             string `json:"fee"`
	FeeAsset        string `json:"feeAsset"`
	FeeDecimal      int    `json:"feeDecimal"`
	FeeAssetDecimal int    `json:"feeAssetDecimal"`
	UsedFee         string `json:"usedFee"`
	GasPrice        string `json:"gasPrice"`
	GasLimit        string `json:"gasLimit"`
	State           int    `json:"state"`
}

type MpcCheckVerifyRequest struct {
	CallbackID                  string `json:"callback_id,omitempty"`
	RequestType                 string `json:"request_type,omitempty"`
	MpcCheckVerifyRequestDetail `json:"request_detail,omitempty"`
	MpcCheckExtraInfo           `json:"extra_info,omitempty"`
}

type MpcCheckVerifyRequestDetail struct {
	T            int      `json:"t,omitempty"`
	N            int      `json:"n,omitempty"`
	Cryptography string   `json:"cryptography,omitempty"`
	PartyIDs     []string `json:"party_ids,omitempty"`

	SignType  string          `json:"sign_type,omitempty" form:"sign_type"`
	PublicKey string          `json:"public_key,omitempty"`
	Path      string          `json:"path,omitempty"`
	Message   string          `json:"message,omitempty"`
	Signature string          `json:"signature,omitempty"`
	TxInfo    json.RawMessage `json:"tx_info,omitempty" form:"tx_info"`
}

type MpcCheckRequestDetail struct {
	T            int      `json:"t,omitempty"`
	N            int      `json:"n,omitempty"`
	Cryptography string   `json:"cryptography,omitempty"`
	PartyIDs     []string `json:"party_ids,omitempty"`

	SignType string          `json:"sign_type,omitempty" form:"sign_type"`
	TxInfo   json.RawMessage `json:"tx_info,omitempty" form:"tx_info"`

	PublicKey   string `json:"public_key,omitempty"`
	Path        string `json:"path,omitempty"`
	Message     string `json:"message,omitempty"`
	Coin        string `json:"coin,omitempty"`
	FromAddress string `json:"from_address,omitempty"`
	ToAddress   string `json:"to_address,omitempty"`
	Amount      string `json:"amount,omitempty"`
	Fee         string `json:"fee,omitempty"`
	GasPrice    string `json:"gas_price,omitempty"`
	GasLimit    string `json:"gas_limit,omitempty"`
	Signature   string `json:"signature,omitempty"`
}

type MpcCheckExtraInfo struct {
	SinoID    string `json:"sino_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

type MpcCheckResponseData struct {
	CallbackID string `json:"callback_id,omitempty"`
	SinoID     string `json:"sino_id,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Action     string `json:"action,omitempty"`
	WaitTime   string `json:"wait_time,omitempty"`
}

type ConfirmRequestDetail struct {
	Amount       string   `json:"amount"`
	APIRequestID string   `json:"apiRequestId"`
	AssetID      string   `json:"assetId"`
	Brc20Detail  struct{} `json:"brc20Detail"`
	ChainSymbol  string   `json:"chainSymbol"`
	Decimal      int      `json:"decimal"`
	Fee          string   `json:"fee"`
	From         string   `json:"from"`
	GasLimit     string   `json:"gasLimit"`
	GasPrice     string   `json:"gasPrice"`
	Note         string   `json:"note"`
	SinoID       string   `json:"sinoId"`
	To           string   `json:"to"`
	ToTag        string   `json:"toTag"`
	WalletID     string   `json:"walletId"`
}
