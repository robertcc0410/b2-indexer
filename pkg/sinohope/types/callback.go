//go:build !lint
// +build !lint

package types

const (
	RequestTypeWithdrawal = 0
	RequestTypeRecharge   = 1
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

type MpcCheckRequestDetail struct {
	T            int      `json:"t,omitempty"`
	N            int      `json:"n,omitempty"`
	Cryptography string   `json:"cryptography,omitempty"`
	PartyIds     []string `json:"party_ids,omitempty"`

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
	SinoId    string `json:"sino_id,omitempty"`
	RequestId string `json:"request_id,omitempty"`
}
