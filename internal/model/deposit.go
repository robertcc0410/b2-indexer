package model

import (
	"time"
)

const (
	BtcTxTypeTransfer = iota // transfer
)

const (
	// b2 rollup status
	DepositB2TxStatusSuccess                    = iota // success
	DepositB2TxStatusPending                           // pending
	DepositB2TxStatusFailed                            // deposit invoke failed
	DepositB2TxStatusWaitMinedFailed                   // deposit wait mined failed
	DepositB2TxStatusTxHashExist                       // tx hash exist, deposit have been called
	DepositB2TxStatusWaitMinedStatusFailed             // deposit wait mined status failed, status != 1
	DepositB2TxStatusInsufficientBalance               // deposit insufficient balance
	DepositB2TxStatusContextDeadlineExceeded           // deposit client context deadline exceeded, Chain transaction is stuck
	DepositB2TxStatusFromAccountGasInsufficient        // deposit evm from account gas insufficient
	DepositB2TxStatusWaitMined                         // deposit wait mined
	DepositB2TxStatusAAAddressNotFound                 // aa address not found,  Start process processing separately
	DepositB2TxStatusIsPending
	DepositB2TxStatusNonceToLow
	DepositB2TxStatusWhitelistBtcAddress
)

const (
	DepositB2EoaTxStatusSuccess         = iota // eoa transfer success
	DepositB2EoaTxStatusPending                // eoa transfer pending
	DepositB2EoaTxStatusFailed                 // eoa transfer failed
	DepositB2EoaTxStatusWaitMinedFailed        // eoa transfer wait mined failed
	DepositB2EoaTxStatusWaitMined
	_
	_
	DepositB2EoaTxStatusContextDeadlineExceeded // eoa transfer client context deadline exceeded
	DepositB2EoaTxStatusUnknown
	DepositB2EoaTxStatusNonceToLow
	_
	_
	_
	DepositB2EoaStatusWhitelistBtcAddress
)

const (
	CallbackStatusSuccess = iota
	CallbackStatusPending
)

const (
	ListenerStatusSuccess = iota
	ListenerStatusPending
)

const (
	B2CheckStatusSuccess = iota
	B2CheckStatusPending
	B2CheckStatusFailed
)

type Deposit struct {
	Base
	BtcBlockNumber   int64     `json:"btc_block_number" gorm:"index;comment:bitcoin block number"`
	BtcTxIndex       int64     `json:"btc_tx_index" gorm:"comment:bitcoin tx index"`
	BtcTxHash        string    `json:"btc_tx_hash" gorm:"type:varchar(64);not null;default:'';uniqueIndex;comment:bitcoin tx hash"`
	BtcTxType        int       `json:"btc_tx_type" gorm:"type:SMALLINT;default:0;comment:btc tx type"`
	BtcFroms         string    `json:"btc_froms" gorm:"type:jsonb;comment:bitcoin transfer, from may be multiple"`
	BtcFrom          string    `json:"btc_from" gorm:"type:varchar(64);not null;default:'';index"`
	BtcTos           string    `json:"btc_tos" gorm:"type:jsonb;comment:bitcoin transfer, to may be multiple"`
	BtcTo            string    `json:"btc_to" gorm:"type:varchar(64);not null;default:'';index"`
	BtcFromAAAddress string    `json:"btc_from_aa_address" gorm:"type:varchar(42);default:'';comment:from aa address"`
	BtcValue         int64     `json:"btc_value" gorm:"default:0;comment:bitcoin transfer value"`
	B2TxFrom         string    `json:"b2_tx_from" gorm:"type:varchar(42);default:'';comment:from address"`
	B2TxHash         string    `json:"b2_tx_hash" gorm:"type:varchar(66);not null;default:'';index;comment:b2 network tx hash"`
	B2TxNonce        uint64    `json:"b2_tx_nonce" gorm:"default:0"`
	B2TxStatus       int       `json:"b2_tx_status" gorm:"type:SMALLINT;default:1"`
	B2TxRetry        int       `json:"b2_tx_retry" gorm:"type:SMALLINT;default:0"`
	B2EoaTxFrom      string    `json:"b2_eoa_tx_from" gorm:"type:varchar(42);default:'';comment:from address"`
	B2EoaTxNonce     uint64    `json:"b2_eoa_tx_nonce" gorm:"default:0"`
	B2EoaTxHash      string    `json:"b2_eoa_tx_hash" gorm:"type:varchar(66);not null;default:'';comment:b2 network eoa tx hash"`
	B2EoaTxStatus    int       `json:"b2_eoa_tx_status" gorm:"type:SMALLINT;default:1"`
	BtcBlockTime     time.Time `json:"btc_block_time"`
	CallbackStatus   int       `json:"callback_status" gorm:"type:SMALLINT;default:0"`
	ListenerStatus   int       `json:"listener_status" gorm:"type:SMALLINT;default:0"`
	B2TxCheck        int       `json:"b2_tx_check" gorm:"type:SMALLINT;default:1"`
}

type DepositColumns struct {
	BtcBlockNumber   string
	BtcTxIndex       string
	BtcTxHash        string
	BtcTxType        string
	BtcFroms         string
	BtcFrom          string
	BtcTos           string
	BtcTo            string
	BtcFromAAAddress string
	BtcValue         string
	B2TxFrom         string
	B2TxHash         string
	B2TxNonce        string
	B2TxStatus       string
	B2TxRetry        string
	B2EoaTxFrom      string
	B2EoaTxNonce     string
	B2EoaTxHash      string
	B2EoaTxStatus    string
	BtcBlockTime     string
	CallbackStatus   string
	ListenerStatus   string
	B2TxCheck        string
}

func (Deposit) TableName() string {
	return "deposit_history"
}

func (Deposit) Column() DepositColumns {
	return DepositColumns{
		BtcBlockNumber:   "btc_block_number",
		BtcTxIndex:       "btc_tx_index",
		BtcTxHash:        "btc_tx_hash",
		BtcTxType:        "btc_tx_type",
		BtcFroms:         "btc_froms",
		BtcFrom:          "btc_from",
		BtcTos:           "btc_tos",
		BtcTo:            "btc_to",
		BtcFromAAAddress: "btc_from_aa_address",
		BtcValue:         "btc_value",
		B2TxFrom:         "b2_tx_from",
		B2TxHash:         "b2_tx_hash",
		B2TxNonce:        "b2_tx_nonce",
		B2TxStatus:       "b2_tx_status",
		B2EoaTxFrom:      "b2_eoa_tx_from",
		B2EoaTxNonce:     "b2_eoa_tx_nonce",
		B2EoaTxHash:      "b2_eoa_tx_hash",
		B2EoaTxStatus:    "b2_eoa_tx_status",
		BtcBlockTime:     "btc_block_time",
		B2TxRetry:        "b2_tx_retry",
		CallbackStatus:   "callback_status",
		ListenerStatus:   "listener_status",
		B2TxCheck:        "b2_tx_check",
	}
}
