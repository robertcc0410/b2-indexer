package bitcoin

import (
	"fmt"
	"github.com/b2network/b2-indexer/internal/config"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/pkg/log"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/cometbft/cometbft/libs/service"
	"gorm.io/gorm"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	BridgeWithdrawServiceName = "BitcoinBridgeWithdrawService"
	WithdrawHandleTime        = 10
	WithdrawTXConfirmTime     = 60 * 5
)

// BridgeWithdrawService indexes transactions for json-rpc service.
type BridgeWithdrawService struct {
	service.BaseService

	btcCli *rpcclient.Client
	ethCli *ethclient.Client
	config *config.BitcoinConfig
	db     *gorm.DB
	log    log.Logger
}

// NewBridgeWithdrawService returns a new service instance.
func NewBridgeWithdrawService(
	btcCli *rpcclient.Client,
	ethCli *ethclient.Client,
	config *config.BitcoinConfig,
	db *gorm.DB,
	log log.Logger,
) *BridgeWithdrawService {
	is := &BridgeWithdrawService{btcCli: btcCli, ethCli: ethCli, config: config, db: db, log: log}
	is.BaseService = *service.NewBaseService(nil, BridgeWithdrawServiceName, is)
	return is
}

// OnStart implements service.Service
func (bis *BridgeWithdrawService) OnStart() error {
	if !bis.db.Migrator().HasTable(&model.Withdraw{}) {
		err := bis.db.AutoMigrate(&model.Withdraw{})
		if err != nil {
			bis.log.Errorw("BridgeWithdrawService create withdraw table", "error", err.Error())
			return err
		}
	}
	for {
		// confirm tx
		var withdrawList []model.Withdraw
		err := bis.db.Model(&model.Withdraw{}).Where(fmt.Sprintf("%s = ?", model.Withdraw{}.Column().Status), model.BtcTxWithdrawPending).Find(&withdrawList).Error
		if err != nil {
			bis.log.Errorw("BridgeWithdrawService get broadcast tx failed", "error", err)
			time.Sleep(time.Duration(WithdrawHandleTime) * time.Second)
			continue
		}
		if len(withdrawList) == 0 {
			time.Sleep(time.Duration(WithdrawHandleTime) * time.Second)
			continue
		}
		for _, v := range withdrawList {
			txHash, err := chainhash.NewHashFromStr(v.BtcTxHash)
			if err != nil {
				bis.log.Errorw("BridgeWithdrawService NewHashFromStr err", "error", err, "txhash", v.BtcTxHash)
				time.Sleep(time.Duration(WithdrawHandleTime) * time.Second)
				continue
			}
			txRawResult, err := bis.btcCli.GetRawTransactionVerbose(txHash)
			if err != nil {
				bis.log.Errorw("BridgeWithdrawService GetRawTransactionVerbose err", "error", err, "b2TxHash", v.B2TxHash)
				time.Sleep(time.Duration(WithdrawHandleTime) * time.Second)
				continue
			}
			if txRawResult.Confirmations >= 6 {
				err = bis.db.Model(&model.Withdraw{}).Where("id = ?", v.ID).Update(model.Withdraw{}.Column().Status, model.BtcTxWithdrawSuccess).Error
				if err != nil {
					bis.log.Errorw("BridgeWithdrawService Update WithdrawTx status err", "error", err, "b2TxHash", v.B2TxHash)
					time.Sleep(time.Duration(WithdrawHandleTime) * time.Second)
					continue
				}
			}
			time.Sleep(time.Duration(WithdrawTXConfirmTime) * time.Second)
		}
	}
}
