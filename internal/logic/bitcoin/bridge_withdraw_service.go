package bitcoin

import (
	"fmt"
	"sync"
	"time"

	"github.com/b2network/b2-indexer/internal/config"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/pkg/log"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/cometbft/cometbft/libs/service"
	"gorm.io/gorm"

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

	btcCli   *rpcclient.Client
	ethCli   *ethclient.Client
	config   *config.BitcoinConfig
	db       *gorm.DB
	auditDB  *gorm.DB
	log      log.Logger
	wg       sync.WaitGroup
	stopChan chan struct{}
}

// NewBridgeWithdrawService returns a new service instance.
func NewBridgeWithdrawService(
	btcCli *rpcclient.Client,
	ethCli *ethclient.Client,
	config *config.BitcoinConfig,
	db *gorm.DB,
	auditDB *gorm.DB,
	log log.Logger,
) *BridgeWithdrawService {
	is := &BridgeWithdrawService{btcCli: btcCli, ethCli: ethCli, config: config, db: db, auditDB: auditDB, log: log}
	is.BaseService = *service.NewBaseService(nil, BridgeWithdrawServiceName, is)
	return is
}

// OnStart implements service.Service
func (bis *BridgeWithdrawService) OnStart() error {
	bis.wg.Add(1)
	go bis.HandleWithdraw()
	bis.stopChan = make(chan struct{})
	select {}
}

func (bis *BridgeWithdrawService) OnStop() {
	bis.log.Warnf("bridge transfer service stoping...")
	close(bis.stopChan)
	bis.wg.Wait()
}

// OnStart implements service.Service
func (bis *BridgeWithdrawService) HandleWithdraw() {
	defer bis.wg.Done()
	if !bis.db.Migrator().HasTable(&model.Withdraw{}) {
		err := bis.db.AutoMigrate(&model.Withdraw{})
		if err != nil {
			bis.log.Errorw("BridgeWithdrawService create withdraw table", "error", err.Error())
			return
		}
	}
	if !bis.db.Migrator().HasTable(&model.WithdrawSinohope{}) {
		err := bis.db.AutoMigrate(&model.WithdrawSinohope{})
		if err != nil {
			bis.log.Errorw("BridgeWithdrawService create withdraw_sinohope table", "error", err.Error())
			return
		}
	}
	if !bis.auditDB.Migrator().HasTable(&model.WithdrawAudit{}) {
		err := bis.auditDB.AutoMigrate(&model.WithdrawAudit{})
		if err != nil {
			bis.log.Errorw("BridgeWithdrawService create withdraw_audit table", "error", err.Error())
			return
		}
	}
	ticker := time.NewTicker(time.Duration(WithdrawHandleTime) * time.Second)
	for {
		select {
		case <-bis.stopChan:
			bis.log.Warnf("withdraw confirm stopping...")
			return
		case <-ticker.C:
			// confirm tx
			var withdrawList []model.Withdraw
			err := bis.db.Model(&model.Withdraw{}).
				Where(fmt.Sprintf("%s = ? and btc_tx_hash != ?", model.Withdraw{}.Column().Status), model.BtcTxWithdrawSinohopeSuccess, "").
				Limit(10).Find(&withdrawList).Error
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
					bis.log.Errorw("BridgeWithdrawService NewHashFromStr err", "error", err, "BtcTxHash", v.BtcTxHash)
					time.Sleep(time.Duration(WithdrawHandleTime) * time.Second)
					continue
				}
				txRawResult, err := bis.btcCli.GetRawTransactionVerbose(txHash)
				if err != nil {
					bis.log.Errorw("BridgeWithdrawService GetRawTransactionVerbose err", "error", err, "BtcTxHash", v.BtcTxHash)
					time.Sleep(time.Duration(WithdrawHandleTime) * time.Second)
					continue
				}
				if txRawResult.Confirmations >= uint64(bis.config.Bridge.ConfirmHeight) {
					bis.log.Infow("BridgeWithdrawService Update WithdrawTx status success", "b2TxHash", v.B2TxHash)
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
}
