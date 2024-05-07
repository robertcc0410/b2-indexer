package bitcoin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/b2network/b2-indexer/internal/config"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/pkg/log"
	"github.com/cometbft/cometbft/libs/service"
	"github.com/sinohope/sinohope-golang-sdk/common"
	"github.com/sinohope/sinohope-golang-sdk/features"
	"gorm.io/gorm"
)

const (
	TransferServiceName = "BitcoinBridgeTransferService"
)

// TransferService for btc transfer
type TransferService struct {
	service.BaseService
	cfg         *config.TransferConfig
	db          *gorm.DB
	log         log.Logger
	sinohopeAPI features.TransactionAPI
	wg          sync.WaitGroup
	stopChan    chan struct{}
}

// NewTransferService returns a new service instance.
func NewTransferService(
	cfg *config.TransferConfig,
	db *gorm.DB,
	log log.Logger,
	sinohopeAPI features.TransactionAPI,
) *TransferService {
	is := &TransferService{cfg: cfg, db: db, log: log, sinohopeAPI: sinohopeAPI}
	is.BaseService = *service.NewBaseService(nil, TransferServiceName, is)

	return is
}

// OnStart implements service.Service
func (bis *TransferService) OnStart() error {
	bis.wg.Add(1)
	go bis.HandleTransfer()
	bis.stopChan = make(chan struct{})
	select {}
}

func (bis *TransferService) OnStop() {
	bis.log.Warnf("bridge transfer service stoping...")
	close(bis.stopChan)
	bis.wg.Wait()
}

func (bis *TransferService) HandleTransfer() {
	defer bis.wg.Done()
	ticker := time.NewTicker(time.Duration(bis.cfg.TimeInterval))
	for {
		select {
		case <-bis.stopChan:
			bis.log.Warnf("transfer stopping...")
			return
		case <-ticker.C:
			var withdrawList []model.Withdraw
			err := bis.db.Model(&model.Withdraw{}).
				Where(fmt.Sprintf("%s = ?", model.Withdraw{}.Column().Status), model.BtcTxWithdrawSubmit).
				Where("created_at <= ?", time.Now().Add(-time.Second*time.Duration(bis.cfg.TimeInterval))).Order(fmt.Sprintf("%s ASC, id ASC", model.Withdraw{}.Column().B2BlockNumber)).
				Limit(10).
				Find(&withdrawList).Error
			if err != nil {
				bis.log.Errorw("TransferService get withdraw List failed", "error", err)
				time.Sleep(time.Second)
				continue
			}
			if len(withdrawList) == 0 {
				time.Sleep(time.Second)
				continue
			}
			for _, v := range withdrawList {
				requestID := v.RequestID
				isOK, err := bis.QueryTransactionsByRequestIDs(requestID)
				if err != nil {
					if err.Error() != "error response, code: 2004 msg: 交易记录不存在" {
						bis.log.Errorw("TransferService QueryTransactionsByRequestIDs error", "error", err, "B2TxHash", v.B2TxHash)
						time.Sleep(time.Second)
						continue
					}
				}
				if isOK {
					continue
				}
				amount := strconv.FormatInt(v.BtcRealValue, 10)
				res, feeRate, err := bis.Transfer(requestID, v.BtcTo, amount)
				if err != nil {
					bis.log.Errorw("TransferService Transfer error", "error", err, "B2TxHash", v.B2TxHash)
					time.Sleep(time.Second)
					continue
				}

				err = bis.db.Transaction(func(tx *gorm.DB) error {
					updateFields := map[string]interface{}{
						model.Withdraw{}.Column().Status:    model.BtcTxWithdrawPending,
						model.Withdraw{}.Column().BtcTxHash: res.Transaction.TxHash,
					}
					err = tx.Model(&model.Withdraw{}).Where("id = ?", v.ID).Updates(updateFields).Error
					if err != nil {
						bis.log.Errorw("TransferService Update WithdrawTx status error", "error", err, "B2TxHash", v.B2TxHash)
						return err
					}
					withdrawSinohope := model.WithdrawSinohope{
						APIRequestID:      requestID,
						B2TxHash:          v.B2TxHash,
						SinohopeID:        res.SinoId,
						SinohopeRequestID: res.RequestId,
						FeeRate:           feeRate,
						State:             res.State,
					}
					if err := tx.Create(&withdrawSinohope).Error; err != nil {
						bis.log.Errorw("TransferService Create withdrawSinohope error", "error", err, "B2TxHash", v.B2TxHash, "SinoId", res.SinoId, "RequestId", res.RequestId)
						return err
					}

					withdrawAudit := model.WithdrawAudit{
						B2TxHash:  v.B2TxHash,
						BtcFrom:   v.BtcFrom,
						BtcTo:     v.BtcTo,
						BtcValue:  v.BtcValue,
						BtcTxHash: res.Transaction.TxHash,
						// Status: 1,
						MPCStatus: res.State,
					}
					if err := tx.Create(&withdrawAudit).Error; err != nil {
						bis.log.Errorw("TransferService Create withdrawAudit error", "error", err, "B2TxHash", v.B2TxHash, "SinoId", res.SinoId, "RequestId", res.RequestId)
						return err
					}
					return nil
				})
				if err != nil {
					bis.log.Errorw("TransferService OnStart error", "error", err)
					time.Sleep(time.Second)
				}
			}
		}
	}
}

func (bis *TransferService) Transfer(requestID string, to string, amount string) (*common.CreateSettlementTxResData, string, error) {
	fee, err := bis.sinohopeAPI.Fee(&common.WalletTransactionFeeWAASParam{
		OperationType: bis.cfg.OperationType,
		From:          bis.cfg.From,
		To:            to,
		AssetId:       bis.cfg.AssetID,
		ChainSymbol:   bis.cfg.ChainSymbol,
		Amount:        amount,
	})
	if err != nil {
		bis.log.Errorw("TransferService Transfer Fee failed", "error", err)
		return nil, "", err
	}
	bis.log.Infow("TransferService Transfer Fee", "fee", fee)
	feeRates, err := bis.GetFeeRate()
	if err != nil {
		bis.log.Errorw("TransferService Transfer GetFeeRate failed", "error", err)
		return nil, "", err
	}
	bis.log.Infow("TransferService Transfer feeRates", "feeRates", feeRates)
	feeRate := strconv.Itoa(feeRates.FastestFee)
	res, err := bis.sinohopeAPI.CreateTransfer(&common.WalletTransactionSendWAASParam{
		RequestId:   requestID,
		VaultId:     bis.cfg.VaultID,
		WalletId:    bis.cfg.WalletID,
		From:        bis.cfg.From,
		To:          to,
		ChainSymbol: bis.cfg.ChainSymbol,
		AssetId:     bis.cfg.AssetID,
		Amount:      amount,
		// Fee:         fee.TransactionFee.AverageFee,
		FeeRate: feeRate,
	})
	if err != nil {
		bis.log.Errorw("TransferService Transfer CreateTransfer failed", "error", err)
		return nil, "", err
	}

	return res, feeRate, nil
}

func (bis *TransferService) QueryTransactionsByRequestIDs(requestID string) (bool, error) {
	res, err := bis.sinohopeAPI.TransactionsByRequestIds(&common.WalletTransactionQueryWAASRequestIdParam{
		RequestIds: requestID,
	})
	if err != nil {
		bis.log.Errorw("TransferService QueryTransactionsByRequestIDs failed", "error", err)
		return false, err
	}
	if len(res.List) == 0 {
		return false, nil
	}
	return true, nil
}

func (bis *TransferService) GetMempoolURL() string {
	networkName := bis.cfg.NetworkName
	switch networkName {
	case chaincfg.MainNetParams.Name:
		return "https://mempool.space/api"
	case chaincfg.TestNet3Params.Name, "testnet":
		return "https://mempool.space/testnet/api"
	case chaincfg.SigNetParams.Name:
		return "https://mempool.space/signet/api"
	}
	return ""
}

func (bis *TransferService) GetFeeRate() (*model.FeeRates, error) {
	mempoolURL := bis.GetMempoolURL()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/fees/recommended", mempoolURL), strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var feeRates model.FeeRates
	err = json.Unmarshal(body, &feeRates)
	if err != nil {
		return nil, err
	}
	return &feeRates, nil
}
