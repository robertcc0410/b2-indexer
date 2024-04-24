package bitcoin

import (
	"fmt"
	"github.com/b2network/b2-indexer/internal/config"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/pkg/log"
	"github.com/cometbft/cometbft/libs/service"
	"github.com/sinohope/sinohope-golang-sdk/common"
	"github.com/sinohope/sinohope-golang-sdk/features"
	"gorm.io/gorm"
	"strconv"
	"time"
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
	for {
		var withdrawList []model.Withdraw
		err := bis.db.Model(&model.Withdraw{}).
			Where(fmt.Sprintf("%s = ?", model.Withdraw{}.Column().Status), model.BtcTxWithdrawSubmit).
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
			isOK, err := bis.QueryTransactionsByRequestIds(v.B2TxHash)
			if err != nil {
				bis.log.Errorw("TransferService QueryTransactionsByRequestIds error", "error", err, "B2TxHash", v.B2TxHash)
				time.Sleep(time.Second)
				continue
			}
			if isOK {
				return nil
			}
			res, err := bis.Transfer(v.B2TxHash, v.BtcTo, strconv.FormatInt(v.BtcValue, 10))
			if err != nil {
				bis.log.Errorw("TransferService Transfer error", "error", err, "B2TxHash", v.B2TxHash)
				time.Sleep(time.Second)
				continue
			}

			updateFields := map[string]interface{}{
				model.Withdraw{}.Column().Status:    model.BtcTxWithdrawPending,
				model.Withdraw{}.Column().BtcTxHash: res.Transaction.TxHash,
			}
			err = bis.db.Model(&model.Withdraw{}).Where("id = ?", v.ID).Updates(updateFields).Error
			if err != nil {
				bis.log.Errorw("TransferService Update WithdrawTx status error", "error", err, "B2TxHash", v.B2TxHash)
				time.Sleep(time.Second)
				continue
			}
		}
	}
}

func (bis *TransferService) Transfer(requestId string, to string, amount string) (*common.CreateSettlementTxResData, error) {
	fee, err := bis.sinohopeAPI.Fee(&common.WalletTransactionFeeWAASParam{
		OperationType: bis.cfg.OperationType,
		From:          bis.cfg.From,
		To:            to,
		AssetId:       bis.cfg.AssetId,
		ChainSymbol:   bis.cfg.ChainSymbol,
		Amount:        amount,
	})
	if err != nil {
		bis.log.Errorw("TransferService Transfer Fee failed", "error", err)
		return nil, err
	}
	res, err := bis.sinohopeAPI.CreateTransfer(&common.WalletTransactionSendWAASParam{
		RequestId:   requestId,
		VaultId:     bis.cfg.VaultId,
		WalletId:    bis.cfg.WalletId,
		From:        bis.cfg.From,
		To:          to,
		ChainSymbol: bis.cfg.ChainSymbol,
		AssetId:     bis.cfg.AssetId,
		Amount:      amount,
		Fee:         fee.TransactionFee.AverageFee,
		FeeRate:     bis.cfg.FeeRate,
		Note:        bis.cfg.Note,
	})
	if err != nil {
		bis.log.Errorw("TransferService Transfer CreateTransfer failed", "error", err)
		return nil, err
	}

	return res, nil
}

func (bis *TransferService) QueryTransactionsByRequestIds(requestId string) (bool, error) {
	res, err := bis.sinohopeAPI.TransactionsByRequestIds(&common.WalletTransactionQueryWAASRequestIdParam{
		RequestIds: requestId,
	})
	if err != nil {
		bis.log.Errorw("TransferService QueryTransactionsByRequestIds failed", "error", err)
		return false, err
	}
	if len(res.List) == 0 {
		return false, nil
	}
	return true, nil
}
