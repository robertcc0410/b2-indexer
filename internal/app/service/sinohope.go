package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	pb "github.com/b2network/b2-indexer/api/protobuf"
	"github.com/b2network/b2-indexer/api/protobuf/vo"
	"github.com/b2network/b2-indexer/internal/app/exceptions"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/pkg/log"
	sinohopeType "github.com/b2network/b2-indexer/pkg/sinohope/types"
	"github.com/b2network/b2-indexer/pkg/utils"
	"gorm.io/gorm"
)

var (
	errParamsMismatch = errors.New("req params mismatch")
	errRecordNotFound = errors.New("record not found")
)

type sinohopeServer struct {
	pb.UnimplementedSinohopeServiceServer
}

func newSinohopeServer() *sinohopeServer {
	return &sinohopeServer{}
}

func ErrorTransactionNotify(code int64, message string) *vo.TransactionNotifyResponse {
	return &vo.TransactionNotifyResponse{
		Code:    code,
		Message: message,
	}
}

func ErrorWithdrawalConfirm(code int64, message string) *vo.WithdrawalConfirmResponse {
	action := ""
	if code == exceptions.WithdrawConfirmReject {
		action = sinohopeType.WithdrawalActionReject
	}
	if code == exceptions.WithdrawConfirmRecordNotFound {
		action = sinohopeType.WithdrawalActionReject
	}
	return &vo.WithdrawalConfirmResponse{
		Code:    code,
		Message: message,
		Action:  action,
	}
}

func (s *sinohopeServer) TransactionNotify(ctx context.Context, req *vo.TransactionNotifyRequest) (*vo.TransactionNotifyResponse, error) {
	logger := log.WithName("TransactionNotify")
	logger.Infow("request data:", "req", req)
	db, err := GetDBContext(ctx)
	if err != nil {
		logger.Errorf("GetDBContext err:%v", err.Error())
		return ErrorTransactionNotify(exceptions.SystemError, "system error"), nil
	}
	listenAddress, err := GetListenAddress(ctx)
	if err != nil {
		logger.Errorf("GetListenAddress err:%v", err.Error())
		return ErrorTransactionNotify(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("listen address config:%v", listenAddress)
	httpCfg, err := GetHTTPConfig(ctx)
	if err != nil {
		logger.Errorf("GetHttpConfig err:%v", err.Error())
		return ErrorTransactionNotify(exceptions.SystemError, "system error"), nil
	}
	// check white list
	isWhiteList := false
	whiteList := httpCfg.IPWhiteList
	whiteListIP := strings.Split(whiteList, ",")
	clientIP := utils.ClientIP(ctx, logger)
	for _, ip := range whiteListIP {
		if clientIP == strings.TrimSpace(ip) {
			isWhiteList = true
		}
	}
	logger.Infof("ip:%v  white list:%v", clientIP, whiteList)
	if !isWhiteList {
		logger.Errorf("ip:%v not in white list", clientIP)
		return ErrorTransactionNotify(exceptions.IPWhiteList, "ip limit"), nil
	}
	if req.RequestType == sinohopeType.RequestTypeRecharge {
		logger.Infof("handle recharge request")
		return s.transactionNotifyRecharge(req, listenAddress, db, logger)
	} else if req.RequestType == sinohopeType.RequestTypeWithdrawal {
		logger.Infof("handle withdraw request")
		return s.transactionNotifyWithdraw(req, db, logger)
	}
	return ErrorTransactionNotify(exceptions.RequestTypeNonsupport, "request type nonsupport"), nil
}

func (s *sinohopeServer) WithdrawalConfirm(ctx context.Context, req *vo.WithdrawalConfirmRequest) (*vo.WithdrawalConfirmResponse, error) {
	logger := log.WithName("WithdrawalConfirm")
	logger.Infow("request data:", "req", req)
	db, err := GetDBContext(ctx)
	if err != nil {
		logger.Errorf("GetDBContext err:%v", err.Error())
		return ErrorWithdrawalConfirm(exceptions.SystemError, "system error"), nil
	}
	httpCfg, err := GetHTTPConfig(ctx)
	if err != nil {
		logger.Errorf("GetHttpConfig err:%v", err.Error())
		return ErrorWithdrawalConfirm(exceptions.SystemError, "system error"), nil
	}
	// check white list
	isWhiteList := false
	whiteList := httpCfg.IPWhiteList
	whiteListIP := strings.Split(whiteList, ",")
	clientIP := utils.ClientIP(ctx, logger)
	for _, ip := range whiteListIP {
		if clientIP == strings.TrimSpace(ip) {
			isWhiteList = true
		}
	}
	logger.Infof("ip:%v  white list:%v", clientIP, whiteList)
	if !isWhiteList {
		logger.Errorf("ip:%v not in white list", clientIP)
		return ErrorWithdrawalConfirm(exceptions.IPWhiteList, "ip limit"), nil
	}
	detail, err := req.RequestDetail.MarshalJSON()
	if err != nil {
		return ErrorWithdrawalConfirm(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("request detail: %s", string(detail))
	requestDetail := sinohopeType.ConfirmRequestDetail{}
	err = json.Unmarshal(detail, &requestDetail)
	if err != nil {
		logger.Errorf("request detail unmarshal err:%v", err.Error())
		return ErrorWithdrawalConfirm(exceptions.RequestDetailUnmarshal, "request detail unmarshal err"), nil
	}
	rollupTxHash := requestDetail.APIRequestID
	logger.Infof("rollupTxHash: %v", rollupTxHash)
	if requestDetail.From == "" || requestDetail.To == "" {
		logger.Errorf("request detail empty")
		return ErrorWithdrawalConfirm(exceptions.RequestDetailParameter, "request detail check err"), nil
	}
	amount, err := strconv.ParseInt(requestDetail.Amount, 10, 64)
	if err != nil {
		return ErrorWithdrawalConfirm(exceptions.RequestDetailAmount, "request detail amount "), nil
	}
	var withdraw model.Withdraw
	err = db.Transaction(func(tx *gorm.DB) error {
		err = tx.
			Set("gorm:query_option", "FOR UPDATE").
			Where(
				fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().B2TxHash),
				requestDetail.APIRequestID,
			).
			First(&withdraw).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errRecordNotFound
			}
			logger.Errorw("failed find tx from db", "error", err)
			return err
		}
		// update check fields
		if !strings.EqualFold(withdraw.BtcFrom, requestDetail.From) {
			logger.Errorf("from address not match")
			return errParamsMismatch
		}
		if !strings.EqualFold(withdraw.BtcTo, requestDetail.To) {
			logger.Errorf("to address not match")
			return errParamsMismatch
		}
		if withdraw.BtcRealValue != amount {
			logger.Errorf("amount not match")
			return errParamsMismatch
		}
		return nil
	})
	if err != nil {
		logger.Errorw("save tx result err", "err", err.Error())
		if errors.Is(err, errParamsMismatch) {
			return ErrorWithdrawalConfirm(exceptions.WithdrawConfirmReject, "Invalid parameter"), nil
		}
		if errors.Is(err, errRecordNotFound) {
			return ErrorWithdrawalConfirm(exceptions.WithdrawConfirmRecordNotFound, "record not found"), nil
		}
		return ErrorWithdrawalConfirm(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("APPROVE")
	return &vo.WithdrawalConfirmResponse{
		RequestId: req.RequestId,
		Code:      200,
		Action:    sinohopeType.WithdrawalActionApprove,
	}, nil
}

func (s *sinohopeServer) transactionNotifyRecharge(req *vo.TransactionNotifyRequest, listenAddress string, db *gorm.DB, logger log.Logger) (*vo.TransactionNotifyResponse, error) {
	detail, err := req.RequestDetail.MarshalJSON()
	if err != nil {
		return ErrorTransactionNotify(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("request detail: %s", string(detail))
	requestDetail := sinohopeType.RequestDetail{}
	err = json.Unmarshal(detail, &requestDetail)
	if err != nil {
		logger.Errorf("request detail unmarshal err:%v", err.Error())
		return ErrorTransactionNotify(exceptions.RequestDetailUnmarshal, "request detail unmarshal err"), nil
	}
	if requestDetail.From == "" || requestDetail.To == "" || requestDetail.TxHash == "" {
		logger.Errorf("request detail empty")
		return ErrorTransactionNotify(exceptions.RequestDetailParameter, "request detail check err"), nil
	}
	if requestDetail.To != listenAddress {
		logger.Errorf("request detail to address not eq listen address")
		return ErrorTransactionNotify(exceptions.RequestDetailToMismatch, "request detail to mismatch"), nil
	}
	amount, err := strconv.ParseInt(requestDetail.Amount, 10, 64)
	if err != nil {
		return ErrorTransactionNotify(exceptions.RequestDetailAmount, "request detail amount fail"), nil
	}
	var deposit model.Deposit
	var sinohope model.Sinohope
	err = db.Transaction(func(tx *gorm.DB) error {
		err = tx.
			Where(
				fmt.Sprintf("%s.%s = ?", model.Sinohope{}.TableName(), model.Sinohope{}.Column().RequestID),
				req.RequestId,
			).
			First(&sinohope).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				sinohope = model.Sinohope{
					RequestID:     req.RequestId,
					RequestType:   int(req.RequestType),
					RequestDetail: string(detail),
				}
				err = tx.Save(&sinohope).Error
				if err != nil {
					logger.Errorw("failed to save tx result", "error", err)
					return err
				}
			} else {
				logger.Errorw("failed find tx from db", "error", err)
				return err
			}
		}

		err = tx.
			Where(
				fmt.Sprintf("%s.%s = ?", model.Deposit{}.TableName(), model.Deposit{}.Column().BtcTxHash),
				requestDetail.TxHash,
			).
			First(&deposit).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				deposit := model.Deposit{
					BtcTxHash:      requestDetail.TxHash,
					BtcFrom:        requestDetail.From,
					BtcTos:         string("{}"),
					BtcTo:          requestDetail.To,
					BtcValue:       amount,
					BtcFroms:       string("{}"),
					B2TxStatus:     model.DepositB2TxStatusPending,
					CallbackStatus: model.CallbackStatusSuccess,
					ListenerStatus: model.ListenerStatusPending,
				}
				err = tx.Create(&deposit).Error
				if err != nil {
					logger.Errorw("failed to save tx result", "error", err)
					return err
				}
			} else {
				logger.Errorw("failed find tx from db", "error", err)
				return err
			}
		} else {
			// update check fields
			if !strings.EqualFold(deposit.BtcFrom, requestDetail.From) {
				return errors.New("from address not match")
			}
			if !strings.EqualFold(deposit.BtcTo, requestDetail.To) {
				return errors.New("to address not match")
			}
			if deposit.BtcValue != amount {
				return errors.New("amount not match")
			}
			updateFields := map[string]interface{}{
				model.Deposit{}.Column().CallbackStatus: model.CallbackStatusSuccess,
			}
			err = tx.Model(&model.Deposit{}).Where("id = ?", deposit.ID).Updates(updateFields).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		logger.Errorw("save tx result err", "err", err.Error())
		return ErrorTransactionNotify(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("recharge notify success")
	return &vo.TransactionNotifyResponse{
		RequestId: req.RequestId,
		Code:      200,
	}, nil
}

func (s *sinohopeServer) transactionNotifyWithdraw(req *vo.TransactionNotifyRequest, db *gorm.DB, logger log.Logger) (*vo.TransactionNotifyResponse, error) {
	detail, err := req.RequestDetail.MarshalJSON()
	if err != nil {
		return ErrorTransactionNotify(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("request detail: %s", string(detail))
	requestDetail := sinohopeType.WithdrawNotifyRequestDetail{}
	err = json.Unmarshal(detail, &requestDetail)
	if err != nil {
		logger.Errorf("request detail unmarshal err:%v", err.Error())
		return ErrorTransactionNotify(exceptions.RequestDetailUnmarshal, "request detail unmarshal err"), nil
	}
	apiRequestID := requestDetail.APIRequestID
	if has0xPrefix(requestDetail.APIRequestID) {
		apiRequestID = apiRequestID[2:]
	}
	if requestDetail.From == "" || requestDetail.To == "" {
		logger.Errorf("request detail empty")
		return ErrorTransactionNotify(exceptions.RequestDetailParameter, "request detail check err"), nil
	}
	amount, err := strconv.ParseInt(requestDetail.Amount, 10, 64)
	if err != nil {
		return ErrorTransactionNotify(exceptions.RequestDetailAmount, "request detail amount fail"), nil
	}
	var withdraw model.Withdraw
	var sinohope model.Sinohope
	err = db.Transaction(func(tx *gorm.DB) error {
		err = tx.
			Where(
				fmt.Sprintf("%s.%s = ?", model.Sinohope{}.TableName(), model.Sinohope{}.Column().RequestID),
				apiRequestID,
			).
			First(&sinohope).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				sinohope = model.Sinohope{
					RequestID:     apiRequestID,
					RequestType:   int(req.RequestType),
					RequestDetail: string(detail),
				}
				err = tx.Save(&sinohope).Error
				if err != nil {
					logger.Errorw("failed to save tx result", "error", err)
					return err
				}
			} else {
				logger.Errorw("failed find tx from db", "error", err)
				return err
			}
		}

		err = tx.
			Set("gorm:query_option", "FOR UPDATE").
			Where(
				fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().B2TxHash),
				requestDetail.APIRequestID,
			).
			First(&withdraw).Error
		if err != nil {
			logger.Errorw("failed find tx from db", "error", err)
			return err
		}
		logger.Infow("query withdraw detail", "withdraw", withdraw)
		// update check fields
		if !strings.EqualFold(withdraw.BtcFrom, requestDetail.From) {
			return errors.New("from address not match")
		}
		if !strings.EqualFold(withdraw.BtcTo, requestDetail.To) {
			return errors.New("to address not match")
		}
		if withdraw.BtcRealValue != amount {
			return errors.New("amount not match")
		}
		// success
		if requestDetail.State == 10 {
			updateFields := map[string]interface{}{
				model.Withdraw{}.Column().Status:    model.BtcTxWithdrawSinohopeSuccess,
				model.Withdraw{}.Column().BtcTxHash: requestDetail.TxHash,
			}
			err = tx.Model(&model.Withdraw{}).Where("id = ?", withdraw.ID).Updates(updateFields).Error
			if err != nil {
				return err
			}
		} else {
			updateFields := map[string]interface{}{
				model.Withdraw{}.Column().Status: model.BtcTxWithdrawFailed,
			}
			err = tx.Model(&model.Withdraw{}).Where("id = ?", withdraw.ID).Updates(updateFields).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		logger.Errorw("save tx result err", "err", err.Error())
		return ErrorTransactionNotify(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("withdraw notify success")
	return &vo.TransactionNotifyResponse{
		RequestId: req.RequestId,
		Code:      200,
	}, nil
}

func has0xPrefix(input string) bool {
	return len(input) >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')
}
