package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	pb "github.com/b2network/b2-indexer/api/protobuf"
	"github.com/b2network/b2-indexer/api/protobuf/vo"
	"github.com/b2network/b2-indexer/internal/app/exceptions"
	"github.com/b2network/b2-indexer/internal/config"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/pkg/log"
	"github.com/b2network/b2-indexer/pkg/sinohope"
	"github.com/b2network/b2-indexer/pkg/sinohope/mpc"
	sinohopeType "github.com/b2network/b2-indexer/pkg/sinohope/types"
	"github.com/b2network/b2-indexer/pkg/utils"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"
)

type mpcServer struct {
	pb.UnimplementedMpcServiceServer
	mpcCallbackPrivateKey *ecdsa.PrivateKey
	mpcNodePublicKey      *ecdsa.PublicKey
}

func newMpcServer(cfg *config.HTTPConfig) *mpcServer {
	if !cfg.EnableMPCCallback {
		return &mpcServer{}
	}
	tssNodePublicKey, err := mpc.LoadTSSNodePublicKey(cfg.Mpc.MpcNodePublicKey)
	if err != nil {
		panic(fmt.Sprintf("load mpc-node public key failed, %v", err))
	}

	if cfg.Mpc.EnableVSM {
		callbackKeyHex, err := sinohope.DecryptKey(cfg.Mpc.CallbackPrivateKey, cfg.Mpc.LocalDecryptKey, cfg.Mpc.VSMIv, cfg.Mpc.VSMInternalKeyIndex)
		if err != nil {
			panic(fmt.Sprintf("decode private key failed, %v", err))
		}
		private, _, err := mpc.LoadHexKeypair(callbackKeyHex)
		if err != nil {
			panic(fmt.Sprintf("load private hex key failed, %v", err))
		}
		return &mpcServer{
			mpcCallbackPrivateKey: private,
			mpcNodePublicKey:      tssNodePublicKey,
		}
	}
	private, _, err := mpc.LoadKeypair(cfg.Mpc.CallbackPrivateKey)
	if err != nil {
		panic(fmt.Sprintf("load private key failed, %v", err))
	}

	return &mpcServer{
		mpcCallbackPrivateKey: private,
		mpcNodePublicKey:      tssNodePublicKey,
	}
}

func (s *mpcServer) ErrorMpcCheck(status int64, error string, rsp sinohopeType.MpcCheckResponseData) *vo.MpcCheckResponse {
	// sign msg
	message, err := json.Marshal(rsp)
	if err != nil {
		return &vo.MpcCheckResponse{
			Status: strconv.Itoa(int(status)),
			Error:  error,
		}
	}
	sig, err := mpc.Sign(s.mpcCallbackPrivateKey, hex.EncodeToString(message))
	if err != nil {
		return &vo.MpcCheckResponse{
			Status: strconv.Itoa(int(status)),
			Error:  error,
		}
	}

	switch status {
	case exceptions.WithdrawMpcReject:
		rspData, _ := structpb.NewStruct(map[string]interface{}{
			"action":      sinohopeType.MpcCheckActionReject,
			"callback_id": rsp.CallbackID,
		})
		return &vo.MpcCheckResponse{
			Status:    strconv.Itoa(int(status)),
			Error:     error,
			Data:      rspData,
			Signature: sig,
		}
	default:
		rspData, _ := structpb.NewStruct(map[string]interface{}{
			"callback_id": rsp.CallbackID,
			"action":      sinohopeType.MpcCheckActionWait,
			"wait_time":   "60",
		})
		return &vo.MpcCheckResponse{
			Status: strconv.Itoa(int(status)),
			Error:  error,
			Data:   rspData,
		}
	}
}

func (s *mpcServer) MpcCheck(ctx context.Context, req *vo.MpcCheckRequest) (*vo.MpcCheckResponse, error) {
	logger := log.WithName("MpcCheck")
	logger.Infow("request data:", "req", req)
	// response data struct
	responseData := sinohopeType.MpcCheckResponseData{
		CallbackID: req.CallbackId,
	}
	httpCfg, err := GetHTTPConfig(ctx)
	if err != nil {
		logger.Errorf("GetHttpConfig err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}
	if !httpCfg.EnableMPCCallback {
		return s.ErrorMpcCheck(exceptions.SystemError, "api disable", responseData), nil
	}

	db, err := GetDBContext(ctx)
	if err != nil {
		logger.Errorf("GetDBContext err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}

	detail, err := req.RequestDetail.MarshalJSON()
	if err != nil {
		logger.Errorf("RequestDetail.MarshalJSON err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}

	logger.Infof("request detail: %s", string(detail))
	requestDetail := sinohopeType.MpcCheckRequestDetail{}
	err = json.Unmarshal(detail, &requestDetail)
	if err != nil {
		logger.Errorf("request detail unmarshal err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.RequestDetailUnmarshal, "request detail unmarshal err", responseData), nil
	}
	extraInfo, err := req.ExtraInfo.MarshalJSON()
	if err != nil {
		logger.Errorf("ExtraInfo.MarshalJSON err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}
	mpcCheckExtraInfo := sinohopeType.MpcCheckExtraInfo{}
	err = json.Unmarshal(extraInfo, &mpcCheckExtraInfo)
	if err != nil {
		logger.Errorf("request extrainfo unmarshal err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.RequestDetailUnmarshal, "request extrainfo unmarshal err", responseData), nil
	}

	mpcCheckVerifyRequest := sinohopeType.MpcCheckVerifyRequest{
		CallbackID:  req.CallbackId,
		RequestType: req.RequestType,
		MpcCheckVerifyRequestDetail: sinohopeType.MpcCheckVerifyRequestDetail{
			T:            requestDetail.T,
			N:            requestDetail.N,
			Cryptography: requestDetail.Cryptography,
			PartyIDs:     requestDetail.PartyIDs,

			SignType:  requestDetail.SignType,
			PublicKey: requestDetail.PublicKey,
			Path:      requestDetail.Path,
			Message:   requestDetail.Message,
			Signature: requestDetail.Signature,
			TxInfo:    requestDetail.TxInfo,
		},
		MpcCheckExtraInfo: mpcCheckExtraInfo,
	}
	mpcCheckVerifyMsg, err := json.Marshal(mpcCheckVerifyRequest)
	if err != nil {
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}
	logger.Infof("mpc check verify req: %s", string(mpcCheckVerifyMsg))
	// mpc node signature verify
	signature := utils.SinohopeSig(ctx, logger)
	if !mpc.Verify(s.mpcNodePublicKey, hex.EncodeToString(mpcCheckVerifyMsg), signature) {
		logger.Errorf("verify signature failed")
		return s.ErrorMpcCheck(exceptions.SystemError, "verify signature failed", responseData), nil
	}
	// decode tx info
	var requestDetailTxInfo sinohopeType.MpcCheckTxInfo
	txInfoJSON, err := requestDetail.TxInfo.MarshalJSON()
	if err != nil {
		logger.Errorf("request detail tx info marshal err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "request detail tx info marshal failed", responseData), nil
	}

	err = json.Unmarshal(txInfoJSON, &requestDetailTxInfo)
	if err != nil {
		logger.Errorf("request detail tx info unmarshal err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "request detail tx info marshal failed", responseData), nil
	}

	amount, err := strconv.ParseInt(requestDetailTxInfo.Amount, 10, 64)
	if err != nil {
		logger.Errorf("amount parse err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.RequestDetailAmount, "request detail amount fail", responseData), nil
	}
	responseData.RequestID = mpcCheckExtraInfo.RequestID
	responseData.SinoID = mpcCheckExtraInfo.SinoID
	// TODO: wait audit system
	responseData.Action = sinohopeType.MpcCheckActionApprove
	// responseData.WaitTime = "10"
	var withdraw model.Withdraw
	err = db.Transaction(func(tx *gorm.DB) error {
		err = tx.
			Set("gorm:query_option", "FOR UPDATE").
			Where(
				fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().RequestID),
				requestDetail.APIRequestID,
			).
			First(&withdraw).Error
		if err != nil {
			logger.Errorw("failed find tx from db", "error", err)
			return err
		}
		logger.Infow("query withdraw detail", "withdraw", withdraw)
		// update check fields
		if !strings.EqualFold(withdraw.BtcFrom, requestDetailTxInfo.From) {
			logger.Errorw("from address not match")
			return errParamsMismatch
		}
		if !strings.EqualFold(withdraw.BtcTo, requestDetailTxInfo.To) {
			logger.Errorw("to address not match")
			return errParamsMismatch
		}
		if withdraw.BtcRealValue != amount {
			logger.Errorw("amount not match")
			return errParamsMismatch
		}
		return nil
	})
	if err != nil {
		logger.Errorw("save tx result err", "err", err.Error())
		if errors.Is(err, errParamsMismatch) {
			return s.ErrorMpcCheck(exceptions.WithdrawMpcReject, "Invalid parameter", responseData), nil
		}
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}

	// mpc callback sign
	message, err := json.Marshal(responseData)
	if err != nil {
		logger.Errorf("marshal response err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}
	sig, err := mpc.Sign(s.mpcCallbackPrivateKey, hex.EncodeToString(message))
	if err != nil {
		logger.Errorf("sign err:%v", err.Error())
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}
	rspData, err := structpb.NewStruct(map[string]interface{}{
		"request_id":  responseData.RequestID,
		"sino_id":     responseData.SinoID,
		"callback_id": responseData.CallbackID,
		"action":      responseData.Action,
		"wait_time":   responseData.WaitTime,
	})
	if err != nil {
		return s.ErrorMpcCheck(exceptions.SystemError, "system error", responseData), nil
	}
	logger.Infof("success")
	rsp := vo.MpcCheckResponse{
		Status:    "0",
		Error:     "",
		Data:      rspData,
		Signature: sig,
	}
	return &rsp, nil
}
