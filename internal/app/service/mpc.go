package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	pb "github.com/b2network/b2-indexer/api/protobuf"
	"github.com/b2network/b2-indexer/api/protobuf/vo"
	"github.com/b2network/b2-indexer/internal/app/exceptions"
	"github.com/b2network/b2-indexer/internal/config"
	"github.com/b2network/b2-indexer/pkg/log"
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
	private, _, err := mpc.LoadKeypair(cfg.Mpc.PrivateKey)
	if err != nil {
		panic(fmt.Sprintf("load private key failed, %v", err))
	}
	// TODO: vsm dec
	return &mpcServer{
		mpcCallbackPrivateKey: private,
		mpcNodePublicKey:      tssNodePublicKey,
	}
}

func ErrorMpcCheck(status int64, error string) *vo.MpcCheckResponse {
	rspData, _ := structpb.NewStruct(map[string]interface{}{
		"action": sinohopeType.MpcCheckActionReject,
	})
	return &vo.MpcCheckResponse{
		Status: strconv.Itoa(int(status)),
		Error:  error,
		Data:   rspData,
	}
}

func (s *mpcServer) MpcCheck(ctx context.Context, req *vo.MpcCheckRequest) (*vo.MpcCheckResponse, error) {
	logger := log.WithName("MpcCheck")
	logger.Infow("request data:", "req", req)
	httpCfg, err := GetHTTPConfig(ctx)
	if err != nil {
		logger.Errorf("GetHttpConfig err:%v", err.Error())
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}
	if !httpCfg.EnableMPCCallback {
		return ErrorMpcCheck(exceptions.SystemError, "api disable"), nil
	}

	// response data struct
	responseData := sinohopeType.MpcCheckResponseData{
		CallbackID: req.CallbackId,
	}

	db, err := GetDBContext(ctx)
	if err != nil {
		logger.Errorf("GetDBContext err:%v", err.Error())
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}

	detail, err := req.RequestDetail.MarshalJSON()
	if err != nil {
		logger.Errorf("RequestDetail.MarshalJSON err:%v", err.Error())
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}

	logger.Infof("request detail: %s", string(detail))
	requestDetail := sinohopeType.MpcCheckRequestDetail{}
	err = json.Unmarshal(detail, &requestDetail)
	if err != nil {
		logger.Errorf("request detail unmarshal err:%v", err.Error())
		return ErrorMpcCheck(exceptions.RequestDetailUnmarshal, "request detail unmarshal err"), nil
	}
	logger.Infof("request detail: %v", requestDetail)
	extraInfo, err := req.ExtraInfo.MarshalJSON()
	if err != nil {
		logger.Errorf("ExtraInfo.MarshalJSON err:%v", err.Error())
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}
	mpcCheckExtraInfo := sinohopeType.MpcCheckExtraInfo{}
	err = json.Unmarshal(extraInfo, &mpcCheckExtraInfo)
	if err != nil {
		logger.Errorf("request extrainfo unmarshal err:%v", err.Error())
		return ErrorMpcCheck(exceptions.RequestDetailUnmarshal, "request extrainfo unmarshal err"), nil
	}

	mpcCheckVerifyRequest := sinohopeType.MpcCheckVerifyRequest{
		CallbackId:  req.CallbackId,
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
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}
	logger.Infof("mpc check verify req: %s", string(mpcCheckVerifyMsg))
	// mpc node signature verify
	signature := utils.SinohopeSig(ctx, logger)
	if !mpc.Verify(s.mpcNodePublicKey, hex.EncodeToString(mpcCheckVerifyMsg), signature) {
		logger.Errorf("verify signature failed")
		return ErrorMpcCheck(exceptions.SystemError, "verify signature failed"), nil
	}

	responseData.RequestId = mpcCheckExtraInfo.RequestID
	responseData.SinoID = mpcCheckExtraInfo.SinoID
	// TODO: debug
	responseData.Action = sinohopeType.MpcCheckActionApprove
	responseData.WaitTime = "10"
	err = db.Transaction(func(_ *gorm.DB) error {
		return nil
	})
	if err != nil {
		logger.Errorw("save tx result err", "err", err.Error())
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}

	// mpc callback sign
	message, err := json.Marshal(responseData)
	if err != nil {
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}
	sig, err := mpc.Sign(s.mpcCallbackPrivateKey, hex.EncodeToString(message))
	if err != nil {
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}
	rspData, err := structpb.NewStruct(map[string]interface{}{
		"request_id":  responseData.RequestId,
		"sino_id":     responseData.SinoID,
		"callback_id": responseData.CallbackID,
		"action":      responseData.Action,
		"wait_time":   responseData.WaitTime,
	})
	if err != nil {
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
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
