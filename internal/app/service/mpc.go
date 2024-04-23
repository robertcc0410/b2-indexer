package service

import (
	"context"
	"encoding/json"

	pb "github.com/b2network/b2-indexer/api/protobuf"
	"github.com/b2network/b2-indexer/api/protobuf/vo"
	"github.com/b2network/b2-indexer/internal/app/exceptions"
	"github.com/b2network/b2-indexer/pkg/log"
	sinohopeType "github.com/b2network/b2-indexer/pkg/sinohope/types"
	"gorm.io/gorm"
)

type mpcCheckServer struct {
	pb.UnimplementedMpcCheckServiceServer
}

func newMpcCheckServer() *mpcCheckServer {
	return &mpcCheckServer{}
}

func ErrorMpcCheck(_ int64, _ string) *vo.MpcCheckResponse {
	return &vo.MpcCheckResponse{
		// Code:    code,
		// Message: message,
	}
}

func (s *mpcCheckServer) MpcCheck(ctx context.Context, req *vo.MpcCheckRequest) (*vo.MpcCheckResponse, error) {
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
	db, err := GetDBContext(ctx)
	if err != nil {
		logger.Errorf("GetDBContext err:%v", err.Error())
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}

	detail, err := req.RequestDetail.MarshalJSON()
	if err != nil {
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
	err = db.Transaction(func(tx *gorm.DB) error {
		return nil
	})
	if err != nil {
		logger.Errorw("save tx result err", "err", err.Error())
		return ErrorMpcCheck(exceptions.SystemError, "system error"), nil
	}
	return &vo.MpcCheckResponse{
		// RequestId: req.RequestId,
		// Code:      200,
	}, nil
}
