package server

import (
	"github.com/b2network/b2-indexer/internal/logic/bitcoin"
	logger "github.com/b2network/b2-indexer/pkg/log"
	"github.com/sinohope/sinohope-golang-sdk/core/sdk"
	"github.com/spf13/cobra"
	"time"
)

func StartTransfer(ctx *Context, cmd *cobra.Command) (err error) {
	logger.Infow("transfer service starting...")
	transferCfg := ctx.TransferCfg
	db, err := GetDBContextFromCmd(cmd)
	if err != nil {
		logger.Errorw("failed to get db context", "error", err.Error())
		return err
	}

	bridgeLogger := newLogger(ctx, "[bridge-transfer]")
	if err != nil {
		return err
	}

	sinohopeAPI, err := sdk.NewTransactionAPI(transferCfg.BaseUrl, transferCfg.FakePrivateKey)
	if err != nil {
		return err
	}
	transferService := bitcoin.NewTransferService(transferCfg, db, bridgeLogger, sinohopeAPI)

	transferErrCh := make(chan error)
	go func() {
		if err := transferService.OnStart(); err != nil {
			transferErrCh <- err
		}
	}()

	select {
	case err := <-transferErrCh:
		return err
	case <-time.After(5 * time.Second): // assume server started successfully
	}

	// wait quit
	code := WaitForQuitSignals()
	logger.Infow("server stop!!!", "quit code", code)
	return nil
}
