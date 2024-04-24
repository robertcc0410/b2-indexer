package server

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/b2network/b2-indexer/pkg/crypto"
	"github.com/b2network/b2-indexer/pkg/vsm"

	"github.com/b2network/b2-indexer/internal/logic/bitcoin"
	logger "github.com/b2network/b2-indexer/pkg/log"
	"github.com/sinohope/sinohope-golang-sdk/core/sdk"
	"github.com/spf13/cobra"

	sincmd "github.com/b2network/b2-indexer/pkg/sinohope/cmd"
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

	privateKey := transferCfg.PrivateKey
	if transferCfg.EnableEncrypt {
		internalKeyIndex, err := cmd.Flags().GetUint(sincmd.FlagVSMInternalKeyIndex)
		if err != nil {
			return err
		}
		localKey, err := cmd.Flags().GetString(sincmd.FlagLocalEncryptKey)
		if err != nil {
			return err
		}
		if len(localKey) == 0 {
			return fmt.Errorf("invalid local encrypt key")
		}

		localKeyByte, err := hex.DecodeString(localKey)
		if err != nil {
			return err
		}

		tassInputData, err := hex.DecodeString(privateKey)
		if err != nil {
			return err
		}
		vsmIv, err := cmd.Flags().GetString(sincmd.FlagVsmIv)
		if err != nil {
			return err
		}
		decKey, _, err := vsm.TassSymmKeyOperation(vsm.TaDec, vsm.AlgAes256, tassInputData, []byte(vsmIv), internalKeyIndex)
		if err != nil {
			return err
		}
		privateKey = string(bytes.TrimRight(decKey, "\x00"))
		decodeLocalData, err := hex.DecodeString(privateKey)
		if err != nil {
			return err
		}
		localEncData, err := crypto.AesDecrypt(decodeLocalData, localKeyByte)
		if err != nil {
			return err
		}
		privateKey = string(localEncData)
	}

	sinohopeAPI, err := sdk.NewTransactionAPI(transferCfg.BaseURL, privateKey)
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
