package server

import (
	"bytes"
	"encoding/hex"
	"time"

	"github.com/b2network/b2-indexer/pkg/vsm"

	"github.com/b2network/b2-indexer/internal/logic/bitcoin"
	b2crypto "github.com/b2network/b2-indexer/pkg/crypto"
	logger "github.com/b2network/b2-indexer/pkg/log"
	"github.com/sinohope/sinohope-golang-sdk/core/sdk"
	"github.com/spf13/cobra"
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
		tassInputData, err := hex.DecodeString(privateKey)
		if err != nil {
			return err
		}
		decKey, _, err := vsm.TassSymmKeyOperation(vsm.TaDec, vsm.AlgAes256, tassInputData, []byte(transferCfg.VSMIv), transferCfg.VSMInternalKeyIndex)
		if err != nil {
			return err
		}
		privateKey = string(bytes.TrimRight(decKey, "\x00"))
		if transferCfg.LocalDecryptAlg == b2crypto.AlgAes {
			decEthPrivKey, err := hex.DecodeString(privateKey)
			if err != nil {
				logger.Errorw("transfer service privKey hex.DecodeString", "error", err)
				return err
			}
			localKey, err := hex.DecodeString(transferCfg.LocalDecryptKey)
			if err != nil {
				logger.Errorw("transfer service localKey hex.DecodeString", "error", err)
				return err
			}
			localDecEthPrivKey, err := b2crypto.AesDecrypt(decEthPrivKey, localKey)
			if err != nil {
				logger.Errorw("transfer service localKey AesDecrypt", "error", err)
				return err
			}
			privateKey = string(localDecEthPrivKey)
		} else if transferCfg.LocalDecryptAlg == b2crypto.AlgRsa {
			localDecEthPrivKey, err := b2crypto.RsaDecryptHex(privateKey, transferCfg.LocalDecryptKey)
			if err != nil {
				logger.Errorw("transfer service privateKey RsaDecryptHex", "error", err)
				return err
			}
			privateKey = localDecEthPrivKey
		}
	}

	sinohopeAPI, err := sdk.NewTransactionAPI(transferCfg.BaseURL, privateKey)
	logger.Infow("transfer service NewTransactionAPI", "privateKey", privateKey)
	if err != nil {
		logger.Errorw("transfer service NewTransactionAPI", "error", err)
		return err
	}
	transferService := bitcoin.NewTransferService(transferCfg, db, bridgeLogger, sinohopeAPI)
	defer func() {
		if err = transferService.Stop(); err != nil {
			logger.Errorf("stop transferService err:%v", err.Error())
		}
	}()
	transferErrCh := make(chan error)
	go func() {
		if err := transferService.Start(); err != nil {
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
