package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/b2network/b2-indexer/internal/config"
	"github.com/b2network/b2-indexer/internal/logic/bitcoin"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/internal/server"
	"github.com/b2network/b2-indexer/internal/types"
	logger "github.com/b2network/b2-indexer/pkg/log"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

func resetDepositIndexerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "retry-index-deposit",
		Short: "retry index deposit transfer",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			home, err := cmd.Flags().GetString(FlagHome)
			if err != nil {
				return err
			}
			return server.InterceptConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				cmd.Println("invalid parameter")
				return
			}
			blockNumber, err := strconv.Atoi(args[0])
			if err != nil {
				cmd.Println("invalid parameter")
				return
			}
			txID := args[1]
			ctx := GetServerContextFromCmd(cmd)
			bitcoinCfg := ctx.BitcoinConfig
			db, err := server.GetDBContextFromCmd(cmd)
			if err != nil {
				cmd.Printf("failed to get db context: %v", err)
				return
			}
			bclient, err := rpcclient.New(&rpcclient.ConnConfig{
				Host:         bitcoinCfg.RPCHost + ":" + bitcoinCfg.RPCPort,
				User:         bitcoinCfg.RPCUser,
				Pass:         bitcoinCfg.RPCPass,
				HTTPPostMode: true,                  // Bitcoin core only supports HTTP POST mode
				DisableTLS:   bitcoinCfg.DisableTLS, // Bitcoin core does not provide TLS by default
			}, nil)
			if err != nil {
				logger.Errorw("failed to create bitcoin client", "error", err.Error())
				return
			}
			defer func() {
				bclient.Shutdown()
			}()
			bitcoinParam := config.ChainParams(bitcoinCfg.NetworkName)
			bidxLogger := logger.NewNopLogger()
			bidxer, err := bitcoin.NewBitcoinIndexer(bidxLogger, bclient, bitcoinParam, bitcoinCfg.IndexerListenAddress, bitcoinCfg.IndexerListenTargetConfirmations)
			if err != nil {
				logger.Errorw("failed to new bitcoin indexer indexer", "error", err.Error())
				return
			}

			var deposit model.Deposit
			err = db.
				Where(
					fmt.Sprintf("%s.%s = ?", model.Deposit{}.TableName(), model.Deposit{}.Column().BtcTxHash),
					txID,
				).
				First(&deposit).Error
			if err != nil {
				cmd.Printf("failed find tx from db: %v", err)
			}

			if deposit.CallbackStatus != model.CallbackStatusSuccess {
				cmd.Println("invalid status")
				return
			}

			if deposit.ListenerStatus != model.ListenerStatusPending {
				cmd.Println("invalid status")
				return
			}

			txParseResult, blockHeader, err := bidxer.ParseBlock(int64(blockNumber), 0)
			if err != nil {
				logger.Errorw("failed to parse block", "error", err.Error())
				return
			}

			prettyDeposit, err := printJSON(deposit)
			if err != nil {
				cmd.Println("failed to print deposit record:", err)
				return
			}
			cmd.Println(prettyDeposit)
			btcBlockNumber := int64(blockNumber)
			btcBlockTime := blockHeader.Timestamp
			var btcTxIndex int64
			parseResult := types.BitcoinTxParseResult{}
			existTxID := false
			for _, v := range txParseResult {
				if v.TxID == txID {
					existTxID = true
					btcTxIndex = v.Index
					if len(v.From) == 0 {
						logger.Errorw("parse result from empty")
						return
					}

					if len(v.Tos) == 0 {
						logger.Errorw("parse result to empty")
						return
					}

					if v.Value != deposit.BtcValue {
						logger.Errorw("amount mismatch")
						return
					}
					parseResult.To = v.To
					parseResult.From = v.From
					parseResult.Tos = v.Tos
					parseResult.Index = v.Index
					parseResult.TxID = v.TxID
					parseResult.Value = v.Value
					parseResult.TxType = v.TxType
				}
			}
			if !existTxID {
				cmd.Println("not found tx")
				return
			}

			froms, err := json.Marshal(parseResult.From)
			if err != nil {
				return
			}
			tos, err := json.Marshal(parseResult.Tos)
			if err != nil {
				return
			}

			prettyParseResult, err := printJSON(parseResult)
			if err != nil {
				cmd.Println("failed to print parseResult record:", err)
				return
			}
			cmd.Println(prettyParseResult)

			var y string
			cmd.Println("reset the deposit transfer: (y/n)")
			_, err = fmt.Scanln(&y)
			if err != nil {
				cmd.Println("failed to read input:", err)
				return
			}
			if y == "N" || y == "n" {
				return
			}
			if y == "Y" || y == "y" {
				err = db.Transaction(func(tx *gorm.DB) error {
					var oldDeposit model.Deposit
					err = tx.
						Set("gorm:query_option", "FOR UPDATE").
						Where(
							fmt.Sprintf("%s.%s = ?", model.Deposit{}.TableName(), model.Deposit{}.Column().BtcTxHash),
							txID,
						).
						First(&oldDeposit).Error
					if err != nil {
						cmd.Printf("failed find tx from db: %v", err)
						return err
					}
					if oldDeposit.CallbackStatus != model.CallbackStatusSuccess {
						cmd.Println("invalid status")
						return fmt.Errorf("invalid status")
					}

					if oldDeposit.ListenerStatus != model.ListenerStatusPending {
						cmd.Println("invalid status")
						return fmt.Errorf("invalid status")
					}

					updateFields := map[string]interface{}{
						model.Deposit{}.Column().BtcBlockNumber: btcBlockNumber,
						model.Deposit{}.Column().BtcTxIndex:     btcTxIndex,
						model.Deposit{}.Column().BtcFroms:       string(froms),
						model.Deposit{}.Column().BtcTos:         string(tos),
						model.Deposit{}.Column().BtcBlockTime:   btcBlockTime,
						model.Deposit{}.Column().ListenerStatus: model.ListenerStatusSuccess,
					}
					err = tx.Model(&model.Deposit{}).Where(
						fmt.Sprintf("%s.%s = ?", model.Deposit{}.TableName(), model.Deposit{}.Column().BtcTxHash),
						txID,
					).Updates(updateFields).Error
					if err != nil {
						return err
					}
					return nil
				})
				if err != nil {
					cmd.Printf("failed to reset transfer: %v", err)
				}
			}
		},
	}
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}
