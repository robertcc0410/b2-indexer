package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/internal/server"
	logger "github.com/b2network/b2-indexer/pkg/log"
	"github.com/b2network/b2-indexer/pkg/sinohope"
	"github.com/sinohope/sinohope-golang-sdk/common"
	"github.com/sinohope/sinohope-golang-sdk/core/sdk"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

func resetTransferCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset-transfer",
		Short: "reset withdraw transfer",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			home, err := cmd.Flags().GetString(FlagHome)
			if err != nil {
				return err
			}
			return server.TransferConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				cmd.Println("invalid parameter")
				return
			}
			apiRequestID := args[0]
			ctx := GetServerContextFromCmd(cmd)
			transferCfg := ctx.TransferCfg
			db, err := server.GetDBContextFromCmd(cmd)
			if err != nil {
				cmd.Printf("failed to get db context: %v", err)
				return
			}
			privateKey := transferCfg.PrivateKey
			// decrypt
			if transferCfg.EnableEncrypt {
				decPrivateKey, err := sinohope.DecryptKey(privateKey, transferCfg.LocalDecryptKey, transferCfg.VSMIv, transferCfg.VSMInternalKeyIndex)
				if err != nil {
					panic(fmt.Sprintf("decode private key failed, %v", err))
				}
				privateKey = decPrivateKey
			}
			var withdraw model.Withdraw
			// query withdraw status
			err = db.
				Where(
					fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().RequestID),
					apiRequestID,
				).
				First(&withdraw).Error
			if err != nil {
				cmd.Printf("failed find tx from db: %v", err)
				return
			}

			if withdraw.Status != model.BtcTxWithdrawFailed {
				cmd.Println("invalid status:", withdraw.Status)
				return
			}

			sinohopeAPI, err := sdk.NewTransactionAPI(transferCfg.BaseURL, privateKey)
			if err != nil {
				cmd.Printf("failed to init transaction api: %v\n", err)
				return
			}

			res, err := sinohopeAPI.TransactionsByRequestIds(&common.WalletTransactionQueryWAASRequestIdParam{
				RequestIds: apiRequestID,
			})
			if err != nil {
				cmd.Printf("failed to query transactions: %v", err)
				return
			}
			if len(res.List) == 0 {
				cmd.Println("no transactions found")
				return
			}
			cmd.Println(res.List)
			for _, tx := range res.List {
				if tx.RequestId == apiRequestID {
					if tx.State != 4 {
						cmd.Println("invalid state:", tx.State)
						return
					}
				}
			}

			err = db.Transaction(func(tx *gorm.DB) error {
				var oldWithdraw model.Withdraw
				err = tx.
					Set("gorm:query_option", "FOR UPDATE").
					Where(
						fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().RequestID),
						apiRequestID,
					).
					First(&oldWithdraw).Error
				if err != nil {
					cmd.Printf("failed find tx from db: %v", err)
					return err
				}
				if oldWithdraw.Status != model.BtcTxWithdrawFailed {
					cmd.Println("invalid status")
					return fmt.Errorf("invalid status")
				}
				oldWithdrawJSON, err := json.Marshal(oldWithdraw)
				if err != nil {
					return err
				}
				var withdrawReset model.WithdrawReset
				err = tx.
					Where(
						fmt.Sprintf("%s.%s = ?", model.WithdrawReset{}.TableName(), model.WithdrawReset{}.Column().RequestID),
						apiRequestID,
					).
					First(&withdrawReset).Error
				if err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						withdrawReset = model.WithdrawReset{
							RequestID: apiRequestID,
							B2TxHash:  oldWithdraw.B2TxHash,
							Withdraw:  string(oldWithdrawJSON),
						}
						err = tx.Save(&withdrawReset).Error
						if err != nil {
							logger.Errorw("failed to save tx result", "error", err)
							return err
						}
						newAPIRequestID, err := resetRequestID(apiRequestID)
						if err != nil {
							return err
						}
						updateFields := map[string]interface{}{
							model.Withdraw{}.Column().Status:    model.BtcTxWithdrawSubmit,
							model.Withdraw{}.Column().RequestID: newAPIRequestID,
						}
						err = tx.Model(&model.Withdraw{}).Where("id = ?", oldWithdraw.ID).Updates(updateFields).Error
						if err != nil {
							return err
						}

						return nil
					}
					logger.Errorw("failed find tx from db", "error", err)
					return err
				}
				cmd.Println(withdrawReset)
				return fmt.Errorf("withdraw reset data already exists")
			})
			if err != nil {
				cmd.Printf("failed to reset transfer: %v", err)
			}
		},
	}
	cmd.AddCommand(createResetTransferTableCmd())
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}

func createResetTransferTableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-table",
		Short: "create withdraw reset transfer",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			home, err := cmd.Flags().GetString(FlagHome)
			if err != nil {
				return err
			}
			return server.TransferConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, _ []string) {
			db, err := server.GetDBContextFromCmd(cmd)
			if err != nil {
				cmd.Printf("failed to get db context: %v\n", err)
				return
			}

			if !db.Migrator().HasTable(&model.WithdrawReset{}) {
				err = db.AutoMigrate(&model.WithdrawReset{})
				if err != nil {
					cmd.Printf("failed to migrate WithdrawReset table: %v\n", err)
					return
				}
			}
		},
	}
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}

func resetRequestID(requestID string) (string, error) {
	arr := strings.Split(requestID, "_")
	if len(arr) == 1 {
		return requestID + "_" + "1", nil
	} else if len(arr) == 2 {
		num, err := strconv.Atoi(arr[1])
		if err != nil {
			return "", err
		}
		num++
		return requestID + "_" + strconv.Itoa(num), nil
	}
	return "", fmt.Errorf("invalid requestID format")
}
