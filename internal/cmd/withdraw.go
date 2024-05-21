package cmd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/b2network/b2-indexer/internal/logic/rollup"
	"github.com/b2network/b2-indexer/internal/model"
	"github.com/b2network/b2-indexer/internal/server"
	"github.com/b2network/b2-indexer/pkg/event"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

func scanWithdrawTxByHash() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan-withdraw-tx-hash",
		Short: "scan withdraw tx by hash",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			home, err := cmd.Flags().GetString(FlagHome)
			if err != nil {
				return err
			}
			return server.InterceptConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				cmd.Println("invalid parameter")
				return
			}
			txHash := args[0]
			ctx := GetServerContextFromCmd(cmd)
			bitcoinCfg := ctx.BitcoinConfig
			db, err := server.GetDBContextFromCmd(cmd)
			if err != nil {
				cmd.Printf("failed to get db context: %v", err)
				return
			}

			var withdrawArry []model.Withdraw
			err = db.
				Where(
					fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().B2TxHash),
					txHash,
				).
				Find(&withdrawArry).Error
			if err != nil {
				if err != gorm.ErrRecordNotFound {
					cmd.Printf("failed find tx from db: %v", err)
					return
				}
			}
			for k, v := range withdrawArry {
				if v.ID != 0 {
					cmd.Println("================")
					prettyWithdraw, err := printJSON(v)
					if err != nil {
						cmd.Println("failed to print withdraw record:", err)
						return
					}
					cmd.Printf("index:%v, value: %+v \n", k, prettyWithdraw)
					cmd.Println("================")
				}
			}

			ethlient, err := ethclient.Dial(bitcoinCfg.Bridge.EthRPCURL)
			if err != nil {
				cmd.Printf("failed dial b2 client: %v", err)
				return
			}
			defer func() {
				ethlient.Close()
			}()

			receipt, err := ethlient.TransactionReceipt(context.Background(), common.HexToHash(txHash))
			if err != nil {
				cmd.Printf("failed transactionReceipt by txHash: %v", err)
				return
			}
			var withdrawList []model.Withdraw
			for _, vlog := range receipt.Logs {
				eventHash := common.BytesToHash(vlog.Topics[0].Bytes())
				if eventHash == common.HexToHash(bitcoinCfg.Bridge.Withdraw) {
					caller := event.TopicToAddress(*vlog, 1).Hex()
					withdrawUUID := hex.EncodeToString(vlog.Data[32*4 : 32*5])
					originalAmount := rollup.DataToBigInt(*vlog, 1)
					withdrawAmount := rollup.DataToBigInt(*vlog, 2)
					withdrawFee := rollup.DataToBigInt(*vlog, 3)
					destAddrStr := rollup.DataToString(*vlog, 0)
					toAddress := event.TopicToAddress(*vlog, 0).Hex()
					withdrawData := model.Withdraw{
						B2TxFrom:      caller,
						B2TxTo:        toAddress,
						UUID:          withdrawUUID,
						RequestID:     fmt.Sprintf("%s-%d-%d", vlog.TxHash.String(), vlog.TxIndex, vlog.Index),
						BtcFrom:       bitcoinCfg.IndexerListenAddress,
						BtcTo:         destAddrStr,
						BtcValue:      originalAmount.Int64(),
						BtcRealValue:  withdrawAmount.Int64(),
						Fee:           withdrawFee.Int64(),
						B2BlockNumber: vlog.BlockNumber,
						B2BlockHash:   vlog.BlockHash.String(),
						B2TxHash:      vlog.TxHash.String(),
						B2TxIndex:     vlog.TxIndex,
						B2LogIndex:    vlog.Index,
						Status:        model.BtcTxWithdrawSubmit,
					}
					withdrawList = append(withdrawList, withdrawData)
				}
			}

			for k, v := range withdrawList {
				prettyWithdraw, err := printJSON(v)
				if err != nil {
					cmd.Println("failed to print withdraw record:", err)
					return
				}
				cmd.Printf("index:%v, value: %+v \n", k, prettyWithdraw)
			}
			var y string
			cmd.Println("scan withdraw tx by hash into db: (y/n)")
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
					for _, v := range withdrawList {
						if err := processWithdraw(cmd, tx, v); err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					cmd.Printf("failed to scan withdraw tx by hash: %v", err)
				}
			}
		},
	}
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}

func processWithdraw(cmd *cobra.Command, tx *gorm.DB, v model.Withdraw) error {
	var withdraw model.Withdraw
	err := tx.
		Where(
			fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().B2TxHash),
			v.B2TxHash,
		).
		Where(
			fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().B2TxIndex),
			v.B2TxIndex,
		).
		Where(
			fmt.Sprintf("%s.%s = ?", model.Withdraw{}.TableName(), model.Withdraw{}.Column().B2LogIndex),
			v.B2LogIndex,
		).
		First(&withdraw).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			cmd.Printf("failed create withdraw: %v", err)
			return err
		}
	}
	if withdraw.ID != 0 {
		cmd.Println("continue id:", withdraw.ID)
		return nil
	}

	if err := tx.Create(&v).Error; err != nil {
		cmd.Printf("failed create withdraw: %v", err)
		return err
	}

	withdrawRecord := model.WithdrawRecord{
		WithdrawID: v.ID,
		RequestID:  v.RequestID,
		B2TxHash:   v.B2TxHash,
		BtcFrom:    v.BtcFrom,
		BtcTo:      v.BtcTo,
		BtcValue:   v.BtcValue,
	}
	if err := tx.Create(&withdrawRecord).Error; err != nil {
		cmd.Printf("failed create withdraw record: %v", err)
		return err
	}

	return nil
}
