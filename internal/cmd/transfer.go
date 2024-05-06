package cmd

import (
	"fmt"

	"github.com/b2network/b2-indexer/internal/server"
	"github.com/spf13/cobra"
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
			return server.InterceptConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, _ []string) {
			ctx := GetServerContextFromCmd(cmd)
			transferCfg := ctx.TransferCfg
			fmt.Println(transferCfg)
		},
	}
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}
