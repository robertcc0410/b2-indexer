package cmd

import (
	"context"
	"os"

	"github.com/b2network/b2-indexer/internal/server"
	"github.com/b2network/b2-indexer/internal/types"
	cryptoCmd "github.com/b2network/b2-indexer/pkg/crypto/cmd"
	"github.com/b2network/b2-indexer/pkg/log"
	sinohopeCmd "github.com/b2network/b2-indexer/pkg/sinohope/cmd"
	gvsmCmd "github.com/b2network/b2-indexer/pkg/vsm/cmd"
	"github.com/spf13/cobra"
)

const (
	FlagHome = "home"
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd().Execute()
	if err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "b2-indexer",
		Short: "index tx",
		Long:  "b2-indexer is a application that index bitcoin tx",
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			ctx := context.Background()
			ctx = context.WithValue(ctx, types.ServerContextKey, server.NewDefaultContext())
			cmd.SetContext(ctx)
		},
	}

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(startCmd())
	rootCmd.AddCommand(startHTTPServer())
	rootCmd.AddCommand(sinohopeCmd.Sinohope())
	rootCmd.AddCommand(gvsmCmd.Gvsm())
	rootCmd.AddCommand(cryptoCmd.Crypto())
	rootCmd.AddCommand(transferServer())
	rootCmd.AddCommand(resetTransferCmd())
	return rootCmd
}

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "start index tx service",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			home, err := cmd.Flags().GetString(FlagHome)
			if err != nil {
				return err
			}
			return server.InterceptConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, _ []string) {
			err := server.Start(GetServerContextFromCmd(cmd), cmd)
			if err != nil {
				log.Errorf("start index tx service failed:%v", err)
			}
		},
	}
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}

// GetServerContextFromCmd returns a Context from a command or an empty Context
// if it has not been set.
func GetServerContextFromCmd(cmd *cobra.Command) *server.Context {
	if v := cmd.Context().Value(types.ServerContextKey); v != nil {
		serverCtxPtr := v.(*server.Context)
		return serverCtxPtr
	}

	return server.NewDefaultContext()
}

func startHTTPServer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http",
		Short: "start http service",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			home, err := cmd.Flags().GetString(FlagHome)
			if err != nil {
				return err
			}
			return server.HTTPConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, _ []string) {
			db, err := server.GetDBContextFromCmd(cmd)
			if err != nil {
				cmd.Println(err)
				return
			}
			err = server.Run(cmd.Context(), GetServerContextFromCmd(cmd), db)
			if err != nil {
				log.Error("start http service failed")
			}
		},
	}
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}

func transferServer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transfer",
		Short: "start transfer service",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			home, err := cmd.Flags().GetString(FlagHome)
			if err != nil {
				return err
			}
			return server.TransferConfigsPreRunHandler(cmd, home)
		},
		Run: func(cmd *cobra.Command, _ []string) {
			err := server.StartTransfer(GetServerContextFromCmd(cmd), cmd)
			if err != nil {
				log.Errorw("start transfer service failed", "error", err)
			}
		},
	}
	cmd.Flags().String(FlagHome, "", "The application home directory")
	return cmd
}
