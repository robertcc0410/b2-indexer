package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/b2network/b2-indexer/pkg/vsm"
	"github.com/spf13/cobra"
)

var FlagVSMInternalKeyIndex = "vsmInternalKeyIndex"

func Gvsm() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gvsm",
		Short: "gvsm command",
		Long:  `gvsm command`,
	}
	cmd.AddCommand(
		encData(),
	)
	return cmd
}

func encData() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enc",
		Short: "gvsm enc data, aes256 ecb mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no data")
			}
			decData, err := vsm.TassSymmKeyOperation(vsm.TaEnc, vsm.AlgAes256, []byte(args[0]), 3)
			if err != nil {
				return err
			}
			cmd.Printf("%s\n", hex.EncodeToString(decData))
			return nil
		},
	}
	cmd.PersistentFlags().Uint(FlagVSMInternalKeyIndex, 1, "vsm encryption/decryption internal Key Index")
	return cmd
}
