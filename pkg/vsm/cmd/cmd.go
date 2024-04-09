package cmd

import (
	"crypto/rand"
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
		genVsmIv(),
	)
	return cmd
}

func encData() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enc",
		Short: "gvsm enc data, aes256 cbc mode, example: enc --vsmInternalKeyIndex 3 {srcData} {iv}",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("invalid parameter")
			}
			internalKeyIndex, err := cmd.Flags().GetUint(FlagVSMInternalKeyIndex)
			if err != nil {
				return err
			}
			decData, _, err := vsm.TassSymmKeyOperation(vsm.TaEnc, vsm.AlgAes256, []byte(args[0]), []byte(args[1]), internalKeyIndex)
			if err != nil {
				return err
			}
			cmd.Println("vsm enc data:")
			cmd.Printf("%s\n", hex.EncodeToString(decData))
			return nil
		},
	}
	cmd.PersistentFlags().Uint(FlagVSMInternalKeyIndex, 1, "vsm encryption/decryption internal Key Index")
	return cmd
}

func genVsmIv() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-iv",
		Short: "gen-iv",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key := make([]byte, 16)
			_, err := rand.Read(key)
			if err != nil {
				return err
			}
			cmd.Println("iv:\n", hex.EncodeToString(key))
			return nil
		},
	}
	return cmd
}
