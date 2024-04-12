package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"syscall"

	"github.com/b2network/b2-indexer/pkg/vsm"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
		safeEncData(),
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
func safeEncData() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "safe-enc",
		Short: "safe gvsm enc data, aes256 cbc mode, example: enc --vsmInternalKeyIndex 3",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				srcData string
				iv      string
			)
			internalKeyIndex, err := cmd.Flags().GetUint(FlagVSMInternalKeyIndex)
			if err != nil {
				return err
			}
			if term.IsTerminal(int(syscall.Stdin)) {
				fmt.Print("Enter srcData: ")
				srcDataStdin, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				fmt.Println()
				srcData = string(srcDataStdin)
				fmt.Print("Enter iv: ")
				ivStdin, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				fmt.Println()
				iv = string(ivStdin)
			} else {
				return fmt.Errorf("error: Cannot read srcData and iv from non-terminal input")
			}
			if srcData == "" || iv == "" {
				return fmt.Errorf("invalid parameter")
			}

			decData, _, err := vsm.TassSymmKeyOperation(vsm.TaEnc, vsm.AlgAes256, []byte(srcData), []byte(iv), internalKeyIndex)
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
func decData() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dec",
		Short: "gvsm dec data, aes256 cbc mode, example: enc --vsmInternalKeyIndex 3 {srcData} {iv}",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("invalid parameter")
			}
			internalKeyIndex, err := cmd.Flags().GetUint(FlagVSMInternalKeyIndex)
			if err != nil {
				return err
			}
			tassInputData, err := hex.DecodeString(args[0])
			if err != nil {
				return err
			}
			decData, _, err := vsm.TassSymmKeyOperation(vsm.TaDec, vsm.AlgAes256, tassInputData, []byte(args[1]), internalKeyIndex)
			if err != nil {
				return err
			}
			cmd.Println("vsm dec data:")
			cmd.Printf("%s\n", hex.EncodeToString(decData))
			return nil
		},
	}
	cmd.PersistentFlags().Uint(FlagVSMInternalKeyIndex, 1, "vsm encryption/decryption internal Key Index")
	return cmd
}
