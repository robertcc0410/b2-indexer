package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/b2network/b2-indexer/pkg/crypto"
	"github.com/spf13/cobra"
)

func Crypto() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "local crypto, Encrypt/Decrypt",
	}
	cmd.AddCommand(
		generateRsaKey(),
		rsaEncrypt(),
		rsaDecrypt(),
		aesEncrypt(),
		aesDecrypt(),
		genAesKey(),
	)
	return cmd
}

func generateRsaKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-rsa-key",
		Short: "generate rsa PrivateKey",
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, pub, err := crypto.GenRsaKey(2048)
			if err != nil {
				return err
			}
			cmd.Println("pubKey:\n", pub)
			cmd.Println("privateKey:\n", priv)
			return nil
		},
	}
	return cmd
}

func rsaEncrypt() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rsa-enc",
		Short: "rsa encrypt hex, example: rsa-enc {srcData} {Key}",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("invalid parameter")
			}
			data, err := crypto.RsaEncryptHex(args[0], args[1])
			if err != nil {
				return err
			}
			cmd.Println("rsa enc data:\n", data)
			return nil
		},
	}
	return cmd
}

func rsaDecrypt() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rsa-dec",
		Short: "rsa decrypt hex, example: src-dec {cryptedData} {Key}",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("invalid parameter")
			}
			data, err := crypto.RsaDecryptHex(args[0], args[1])
			if err != nil {
				return err
			}
			cmd.Println("rsa dec data:\n", data)
			return nil
		},
	}
	return cmd
}

func aesEncrypt() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aes-enc",
		Short: "aes256 encrypt hex, example: aes-enc {srcData} {Key}",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("invalid parameter")
			}
			key, err := hex.DecodeString(args[1])
			if err != nil {
				return err
			}
			data, err := crypto.AesEncrypt([]byte(args[0]), key)
			if err != nil {
				return err
			}
			cmd.Println("aes enc data:\n", hex.EncodeToString(data))
			return nil
		},
	}
	return cmd
}

func aesDecrypt() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aes-dec",
		Short: "aes256 decrypt hex, example: aes-dec {cryptedData} {Key}",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return fmt.Errorf("invalid parameter")
			}
			srcData, err := hex.DecodeString(args[0])
			if err != nil {
				return err
			}
			key, err := hex.DecodeString(args[1])
			if err != nil {
				return err
			}
			data, err := crypto.AesDecrypt(srcData, key)
			if err != nil {
				return err
			}
			cmd.Println("aes dec data:\n", string(data))
			return nil
		},
	}
	return cmd
}

func genAesKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-aes-key",
		Short: "generate aes256 key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := crypto.GenAesKey()
			if err != nil {
				return err
			}
			cmd.Println("aes key:\n", hex.EncodeToString(key))
			return nil
		},
	}
	return cmd
}
