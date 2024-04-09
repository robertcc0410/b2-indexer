package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/b2network/b2-indexer/pkg/crypto"
	"github.com/b2network/b2-indexer/pkg/vsm"
	"github.com/google/uuid"
	"github.com/sinohope/sinohope-golang-sdk/common"
	"github.com/sinohope/sinohope-golang-sdk/core/sdk"
	"github.com/spf13/cobra"
)

var (
	FlagBaseURL             = "baseUrl"
	FlagPrivateKey          = "privateKey"
	FlagVaultID             = "vaultId"
	FlagCreateWalletName    = "createWalletName"
	FlagWalletID            = "walletId"
	FlagChainSymbol         = "chainSymbol"
	FlagEncrypt             = "encryptModel"
	FlagVSMInternalKeyIndex = "vsmInternalKeyIndex"
	FlagVsmIv               = "vsmIv"
	FlagLocalEncryptKey     = "localCryptKey"
)

var (
	FakePrivateKey = ""
	BaseURL        = "https://api.sinohope.com"
)

func Sinohope() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sinohope",
		Short: "sinohope command",
		Long:  `sinohope command`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			key, err := cmd.Flags().GetString(FlagPrivateKey)
			if err != nil {
				return err
			}
			enableEncrypt, err := cmd.Flags().GetBool(FlagEncrypt)
			if err != nil {
				return err
			}
			if enableEncrypt {
				internalKeyIndex, err := cmd.Flags().GetUint(FlagVSMInternalKeyIndex)
				if err != nil {
					return err
				}
				localKey, err := cmd.Flags().GetString(FlagLocalEncryptKey)
				if err != nil {
					return err
				}
				if len(localKey) == 0 {
					return fmt.Errorf("invalid local encrypt key")
				}

				localKeyByte, err := hex.DecodeString(localKey)
				if err != nil {
					return err
				}

				tassInputData, err := hex.DecodeString(key)
				if err != nil {
					return err
				}
				vsmIv, err := cmd.Flags().GetString(FlagVsmIv)
				if err != nil {
					return err
				}
				decKey, _, err := vsm.TassSymmKeyOperation(vsm.TaDec, vsm.AlgAes256, tassInputData, []byte(vsmIv), internalKeyIndex)
				if err != nil {
					return err
				}
				key = string(bytes.TrimRight(decKey, "\x00"))
				decodeLocalData, err := hex.DecodeString(key)
				if err != nil {
					return err
				}
				localEncData, err := crypto.AesDecrypt(decodeLocalData, localKeyByte)
				if err != nil {
					return err
				}
				key = string(localEncData)
			}
			url, err := cmd.Flags().GetString(FlagBaseURL)
			if err != nil {
				return err
			}
			BaseURL = url
			FakePrivateKey = key
			return nil
		},
	}
	cmd.AddCommand(
		listVault(),
		listSupportedChainAndCoins(),
		createWallet(),
		genAddress(),
		generateECDSAPrivateKey(),
	)
	cmd.PersistentFlags().String(FlagBaseURL, "https://api.sinohope.com", "sinohope base url")
	cmd.PersistentFlags().String(FlagPrivateKey, "", "fakePrivateKey")
	cmd.PersistentFlags().String(FlagVaultID, "", "sinohope vaultId")
	cmd.PersistentFlags().String(FlagWalletID, "", "sinohope wallet id")
	cmd.PersistentFlags().String(FlagChainSymbol, "BTC", "sinohope chainSymbol")
	cmd.PersistentFlags().Bool(FlagEncrypt, false, "enable encrypt model")
	cmd.PersistentFlags().Uint(FlagVSMInternalKeyIndex, 1, "vsm encryption/decryption internal Key Index")
	cmd.PersistentFlags().String(FlagVsmIv, "", "vsm iv data")
	cmd.PersistentFlags().String(FlagLocalEncryptKey, "", "local encryption/decryption  key")
	return cmd
}

func listVault() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vaults",
		Short: "list usable vaults",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := sdk.NewCommonAPI(BaseURL, FakePrivateKey)
			if err != nil {
				return err
			}

			var vaults []*common.WaaSVaultInfoData
			if vaults, err = c.GetVaults(); err != nil {
				return err
			}
			for _, v := range vaults {
				for _, v2 := range v.VaultInfoOfOpenApiList {
					cmd.Printf("vaultId: %v, vaultName: %v, authorityType: %v, createTime: %v\n",
						v2.VaultId, v2.VaultName, v2.AuthorityType, v2.CreateTime)
				}
			}
			return nil
		},
	}
	return cmd
}

func listSupportedChainAndCoins() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "coins",
		Short: "list usable coins",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := sdk.NewCommonAPI(BaseURL, FakePrivateKey)
			if err != nil {
				return err
			}
			var supportList []*common.WaasChainData
			if supportList, err = c.GetSupportedChains(); err != nil {
				return err
			}
			cmd.Printf("supported chains:\n")
			for _, v := range supportList {
				cmd.Printf("chainName: %v, chainSymbol: %v\n", v.ChainName, v.ChainSymbol)
			}
			cmd.Println()
			var supportCoins []*common.WaaSCoinDTOData
			for _, v := range supportList {
				param := &common.WaasChainParam{
					ChainSymbol: v.ChainSymbol,
				}
				if supportCoins, err = c.GetSupportedCoins(param); err != nil {
					return err
				}
				cmd.Printf("supported coins:\n")
				for _, v := range supportCoins {
					cmd.Printf("assetName: %v, assetId: %v, assetDecimal: %v\n",
						v.AssetName, v.AssetId, v.AssetDecimal)
				}
			}
			return nil
		},
	}
	return cmd
}

func createWallet() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-wallet",
		Short: "create wallet",
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := sdk.NewAccountAndAddressAPI(BaseURL, FakePrivateKey)
			if err != nil {
				return err
			}
			vaultID, err := cmd.Flags().GetString(FlagVaultID)
			if err != nil {
				return err
			}
			walletName, err := cmd.Flags().GetString(FlagCreateWalletName)
			if err != nil {
				return err
			}
			if vaultID == "" || walletName == "" {
				return errors.New("vaultId or walletName is empty")
			}
			requestID := genRequestID()

			cmd.Println("VaultId:", vaultID)
			cmd.Println("WalletName:", walletName)
			cmd.Println("RequestId:", requestID)
			cmd.Println()

			var walletInfo []*common.WaaSWalletInfoData
			if walletInfo, err = m.CreateWallets(&common.WaaSCreateBatchWalletParam{
				VaultId:   vaultID,
				RequestId: requestID,
				Count:     1,
				WalletInfos: []common.WaaSCreateWalletInfo{
					{
						WalletName: walletName,
					},
				},
			}); err != nil {
				return err
			}
			cmd.Println("create wallet success")
			for _, v := range walletInfo {
				cmd.Printf("walletId:%v, walletName:%v\n", v.WalletId, v.WalletName)
			}
			return nil
		},
	}
	cmd.Flags().String(FlagCreateWalletName, "", "The name of the wallet to be created")
	return cmd
}

func genAddress() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-address",
		Short: "generate address",
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := sdk.NewAccountAndAddressAPI(BaseURL, FakePrivateKey)
			if err != nil {
				return err
			}
			vaultID, err := cmd.Flags().GetString(FlagVaultID)
			if err != nil {
				return err
			}

			walletID, err := cmd.Flags().GetString(FlagWalletID)
			if err != nil {
				return err
			}

			chainSymbol, err := cmd.Flags().GetString(FlagChainSymbol)
			if err != nil {
				return err
			}

			requestID := genRequestID()

			cmd.Println("VaultId:", vaultID)
			cmd.Println("WalletId:", walletID)
			cmd.Println("RequestId:", requestID)
			cmd.Println()

			var walletInfo []*common.WaaSAddressInfoData
			if walletInfo, err = m.GenerateChainAddresses(&common.WaaSGenerateChainAddressParam{
				RequestId:   requestID,
				VaultId:     vaultID,
				WalletId:    walletID,
				ChainSymbol: chainSymbol,
			}); err != nil {
				return err
			}
			for _, v := range walletInfo {
				cmd.Printf("address:%v, encoding:%v, hdPath:%v, pubkey:%v\n", v.Address, v.Encoding, v.HdPath, v.Pubkey)
			}
			return nil
		},
	}

	return cmd
}

func generateECDSAPrivateKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-ecdsa-key",
		Short: "generate ECDSA PrivateKey",
		RunE: func(cmd *cobra.Command, _ []string) error {
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				return err
			}
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if err != nil {
				return err
			}
			cmd.Println("pubKey:", hex.EncodeToString(pubKeyBytes))
			cmd.Println("privateKey:", hex.EncodeToString(pkcs8Bytes))
			return nil
		},
	}
	return cmd
}

func genRequestID() string {
	return uuid.New().String()
}
