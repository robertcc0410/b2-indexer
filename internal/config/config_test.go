package config_test

import (
	"os"
	"testing"

	"github.com/b2network/b2-indexer/internal/config"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

func TestBitcoinConfig(t *testing.T) {
	// clean BITCOIN env set
	// This is because the value set by the environment variable affects viper reading file
	os.Unsetenv("BITCOIN_NETWORK_NAME")
	os.Unsetenv("BITCOIN_RPC_HOST")
	os.Unsetenv("BITCOIN_RPC_PORT")
	os.Unsetenv("BITCOIN_RPC_USER")
	os.Unsetenv("BITCOIN_RPC_PASS")
	os.Unsetenv("BITCOIN_DISABLE_TLS")
	os.Unsetenv("BITCOIN_WALLET_NAME")
	os.Unsetenv("BITCOIN_ENABLE_INDEXER")
	os.Unsetenv("BITCOIN_INDEXER_LISTEN_ADDRESS")
	os.Unsetenv("BITCOIN_INDEXER_LISTEN_TARGET_CONFIRMATIONS")
	os.Unsetenv("BITCOIN_BRIDGE_ETH_RPC_URL")
	os.Unsetenv("BITCOIN_BRIDGE_CONTRACT_ADDRESS")
	os.Unsetenv("BITCOIN_BRIDGE_ETH_PRIV_KEY")
	os.Unsetenv("BITCOIN_BRIDGE_ABI")
	os.Unsetenv("BITCOIN_BRIDGE_GAS_LIMIT")
	os.Unsetenv("BITCOIN_BRIDGE_ENABLE_EOA_TRANSFER")
	os.Unsetenv("BITCOIN_BRIDGE_AA_B2_API")
	os.Unsetenv("BITCOIN_BRIDGE_AA_PARTICLE_RPC")
	os.Unsetenv("BITCOIN_BRIDGE_AA_PARTICLE_PROJECT_ID")
	os.Unsetenv("BITCOIN_BRIDGE_AA_PARTICLE_SERVER_KEY")
	os.Unsetenv("BITCOIN_BRIDGE_AA_PARTICLE_CHAIN_ID")
	os.Unsetenv("ENABLE_EPS")
	os.Unsetenv("EPS_URL")
	os.Unsetenv("EPS_AUTHORIZATION")
	os.Unsetenv("BITCOIN_BRIDGE_DEPOSIT")
	os.Unsetenv("BITCOIN_BRIDGE_WITHDRAW")
	os.Unsetenv("BITCOIN_BRIDGE_ROLLUP_ENABLE_LISTENER")
	os.Unsetenv("BITCOIN_BRIDGE_ENABLE_VSM")
	os.Unsetenv("BITCOIN_BRIDGE_VSM_INTERNAL_KEY_INDEX")
	os.Unsetenv("BITCOIN_BRIDGE_VSM_IV")
	os.Unsetenv("BITCOIN_BRIDGE_LOCAL_DECRYPT_KEY")
	os.Unsetenv("BITCOIN_BRIDGE_LOCAL_DECRYPT_ALG")
	os.Unsetenv("BITCOIN_BRIDGE_CONFIRM_HEIGHT")
	config, err := config.LoadBitcoinConfig("./testdata")
	require.NoError(t, err)
	require.Equal(t, "signet", config.NetworkName)
	require.Equal(t, "localhost", config.RPCHost)
	require.Equal(t, "8332", config.RPCPort)
	require.Equal(t, "b2node", config.RPCUser)
	require.Equal(t, "b2node", config.RPCPass)
	require.Equal(t, true, config.DisableTLS)
	require.Equal(t, "b2node", config.WalletName)
	require.Equal(t, true, config.EnableIndexer)
	require.Equal(t, "tb1qfhhxljfajcppfhwa09uxwty5dz4xwfptnqmvtv", config.IndexerListenAddress)
	require.Equal(t, uint64(1), config.IndexerListenTargetConfirmations)
	require.Equal(t, "localhost:8545", config.Bridge.EthRPCURL)
	require.Equal(t, "0xB457BF68D71a17Fa5030269Fb895e29e6cD2DFF2", config.Bridge.ContractAddress)
	require.Equal(t, "", config.Bridge.EthPrivKey)
	require.Equal(t, "abi.json", config.Bridge.ABI)
	require.Equal(t, false, config.Bridge.EnableEoaTransfer)
	require.Equal(t, "127.0.0.1:8080/v1/btc/pubkey", config.Bridge.AAB2PI)
	require.Equal(t, "127.0.0.1:8080", config.Bridge.AAParticleRPC)
	require.Equal(t, "11111", config.Bridge.AAParticleProjectID)
	require.Equal(t, "22222", config.Bridge.AAParticleServerKey)
	require.Equal(t, 1102, config.Bridge.AAParticleChainID)
	require.Equal(t, true, config.Eps.EnableEps)
	require.Equal(t, "127.0.0.1", config.Eps.URL)
	require.Equal(t, "", config.Eps.Authorization)
	require.Equal(t, "", config.Bridge.Deposit)
	require.Equal(t, "", config.Bridge.Withdraw)
	require.Equal(t, false, config.Bridge.EnableRollupListener)
	require.Equal(t, false, config.Bridge.EnableVSM)
	require.Equal(t, uint(10), config.Bridge.VSMInternalKeyIndex)
	require.Equal(t, "abc", config.Bridge.VSMIv)
	require.Equal(t, "aaa", config.Bridge.LocalDecryptKey)
	require.Equal(t, "aes", config.Bridge.LocalDecryptAlg)
	require.Equal(t, 6, config.Bridge.ConfirmHeight)
}

func TestBitcoinConfigEnv(t *testing.T) {
	os.Setenv("BITCOIN_NETWORK_NAME", "testnet")
	os.Setenv("BITCOIN_RPC_HOST", "127.0.0.1")
	os.Setenv("BITCOIN_RPC_PORT", "8888")
	os.Setenv("BITCOIN_RPC_USER", "abc")
	os.Setenv("BITCOIN_RPC_PASS", "abcd")
	os.Setenv("BITCOIN_DISABLE_TLS", "false")
	os.Setenv("BITCOIN_WALLET_NAME", "b2node")
	os.Setenv("BITCOIN_ENABLE_INDEXER", "false")
	os.Setenv("BITCOIN_INDEXER_LISTEN_ADDRESS", "tb1qgm39cu009lyvq93afx47pp4h9wxq5x92lxxgnz")
	os.Setenv("BITCOIN_INDEXER_LISTEN_TARGET_CONFIRMATIONS", "2")
	os.Setenv("BITCOIN_BRIDGE_ETH_RPC_URL", "127.0.0.1:8545")
	os.Setenv("BITCOIN_BRIDGE_CONTRACT_ADDRESS", "0xB457BF68D71a17Fa5030269Fb895e29e6cD2DF22")
	os.Setenv("BITCOIN_BRIDGE_ETH_PRIV_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	os.Setenv("BITCOIN_BRIDGE_ABI", "aaa.abi")
	os.Setenv("BITCOIN_BRIDGE_GAS_LIMIT", "23333")
	os.Setenv("BITCOIN_BRIDGE_ENABLE_EOA_TRANSFER", "true")
	os.Setenv("BITCOIN_BRIDGE_AA_B2_API", "127.1.1.1:1234/v1/btc/xx")
	os.Setenv("BITCOIN_BRIDGE_AA_PARTICLE_RPC", "192.168.1.1/aa")
	os.Setenv("BITCOIN_BRIDGE_AA_PARTICLE_PROJECT_ID", "1234")
	os.Setenv("BITCOIN_BRIDGE_AA_PARTICLE_SERVER_KEY", "12345")
	os.Setenv("BITCOIN_BRIDGE_AA_PARTICLE_CHAIN_ID", "1101")
	os.Setenv("BITCOIN_EVM_ENABLE_LISTENER", "false")
	os.Setenv("BITCOIN_EVM_DEPOSIT", "0x01bee1bfa4116bd0440a1108ef6cb6a2f6eb9b611d8f53260aec20d39e84ee88")
	os.Setenv("BITCOIN_EVM_WITHDRAW", "0xda335c6ae73006d1145bdcf9a98bc76d789b653b13fe6200e6fc4c5dd54add85")
	os.Setenv("ENABLE_EPS", "true")
	os.Setenv("EPS_URL", "127.0.0.1")
	os.Setenv("EPS_AUTHORIZATION", "")
	os.Setenv("BITCOIN_BRIDGE_DEPOSIT", "")
	os.Setenv("BITCOIN_BRIDGE_WITHDRAW", "")
	os.Setenv("BITCOIN_BRIDGE_ROLLUP_ENABLE_LISTENER", "false")
	os.Setenv("BITCOIN_BRIDGE_ENABLE_VSM", "true")
	os.Setenv("BITCOIN_BRIDGE_VSM_INTERNAL_KEY_INDEX", "11")
	os.Setenv("BITCOIN_BRIDGE_VSM_IV", "1111abc")
	os.Setenv("BITCOIN_BRIDGE_LOCAL_DECRYPT_KEY", "abcd")
	os.Setenv("BITCOIN_BRIDGE_LOCAL_DECRYPT_ALG", "rsa")
	os.Setenv("BITCOIN_BRIDGE_CONFIRM_HEIGHT", "6")

	config, err := config.LoadBitcoinConfig("./")
	require.NoError(t, err)
	require.Equal(t, "testnet", config.NetworkName)
	require.Equal(t, "127.0.0.1", config.RPCHost)
	require.Equal(t, "8888", config.RPCPort)
	require.Equal(t, "abc", config.RPCUser)
	require.Equal(t, "abcd", config.RPCPass)
	require.Equal(t, false, config.DisableTLS)
	require.Equal(t, "b2node", config.WalletName)
	require.Equal(t, false, config.EnableIndexer)
	require.Equal(t, "tb1qgm39cu009lyvq93afx47pp4h9wxq5x92lxxgnz", config.IndexerListenAddress)
	require.Equal(t, uint64(2), config.IndexerListenTargetConfirmations)
	require.Equal(t, "127.0.0.1:8545", config.Bridge.EthRPCURL)
	require.Equal(t, "0xB457BF68D71a17Fa5030269Fb895e29e6cD2DF22", config.Bridge.ContractAddress)
	require.Equal(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", config.Bridge.EthPrivKey)
	require.Equal(t, "aaa.abi", config.Bridge.ABI)
	require.Equal(t, true, config.Bridge.EnableEoaTransfer)
	require.Equal(t, "127.1.1.1:1234/v1/btc/xx", config.Bridge.AAB2PI)
	require.Equal(t, "192.168.1.1/aa", config.Bridge.AAParticleRPC)
	require.Equal(t, "1234", config.Bridge.AAParticleProjectID)
	require.Equal(t, "12345", config.Bridge.AAParticleServerKey)
	require.Equal(t, 1101, config.Bridge.AAParticleChainID)
	require.Equal(t, true, config.Eps.EnableEps)
	require.Equal(t, "127.0.0.1", config.Eps.URL)
	require.Equal(t, "", config.Eps.Authorization)
	require.Equal(t, "", config.Bridge.Deposit)
	require.Equal(t, "", config.Bridge.Withdraw)
	require.Equal(t, false, config.Bridge.EnableRollupListener)
	require.Equal(t, true, config.Bridge.EnableVSM)
	require.Equal(t, uint(11), config.Bridge.VSMInternalKeyIndex)
	require.Equal(t, "1111abc", config.Bridge.VSMIv)
	require.Equal(t, "abcd", config.Bridge.LocalDecryptKey)
	require.Equal(t, "rsa", config.Bridge.LocalDecryptAlg)
	require.Equal(t, 6, config.Bridge.ConfirmHeight)
}

func TestChainParams(t *testing.T) {
	testCases := []struct {
		network string
		params  *chaincfg.Params
	}{
		{
			network: "mainnet",
			params:  &chaincfg.MainNetParams,
		},
		{
			network: "testnet",
			params:  &chaincfg.TestNet3Params,
		},
		{
			network: "signet",
			params:  &chaincfg.SigNetParams,
		},
		{
			network: "simnet",
			params:  &chaincfg.SimNetParams,
		},
		{
			network: "regtest",
			params:  &chaincfg.RegressionNetParams,
		},
		{
			network: "invalid",
			params:  &chaincfg.TestNet3Params,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.network, func(t *testing.T) {
			result := config.ChainParams(tc.network)
			if result == nil || result != tc.params {
				t.Errorf("ChainParams(%s) = %v, expected %v", tc.network, result, tc.params)
			}
		})
	}
}

func TestConfig(t *testing.T) {
	os.Unsetenv("INDEXER_ROOT_DIR")
	os.Unsetenv("INDEXER_LOG_LEVEL")
	os.Unsetenv("INDEXER_LOG_FORMAT")
	os.Unsetenv("INDEXER_DATABASE_SOURCE")
	os.Unsetenv("INDEXER_DATABASE_MAX_IDLE_CONNS")
	os.Unsetenv("INDEXER_DATABASE_MAX_OPEN_CONNS")
	os.Unsetenv("INDEXER_DATABASE_CONN_MAX_LIFETIME")

	config, err := config.LoadConfig("./testdata")
	require.NoError(t, err)
	require.Equal(t, "/data/b2-indexer", config.RootDir)
	require.Equal(t, "info", config.LogLevel)
	require.Equal(t, "json", config.LogFormat)
	require.Equal(t, "postgres://postgres:postgres@127.0.0.2:5432/b2-indexer", config.DatabaseSource)
	require.Equal(t, 1, config.DatabaseMaxIdleConns)
	require.Equal(t, 2, config.DatabaseMaxOpenConns)
	require.Equal(t, 3600, config.DatabaseConnMaxLifetime)
}

func TestConfigEnv(t *testing.T) {
	os.Setenv("INDEXER_ROOT_DIR", "/data/test")
	os.Setenv("INDEXER_LOG_LEVEL", "debug")
	os.Setenv("INDEXER_LOG_FORMAT", "json")
	os.Setenv("INDEXER_DATABASE_SOURCE", "testtest")
	os.Setenv("INDEXER_DATABASE_MAX_IDLE_CONNS", "12")
	os.Setenv("INDEXER_DATABASE_MAX_OPEN_CONNS", "22")
	os.Setenv("INDEXER_DATABASE_CONN_MAX_LIFETIME", "2100")
	config, err := config.LoadConfig("./")
	require.NoError(t, err)
	require.Equal(t, "/data/test", config.RootDir)
	require.Equal(t, "debug", config.LogLevel)
	require.Equal(t, "json", config.LogFormat)
	require.Equal(t, "testtest", config.DatabaseSource)
	require.Equal(t, 12, config.DatabaseMaxIdleConns)
	require.Equal(t, 22, config.DatabaseMaxOpenConns)
	require.Equal(t, 2100, config.DatabaseConnMaxLifetime)
}

func TestHTTPConfig(t *testing.T) {
	os.Unsetenv("HTTP_PORT")
	os.Unsetenv("HTTP_GRPC_PORT")
	os.Unsetenv("HTTP_IP_WHITE_LIST")
	os.Unsetenv("ENABLE_MPC_CALLBACK")

	config, err := config.LoadHTTPConfig("./testdata")
	require.NoError(t, err)
	require.Equal(t, "8080", config.HTTPPort)
	require.Equal(t, "8081", config.GrpcPort)
	require.Equal(t, "127.0.0.1", config.IPWhiteList)
	require.Equal(t, false, config.EnableMPCCallback)
}

func TestHTTPConfigEnv(t *testing.T) {
	os.Setenv("HTTP_PORT", "8080")
	os.Setenv("HTTP_GRPC_PORT", "8081")
	os.Setenv("HTTP_IP_WHITE_LIST", "127.0.0.2")
	os.Setenv("ENABLE_MPC_CALLBACK", "true")
	config, err := config.LoadHTTPConfig("./")
	require.NoError(t, err)
	require.Equal(t, "8080", config.HTTPPort)
	require.Equal(t, "8081", config.GrpcPort)
	require.Equal(t, "127.0.0.2", config.IPWhiteList)
	require.Equal(t, true, config.EnableMPCCallback)
}

func TestTransferConfig(t *testing.T) {
	os.Unsetenv("TRANSFER_BASE_URL")
	os.Unsetenv("TRANSFER_PRIVATE_KEY")
	os.Unsetenv("TRANSFER_VAULT_ID")
	os.Unsetenv("TRANSFER_WALLET_ID")
	os.Unsetenv("TRANSFER_FROM")
	os.Unsetenv("TRANSFER_CHAIN_SYMBOL")
	os.Unsetenv("TRANSFER_ASSET_ID")
	os.Unsetenv("TRANSFER_OPERATION_TYPE")
	os.Unsetenv("TRANSFER_NETWORK_NAME")
	os.Unsetenv("TRANSFER_ENABLE_ENCRYPT")
	os.Unsetenv("TRANSFER_FEE")
	os.Unsetenv("TRANSFER_TIME_INTERVAL")

	config, err := config.LoadTransferConfig("./testdata")
	require.NoError(t, err)
	require.Equal(t, "https://api.sinohope.com", config.BaseURL)
	require.Equal(t, "", config.PrivateKey)
	require.Equal(t, "", config.VaultID)
	require.Equal(t, "", config.WalletID)
	require.Equal(t, "", config.From)
	require.Equal(t, "BTC_BTC", config.AssetID)
	require.Equal(t, "BTC", config.ChainSymbol)
	require.Equal(t, "TRANSFER", config.OperationType)
	require.Equal(t, "testnet", config.NetworkName)
	require.Equal(t, false, config.EnableEncrypt)
	require.Equal(t, "0.02", config.Fee)
	require.Equal(t, 60, config.TimeInterval)
}

func TestTransferConfigEnv(t *testing.T) {
	os.Setenv("TRANSFER_BASE_URL", "https://api.sinohope.com")
	os.Setenv("TRANSFER_PRIVATE_KEY", "")
	os.Setenv("TRANSFER_VAULT_ID", "")
	os.Setenv("TRANSFER_WALLET_ID", "")
	os.Setenv("TRANSFER_FROM", "")
	os.Setenv("TRANSFER_CHAIN_SYMBOL", "BTC_BTC")
	os.Setenv("TRANSFER_ASSET_ID", "BTC")
	os.Setenv("TRANSFER_OPERATION_TYPE", "TRANSFER")
	os.Setenv("TRANSFER_NETWORK_NAME", "testnet")
	os.Setenv("TRANSFER_ENABLE_ENCRYPT", "false")
	os.Setenv("TRANSFER_FEE", "0.02")
	os.Setenv("TRANSFER_TIME_INTERVAL", "60")

	config, err := config.LoadTransferConfig("")
	require.NoError(t, err)
	require.Equal(t, "https://api.sinohope.com", config.BaseURL)
	require.Equal(t, "", config.PrivateKey)
	require.Equal(t, "", config.VaultID)
	require.Equal(t, "", config.WalletID)
	require.Equal(t, "", config.From)
	require.Equal(t, "BTC", config.AssetID)
	require.Equal(t, "BTC_BTC", config.ChainSymbol)
	require.Equal(t, "TRANSFER", config.OperationType)
	require.Equal(t, "testnet", config.NetworkName)
	require.Equal(t, false, config.EnableEncrypt)
	require.Equal(t, "0.02", config.Fee)
	require.Equal(t, 60, config.TimeInterval)
}

func TestAuditConfig(t *testing.T) {
	os.Unsetenv("AUDIT_DATABASE_SOURCE")
	os.Unsetenv("AUDIT_DATABASE_MAX_IDLE_CONNS")
	os.Unsetenv("AUDIT_DATABASE_MAX_OPEN_CONNS")
	os.Unsetenv("AUDIT_DATABASE_CONN_MAX_LIFETIME")

	config, err := config.LoadAuditConfig("./testdata")
	require.NoError(t, err)
	require.Equal(t, "postgres://postgres:postgres@127.0.0.2:5432/b2-indexer", config.DatabaseSource)
	require.Equal(t, 1, config.DatabaseMaxIdleConns)
	require.Equal(t, 2, config.DatabaseMaxOpenConns)
	require.Equal(t, 3600, config.DatabaseConnMaxLifetime)
}

func TestAuditConfigEnv(t *testing.T) {
	os.Setenv("AUDIT_DATABASE_SOURCE", "testtest")
	os.Setenv("AUDIT_DATABASE_MAX_IDLE_CONNS", "12")
	os.Setenv("AUDIT_DATABASE_MAX_OPEN_CONNS", "22")
	os.Setenv("AUDIT_DATABASE_CONN_MAX_LIFETIME", "2100")
	config, err := config.LoadAuditConfig("./")
	require.NoError(t, err)
	require.Equal(t, "testtest", config.DatabaseSource)
	require.Equal(t, 12, config.DatabaseMaxIdleConns)
	require.Equal(t, 22, config.DatabaseMaxOpenConns)
	require.Equal(t, 2100, config.DatabaseConnMaxLifetime)
}
