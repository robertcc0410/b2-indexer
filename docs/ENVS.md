# Run-time environment variables

## Indexer configuration

| Variable                           | Type     | Description             | Compulsoriness | Default value | Example value                                            |
|------------------------------------|----------|-------------------------|----------------|---------------|----------------------------------------------------------|
| INDEXER_ROOT_DIR                   | `string` | Config file used dir    | -              |               |                                                          |
| INDEXER_LOG_LEVEL                  | `string` | Log level               | -              | `info`        | `info debug warn error panic fatal`                      |
| INDEXER_LOG_FORMAT                 | `string` | Log format              | -              | `console`     | ``                                                       |
| INDEXER_DATABASE_SOURCE            | `string` | database source         | Required       |               | `postgres://postgres:postgres@127.0.0.1:5432/b2-indexer` |
| INDEXER_DATABASE_MAX_IDLE_CONNS    | `number` | database max idle conns | -              | `10`          | `10`                                                     |
| INDEXER_DATABASE_MAX_OPEN_CONNS    | `number` | database max open conns | -              | `20`          | `20`                                                     |
| INDEXER_DATABASE_CONN_MAX_LIFETIME | `number` | database max lifetime   | -              | `3600`        | `3600`                                                   |

## Bitcoin configuration

| Variable                                    | Type     | Description                                           | Compulsoriness | Default value | Example value                            |
|---------------------------------------------|----------|-------------------------------------------------------|----------------|---------------|------------------------------------------|
| BITCOIN_NETWORK_NAME                        | `string` | bitcoin network name                                  | Required       | testnet3      | `mainnet testnet3 regtest`               |
| BITCOIN_RPC_HOST                            | `string` | bitcoin rpc host                                      | Required       |               | `127.0.0.1`                              |
| BITCOIN_RPC_PORT                            | `string` | bitcoin rpc port                                      | Required       |               | `8332`                                   |
| BITCOIN_RPC_USER                            | `string` | bitcoin rpc user                                      | Required       |               |                                          |
| BITCOIN_RPC_PASS                            | `string` | bitcoin rpc password                                  | Required       |               |                                          |
| BITCOIN_DISABLE_TLS                         | `bool`   | bitcoin disable tls                                   | Required       | `true`        |                                          |
| BITCOIN_ENABLE_INDEXER                      | `bool`   | enable indexer service                                | Required       |               | `false true`                             |
| BITCOIN_INDEXER_LISTEN_ADDRESS              | `string` | indexer service listen btc address                    | Required       |               |                                          |
| BITCOIN_INDEXER_LISTEN_TARGET_CONFIRMATIONS | `number` | target confirmations, adjust as needed                | -              | `1`           |                                          |
| BITCOIN_BRIDGE_ETH_RPC_URL                  | `string` | bridge contract eth rpc url                           | Required       |               | `https://zkevm-rpc.bsquared.network`     |
| BITCOIN_BRIDGE_ETH_PRIV_KEY                 | `string` | bridge contract eth invoke priv key                   | Required       |               |                                          |
| BITCOIN_BRIDGE_CONTRACT_ADDRESS             | `string` | bridge contract address                               | Required       |               |                                          |
| BITCOIN_BRIDGE_ABI                          | `string` | bridge contract abi, if not set, will use default abi | -              |               |                                          |
| BITCOIN_BRIDGE_AA_B2_API                    | `string` | b2 aa api                                             | Required       |               |                                          |
| BITCOIN_BRIDGE_GAS_PRICE_MULTIPLE           | `number` | base gas price multiple                               | Required       | `1`           |                                          |
| BITCOIN_BRIDGE_B2_EXPLORER_URL              | `string` | b2 explorer api url                                   | -              |               |                                          |
| BITCOIN_BRIDGE_AA_PARTICLE_RPC              | `string` | particle rpc url                                      | Required       |               | `https://rpc.particle.network/evm-chain` |
| BITCOIN_BRIDGE_AA_PARTICLE_PROJECT_ID       | `string` | particle project id                                   | Required       |               |                                          |
| BITCOIN_BRIDGE_AA_PARTICLE_SERVER_KEY       | `string` | particle server key                                   | Required       |               |                                          |
| BITCOIN_BRIDGE_AA_PARTICLE_CHAIN_ID         | `string` | particle chain id                                     | Required       |               |                                          |
| BITCOIN_BRIDGE_ENABLE_EOA_TRANSFER          | `bool`   | enable eoa transfer                                   | -              | `true`        | false true                               |
| ENABLE_EPS                                  | `bool`   | enable eps service                                    | Required       |               | false true                               |
| EPS_URL                                     | `string` | eps url                                               | Required       |               |                                          |
| EPS_AUTHORIZATION                           | `string` | eps authorization                                     | Required       |               |                                          |
| BITCOIN_BRIDGE_DEPOSIT                      | `string` | bridge deposit event hash                             | Required       |               |                                          |
| BITCOIN_BRIDGE_WITHDRAW                     | `string` | bridge withdraw event hash                            | Required       |               |                                          |
| BITCOIN_BRIDGE_WITHDRAW_ENABLE_LISTENER     | `bool`   | enable bridge withdraw service                        | Required       |               | false true                               |
| BITCOIN_BRIDGE_ROLLUP_ENABLE_LISTENER       | `bool`   | enable rollup indexer service                         | Required       |               | false true                               |

## http configuration

| Variable           | Type     | Description   | Compulsoriness | Default value | Example value |
|--------------------|----------|---------------|----------------|---------------|---------------|
| HTTP_PORT          | `string` | Http port     | -              | 8080          | -             |
| HTTP_GRPC_PORT     | `string` | grpc port     | -              | 8081          | -             |
| HTTP_IP_WHITE_LIST | `string` | ip white list | Required       |               | -             |

## transfer configuration

| Variable                  | Type     | Description      | Compulsoriness | Default value | Example value            |
|---------------------------|----------|------------------|----------------|---------------|--------------------------|
| TRANSFER_BASE_URL         | `string` | base-url         | -              |               | https://api.sinohope.com |
| TRANSFER_FAKE_PRIVATE_KEY | `string` | fake-private-key | -              | 8081          | -                        |
| TRANSFER_VAULT_ID         | `string` | vault-id         | -              |               | -                        |
| TRANSFER_WALLET_ID        | `string` | wallet-id        | -              |               | -                        |
| TRANSFER_FROM             | `string` | from             | -              |               | -                        |
| TRANSFER_CHAIN_SYMBOL     | `string` | chain-symbol     | -              |               | BTC_BTC                  |
| TRANSFER_ASSET_ID         | `string` | asset-id         | -              |               | BTC                      |
| TRANSFER_OPERATION_TYPE   | `string` | operation-type   | -              |               | TRANSFER                 |
| TRANSFER_NETWORK_NAME     | `string` | network-name     | -              |               | -                        |
| TRANSFER_ENABLE_ENCRYPT   | `bool`   | enable-encrypt   | -              |               | -                        |

# Service requirement environment variable

## b2-indexer

```
INDEXER_LOG_LEVEL
INDEXER_LOG_FORMAT
INDEXER_DATABASE_SOURCE
INDEXER_DATABASE_MAX_IDLE_CONNS
INDEXER_DATABASE_MAX_OPEN_CONNS
INDEXER_DATABASE_CONN_MAX_LIFETIME

BITCOIN_NETWORK_NAME
BITCOIN_RPC_HOST
BITCOIN_RPC_PORT
BITCOIN_RPC_USER
BITCOIN_RPC_PASS
BITCOIN_ENABLE_INDEXER
BITCOIN_INDEXER_LISTEN_ADDRESS
BITCOIN_INDEXER_LISTEN_TARGET_CONFIRMATIONS

BITCOIN_BRIDGE_ETH_RPC_URL
BITCOIN_BRIDGE_CONTRACT_ADDRESS
BITCOIN_BRIDGE_ETH_PRIV_KEY

BITCOIN_BRIDGE_GAS_PRICE_MULTIPLE
BITCOIN_BRIDGE_B2_EXPLORER_URL

BITCOIN_BRIDGE_AA_B2_API

BITCOIN_BRIDGE_AA_PARTICLE_RPC
BITCOIN_BRIDGE_AA_PARTICLE_PROJECT_ID
BITCOIN_BRIDGE_AA_PARTICLE_SERVER_KEY
BITCOIN_BRIDGE_AA_PARTICLE_CHAIN_ID

BITCOIN_BRIDGE_DEPOSIT
BITCOIN_BRIDGE_ROLLUP_ENABLE_LISTENER

BITCOIN_BRIDGE_WITHDRAW_ENABLE_LISTENER=false

BITCOIN_BRIDGE_ENABLE_EOA_TRANSFER=true

ENABLE_EPS
EPS_URL
EPS_AUTHORIZATION


BITCOIN_BRIDGE_ENABLE_VSM
BITCOIN_BRIDGE_VSM_INTERNAL_KEY_INDEX
BITCOIN_BRIDGE_VSM_IV
BITCOIN_BRIDGE_LOCAL_DECRYPT_KEY
BITCOIN_BRIDGE_LOCAL_DECRYPT_ALG=rsa
```

## b2-indexer-api

```
BITCOIN_INDEXER_LISTEN_ADDRESS
HTTP_IP_WHITE_LIST
INDEXER_LOG_LEVEL
INDEXER_LOG_FORMAT
INDEXER_DATABASE_SOURCE
INDEXER_DATABASE_MAX_IDLE_CONNS
INDEXER_DATABASE_MAX_OPEN_CONNS
INDEXER_DATABASE_CONN_MAX_LIFETIME
HTTP_PORT
```

## transfer-server

```
TRANSFER_BASE_URL
TRANSFER_PRIVATE_KEY
TRANSFER_VAULT_ID
TRANSFER_WALLET_ID
TRANSFER_FROM
TRANSFER_CHAIN_SYMBOL
TRANSFER_ASSET_ID
TRANSFER_OPERATION_TYPE
TRANSFER_NETWORK_NAME
TRANSFER_ENABLE_ENCRYPT
TRANSFER_TIME_INTERVAL
TRANSFER_BATCH_WAIT_TIME
TRANSFER_BATCH_COUNT

AUDIT_DATABASE_SOURCE
AUDIT_DATABASE_MAX_IDLE_CONNS
AUDIT_DATABASE_MAX_OPEN_CONNS
AUDIT_DATABASE_CONN_MAX_LIFETIME
```

## b2-indexer-mpc

```
INDEXER_LOG_LEVEL
INDEXER_LOG_FORMAT
INDEXER_DATABASE_SOURCE
INDEXER_DATABASE_MAX_IDLE_CONNS
INDEXER_DATABASE_MAX_OPEN_CONNS
INDEXER_DATABASE_CONN_MAX_LIFETIME
HTTP_PORT
ENABLE_MPC_CALLBACK=true
HTTP_MPC_CALLBACK_PRIVATE_KEY
HTTP_MPC_NODE_PUBLIC_KEY
HTTP_MPC_ENABLE_VSM
HTTP_MPC_VSM_INTERNAL_KEY_INDEX
HTTP_MPC_VSM_IV
HTTP_MPC_LOCAL_DECRYPT_KEY
HTTP_MPC_LOCAL_DECRYPT_ALG
```
