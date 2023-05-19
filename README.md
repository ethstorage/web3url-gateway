# Web3 URL Gateway
A gateway implementation of the web3 access protocol (web3://) that can serve HTTP-style Web3 URL for blockchain resource access.

## Feature list
* Implements EIP-4804: Web3 URL to EVM Call Message Translation
* Supports EIP-6821: ENS Name for Web3 URL
* Supports contract address or ENS name as the subdomain of a URL
* Supports EIP-5219/EIP-6944: access to contracts with certain [interface](https://eips.ethereum.org/assets/eip-5219/IDecentralizedApp.sol)
* Supports BTC ordinals access by both [ordinals id](https://ordinals.btc.w3link.io/txid/83997e2cfad159dd6f1fde263d0dbca88879e747c6ccf2b7fcfc0f5638c17511i0) or [number](https://ordinals.btc.w3link.io/number/2232)
* A Grafana dashboard backed by influxdb
* Caches resolved domain name to save RPC access cost

## Build the source

```
make
```
## Configurations

Before running any test or a product server, you need a copy of `config.toml` based on `config.toml.template`, 
and make changes of your own. 

## Run all tests

1. Start a test server
```sh
./run_test.sh
```
2. Then in another CLI, run 
```sh
 make test
```

##  Running a customized server

You can run the server with parameters that will override configurations in `config.toml`. 

Example 1: `w3eth.io` (handles ENS on Ethereum mainnet only)
```
./server \
  -port xx \
  -defaultChain 1 \
  -homePage https://w3url.w3eth.io/ \
  -dbToken xxxxxx
```

Example 2: `w3link.io` (for general web3 links)
```
./server \
  -setNSChain w3q,333 \
  -homePage https://w3url.eth.1.w3link.io/ \
  -dbToken xxxxxx
```

## Supported chains on `w3link.io`:

|ChainID|Chain Name|Short Name|
|----|----|----|
|3334|Web3Q Galileo|w3q-g|
|1|Ethereum Mainnet|eth|
|5|Ethereum Testnet Goerli|gor|
|11155111|Ethereum Testnet Sepolia|sep|
|10|Optimism|oeth|
|42161|Arbitrum One|arb1|
|420|Optimism Goerli Testnet|ogor|
|421613|Arbitrum Goerli Rollup Testnet|arb-goerli|
|9001|Evmos|evmos|
|9000|Evmos Testnet|evmos-testnet|
|42170|Arbitrum Nova|arb-nova|
|56|Binance Smart Chain Mainnet|bnb|
|97|Binance Smart Chain Testnet|bnbt|
|43114|Avalanche C-Chain|avax|
|43113|Avalanche Fuji Testnet|fuji|
|250|Fantom Opera|ftm|
|4002|Fantom Testnet|tftm|
|1666600000|Harmony Mainnet Shard 0|hmy-s0|
|1666700000|Harmony Testnet Shard 0|hmy-b-s0|
|137|Polygon Mainnet|matic|
|80001|Mumbai|maticmum|
|1402|Polygon zkEVM Testnet|zkevmtest|
|100001|QuarkChain Mainnet Shard 0|qkc-s0|
|110001|QuarkChain Devnet Shard 0|qkc-d-s0|
|1088|Metis Andromeda Mainnet|metis-andromed|
|599|Metis Goerli Testnet|metis-goerli|
|534351|Scroll L1 Testnet|scr-testl1|
|534354|Scroll L2 Testnet|scr-prealpha|
|84531|Base Goerli Testnet|basegor|
