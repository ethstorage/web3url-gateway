# Web3:// Gateway
A gateway implementation of the web3 access protocol (web3://) that can serve HTTP-style web3 URL for blockchain resource access.

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
  -homePage https://web3url.w3eth.io/ \
  -dbToken xxxxxx
```

Example 2: `w3link.io` (for general web3 links)
```
./server \
  -homePage https://web3url.eth.1.w3link.io/ \
  -dbToken xxxxxx
```

## Supported chains on `w3link.io`:

|ChainID|Chain Name|Short Name|
|----|----|----|
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
|1513|Story Protocol Testnet|storyprotocoltest|

## How to create a wildcard certificate for `w3link.io`

The gateway now has the capability to generate domain certificates on-the-fly using `autocert`. 
However, the wildcard certificates are not supported in this way.

To use a wildcard certificate, we can create it beforehand using [certbot](certbot.eff.org).

The steps are as follows:

1. Install `certbot` and DNS plugin for DigitalOcean

```
snap install --classic certbot
ln -s /snap/bin/certbot /usr/bin/certbot
snap set certbot trust-plugin-with-root=ok
snap install certbot-dns-digitalocean
```
Refer to [this instruction](https://certbot.eff.org/instructions?ws=other&os=ubuntufocal&tab=wildcard) for detailed information.

2. Setup DigitalOcean API credentials used by Certbot

Go to [DigitalOcean website](https://cloud.digitalocean.com/account/api/tokens?i=8b4851&preserveScrollPosition=true) to generate an API token

Create a file `/root/.secrets/certbot/digitalocean.ini` with the following content:
```
# DigitalOcean API credentials used by Certbot
dns_digitalocean_token = <digitalocean-token>
```

Authorize permissions to the file:

```
chmod 600 /root/.secrets/certbot/digitalocean.ini
```


 3. create certificate：

 ```bash
 certbot certonly --dns-digitalocean \
  --dns-digitalocean-credentials \
  ~/.secrets/certbot/digitalocean.ini \
  -d '*.1.web3gateway.dev' \
  -d '*.10.web3gateway.dev' \
  -d '*.100001.web3gateway.dev' \
  -d '*.1088.web3gateway.dev' \
  -d '*.110001.web3gateway.dev' \
  -d '*.11155111.web3gateway.dev' \
  -d '*.137.web3gateway.dev' \
  -d '*.1402.web3gateway.dev' \
  -d '*.1666600000.web3gateway.dev' \
  -d '*.1666700000.web3gateway.dev' \
  -d '*.250.web3gateway.dev' \
  -d '*.333.web3gateway.dev' \
  -d '*.3333.web3gateway.dev' \
  -d '*.4002.web3gateway.dev' \
  -d '*.420.web3gateway.dev' \
  -d '*.42161.web3gateway.dev' \
  -d '*.421613.web3gateway.dev' \
  -d '*.42170.web3gateway.dev' \
  -d '*.43113.web3gateway.dev' \
  -d '*.43114.web3gateway.dev' \
  -d '*.534351.web3gateway.dev' \
  -d '*.534354.web3gateway.dev' \
  -d '*.56.web3gateway.dev' \
  -d '*.80001.web3gateway.dev' \
  -d '*.9000.web3gateway.dev' \
  -d '*.9001.web3gateway.dev' \
  -d '*.97.web3gateway.dev' \
  -d '*.arb-nova.web3gateway.dev' \
  -d '*.arb1.web3gateway.dev' \
  -d '*.avax.web3gateway.dev' \
  -d '*.bnb.web3gateway.dev' \
  -d '*.bnbt.web3gateway.dev' \
  -d '*.eth.1.web3gateway.dev' \
  -d '*.eth.10.web3gateway.dev' \
  -d '*.eth.11155111.web3gateway.dev' \
  -d '*.eth.42161.web3gateway.dev' \
  -d '*.eth.arb1.web3gateway.dev' \
  -d '*.eth.eth.web3gateway.dev' \
  -d '*.eth.oeth.web3gateway.dev' \
  -d '*.eth.sep.web3gateway.dev' \
  -d '*.eth.web3gateway.dev' \
  -d '*.evmos-testnet.web3gateway.dev' \
  -d '*.evmos.web3gateway.dev' \
  -d '*.ftm.web3gateway.dev' \
  -d '*.fuji.web3gateway.dev' \
  -d '*.hmy-b-s0.web3gateway.dev' \
  -d '*.hmy-s0.web3gateway.dev' \
  -d '*.matic.web3gateway.dev' \
  -d '*.maticmum.web3gateway.dev' \
  -d '*.metis-andromeda.web3gateway.dev' \
  -d '*.oeth.web3gateway.dev' \
  -d '*.qkc-d-s0.web3gateway.dev' \
  -d '*.qkc-s0.web3gateway.dev' \
  -d '*.scr-prealpha.web3gateway.dev' \
  -d '*.scr-testl1.web3gateway.dev' \
  -d '*.sep.web3gateway.dev' \
  -d '*.tftm.web3gateway.dev' \
  -d '*.zkevmtest.web3gateway.dev' \
  -d '*.web3gateway.dev' \
  -d ordinals.btc.web3gateway.dev  
  -d web3gateway.dev  
  -d '*.storyprotocoltest.web3gateway.dev' \
  -d '*.1513.web3gateway.dev' \
  -d '*.holesky.web3gateway.dev' \
  -d '*.17000.web3gateway.dev' \
  -d '*.base.web3gateway.dev' \
  -d '*.8453.web3gateway.dev' \
  -d '*.es-d.web3gateway.dev' \
  -d '*.3337.web3gateway.dev' \
  -d '*.esl2-d.web3gateway.dev' \
  -d '*.3335.web3gateway.dev'
```
If successful, some messages like the following will appear where you can find the location of the private key and certificates:

```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/1.web3gateway.dev/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/1.web3gateway.dev/privkey.pem
This certificate expires on 2024-12-11.
These files will be updated when the certificate renews.
Certbot has set up a scheduled task to automatically renew this certificate in the background.
```

By default, the certificate will be renewed 30 days before expiration. 


Check if the renew service is running normally：

```
  certbot renew --dry-run
```

## Autocert configuration

To enable `autocert`, make changes to `config.toml` as follows:

```
RunAsHttp = false
SystemCertDir = "/root/dl/web3url-gateway/sys_cert"
...
```
Where `SystemCertDir` is the folder to store the file of the combination of the private key and the system certificate.

Currently, the `autocert` module is activated on the `web3gateway.dev` gateway, with system certificate and private key generated by `certbot`:

```
/etc/letsencrypt/live/1.web3gateway.dev/fullchain.pem
/etc/letsencrypt/live/1.web3gateway.dev/privkey.pem
``` 

Meanwhile, `w3link.io` and `w3eth.io` are running with `RunAsHttp` set to `true`, which indicates `autocert` service is not utilized.

