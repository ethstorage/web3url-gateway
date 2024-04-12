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

 ```
 certbot certonly \
  --dns-digitalocean \
  --dns-digitalocean-credentials ~/.secrets/certbot/digitalocean.ini \
    -d '*.1.w3link.io' \
    -d '*.10.w3link.io' \
    -d '*.100001.w3link.io' \
    -d '*.1088.w3link.io' \
    -d '*.110001.w3link.io' \
    -d '*.11155111.w3link.io' \
    -d '*.137.w3link.io' \
    -d '*.1402.w3link.io' \
    -d '*.1666600000.w3link.io' \
    -d '*.1666700000.w3link.io' \
    -d '*.250.w3link.io' \
    -d '*.333.w3link.io' \
    -d '*.3333.w3link.io' \
    -d '*.3334.w3link.io' \
    -d '*.4002.w3link.io' \
    -d '*.420.w3link.io' \
    -d '*.42161.w3link.io' \
    -d '*.421613.w3link.io' \
    -d '*.42170.w3link.io' \
    -d '*.43113.w3link.io' \
    -d '*.43114.w3link.io' \
    -d '*.5.w3link.io' \
    -d '*.534351.w3link.io' \
    -d '*.534354.w3link.io' \
    -d '*.56.w3link.io' \
    -d '*.599.w3link.io' \
    -d '*.80001.w3link.io' \
    -d '*.84531.w3link.io' \
    -d '*.9000.w3link.io' \
    -d '*.9001.w3link.io' \
    -d '*.97.w3link.io' \
    -d '*.arb-goerli.w3link.io' \
    -d '*.arb-nova.w3link.io' \
    -d '*.arb1.w3link.io' \
    -d '*.avax.w3link.io' \
    -d '*.basegor.w3link.io' \
    -d '*.bnb.w3link.io' \
    -d '*.bnbt.w3link.io' \
    -d '*.eth.1.w3link.io' \
    -d '*.eth.10.w3link.io' \
    -d '*.eth.11155111.w3link.io' \
    -d '*.eth.420.w3link.io' \
    -d '*.eth.42161.w3link.io' \
    -d '*.eth.421613.w3link.io' \
    -d '*.eth.5.w3link.io' \
    -d '*.eth.arb-goerli.w3link.io' \
    -d '*.eth.arb1.w3link.io' \
    -d '*.eth.eth.w3link.io' \
    -d '*.eth.gor.w3link.io' \
    -d '*.eth.oeth.w3link.io' \
    -d '*.eth.ogor.w3link.io' \
    -d '*.eth.sep.w3link.io' \
    -d '*.eth.w3link.io' \
    -d '*.evmos-testnet.w3link.io' \
    -d '*.evmos.w3link.io' \
    -d '*.ftm.w3link.io' \
    -d '*.fuji.w3link.io' \
    -d '*.gor.w3link.io' \
    -d '*.hmy-b-s0.w3link.io' \
    -d '*.hmy-s0.w3link.io' \
    -d '*.matic.w3link.io' \
    -d '*.maticmum.w3link.io' \
    -d '*.metis-andromeda.w3link.io' \
    -d '*.metis-goerli.w3link.io' \
    -d '*.oeth.w3link.io' \
    -d '*.ogor.w3link.io' \
    -d '*.qkc-d-s0.w3link.io' \
    -d '*.qkc-s0.w3link.io' \
    -d '*.scr-prealpha.w3link.io' \
    -d '*.scr-testl1.w3link.io' \
    -d '*.sep.w3link.io' \
    -d '*.tftm.w3link.io' \
    -d '*.w3q-g.w3link.io' \
    -d '*.w3q.333.w3link.io' \
    -d '*.w3q.3334.w3link.io' \
    -d '*.w3q.w3link.io' \
    -d '*.w3q.w3q-g.w3link.io' \
    -d '*.zkevmtest.w3link.io' \
    -d '*.w3link.io' \
    -d ordinals.btc.w3link.io \
    -d w3link.io

  ```
If successful, some messages like the following will appear where you can find the location of the private key and certificates:

```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/1.w3link.io/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/1.w3link.io/privkey.pem
This certificate expires on 2024-04-24.
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

