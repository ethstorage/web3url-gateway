package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/web3-protocol/web3protocol-go"
)

func init() {
	err := loadConfig("../../config.toml", &config)
	if err != nil {
		panic(err)
	}
	config.NSDefaultChains["eth"] = 1
	initWeb3protocolClient()
}

var w3links = []struct {
	domain     string
	path       string
	mt         string
	expect     string
	statusCode int
}{
	// contract address
	{"0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.sep.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Ether\"]", http.StatusOK},
	{"0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.11155111.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Ether\"]", http.StatusOK},
	// l2
	{"0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8.arb1.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]", http.StatusOK},
	{"0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8.42161.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.oeth.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.10.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]", http.StatusOK},
	{"0xc5e00d3b04563950941f7137b5afa3a534f0d6d6.evmos.w3link.io", "/name?returns=(string)", "application/json", "[\"Cosmos Hub\"]", http.StatusOK},
	{"0xc5e00d3b04563950941f7137b5afa3a534f0d6d6.9001.w3link.io", "/name?returns=(string)", "application/json", "[\"Cosmos Hub\"]", http.StatusOK},
	{"0x2cE21976443622ab8F0B7F6fa3aF953ff9BCdCf6.arb-nova.w3link.io", "/name?returns=(string)", "application/json", "[\"Arbitrum Nova Gaming\"]", http.StatusOK},
	{"0x2cE21976443622ab8F0B7F6fa3aF953ff9BCdCf6.42170.w3link.io", "/name?returns=(string)", "application/json", "[\"Arbitrum Nova Gaming\"]", http.StatusOK},
	{"0xe9e7cea3dedca5984780bafc599bd69add087d56.56.w3link.io", "/name?returns=(string)", "application/json", "[\"BUSD Token\"]", http.StatusOK},
	{"0xe9e7cea3dedca5984780bafc599bd69add087d56.bnb.w3link.io", "/name?returns=(string)", "application/json", "[\"BUSD Token\"]", http.StatusOK},
	{"0xc5976c1ff6c550150293a31b5f9da787a3ebf5f0.97.w3link.io", "/name?returns=(string)", "application/json", "[\"FakeUSDC\"]", http.StatusOK},
	{"0xc5976c1ff6c550150293a31b5f9da787a3ebf5f0.bnbt.w3link.io", "/name?returns=(string)", "application/json", "[\"FakeUSDC\"]", http.StatusOK},
	{"0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7.43114.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped AVAX\"]", http.StatusOK},
	{"0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7.avax.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped AVAX\"]", http.StatusOK},
	{"0x2796BAED33862664c08B8Ee5Fa2D1283C79593b1.43113.w3link.io", "/name?returns=(string)", "application/json", "[\"wAVAX\"]", http.StatusOK},
	{"0x2796BAED33862664c08B8Ee5Fa2D1283C79593b1.fuji.w3link.io", "/name?returns=(string)", "application/json", "[\"wAVAX\"]", http.StatusOK},
	{"0x69c744d3444202d35a2783929a0f930f2fbb05ad.250.w3link.io", "/name?returns=(string)", "application/json", "[\"Staked FTM\"]", http.StatusOK},
	{"0x69c744d3444202d35a2783929a0f930f2fbb05ad.ftm.w3link.io", "/name?returns=(string)", "application/json", "[\"Staked FTM\"]", http.StatusOK},
	{"0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.1666600000.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped ONE\"]", http.StatusOK},
	{"0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.hmy-s0.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped ONE\"]", http.StatusOK},
	{"0xc9c8ba8c7e2eaf43e84330db08915a8106d7bd74.1666700000.w3link.io", "/name?returns=(string)", "application/json", "[\"E2E_TEST_TOKEN\"]", http.StatusOK},
	{"0xc9c8ba8c7e2eaf43e84330db08915a8106d7bd74.hmy-b-s0.w3link.io", "/name?returns=(string)", "application/json", "[\"E2E_TEST_TOKEN\"]", http.StatusOK},
	{"0x0000000000000000000000000000000000001010.137.w3link.io", "/name?returns=(string)", "application/json", "[\"Polygon Ecosystem Token\"]", http.StatusOK},
	{"0x0000000000000000000000000000000000001010.matic.w3link.io", "/name?returns=(string)", "application/json", "[\"Polygon Ecosystem Token\"]", http.StatusOK},
	{"0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.100001.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKC\"]", http.StatusOK},
	{"0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.qkc-s0.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKC\"]", http.StatusOK},
	{"0xF2Fa1B7C11c33BAC1dB7b037478453289AC90E60.110001.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKCDev\"]", http.StatusOK},
	{"0xF2Fa1B7C11c33BAC1dB7b037478453289AC90E60.qkc-d-s0.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKCDev\"]", http.StatusOK},
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.metis-andromeda.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]", http.StatusOK},
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.1088.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]", http.StatusOK},
	{"0x88de9058a1503A1d50542d8402Be76812BfE66A7.84532.w3link.io", "/name?returns=(string)", "application/json", "[\"Base Sepolia\"]", http.StatusOK},
	{"0x88de9058a1503A1d50542d8402Be76812BfE66A7.basesep.w3link.io", "/name?returns=(string)", "application/json", "[\"Base Sepolia\"]", http.StatusOK},
	{"0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed.base.w3link.io", "/symbol?returns=(string)", "application/json", "[\"DEGEN\"]", http.StatusOK},
	{"0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed.8453.w3link.io", "/symbol?returns=(string)", "application/json", "[\"DEGEN\"]", http.StatusOK},
}

func TestW3links(t *testing.T) {
	config.DefaultChain = 0
	for _, test := range w3links {
		t.Run(test.domain+test.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", test.path, nil)
			req.Host = test.domain
			w := httptest.NewRecorder()
			handle(w, req)
			res := w.Result()
			defer res.Body.Close()
			data, err := ioutil.ReadAll(res.Body)
			assert.NoError(t, err)
			if test.statusCode == http.StatusOK {
				assert.Equal(t, test.expect, string(data))
			} else {
				assert.Equal(t, test.statusCode, res.StatusCode)
			}
		})
	}
}

var w3urls = []struct {
	chainId    int
	domain     string
	path       string
	expect     string
	statusCode int
}{
	{1, "0xdac17f958d2ee523a2206206994597c13d831ec7.w3eth.io", "/name?returns=(string)", "[\"Tether USD\"]", http.StatusOK},
	{56, "0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io", "/name?returns=(string)", "[\"BUSD Token\"]", http.StatusOK},
	{43114, "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7.w3avax.io", "/name?returns=(string)", "[\"Wrapped AVAX\"]", http.StatusOK},
	{9001, "0xc5e00d3b04563950941f7137b5afa3a534f0d6d6.w3evmos.io", "/name?returns=(string)", "[\"Cosmos Hub\"]", http.StatusOK},
	{1666600000, "0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.w3one.io", "/name?returns=(string)", "[\"Wrapped ONE\"]", http.StatusOK},
	{137, "0x0000000000000000000000000000000000001010.w3matic.io", "/name?returns=(string)", "[\"Polygon Ecosystem Token\"]", http.StatusOK},
	{100001, "0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.w3qkc.io", "/greet?returns=(string)", "[\"Hello QKC\"]", http.StatusOK},
}

func TestW3urls(t *testing.T) {
	for _, test := range w3urls {
		t.Run(test.domain+test.path, func(t *testing.T) {
			config.DefaultChain = test.chainId
			req := httptest.NewRequest("GET", test.path, nil)
			req.Host = test.domain
			w := httptest.NewRecorder()
			handle(w, req)
			res := w.Result()
			defer res.Body.Close()
			data, err := ioutil.ReadAll(res.Body)
			assert.NoError(t, err)
			if test.statusCode == http.StatusOK {
				assert.Equal(t, test.expect, string(data)[:])
			} else {
				assert.Equal(t, test.statusCode, res.StatusCode)
			}
		})
	}
}

var mimeTypeUrls = []struct {
	domain     string
	path       string
	mt         string
	statusCode int
}{
	{"cyberbrokers-meta.w3eth.io", "/renderBroker/5", "", http.StatusOK},
	// use mime if specified
	{"0x4e1f41613c9084fdb9e34e11fae9412427480e56.w3eth.io", "/tokenSVG/1?mime.type=svg", "image/svg+xml", http.StatusOK},
	// mime.type overrides mime.content
	{"0x4e1f41613c9084fdb9e34e11fae9412427480e56.w3eth.io", "/tokenSVG/1?mime.content=image/svg+xml&mime.type=htm", "text/html; charset=utf-8", http.StatusOK},
	// returns overrides mime
	{"0x4e1f41613c9084fdb9e34e11fae9412427480e56.w3eth.io", "/tokenByIndex/1?returns=(uint256)&mime.type=xml", "application/json", http.StatusOK},
	// use extention of last param if no mime specified
	{"0xb3dc8d94a698278814b051df3e78834c7c2e44f5.3337.w3link.io", "/2/0.png", "image/png", http.StatusOK},
	// // mime overrides extention
	{"0x0f6a39bd95907b044cc13fd782dcdf7c2515e4ee.3337.w3link.io", "/compose/string!1.svg?mime.type=html", "text/html; charset=utf-8", http.StatusOK},
	// // mime.type is ignored if cannot find the corresponding content type
	{"0x0f6a39bd95907b044cc13fd782dcdf7c2515e4ee.3337.w3link.io", "/compose/string!1.svg?mime.type=foo", "image/svg+xml", http.StatusOK},
	// // use mime.content if mime.type cannot find the corresponding content type
	{"0x0f6a39bd95907b044cc13fd782dcdf7c2515e4ee.3337.w3link.io", "/compose/string!1.svg?mime.content=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", http.StatusOK},
}

func TestMimeTypes(t *testing.T) {
	for _, test := range mimeTypeUrls {
		config.DefaultChain = 1
		config.NSDefaultChains["eth"] = 1
		ensConfig := web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceENS]
		ensConfig.DefaultChainId = 1
		web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceENS] = ensConfig
		t.Run(test.domain+test.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", test.path, nil)
			req.Host = test.domain
			w := httptest.NewRecorder()
			handle(w, req)
			res := w.Result()
			defer res.Body.Close()
			if test.statusCode == http.StatusOK {
				assert.Equal(t, test.mt, res.Header.Get("Content-Type"))
			} else {
				assert.Equal(t, test.statusCode, res.StatusCode)
			}
		})
	}
}
