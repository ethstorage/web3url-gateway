package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	// "fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"

	"github.com/web3-protocol/web3protocol-go"
)

func init() {
	err := loadConfig("../../config.toml", &config)
	if err != nil {
		panic(err)
	}
	config.NSDefaultChains["eth"] = 5
	config.NSDefaultChains["w3q"] = 3334
	config.DefaultChain = 3334

	initWeb3protocolClient()
}

var testURLs = []struct {
	domain     string
	path       string
	mt         string
	expect     string
	statusCode int
}{
	{"localhost", "/0x6587e67F1FBEAabDEe8b70EFb396E750e216283B:w3q-g/asdf/1234?foo=bar", "application/json", "{\"resource\":[\"asdf\",\"1234\"], \"params\":[{\"key\":\"foo\", \"value\": \"bar\"}}", http.StatusOK},
	{"localhost", "/quark.w3q/index.txt", "text/plain; charset=utf-8", "hello, world", http.StatusOK},
	{"localhost", "/concat.w3q/concat/bytes!0x61/bytes!0x62/bytes!0x63?returnTypes=(string)", "application/json", "[\"abc\"]", http.StatusOK},
	{"localhost", "/concat.w3q/concat/bytes!0x/bytes!0x/bytes!0x?returnTypes=(string)", "application/json", "[\"\"]", http.StatusOK},
	{"localhost", "/concat.w3q/retrieve?returns=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"Galileo\",true]", http.StatusOK},
	{"localhost", "/concat.w3q/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"Galileo\",true]", http.StatusOK},
	// ethereum
	// {"localhost", "/0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699:gor/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"goerli\",true]", http.StatusOK},
	// {"localhost", "/0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699:5/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"goerli\",true]", http.StatusOK},
	{"localhost", "/quark.eth:gor/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"goerli\",true]", http.StatusOK},
	{"localhost", "/0x79550b825ef3d7b1f825be9965fae80bdf77a7e2:3334/hello.txt", "text/plain; charset=utf-8", "hello! ethstorage!", http.StatusOK},
	// wrong domain
	{"localhost", "/quarkd.w3q/files/index.txt", "", "", http.StatusNotFound},
	// wrong suffix
	{"localhost", "/quark.w4q/index.txt", "", "", http.StatusBadRequest},
	// duplicate return attributes: Last one is used
	{"localhost", "/concat.w3q/retrieve?returnTypes=(uint256)&returns=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"Galileo\",true]", http.StatusOK},
}

func TestHandle(t *testing.T) {
	for _, test := range testURLs {
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
				assert.Equal(t, test.mt, res.Header.Get("Content-Type"))
				assert.Equal(t, test.expect, string(data))
			} else {
				assert.Equal(t, test.statusCode, res.StatusCode)
			}
		})
	}
}

func TestServer(t *testing.T) {
	for _, test := range testURLs {
		t.Run(test.path, func(t *testing.T) {
			resp, err := http.Get("http://localhost:" + config.ServerPort + test.path)
			assert.NoError(t, err)
			defer resp.Body.Close()
			data, err := ioutil.ReadAll(resp.Body)
			assert.NoError(t, err)
			if test.statusCode == http.StatusOK {
				assert.Equal(t, test.mt, resp.Header.Get("Content-Type"))
				assert.Equal(t, test.expect, string(data))
			} else {
				assert.Equal(t, test.statusCode, resp.StatusCode)
			}
		})
	}
}

var w3links = []struct {
	domain     string
	path       string
	mt         string
	expect     string
	statusCode int
}{
	// subdomain
	{"quark.w3q.w3q-g.w3link.io", "/index.txt", "text/plain; charset=utf-8", "hello, world", http.StatusOK},
	{"quark.w3q.w3q-g.w3link.io:80", "/index.txt", "text/plain; charset=utf-8", "hello, world", http.StatusOK},
	{"0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9.w3q-g.w3link.io", "/index.txt", "text/plain; charset=utf-8", "hello, world", http.StatusOK},
	// no default chain for w3link
	{"quark.w3link.io", "/index.txt", "", "", http.StatusBadRequest},
	// [name].[tld].[chain id or short name].w3link.io
	{"concat.w3q.w3q-g.w3link.io", "/concat/bytes!0x61/bytes!0x62/bytes!0x63?returns=(string)", "application/json", "[\"abc\"]", http.StatusOK},
	{"concat.w3q.3334.w3link.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"Galileo\",true]", http.StatusOK},
	{"concat.w3q.w3link.io", "/retrieve?returns=(uint256,string,bool)", "", "", http.StatusBadRequest},
	{"concat.w3link.io", "/retrieve?returns=(uint256,string,bool)", "", "", http.StatusBadRequest},
	{"usdt.w3q.3334.w3link.io", "/balanceOf/0x8f315cEBD2Eb6304a49d50D551608ffD06C8810a?returns=(uint256)", "application/json", "[\"0x9184e729fff\"]", http.StatusOK},
	{"usdt.w3q.3334.w3link.io", "/balanceOf/address!charles.w3q?returns=()", "application/json", "[\"0x000000000000000000000000000000000000000000000000000009184e729fff\"]", http.StatusOK},
	{"usdt.w3q.3334.w3link.io", "/balanceOf/address!charles.w3q?returns=(uint256)", "application/json", "[\"0x9184e729fff\"]", http.StatusOK},
	// ethereum
	// {"quark.eth.gor.w3link.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"goerli\",true]", http.StatusOK},
	// {"quark.eth.5.w3link.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"goerli\",true]", http.StatusOK},
	// {"ethstorage.eth.gor.w3link.io", "/hello.txt", "text/plain; charset=utf-8", "hello! ethstorage!", http.StatusOK},
	// {"w3eth.eth.gor.w3link.io", "/symbol?returns=(string)", "application/json", "[\"UNI-V3-POS\"]", http.StatusOK},
	{"ethstorage.eth.w3link.io", "/hello.txt", "", "", http.StatusBadRequest},
	// wrong chain
	{"quark.eth.w3q-g.w3link.io", "/files/index.txt", "", "", http.StatusBadRequest},
	// wrong domain
	// {"quarkk.eth.5.w3link.io", "/files/index.txt", "", "", http.StatusNotFound},
	// wrong suffix
	{"quark.w4q.3334.w3link.io", "/index.txt", "", "", http.StatusBadRequest},
	// back compatible with hosted dweb files
	{"concat.w3q.3334.w3link.io", "/concat.w3q/concat/bytes!0x61/bytes!0x62/bytes!0x63?returns=(string)", "application/json", "[\"abc\"]", http.StatusOK},
	// address as subdomain is supported
	{"0x17BCDdfD83bBA0dBed86Ca8b7444145A3ee3acad.w3q-g.w3link.io", "/balanceOf/address!charles.w3q?returns=(uint256)", "application/json", "[\"0x9184e729fff\"]", http.StatusOK},
	{"0x17BCDdfD83bBA0dBed86Ca8b7444145A3ee3acad.w3link.io", "/balanceOf/address!charles.w3q?returns=(uint256)", "application/json", "[\"0x9184e729fff\"]", http.StatusBadRequest},
	// IP address banned
	{"111.111.111.111", "/quark.w3q/index.txt", "", "", http.StatusBadRequest},
	{"111.111.111.111:80", "/quark.w3q/index.txt", "", "", http.StatusBadRequest},
	// contract address
	{"0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.sep.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Ether\"]", http.StatusOK},
	{"0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.11155111.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Ether\"]", http.StatusOK},
	// l2
	// {"w3link.eth.gor.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]", http.StatusOK},
	{"0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8.arb1.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]", http.StatusOK},
	{"0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8.42161.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.oeth.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.10.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]", http.StatusOK},
	// {"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.ogor.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]", http.StatusOK},
	// {"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.420.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]", http.StatusOK},
	// {"0x0997fb92ee366c93d66fF43ba337ACA94F56EAe0.421613.w3link.io", "/totalSupply?returns=(uint256)", "application/json", "[\"0x2386f26fc10000\"]", http.StatusOK},
	// {"0x0997fb92ee366c93d66fF43ba337ACA94F56EAe0.arb-goerli.w3link.io", "/totalSupply?returns=(uint256)", "application/json", "[\"0x2386f26fc10000\"]", http.StatusOK},
	// {"0xae95d4890bf4471501e0066b6c6244e1caaee791.evmos-testnet.w3link.io", "/name?returns=(string)", "application/json", "[\"USDC Mock\"]", http.StatusOK}, // RPC looks dead
	// {"0xae95d4890bf4471501e0066b6c6244e1caaee791.9000.w3link.io", "/name?returns=(string)", "application/json", "[\"USDC Mock\"]", http.StatusOK}, // RPC looks dead
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
	{"0xf1277d1ed8ad466beddf92ef448a132661956621.4002.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Fantom\"]", http.StatusOK},
	{"0xf1277d1ed8ad466beddf92ef448a132661956621.tftm.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Fantom\"]", http.StatusOK},
	{"0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.1666600000.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped ONE\"]", http.StatusOK},
	{"0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.hmy-s0.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped ONE\"]", http.StatusOK},
	{"0xc9c8ba8c7e2eaf43e84330db08915a8106d7bd74.1666700000.w3link.io", "/name?returns=(string)", "application/json", "[\"E2E_TEST_TOKEN\"]", http.StatusOK},
	{"0xc9c8ba8c7e2eaf43e84330db08915a8106d7bd74.hmy-b-s0.w3link.io", "/name?returns=(string)", "application/json", "[\"E2E_TEST_TOKEN\"]", http.StatusOK},
	{"0x0000000000000000000000000000000000001010.137.w3link.io", "/name?returns=(string)", "application/json", "[\"Matic Token\"]", http.StatusOK},
	{"0x0000000000000000000000000000000000001010.matic.w3link.io", "/name?returns=(string)", "application/json", "[\"Matic Token\"]", http.StatusOK},
	// {"0x431e9631cda6da17acb3ff3784df6cebed86b5f4.80001.w3link.io", "/name?returns=(string)", "application/json", "[\"MaticTest\"]", http.StatusOK},
	// {"0x431e9631cda6da17acb3ff3784df6cebed86b5f4.maticmum.w3link.io", "/name?returns=(string)", "application/json", "[\"MaticTest\"]", http.StatusOK},
	// {"0x6091F52B352Ea22a34d8a89812BA1f85D197F877.1402.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin\"]\n", http.StatusOK},
	// {"0x6091F52B352Ea22a34d8a89812BA1f85D197F877.zkevmtest.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin\"]\n", http.StatusOK},
	{"0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.100001.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKC\"]", http.StatusOK},
	{"0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.qkc-s0.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKC\"]", http.StatusOK},
	// {"0xF2Fa1B7C11c33BAC1dB7b037478453289AC90E60.110001.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKCDev\"]", http.StatusOK}, // Disabled due to RPC timeout
	// {"0xF2Fa1B7C11c33BAC1dB7b037478453289AC90E60.qkc-d-s0.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKCDev\"]", http.StatusOK}, // Disabled due to RPC timeout
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.metis-andromeda.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]", http.StatusOK},
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.1088.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]", http.StatusOK},
	// {"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.metis-goerli.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]", http.StatusOK},
	// {"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.599.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]", http.StatusOK},
	// {"0x6b57e328a83e91CD7721b06F8C72f4977aD4896D.scr-testl1.w3link.io", "/name?returns=(string)", "application/json", "[\"Scroll Tast1\"]\n", http.StatusOK},
	// {"0x6b57e328a83e91CD7721b06F8C72f4977aD4896D.534351.w3link.io", "/name?returns=(string)", "application/json", "[\"Scroll Tast1\"]\n", http.StatusOK},
	// {"0x91034bA7F184C40745321A10e00f4aBC5E0f1bB5.scr-prealpha.w3link.io", "/name?returns=(string)", "application/json", "[\"SCROLLOG\"]\n", http.StatusOK},
	// {"0x91034bA7F184C40745321A10e00f4aBC5E0f1bB5.534354.w3link.io", "/name?returns=(string)", "application/json", "[\"SCROLLOG\"]\n", http.StatusOK},
	// {"0x6bfcc5feef5ce1049e409df0e1072ca988d62612.84531.w3link.io", "/symbol?returns=(string)", "application/json", "[\"Base\"]", http.StatusOK},
	// {"0x6bfcc5feef5ce1049e409df0e1072ca988d62612.basegor.w3link.io", "/symbol?returns=(string)", "application/json", "[\"Base\"]", http.StatusOK},
	{"0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed.base.w3link.io", "/symbol?returns=(string)", "application/json", "[\"DEGEN\"]", http.StatusOK},
	{"0x4ed4E862860beD51a9570b96d89aF5E1B0Efefed.8453.w3link.io", "/symbol?returns=(string)", "application/json", "[\"DEGEN\"]", http.StatusOK},
	{"0x87a9636ab208e6861d0b7c039a14d5af67a337cd.1513.w3link.io", "/name?returns=(string)", "application/json", "[\"Programmable IP License Token\"]", http.StatusOK},
	{"0x87a9636ab208e6861d0b7c039a14d5af67a337cd.storyprotocoltest.w3link.io", "/name?returns=(string)", "application/json", "[\"Programmable IP License Token\"]", http.StatusOK},
	{"ordinals.btc.w3link.io", "/number/234524", "text/plain; charset=utf-8", "{\"p\":\"sns\",\"op\":\"reg\",\"name\":\"0278.sats\"}", http.StatusOK},
	{"ordinals.btc.w3link.io", "/txid/4d4a4a3397c62ae43889d40d7f8410b0209db59d2afba97850b0f6e11c060922i0", "text/plain; charset=utf-8", "{\"p\":\"sns\",\"op\":\"reg\",\"name\":\"0278.sats\"}", http.StatusOK},
	{"ordinals.btc.w3link.io", "/number1/234524", "", "", http.StatusBadRequest},
	{"ordinals.btc.w3link.io", "/txid/4d4a4a3397c62ae43889d40d7f8410b0209db59d2afba97850b0f6e11c060922i0/", "", "", http.StatusBadRequest},
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
				assert.Equal(t, test.mt, res.Header.Get("Content-Type"))
				assert.Equal(t, test.expect, string(data))
			} else {
				assert.Equal(t, test.statusCode, res.StatusCode)
			}
		})
	}
}

var w3eths = []struct {
	domain     string
	path       string
	mt         string
	expect     string
	statusCode int
}{

	{"quark.w3eth.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"goerli\",true]", http.StatusOK},
	{"0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699.w3eth.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"0xbc4ff2\",\"goerli\",true]", http.StatusOK},
	{"ethstorage.w3eth.io", "/hello.txt", "text/plain; charset=utf-8", "hello! ethstorage!", http.StatusOK},
	{"eth-store.eth.w3eth.io", "/", "", "", http.StatusBadRequest},
	{"ethstorage.eth.gor.w3eth.io", "/hello.txt", "", "", http.StatusBadRequest},
}

func TestW3eths(t *testing.T) {
	config.DefaultChain = 5
	for _, test := range w3eths {
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
				assert.Equal(t, test.mt, res.Header.Get("Content-Type"))
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
	{56, "0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io", "/name?returns=(string)", "[\"BUSD Token\"]", http.StatusOK},
	{56, "w3bnb.io", "/0xe9e7cea3dedca5984780bafc599bd69add087d56:56/name?returns=(string)", "[\"BUSD Token\"]", http.StatusOK},
	{43114, "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7.w3avax.io", "/name?returns=(string)", "[\"Wrapped AVAX\"]", http.StatusOK},
	{43114, "w3avax.io", "/0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7:43114/name?returns=(string)", "[\"Wrapped AVAX\"]", http.StatusOK},
	{9001, "0xc5e00d3b04563950941f7137b5afa3a534f0d6d6.w3evmos.io", "/name?returns=(string)", "[\"Cosmos Hub\"]", http.StatusOK},
	{9001, "w3evmos.io", "/0xc5e00d3b04563950941f7137b5afa3a534f0d6d6:9001/name?returns=(string)", "[\"Cosmos Hub\"]", http.StatusOK},
	{250, "0x69c744d3444202d35a2783929a0f930f2fbb05ad.w3ftm.io", "/name?returns=(string)", "[\"Staked FTM\"]", http.StatusOK},
	{250, "w3ftm.io", "/0x69c744d3444202d35a2783929a0f930f2fbb05ad/name?returns=(string)", "[\"Staked FTM\"]", http.StatusOK},
	// {1666600000, "0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.w3one.io", "/name?returns=(string)", "[\"Wrapped ONE\"]", http.StatusOK}, // Disable due to bad RPC/"input" ignored
	// {1666600000, "w3one.io", "/0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a/name?returns=(string)", "[\"Wrapped ONE\"]", http.StatusOK}, // Disable due to bad RPC/"input" ignored
	{137, "0x0000000000000000000000000000000000001010.w3matic.io", "/name?returns=(string)", "[\"Matic Token\"]", http.StatusOK},
	{137, "w3matic.io", "/0x0000000000000000000000000000000000001010/name?returns=(string)", "[\"Matic Token\"]", http.StatusOK},
	// {100001, "0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.w3qkc.io", "/greet?returns=(string)", "[\"Hello QKC\"]", http.StatusOK}, // Disable due to bad RPC/"input" ignored
	// {100001, "w3qkc.io", "/0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5/greet?returns=(string)", "[\"Hello QKC\"]", http.StatusOK}, // Disable due to bad RPC/"input" ignored
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
	chainId    int
	domain     string
	path       string
	mt         string
	statusCode int
}{
	{1, "cyberbrokers-meta.w3eth.io", "/renderBroker/5", "", http.StatusOK},
	// use mime if specified
	{1, "cyberbrokers-meta.w3eth.io", "/renderBroker/5?mime.content=image%2Fsvg%2Bxml", "image/svg+xml", http.StatusOK},
	{1, "0x4e1f41613c9084fdb9e34e11fae9412427480e56.w3eth.io", "/tokenSVG/1?mime.type=svg", "image/svg+xml", http.StatusOK},
	// mime.type overrides mime.content
	{1, "0x4e1f41613c9084fdb9e34e11fae9412427480e56.w3eth.io", "/tokenSVG/1?mime.content=image/svg%2Bxml&mime.type=htm", "text/html; charset=utf-8", http.StatusOK},
	// returns overrides mime
	{1, "0x4e1f41613c9084fdb9e34e11fae9412427480e56.w3eth.io", "/tokenByIndex/1?returns=(uint256)&mime.type=xml", "application/json", http.StatusOK},
	// use extention of last param if no mime specified
	{3334, "0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string!10.svg", "image/svg+xml", http.StatusOK},
	// mime overrides extention
	{3334, "0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string!10.svg?mime.type=html", "text/html; charset=utf-8", http.StatusOK},
	// mime.type is ignored if cannot find the corresponding content type
	{3334, "0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string!10.svg?mime.type=foo", "image/svg+xml", http.StatusOK},
	// use mime.content if mime.type cannot find the corresponding content type
	{3334, "0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string!10.svg?mime.content=application%2Fvnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", http.StatusOK},
}

func TestMimeTypes(t *testing.T) {
	for _, test := range mimeTypeUrls {
		config.DefaultChain = test.chainId
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

var (
	composecalldata = "0x85609b1c0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b706f6472c3a1732e737667000000000000000000000000000000000000000000"
	the5219calldata = "0x1374c460000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000006612462632b6400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000162000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e5b8810000000000000000000000000000000000000000000000000000000000"
)
var decodingTestLinks = []struct {
	domain              string
	path                string
	mode                string
	returns             string
	calldata            string
	expectCalldataEqual bool
}{
	// remain encoded for manual mode to pass calldata
	{"quark.w3q.w3q-g.w3link.io", "/y%C3u%40here.txt", "manual", "", hexutil.Encode([]byte("/y%C3u%40here.txt")), true},
	// not same calldata as decoded one
	{"quark.w3q.w3q-g.w3link.io", "/y%C3u%40here.txt", "manual", "", hexutil.Encode([]byte("/yöu@here.txt")), false},
	{"0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9.w3q-g.w3link.io", "/y%C3u%40here.txt", "manual", "", hexutil.Encode([]byte("/yöu@here.txt")), false},
	//make sure hosted website resources work on w3link.io. e.g., http://w3box.w3q.w3q-g.w3link.io/css/app~748942c6.5e9ce3e0.css
	{"w3box.w3q.w3q-g.w3link.io", "/css/app~748942c6.5e9ce3e0.css", "manual", "", hexutil.Encode([]byte("/css/app~748942c6.5e9ce3e0.css")), true},
	{"0x1499A319278e81390d2F32afA3Ab08617d5E8c0D.w3q-g.w3link.io", "/css/app~748942c6.5e9ce3e0.css", "manual", "", hexutil.Encode([]byte("/css/app~748942c6.5e9ce3e0.css")), true},
	{"w3link.io", "/quark.w3q:w3q-g/y%C3u%40here.txt", "manual", "", hexutil.Encode([]byte("/y%C3u%40here.txt")), true},
	{"w3link.io", "/0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9:w3q-g/y%C3u%40here.txt", "manual", "", hexutil.Encode([]byte("/y%C3u%40here.txt")), true},

	// make sure hosted website resources work on w3eth.io. e.g., https://w3url.w3eth.io/css/app~d0ae3f07.e6592741.css
	{"w3url.w3eth.io", "/css/app~d0ae3f07.e6592741.css", "manual", "", hexutil.Encode([]byte("/css/app~d0ae3f07.e6592741.css")), true},
	{"w3eth.io", "/w3url.eth/css/app~d0ae3f07.e6592741.css", "manual", "", hexutil.Encode([]byte("/css/app~d0ae3f07.e6592741.css")), true},

	// decoded for auto mode, so encoded has same return type and calldata as unencoded
	{"w3eth.eth.gor.w3link.io", "/symbol?returns=(string)", "auto", "string", "0x95d89b41", true},
	{"w3eth.eth.gor.w3link.io", "/symbol?returns=%28string%29", "auto", "string", "0x95d89b41", true},
	// {"w3link.io", "/test.w3q-%3E(bytes%5B%5D%5B%5D)/getA", "auto", "(bytes[][])", "0xd46300fd", true},
	// These 2 trigger an out of gas error
	// {"0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string!podrás.svg", "auto", "(bytes)", composecalldata, true},
	// {"0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string%21podr%c3%a1s.svg", "auto", "(bytes)", composecalldata, true},

	// decoded for 5219 mode so encoded has same calldata as unencoded; if >2 params are provided the calldata is not stable because the order is random
	{"0x6587e67F1FBEAabDEe8b70EFb396E750e216283B.w3q-g.w3link.io", "/a$bc+d?b=%e5%b8%81", "resourceRequest", "", the5219calldata, true},
	{"0x6587e67F1FBEAabDEe8b70EFb396E750e216283B.w3q-g.w3link.io", "/a%24bc%2bd?b=%e5%b8%81", "resourceRequest", "", the5219calldata, true},
}

func TestEncoded(t *testing.T) {
	for _, test := range decodingTestLinks {
		if strings.Contains(test.domain, "w3eth.io") {
			config.DefaultChain = 1
			config.NSDefaultChains["eth"] = 1
			config.NSDefaultChains["w3q"] = 333

			ensConfig := web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceENS]
			ensConfig.DefaultChainId = 1
			web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceENS] = ensConfig

			w3nsConfig := web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceW3NS]
			w3nsConfig.DefaultChainId = 333
			web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceW3NS] = w3nsConfig
		} else {
			config.DefaultChain = 0
			config.NSDefaultChains["eth"] = 5
			config.NSDefaultChains["w3q"] = 3334

			ensConfig := web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceENS]
			ensConfig.DefaultChainId = 5
			web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceENS] = ensConfig

			w3nsConfig := web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceW3NS]
			w3nsConfig.DefaultChainId = 3334
			web3protocolClient.Config.DomainNameServices[web3protocol.DomainNameServiceW3NS] = w3nsConfig
		}
		t.Run(test.domain+test.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", test.path, nil)
			req.Host = test.domain
			w := httptest.NewRecorder()
			handle(w, req)
			res := w.Result()
			defer res.Body.Close()
			assert.Equal(t, test.mode, res.Header.Get("Web3-Resolve-Mode"))
			assert.Equal(t, test.returns, res.Header.Get("Web3-Json-Encoded-Value-Types"))
			if test.expectCalldataEqual {
				assert.Equal(t, test.calldata, res.Header.Get("Web3-Calldata"))
			} else {
				assert.NotEqual(t, test.calldata, res.Header.Get("Web3-Calldata"))
			}
		})
	}
}
