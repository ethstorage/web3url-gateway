package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"os"
	"bufio"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
	"github.com/naoina/toml"

	"github.com/ethstorage/web3url-gateway/pkg/web3protocol"
)

func init() {
	err := loadConfig("../../config.toml", &config)
	if err != nil {
		panic(err)
	}
	config.NSDefaultChains["eth"] = 5
	config.NSDefaultChains["w3q"] = 3334
	config.DefaultChain = 3334
}

type AbiType struct {
	Type string
}

type TestError struct {
	Label string
	HttpCode int
}

type Test struct {
	Name string
	Url string

	ContractAddress common.Address
	ChainId int

	HostDomainNameResolver web3protocol.DomainNameService
	HostDomainNameResolverChainId int
	
	ResolveMode web3protocol.ResolveMode
	ContractCallMode web3protocol.ContractCallMode

	Calldata string
	
	MethodName string
	MethodArgs []AbiType
	MethodArgValues []interface{}
	MethodReturn []AbiType
	
	ContractReturnProcessing web3protocol.ContractReturnProcessing
	FirstValueAsBytesMimeType string
	Error TestError
}

type TestGroup struct {
	Name string
	Standard string
	Tests []Test
}

type TestGroups struct {
	Name      string
	Groups map[string]TestGroup
	// Name2Chain      map[string]string
	// ChainConfigs    map[string]ChainConfig
}

func TestSuite(t *testing.T) {
	// file := "../../tests/mode-manual.toml"
	file := "../../tests/mode-auto.toml"
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer func(f *os.File) {
		err = f.Close()
	}(f)

	testGroups := TestGroups{}
	err = toml.NewDecoder(bufio.NewReader(f)).Decode(&testGroups)
	if _, ok := err.(*toml.LineError); ok {
		err = fmt.Errorf(file + ", " + err.Error())
		panic(err)
	}
// fmt.Printf("%+v\n\n", testGroups)

	for _, testGroup := range testGroups.Groups {
		for _, test := range testGroup.Tests {
			testName := fmt.Sprintf("%v/%v/%v/%v", testGroups.Name, testGroup.Name, test.Name, test.Url)
			t.Run(testName, func(t *testing.T) {

				client := web3protocol.NewClient()
				client.Config.ChainConfigs = config.ChainConfigs
				client.Config.Name2Chain = config.Name2Chain

				parsedUrl, err := client.ParseUrl(test.Url)

				if err == nil {
					// If we were expecting an error, fail
					if test.Error.Label != "" || test.Error.HttpCode > 0 {
						assert.Fail(t, "An error was expected")
					}

					if test.ContractAddress.Hex() != "0x0000000000000000000000000000000000000000" {
						assert.Equal(t, test.ContractAddress, parsedUrl.ContractAddress)
					}
					if test.ChainId > 0 {
						assert.Equal(t, test.ChainId, parsedUrl.ChainId)
					}
					
					if test.HostDomainNameResolver != "" {
						assert.Equal(t, test.HostDomainNameResolver, parsedUrl.HostDomainNameResolver)
					}
					if test.HostDomainNameResolverChainId > 0 {
						assert.Equal(t, test.HostDomainNameResolverChainId, parsedUrl.HostDomainNameResolverChainId)
					}

					if test.ResolveMode != "" {
						assert.Equal(t, test.ResolveMode, parsedUrl.ResolveMode)
					}
					if test.ContractCallMode != "" {
						assert.Equal(t, test.ContractCallMode, parsedUrl.ContractCallMode)
					}
					
					if test.Calldata != "" {
						testCalldata, err := hexutil.Decode(test.Calldata)
						if err != nil {
							panic(err)
						}
						assert.Equal(t, testCalldata, parsedUrl.Calldata)
					}

					if test.MethodName != "" {
						assert.Equal(t, test.MethodName, parsedUrl.MethodName)
					}
					if len(test.MethodArgs) > 0 {
						assert.Equal(t, len(test.MethodArgs), len(parsedUrl.MethodArgs), "Unexpected number of arguments")
						for i, methodArg := range test.MethodArgs {
							assert.Equal(t, methodArg.Type, parsedUrl.MethodArgs[i].String())
						}
					}
					if len(test.MethodArgValues) > 0 {
						assert.Equal(t, len(test.MethodArgValues), len(parsedUrl.MethodArgValues), "Unexpected number of argument values")
						for i, methodArgValue := range test.MethodArgValues {
							switch methodArgValue.(type) {
								// Convert into to bigint
								case int64:
									newValue := new(big.Int)
									newValue.SetInt64(methodArgValue.(int64))
									methodArgValue = newValue
							}
							switch test.MethodArgs[i].Type {
								case "bytes32":
									methodArgValue = common.HexToHash(methodArgValue.(string))
							}
							assert.Equal(t, methodArgValue, parsedUrl.MethodArgValues[i])
						}
					}

					if test.ContractReturnProcessing != "" {
						assert.Equal(t, test.ContractReturnProcessing, parsedUrl.ContractReturnProcessing)
					}
					if test.FirstValueAsBytesMimeType != "" {
						assert.Equal(t, test.FirstValueAsBytesMimeType, parsedUrl.FirstValueAsBytesMimeType)
					}
				} else { // err != nil
					// If no error was expected, fail
					if test.Error.Label == "" && test.Error.HttpCode == 0 {
						assert.Fail(t, "Unexpected error", err)
					}

					if test.Error.Label != "" {
						assert.Equal(t, test.Error.Label, err.Error())
					}
					if test.Error.HttpCode > 0 {
						if web3Err, ok := err.(*web3protocol.Web3Error); ok {
							assert.Equal(t, web3Err.HttpCode, test.Error.HttpCode)
						} else {
							assert.Fail(t, "Error is unexpectly not a Web3Error", err)
						}
					}
				}



// fmt.Printf("\nParsedUrl: %+v\n", parsedUrl)

				
			})
		}
	}
}

func TestParseWeb3URL(t *testing.T) {
	var testCases = []struct {
		input  string
		expect Web3URL
		err    bool
	}{
		// with or without chainId
		{"/quark.w3q/files/index.txt",
			Web3URL{
				Contract:    common.HexToAddress("0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9"),
				NSChain:     3334,
				TargetChain: 3334,
				RawPath:     "/files/index.txt",
				Arguments:   []string{"files", "index.txt"},
				NSType:      "W3NS",
			},
			false,
		},
		// empty path handling
		{"/0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9/",
			Web3URL{
				Contract:    common.HexToAddress("0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9"),
				NSChain:     3334,
				TargetChain: 3334,
				RawPath:     "/",
				Arguments:   []string{""},
				NSType:      "Address",
			},
			false,
		},
		{"/quark.w3q",
			Web3URL{
				Contract:    common.HexToAddress("0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9"),
				NSChain:     3334,
				TargetChain: 3334,
				RawPath:     "",
				Arguments:   []string{},
				NSType:      "W3NS",
			},
			false,
		},

		{"/quark.w3q//",
			Web3URL{
				Contract:    common.HexToAddress("0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9"),
				NSChain:     3334,
				TargetChain: 3334,
				RawPath:     "//",
				Arguments:   []string{"", ""},
				NSType:      "W3NS",
			},
			false,
		},
		{"/quark.w3q:w3q-g/",
			Web3URL{
				Contract:    common.HexToAddress("0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9"),
				NSChain:     3334,
				TargetChain: 3334,
				RawPath:     "/",
				Arguments:   []string{""},
				NSType:      "W3NS",
			},
			false,
		},
		{"/quark.eth:gor->(uint256,string,bool)/retrieve",
			Web3URL{
				Contract:    common.HexToAddress("0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699"),
				NSChain:     5,
				TargetChain: 5,
				RawPath:     "/retrieve",
				Arguments:   []string{"retrieve"},
				ReturnType:  "(uint256,string,bool)",
				NSType:      "ENS",
			},
			false,
		},
	}
	for _, test := range testCases {
		t.Run(test.input, func(t *testing.T) {
			url, e := parseWeb3URL(test.input)
			if test.err {
				assert.NotEqual(t, 0, e.code)
				return
			}
			assert.Equal(t, test.expect, url)
		})
	}
}

func TestParseArgument(t *testing.T) {
	type output struct {
		arg    interface{}
		T      byte
		ty_str string
		err    error
	}

	var testCases = []struct {
		input  string
		expect output
	}{
		// uint types
		{"uint256!1!2", output{"", 0, "", errors.New("argument wrong format")}},
		{"uint256!abc", output{"", 0, "", errors.New("argument is not a number")}},
		{"uint128!1", output{"", 0, "", errors.New("unknown type")}},
		{"uint256!0x1", output{big.NewInt(1), abi.UintTy, "uint256", nil}},
		// bytes types
		{"address!0x" + strings.Repeat("0", 39) + "1", output{common.HexToAddress("0x1"), abi.AddressTy, "address", nil}},
		{"bytes!0x01", output{[]byte{0x1}, abi.BytesTy, "bytes", nil}},
		{"bytes!0xab", output{[]byte{0xab}, abi.BytesTy, "bytes", nil}},
		{"bytes32!1", output{"", 0, "", errors.New("argument is not a valid hex string")}},
		{"bytes!0x1", output{"", 0, "", errors.New("argument is not a valid hex string")}},
		{"bytes!1a", output{"", 0, "", errors.New("argument is not a valid hex string")}},
		// auto detect
		{"0x1", output{"", abi.AddressTy, "address", errors.New("invalid domain")}},
		{"1", output{big.NewInt(1), abi.UintTy, "uint256", nil}},
		{"0x" + strings.Repeat("0", 39) + "1", output{common.HexToAddress("0x1"), abi.AddressTy, "address", nil}},
		{"0x" + strings.Repeat("0", 63) + "1", output{common.HexToHash("0x1"), abi.FixedBytesTy, "bytes32", nil}},
		{"0xabcd", output{[]byte{0xab, 0xcd}, abi.BytesTy, "bytes", nil}},
		// dynamic length
		{"string!abc", output{"abc", abi.StringTy, "string", nil}},
		// empty values
		{"0x1", output{"", abi.AddressTy, "address", errors.New("invalid domain")}},
	}
	for _, test := range testCases {
		t.Run(test.input, func(t *testing.T) {
			ty, tystr, value, err := parseArgument(test.input, "")
			if test.expect.err != nil {
				assert.True(t, strings.HasPrefix(err.Error(), test.expect.err.Error()))
			} else {
				assert.Equal(t, test.expect.T, ty.T)
				assert.Equal(t, test.expect.ty_str, tystr)
				assert.Equal(t, test.expect.arg, value)
			}
		})
	}
}

func TestGetAddress(t *testing.T) {
	// var testCases = []struct {
	// 	chainId    string
	// 	domain     string
	// 	expect     string
	// 	webHandler bool
	// }{
	// 	// not use web handler
	// 	{"3334", "quark.w3q", "0x6D4a199f603b084a2f1761Dc9F322F92E68bfd5E", false},
	// 	// user Web handler
	// 	{"3334", "quark.w3q", "0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9", true},
	// 	// skip deprecated key and fallback to address
	// 	{"5", "quark.eth", "0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699", true},
	// 	// text key is contentcontract, prefix is w3q-g: fallback to address
	// 	{"5", "ethstorage.eth", "0x79550b825Ef3D7B1f825BE9965FaE80BdF77A7e2", true},
	// 	// text key is contentcontract, prefix is w3q-g:
	// 	{"5", "testcontentcontract.eth", "0xBccb33C4D28AB444E22F3519736270a3bA412d9b", true},
	// 	// direct mapping if not web handler
	// 	{"1", "terraformnavigator.eth", "0x9A595bc28F1c40ab96247E8157A2b0A6762E7543", false},
	// 	// fall back to addr using web handler
	// 	{"1", "terraformnavigator.eth", "0x9A595bc28F1c40ab96247E8157A2b0A6762E7543", true},
	// }
	// var addr common.Address
	// var err Web3Error
	// for _, test := range testCases {
	// 	t.Run(test.expect, func(t *testing.T) {
	// 		if test.webHandler {
	// 			addr, _, err = getAddressFromNameServiceWebHandler(test.chainId, test.domain)
	// 		} else {
	// 			addr, _, err = getAddressFromNameService(test.chainId, test.domain)
	// 		}
	// 		assert.Equal(t, 0, err.code)
	// 		assert.Equal(t, test.expect, addr.Hex())
	// 	})
	// }
}

func TestCheckResolveMode(t *testing.T) {
	var testCases = []struct {
		addr   string
		expect int
	}{
		{"0x17BCDdfD83bBA0dBed86Ca8b7444145A3ee3acad", ResolveModeAuto},
	}
	for _, test := range testCases {
		w3url := Web3URL{
			Contract:    common.HexToAddress(test.addr),
			TargetChain: 3334,
		}
		t.Run(fmt.Sprintf("Resolve mode:%d", test.expect), func(t *testing.T) {
			assert.Equal(t, test.expect, checkResolveMode(w3url))
		})
	}
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
	{"localhost", "/concat.w3q->(string)/concat/bytes!0x61/bytes!0x62/bytes!0x63", "application/json", "[\"abc\"]\n", http.StatusOK},
	{"localhost", "/concat.w3q/concat/bytes!0x61/bytes!0x62/bytes!0x63?returnTypes=(string)", "application/json", "[\"abc\"]\n", http.StatusOK},
	{"localhost", "/concat.w3q->(string)/concat/bytes!0x/bytes!0x/bytes!0x", "application/json", "[\"\"]\n", http.StatusOK},
	{"localhost", "/concat.w3q/concat/bytes!0x/bytes!0x/bytes!0x?returnTypes=(string)", "application/json", "[\"\"]\n", http.StatusOK},
	{"localhost", "/concat.w3q->(uint256,string,bool)/retrieve", "application/json", "[\"12341234\",\"Galileo\",true]\n", http.StatusOK},
	{"localhost", "/concat.w3q/retrieve?returns=(uint256,string,bool)", "application/json", "[\"12341234\",\"Galileo\",true]\n", http.StatusOK},
	{"localhost", "/concat.w3q/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"12341234\",\"Galileo\",true]\n", http.StatusOK},
	// same return types
	{"localhost", "/concat.w3q->(uint256,string,bool)/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"12341234\",\"Galileo\",true]\n", http.StatusOK},
	{"localhost", "/usdt.w3q->(uint256)/balanceOf/0x8f315cEBD2Eb6304a49d50D551608ffD06C8810a", "application/json", "[\"9999999999999\"]\n", http.StatusOK},
	{"localhost", "/0x17BCDdfD83bBA0dBed86Ca8b7444145A3ee3acad:w3q-g->(uint256)/balanceOf/address!charles.w3q", "application/json", "[\"9999999999999\"]\n", http.StatusOK},
	{"localhost", "/usdt.w3q->()/balanceOf/address!charles.w3q", "application/json", "[\"0x000000000000000000000000000000000000000000000000000009184e729fff\"]\n", http.StatusOK},
	// array types and bytes processing
	{"localhost", "/test.w3q->(bytes[][])/getA", "application/json", "[[[\"0x61\"],[\"0x62\"]]]\n", http.StatusOK},
	{"localhost", "/test.w3q->(uint8[][][])/getB", "application/json", "[[[[\"0\"],[\"1\"]],[[\"2\"],[\"3\"]],[[\"4\"],[\"5\"]]]]\n", http.StatusOK},
	{"localhost", "/test.w3q->(bytes8[2][1])/getC", "application/json", "[[[\"0x6300000000000000\",\"0x6400000000000000\"]]]\n", http.StatusOK},
	{"localhost", "/test.w3q->(bytes32[2])/getD", "application/json", "[[\"0x7465737400000000000000000000000000000000000000000000000000000000\",\"0x6279746573000000000000000000000000000000000000000000000000000000\"]]\n", http.StatusOK},
	{"localhost", "/test.w3q->(address[2])/getE", "application/json", "[[\"0xd95fa5e8C8C6920430c0406f9A819576759911e3\",\"0x0000000000000000000000000000000000000000\"]]\n", http.StatusOK},
	{"localhost", "/test.w3q->(string[2])/getF", "application/json", "[[\"test\",\"string\"]]\n", http.StatusOK},
	{"localhost", "/test.w3q->(uint256[2])/getG", "application/json", "[[\"0\",\"115792089237316195423570985008687907853269984665640564039457584007913129639935\"]]\n", http.StatusOK},
	{"localhost", "/test.w3q->(bytes)/getH", "application/json", "[\"0x74657374\"]\n", http.StatusOK},
	{"localhost", "/test.w3q->(string)/getI", "application/json", "[\"test\\\"string\"]\n", http.StatusOK},
	// ethereum
	{"localhost", "/0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699:gor/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"12341234\",\"goerli\",true]\n", http.StatusOK},
	{"localhost", "/0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699:5/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"12341234\",\"goerli\",true]\n", http.StatusOK},
	{"localhost", "/quark.eth:gor/retrieve?returnTypes=(uint256,string,bool)", "application/json", "[\"12341234\",\"goerli\",true]\n", http.StatusOK},
	{"localhost", "/0x79550b825ef3d7b1f825be9965fae80bdf77a7e2:3334/hello.txt", "text/plain; charset=utf-8", "hello! ethstorage!", http.StatusOK},
	// wrong domain
	{"localhost", "/quarkd.w3q/files/index.txt", "", "", http.StatusBadRequest},
	// wrong suffix
	{"localhost", "/quark.w4q/index.txt", "", "", http.StatusBadRequest},
	// conflict return types
	{"localhost", "/concat.w3q->(uint256,string,bool)/retrieve?returnTypes=(uint256,string)", "", "", http.StatusBadRequest},
	// duplicate return attributes
	{"localhost", "/concat.w3q/retrieve?returnTypes=(uint256,string,bool)&returns=(uint256,string,bool)", "", "", http.StatusBadRequest},
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
			resp, err := http.Get("http://localhost" + test.path)
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
	{"concat.w3q.w3q-g.w3link.io", "/concat/bytes!0x61/bytes!0x62/bytes!0x63?returns=(string)", "application/json", "[\"abc\"]\n", http.StatusOK},
	{"concat.w3q.3334.w3link.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"12341234\",\"Galileo\",true]\n", http.StatusOK},
	{"concat.w3q.w3link.io", "/retrieve?returns=(uint256,string,bool)", "", "", http.StatusBadRequest},
	{"concat.w3link.io", "/retrieve?returns=(uint256,string,bool)", "", "", http.StatusBadRequest},
	{"usdt.w3q.3334.w3link.io", "/balanceOf/0x8f315cEBD2Eb6304a49d50D551608ffD06C8810a?returns=(uint256)", "application/json", "[\"9999999999999\"]\n", http.StatusOK},
	{"usdt.w3q.3334.w3link.io", "/balanceOf/address!charles.w3q?returns=()", "application/json", "[\"0x000000000000000000000000000000000000000000000000000009184e729fff\"]\n", http.StatusOK},
	{"usdt.w3q.3334.w3link.io", "/balanceOf/address!charles.w3q?returns=(uint256)", "application/json", "[\"9999999999999\"]\n", http.StatusOK},
	// ethereum
	{"quark.eth.gor.w3link.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"12341234\",\"goerli\",true]\n", http.StatusOK},
	{"quark.eth.5.w3link.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"12341234\",\"goerli\",true]\n", http.StatusOK},
	{"ethstorage.eth.gor.w3link.io", "/hello.txt", "text/plain; charset=utf-8", "hello! ethstorage!", http.StatusOK},
	{"w3eth.eth.gor.w3link.io", "/symbol?returns=(string)", "application/json", "[\"UNI-V3-POS\"]\n", http.StatusOK},
	{"ethstorage.eth.w3link.io", "/hello.txt", "", "", http.StatusBadRequest},
	// wrong chain
	{"quark.eth.w3q-g.w3link.io", "/files/index.txt", "", "", http.StatusBadRequest},
	// wrong domain
	{"quarkk.eth.5.w3link.io", "/files/index.txt", "", "", http.StatusBadRequest},
	// wrong suffix
	{"quark.w4q.3334.w3link.io", "/index.txt", "", "", http.StatusBadRequest},
	// if subdomain is specified, path should start with a method
	{"usdt.w3q.3334.w3link.io", "/0x17BCDdfD83bBA0dBed86Ca8b7444145A3ee3acad:w3q-g->(uint256)/balanceOf/address!charles.w3q", "", "", http.StatusBadRequest},
	{"concat.w3q.3334.w3link.io", "/concat.w3q:3334->(string)/concat/bytes!0x61/bytes!0x62/bytes!0x63", "", "", http.StatusBadRequest},
	{"concat.w3q.3334.w3link.io", "/->(string)/concat/bytes!0x61/bytes!0x62/bytes!0x63", "", "", http.StatusBadRequest},
	// back compatible with hosted dweb files
	{"concat.w3q.3334.w3link.io", "/concat.w3q/concat/bytes!0x61/bytes!0x62/bytes!0x63?returns=(string)", "application/json", "[\"abc\"]\n", http.StatusOK},
	// address as subdomain is supported
	{"0x17BCDdfD83bBA0dBed86Ca8b7444145A3ee3acad.w3q-g.w3link.io", "/balanceOf/address!charles.w3q?returns=(uint256)", "application/json", "[\"9999999999999\"]\n", http.StatusOK},
	{"0x17BCDdfD83bBA0dBed86Ca8b7444145A3ee3acad.w3link.io", "/balanceOf/address!charles.w3q?returns=(uint256)", "application/json", "[\"9999999999999\"]\n", http.StatusBadRequest},
	// IP address banned
	{"111.111.111.111", "/quark.w3q/index.txt", "", "", http.StatusBadRequest},
	{"111.111.111.111:80", "/quark.w3q/index.txt", "", "", http.StatusBadRequest},
	// contract address
	{"0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.sep.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Ether\"]\n", http.StatusOK},
	{"0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.11155111.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Ether\"]\n", http.StatusOK},
	// l2
	{"w3link.eth.gor.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]\n", http.StatusOK},
	{"0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8.arb1.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]\n", http.StatusOK},
	{"0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8.42161.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin (Arb1)\"]\n", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.oeth.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]\n", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.10.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]\n", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.ogor.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]\n", http.StatusOK},
	{"0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1.420.w3link.io", "/name?returns=(string)", "application/json", "[\"Dai Stablecoin\"]\n", http.StatusOK},
	{"0x0997fb92ee366c93d66fF43ba337ACA94F56EAe0.421613.w3link.io", "/totalSupply?returns=(uint256)", "application/json", "[\"10000000000000000\"]\n", http.StatusOK},
	{"0x0997fb92ee366c93d66fF43ba337ACA94F56EAe0.arb-goerli.w3link.io", "/totalSupply?returns=(uint256)", "application/json", "[\"10000000000000000\"]\n", http.StatusOK},
	{"0xae95d4890bf4471501e0066b6c6244e1caaee791.evmos-testnet.w3link.io", "/name?returns=(string)", "application/json", "[\"USDC Mock\"]\n", http.StatusOK},
	{"0xae95d4890bf4471501e0066b6c6244e1caaee791.9000.w3link.io", "/name?returns=(string)", "application/json", "[\"USDC Mock\"]\n", http.StatusOK},
	{"0xc5e00d3b04563950941f7137b5afa3a534f0d6d6.evmos.w3link.io", "/name?returns=(string)", "application/json", "[\"Cosmos Hub\"]\n", http.StatusOK},
	{"0xc5e00d3b04563950941f7137b5afa3a534f0d6d6.9001.w3link.io", "/name?returns=(string)", "application/json", "[\"Cosmos Hub\"]\n", http.StatusOK},
	{"0x2cE21976443622ab8F0B7F6fa3aF953ff9BCdCf6.arb-nova.w3link.io", "/name?returns=(string)", "application/json", "[\"Arbitrum Nova Gaming\"]\n", http.StatusOK},
	{"0x2cE21976443622ab8F0B7F6fa3aF953ff9BCdCf6.42170.w3link.io", "/name?returns=(string)", "application/json", "[\"Arbitrum Nova Gaming\"]\n", http.StatusOK},
	{"0xe9e7cea3dedca5984780bafc599bd69add087d56.56.w3link.io", "/name?returns=(string)", "application/json", "[\"BUSD Token\"]\n", http.StatusOK},
	{"0xe9e7cea3dedca5984780bafc599bd69add087d56.bnb.w3link.io", "/name?returns=(string)", "application/json", "[\"BUSD Token\"]\n", http.StatusOK},
	{"0xc5976c1ff6c550150293a31b5f9da787a3ebf5f0.97.w3link.io", "/name?returns=(string)", "application/json", "[\"FakeUSDC\"]\n", http.StatusOK},
	{"0xc5976c1ff6c550150293a31b5f9da787a3ebf5f0.bnbt.w3link.io", "/name?returns=(string)", "application/json", "[\"FakeUSDC\"]\n", http.StatusOK},
	{"0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7.43114.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped AVAX\"]\n", http.StatusOK},
	{"0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7.avax.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped AVAX\"]\n", http.StatusOK},
	{"0x2796BAED33862664c08B8Ee5Fa2D1283C79593b1.43113.w3link.io", "/name?returns=(string)", "application/json", "[\"wAVAX\"]\n", http.StatusOK},
	{"0x2796BAED33862664c08B8Ee5Fa2D1283C79593b1.fuji.w3link.io", "/name?returns=(string)", "application/json", "[\"wAVAX\"]\n", http.StatusOK},
	{"0x69c744d3444202d35a2783929a0f930f2fbb05ad.250.w3link.io", "/name?returns=(string)", "application/json", "[\"Staked FTM\"]\n", http.StatusOK},
	{"0x69c744d3444202d35a2783929a0f930f2fbb05ad.ftm.w3link.io", "/name?returns=(string)", "application/json", "[\"Staked FTM\"]\n", http.StatusOK},
	{"0xf1277d1ed8ad466beddf92ef448a132661956621.4002.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Fantom\"]\n", http.StatusOK},
	{"0xf1277d1ed8ad466beddf92ef448a132661956621.tftm.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped Fantom\"]\n", http.StatusOK},
	{"0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.1666600000.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped ONE\"]\n", http.StatusOK},
	{"0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.hmy-s0.w3link.io", "/name?returns=(string)", "application/json", "[\"Wrapped ONE\"]\n", http.StatusOK},
	{"0xc9c8ba8c7e2eaf43e84330db08915a8106d7bd74.1666700000.w3link.io", "/name?returns=(string)", "application/json", "[\"E2E_TEST_TOKEN\"]\n", http.StatusOK},
	{"0xc9c8ba8c7e2eaf43e84330db08915a8106d7bd74.hmy-b-s0.w3link.io", "/name?returns=(string)", "application/json", "[\"E2E_TEST_TOKEN\"]\n", http.StatusOK},
	{"0x0000000000000000000000000000000000001010.137.w3link.io", "/name?returns=(string)", "application/json", "[\"Matic Token\"]\n", http.StatusOK},
	{"0x0000000000000000000000000000000000001010.matic.w3link.io", "/name?returns=(string)", "application/json", "[\"Matic Token\"]\n", http.StatusOK},
	{"0x431e9631cda6da17acb3ff3784df6cebed86b5f4.80001.w3link.io", "/name?returns=(string)", "application/json", "[\"MaticTest\"]\n", http.StatusOK},
	{"0x431e9631cda6da17acb3ff3784df6cebed86b5f4.maticmum.w3link.io", "/name?returns=(string)", "application/json", "[\"MaticTest\"]\n", http.StatusOK},
	// {"0x6091F52B352Ea22a34d8a89812BA1f85D197F877.1402.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin\"]\n", http.StatusOK},
	// {"0x6091F52B352Ea22a34d8a89812BA1f85D197F877.zkevmtest.w3link.io", "/name?returns=(string)", "application/json", "[\"USD Coin\"]\n", http.StatusOK},
	{"0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.100001.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKC\"]\n", http.StatusOK},
	{"0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.qkc-s0.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKC\"]\n", http.StatusOK},
	{"0xF2Fa1B7C11c33BAC1dB7b037478453289AC90E60.110001.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKCDev\"]\n", http.StatusOK},
	{"0xF2Fa1B7C11c33BAC1dB7b037478453289AC90E60.qkc-d-s0.w3link.io", "/greet?returns=(string)", "application/json", "[\"Hello QKCDev\"]\n", http.StatusOK},
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.metis-andromeda.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]\n", http.StatusOK},
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.1088.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]\n", http.StatusOK},
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.metis-goerli.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]\n", http.StatusOK},
	{"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000.599.w3link.io", "/name?returns=(string)", "application/json", "[\"Metis Token\"]\n", http.StatusOK},
	// {"0x6b57e328a83e91CD7721b06F8C72f4977aD4896D.scr-testl1.w3link.io", "/name?returns=(string)", "application/json", "[\"Scroll Tast1\"]\n", http.StatusOK},
	// {"0x6b57e328a83e91CD7721b06F8C72f4977aD4896D.534351.w3link.io", "/name?returns=(string)", "application/json", "[\"Scroll Tast1\"]\n", http.StatusOK},
	// {"0x91034bA7F184C40745321A10e00f4aBC5E0f1bB5.scr-prealpha.w3link.io", "/name?returns=(string)", "application/json", "[\"SCROLLOG\"]\n", http.StatusOK},
	// {"0x91034bA7F184C40745321A10e00f4aBC5E0f1bB5.534354.w3link.io", "/name?returns=(string)", "application/json", "[\"SCROLLOG\"]\n", http.StatusOK},
	{"0x6bfcc5feef5ce1049e409df0e1072ca988d62612.84531.w3link.io", "/symbol?returns=(string)", "application/json", "[\"Base\"]\n", http.StatusOK},
	{"0x6bfcc5feef5ce1049e409df0e1072ca988d62612.basegor.w3link.io", "/symbol?returns=(string)", "application/json", "[\"Base\"]\n", http.StatusOK},
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

	{"quark.w3eth.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"12341234\",\"goerli\",true]\n", http.StatusOK},
	{"0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699.w3eth.io", "/retrieve?returns=(uint256,string,bool)", "application/json", "[\"12341234\",\"goerli\",true]\n", http.StatusOK},
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
	{56, "0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io", "/name?returns=(string)", "[\"BUSD Token\"]\n", http.StatusOK},
	{56, "w3bnb.io", "/0xe9e7cea3dedca5984780bafc599bd69add087d56:56/name?returns=(string)", "[\"BUSD Token\"]\n", http.StatusOK},
	{43114, "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7.w3avax.io", "/name?returns=(string)", "[\"Wrapped AVAX\"]\n", http.StatusOK},
	{43114, "w3avax.io", "/0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7:43114/name?returns=(string)", "[\"Wrapped AVAX\"]\n", http.StatusOK},
	{9001, "0xc5e00d3b04563950941f7137b5afa3a534f0d6d6.w3evmos.io", "/name?returns=(string)", "[\"Cosmos Hub\"]\n", http.StatusOK},
	{9001, "w3evmos.io", "/0xc5e00d3b04563950941f7137b5afa3a534f0d6d6:9001/name?returns=(string)", "[\"Cosmos Hub\"]\n", http.StatusOK},
	{250, "0x69c744d3444202d35a2783929a0f930f2fbb05ad.w3ftm.io", "/name?returns=(string)", "[\"Staked FTM\"]\n", http.StatusOK},
	{250, "w3ftm.io", "/0x69c744d3444202d35a2783929a0f930f2fbb05ad/name?returns=(string)", "[\"Staked FTM\"]\n", http.StatusOK},
	{1666600000, "0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a.w3one.io", "/name?returns=(string)", "[\"Wrapped ONE\"]\n", http.StatusOK},
	{1666600000, "w3one.io", "/0xcF664087a5bB0237a0BAd6742852ec6c8d69A27a/name?returns=(string)", "[\"Wrapped ONE\"]\n", http.StatusOK},
	{137, "0x0000000000000000000000000000000000001010.w3matic.io", "/name?returns=(string)", "[\"Matic Token\"]\n", http.StatusOK},
	{137, "w3matic.io", "/0x0000000000000000000000000000000000001010/name?returns=(string)", "[\"Matic Token\"]\n", http.StatusOK},
	{100001, "0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5.w3qkc.io", "/greet?returns=(string)", "[\"Hello QKC\"]\n", http.StatusOK},
	{100001, "w3qkc.io", "/0xc2f21F8F573Ab93477E23c4aBB363e66AE11Bac5/greet?returns=(string)", "[\"Hello QKC\"]\n", http.StatusOK},
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
	// content-type is detected by http.DetectContentType()
	{1, "cyberbrokers-meta.w3eth.io", "/renderBroker/5", "text/xml; charset=utf-8", http.StatusOK},
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
	{"quark.w3q.w3q-g.w3link.io", "/y%C3u%40here.txt", "manual", "(bytes)", hexutil.Encode([]byte("/y%C3u%40here.txt")), true},
	// not same calldata as decoded one
	{"quark.w3q.w3q-g.w3link.io", "/y%C3u%40here.txt", "manual", "(bytes)", hexutil.Encode([]byte("/yöu@here.txt")), false},
	{"0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9.w3q-g.w3link.io", "/y%C3u%40here.txt", "manual", "(bytes)", hexutil.Encode([]byte("/yöu@here.txt")), false},
	//make sure hosted website resources work on w3link.io. e.g., http://w3box.w3q.w3q-g.w3link.io/css/app~748942c6.5e9ce3e0.css
	{"w3box.w3q.w3q-g.w3link.io", "/css/app~748942c6.5e9ce3e0.css", "manual", "(bytes)", hexutil.Encode([]byte("/css/app~748942c6.5e9ce3e0.css")), true},
	{"0x1499A319278e81390d2F32afA3Ab08617d5E8c0D.w3q-g.w3link.io", "/css/app~748942c6.5e9ce3e0.css", "manual", "(bytes)", hexutil.Encode([]byte("/css/app~748942c6.5e9ce3e0.css")), true},
	{"w3link.io", "/quark.w3q:w3q-g/y%C3u%40here.txt", "manual", "(bytes)", hexutil.Encode([]byte("/y%C3u%40here.txt")), true},
	{"w3link.io", "/0xc934D34DF21dE61A62b3D12E929b65D0bCfaf8b9:w3q-g/y%C3u%40here.txt", "manual", "(bytes)", hexutil.Encode([]byte("/y%C3u%40here.txt")), true},

	//make sure hosted website resources work on w3eth.io. e.g., https://w3url.w3eth.io/css/app~d0ae3f07.e6592741.css
	{"w3url.w3eth.io", "/css/app~d0ae3f07.e6592741.css", "manual", "(bytes)", hexutil.Encode([]byte("/css/app~d0ae3f07.e6592741.css")), true},
	{"w3eth.io", "/w3url.eth/css/app~d0ae3f07.e6592741.css", "manual", "(bytes)", hexutil.Encode([]byte("/css/app~d0ae3f07.e6592741.css")), true},

	// decoded for auto mode, so encoded has same return type and calldata as unencoded
	{"w3eth.eth.gor.w3link.io", "/symbol?returns=(string)", "auto", "(string)", "0x95d89b41", true},
	{"w3eth.eth.gor.w3link.io", "/symbol?returns=%28string%29", "auto", "(string)", "0x95d89b41", true},
	{"w3link.io", "/test.w3q:w3q-g->(bytes[][])/getA", "auto", "(bytes[][])", "0xd46300fd", true},
	{"w3link.io", "/test.w3q-%3E(bytes%5B%5D%5B%5D)/getA", "auto", "(bytes[][])", "0xd46300fd", true},
	{"0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string!podrás.svg", "auto", "(bytes)", composecalldata, true},
	{"0x804a6b66b071e7e6494ae0e03768a536ded64262.w3q-g.w3link.io", "/compose/string%21podr%c3%a1s.svg", "auto", "(bytes)", composecalldata, true},

	// decoded for 5219 mode so encoded has same calldata as unencoded; if >2 params are provided the calldata is not stable because the order is random
	{"0x6587e67F1FBEAabDEe8b70EFb396E750e216283B.w3q-g.w3link.io", "/a$bc+d?b=币", "5219", "(bytes)", the5219calldata, true},
	{"0x6587e67F1FBEAabDEe8b70EFb396E750e216283B.w3q-g.w3link.io", "/a%24bc%2bd?b=%e5%b8%81", "5219", "(bytes)", the5219calldata, true},
}

func TestEncoded(t *testing.T) {
	for _, test := range decodingTestLinks {
		if strings.Contains(test.domain, "w3eth.io") {
			config.DefaultChain = 1
			config.NSDefaultChains["eth"] = 1
			config.NSDefaultChains["w3q"] = 333
		} else {
			config.DefaultChain = 0
			config.NSDefaultChains["eth"] = 5
			config.NSDefaultChains["w3q"] = 3334
		}
		t.Run(test.domain+test.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", test.path, nil)
			req.Host = test.domain
			w := httptest.NewRecorder()
			handle(w, req)
			res := w.Result()
			defer res.Body.Close()
			assert.Equal(t, test.mode, res.Header.Get("Web3-Resolve-Mode"))
			assert.Equal(t, test.returns, res.Header.Get("Web3-Return-Type"))
			if test.expectCalldataEqual {
				assert.Equal(t, test.calldata, res.Header.Get("Web3-Calldata"))
			} else {
				assert.NotEqual(t, test.calldata, res.Header.Get("Web3-Calldata"))
			}
		})
	}
}
