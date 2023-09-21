package web3protocol

import (
	"context"
	// "encoding/hex"
	// "encoding/json"
	"fmt"
	"math/big"
	"mime"
	// "net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"regexp"

	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Client struct {
	Config Config
	nameAddrCache *localCache
}

type DomainNameResolver string
const (
	DomainNameResolverNone = "none"
	DomainNameResolverENS = "ens"
	DomainNameResolverW3NS = "w3ns"
)

type ContractCallMode string
const (
	ContractCallModeCalldata = "calldata"
	ContractCallModeMethod = "method"
)

type ContractReturnProcessing string
const (
	// Expect a []byte as first return value, return it
	ContractReturnProcessingFirstValueAsBytes = "firstValueAsBytes"
	// JSON-encode the different return values
	ContractReturnProcessingJsonEncodeValues = "jsonEncodeValues"
	// Expect a string as first return value, parse it as a dataUrl
	// ContractReturnProcessingDataUrl = "dataUrl" // To implement
	// Expect a return following the erc5219 spec, will decode it using this spec
	ContractReturnProcessingErc5219 = "erc5219"
)

type Web3URL struct {
	// TODO : to remove
	Url         string         // The actual url string "web3://...."

	ContractAddress    common.Address // actual address
	NSChain     string         // chain where the name service is running
	TargetChain string         // chain where the contract is deployed

	ResolveMode ResolveMode   // The resolve mode used

    // How do we call the smartcontract
    // 'calldata' : We use a raw calldata
    // 'method': We use the specified method and method parameters
	ContractCallMode ContractCallMode

	Calldata []byte

	// How to process the return of the contract. See enum for doc
	ContractReturnProcessing ContractReturnProcessing

	// In case of contractReturnProcessing being firstValueAsBytes,
	// this will set the mime type to return
	FirstValueAsBytesMimeType string

	RawPath     string         // All after contract name
	Arguments   []string       // arguments to call
	ReturnType  string         // return type
	NSType      string
}

type FetchedWeb3Url struct {
	ParsedUrl Web3URL
	Output []byte
	HttpCode int
	HttpHeaders map[string]string
}


func NewClient() (client *Client) {
	// Default values
	config := Config{
		NameAddrCacheDurationInMinutes: 60,
	}

    client = &Client{
    	Config: config,
        nameAddrCache: newLocalCache(time.Duration(config.NameAddrCacheDurationInMinutes)*time.Minute, 10*time.Minute),
    }

    return
}

func (client *Client) FetchUrl(url string) (fetchedUrl FetchedWeb3Url, err error) {
	// Parse the URL
	parsedUrl, err := client.ParseUrl(url)
	if err != nil {
		return
	}

	// Execute it
	fetchedUrl, err = client.FetchParsedUrl(parsedUrl)

	return
}

func (client *Client) ParseUrl(url string) (web3Url Web3URL, err error) {
	web3Url.Url = url

	web3UrlRegexp, err := regexp.Compile(`^(?P<protocol>[^:]+):\/\/(?P<hostname>[^:\/]+)(:(?P<chainId>[1-9][0-9]*))?(?P<path>\/.*)?$`)
	if err != nil {
		return
	}
	matches := web3UrlRegexp.FindStringSubmatch(url)
	if len(matches) == 0 {
		return web3Url, &Web3Error{http.StatusBadRequest, "Invalid URL format"}
	}
	urlMainParts := map[string]string{}
	for i, name := range web3UrlRegexp.SubexpNames() {
		if i != 0 && name != "" {
			urlMainParts[name] = matches[i]
		}
	}
// fmt.Println("%+v\n", urlMainParts)

	if urlMainParts["protocol"] != "web3" {
		return web3Url, &Web3Error{http.StatusBadRequest, "Protocol name is invalid"}
	}


// var contract string
// ss := strings.Split(path, "/")
// contract = ss[1]
// web3Url.RawPath = path[len(ss[1])+1:]

	// sr[0] means all part before a potential symbol "->", split it to get chainId


	// 	contract = st[0]
	// 	web3Url.NSChain = st[1]

	// 	// check if chainID is valid, against cached config(can stem from a config file)
	// 	_, ok := client.Config.ChainConfigs[web3Url.NSChain]
	// 	if !ok {
	// 		// check if chainName is valid
	// 		chainId, ok := client.Config.Name2Chain[strings.ToLower(web3Url.NSChain)]
	// 		if !ok {
	// 			return web3Url, &Web3Error{http.StatusBadRequest, "unsupported chain: " + web3Url.NSChain}
	// 		}
	// 		web3Url.NSChain = chainId
	// 	}
	// }

	// Default chain is ethereum mainnet
	web3Url.TargetChain = "1"
	if len(urlMainParts["chaindId"]) > 0 {
		web3Url.TargetChain = urlMainParts["chaindId"]
	}

	// Check that we support the chain
	_, ok := client.Config.ChainConfigs[web3Url.TargetChain]
	if !ok {
		return web3Url, &Web3Error{http.StatusBadRequest, "Unsupported chain: " + web3Url.TargetChain}
	}

	// after spliting from "->" and ":", var contact shall be a pure name service or a hex address
	if common.IsHexAddress(urlMainParts["hostname"]) {
		web3Url.ContractAddress = common.HexToAddress(urlMainParts["hostname"])
		web3Url.NSType = "Address"
	} else {
		// Determine name suffix
		ss := strings.Split(urlMainParts["hostname"], ".")
		if len(ss) <= 1 {
			return web3Url, &Web3Error{http.StatusBadRequest, "Invalid contract address"}
		}
		nameServiceSuffix := ss[len(ss)-1]

		// We will use a nameservice in the current target chain
		web3Url.NSChain = web3Url.TargetChain

		chainInfo, _ := client.Config.ChainConfigs[web3Url.NSChain]
		nsInfo, ok := chainInfo.NSConfig[nameServiceSuffix]
		if !ok {
			return web3Url, &Web3Error{http.StatusBadRequest, "unsupported name service suffix: " + nameServiceSuffix}
		}

		// TODO change
		if nsInfo.NSType == 1 {
			web3Url.NSType = "W3NS"
		} else if nsInfo.NSType == 2 {
			web3Url.NSType = "ENS"
		} else {
			web3Url.NSType = "Others"
		}

		var addr common.Address
		var targetChain string
		var hit bool
		cacheKey := web3Url.NSChain + ":" + urlMainParts["hostname"]
		if client.nameAddrCache != nil {
			addr, targetChain, hit = client.nameAddrCache.get(cacheKey)
		}
		if !hit {
			var err error
			addr, targetChain, err = client.getAddressFromNameServiceWebHandler(web3Url.NSChain, urlMainParts["hostname"])
			if err != nil {
				return web3Url, err
			}
			if client.nameAddrCache != nil {
				client.nameAddrCache.add(cacheKey, addr, targetChain)
			}
		}
		web3Url.ContractAddress = addr
		if len(targetChain) > 0 {
			web3Url.TargetChain = targetChain
		}

		_, ok = client.Config.ChainConfigs[web3Url.TargetChain]
		if !ok {
			return web3Url, &Web3Error{http.StatusBadRequest, fmt.Sprintf("unsupported chain id: %v", web3Url.TargetChain)}
		}
	}

	// Determine the web3 mode
	// 3 modes:
	// - Auto : we parse the path and arguments and send them
	// - Manual : we forward all the path & arguments as calldata
	// - 5219 : we parse the path and arguments and send them
	web3Url.ResolveMode = client.checkResolveMode(web3Url)

	if web3Url.ResolveMode == ResolveModeManual {
		// undecoded := req.RequestURI
		// if useSubdomain {
		// 	web3Url.RawPath = undecoded
		// } else {
		// 	web3Url.RawPath = undecoded[strings.Index(undecoded[1:], "/")+1:]
		// }
		err = client.parseManualModeUrl(&web3Url, urlMainParts["path"])
	} else if web3Url.ResolveMode == ResolveModeAuto {
		err = client.parseAutoModeUrl(&web3Url)
	} else if web3Url.ResolveMode == ResolveModeResourceRequests {
		// spliterIdx := strings.Index(p[1:], "/")
		// path := p[spliterIdx+1:]
		// if len(req.URL.RawQuery) > 0 {
		// 	path += "?" + req.URL.RawQuery
		// }
		// bs, er = handleEIP5219(w, web3Url.Contract, web3Url.TargetChain, path)
		// if er != nil {
		// 	respondWithErrorPage(w, &Web3Error{http.StatusBadRequest, er.Error()})
		// 	return
		// }
	}
	if err != nil {
		return
	}

	return web3Url, nil
}

func (client *Client) FetchParsedUrl(web3Url Web3URL) (fetchedWeb3Url FetchedWeb3Url, err error) {
	fetchedWeb3Url = FetchedWeb3Url{
		ParsedUrl: web3Url,
	}

	// res, err := parseOutput(bs, web3Url.ReturnType)
	// if err != nil {
	// 	return web3Url, err
	// }
	// var mimeType string
	// err = render(w, req, web3Url.ReturnType, mimeType, res)
	// if err != nil {
	// 	return
	// }

	return
}





func (client *Client) parseManualModeUrl(web3Url *Web3URL, path string) (err error) {
	// Path must be at least "/"
	if(len(path) == 0) {
		path = "/"
	}

	// Default MIME type is text/html
	web3Url.FirstValueAsBytesMimeType = "text/html"
	// The path can contain an extension, which will override the mime type to use


	// var mimeType string
	// ss := strings.Split(path, ".")
	// if len(ss) > 1 {
	// 	mimeType = mime.TypeByExtension("." + ss[len(ss)-1])
	// }

	web3Url.ContractCallMode = ContractCallModeCalldata
	web3Url.Calldata = []byte(path)
	web3Url.ContractReturnProcessing = ContractReturnProcessingFirstValueAsBytes

	return
}

// func handleManualMode(web3Url Web3URL) ([]byte, string, error) {
// 	var mimeType string
// 	ss := strings.Split(web3Url.RawPath, ".")
// 	if len(ss) > 1 {
// 		mimeType = mime.TypeByExtension("." + ss[len(ss)-1])
// 		log.Info("type: ", mimeType)
// 	}
// 	calldata := []byte(web3Url.RawPath)
// 	log.Info("calldata (manual): ", "0x"+hex.EncodeToString(calldata))
// 	addWeb3Header(w, "Calldata", "0x"+hex.EncodeToString(calldata))
// 	bs, werr := callContract(web3Url.Contract, web3Url.TargetChain, calldata)
// 	if werr.HasError() {
// 		return nil, "", werr
// 	}
// 	return bs, mimeType, nil
// }

func (client *Client) parseAutoModeUrl(web3Url *Web3URL) (err error) {
	_, _, err = client.parseArguments(web3Url.TargetChain, web3Url.ContractAddress, web3Url.Arguments)

	if err != nil {
		log.Infof("Cannot parse message: %v\n", err)
		return
	}

	err = checkReturnType(web3Url)
	if err != nil {
		return
	}

	// ethClient, linkErr := ethclient.Dial(client.Config.ChainConfigs[web3Url.TargetChain].RPC)
	// if linkErr != nil {
	// 	log.Info("Dial failed: ", linkErr.Error())
	// 	return nil, &Web3Error{http.StatusNotFound, linkErr.Error()}
	// }
	// defer ethClient.Close()
	// bs, e := ethClient.CallContract(context.Background(), msg, nil)
	// if e != nil {
	// 	log.Info("Call Contract failed ", e.Error())
	// 	return nil, &Web3Error{http.StatusNotFound, e.Error()}
	// }
	// log.Info("return data len: ", len(bs))
	// log.Debug("return data: 0x", hex.EncodeToString(bs))

	return
}

// func handleAutoMode(web3Url Web3URL) ([]byte, string, Web3Error) {
// 	msg, argInfo, err := parseArguments(web3Url.TargetChain, web3Url.Contract, web3Url.Arguments)
// 	addWeb3Header(w, "Method-Signature", argInfo.methodSignature)
// 	addWeb3Header(w, "Calldata", argInfo.calldata)
// 	if err.HasError() {
// 		log.Infof("Cannot parse message: %v\n", err)
// 		return nil, "", err
// 	}
// 	client, linkErr := ethclient.Dial(config.ChainConfigs[web3Url.TargetChain].RPC)
// 	if linkErr != nil {
// 		log.Info("Dial failed: ", linkErr.Error())
// 		return nil, "", &Web3Error{http.StatusNotFound, linkErr.Error()}
// 	}
// 	defer client.Close()
// 	bs, e := client.CallContract(context.Background(), msg, nil)
// 	if e != nil {
// 		log.Info("Call Contract failed ", e.Error())
// 		return nil, "", &Web3Error{http.StatusNotFound, e.Error()}
// 	}
// 	log.Info("return data len: ", len(bs))
// 	log.Debug("return data: 0x", hex.EncodeToString(bs))

// 	return bs, argInfo.mimeType, err
// }

func addWeb3Header(w http.ResponseWriter, header string, value string) {
	w.Header().Add("Web3-"+header, value)
}

func respondWithErrorPage(w http.ResponseWriter, err Web3Error) {
	w.WriteHeader(err.HttpCode)
	_, e := fmt.Fprintf(w, "<html><h1>%d: %s</h1>%v<html/>", err.HttpCode, http.StatusText(err.HttpCode), err.Error())
	if e != nil {
		log.Errorf("Cannot write error page: %v\n", e)
		return
	}
}

func (client *Client) checkResolveMode(web3Url Web3URL) ResolveMode {
	msg, _, err := client.parseArguments("", web3Url.ContractAddress, []string{"resolveMode"})
	if err != nil {
		panic(err)
	}
	ethClient, _ := ethclient.Dial(client.Config.ChainConfigs[web3Url.TargetChain].RPC)
	defer ethClient.Close()
	bs, e := ethClient.CallContract(context.Background(), msg, nil)
	if e != nil {
		return ResolveModeAuto
	}
	if len(bs) == 32 {
		if common.Bytes2Hex(bs) == "6d616e75616c0000000000000000000000000000000000000000000000000000" {
			return ResolveModeManual
		}
		// 5219
		if common.Bytes2Hex(bs) == "3532313900000000000000000000000000000000000000000000000000000000" {
			return ResolveModeResourceRequests
		}
	}
	return ResolveModeAuto
}

// parseArguments parses a [METHOD_NAME, ARG0, ARG1, ...] string array into an ethereum message with provided address, and return the mime type if end with type extension
func (client *Client) parseArguments(nameServiceChain string, addr common.Address, args []string) (ethereum.CallMsg, ArgInfo, error) {
	msig := "("
	mimeType := ""
	var arguments abi.Arguments = make([]abi.Argument, 0)
	values := make([]interface{}, 0)
	for i := 1; i < len(args); i++ {
		if len(args[i]) == 0 {
			continue
		}
		ty, typeStr, value, err := client.parseArgument(args[i], nameServiceChain)
		if err != nil {
			return ethereum.CallMsg{}, ArgInfo{}, err
		}
		arguments = append(arguments, abi.Argument{Type: ty})
		values = append(values, value)
		if i != 1 {
			msig = msig + ","
		}
		msig = msig + typeStr
		ss := strings.Split(args[i], ".")
		if i == len(args)-1 && len(ss) > 1 {
			mimeType = mime.TypeByExtension("." + ss[len(ss)-1])
		}
	}
	dataField, err := arguments.Pack(values...)
	if err != nil {
		return ethereum.CallMsg{}, ArgInfo{}, &Web3Error{http.StatusBadRequest, err.Error()}
	}
	msig = msig + ")"

	var calldata []byte
	var argInfo ArgInfo

	// skip parsing the calldata if there's no argument or the method signature(args[0]) is empty
	if len(args) != 0 && args[0] != "" {
		h := crypto.Keccak256Hash(append([]byte(args[0]), msig...))
		mid := h[0:4]
		calldata = append(mid, dataField...)
		argInfo.methodSignature = args[0] + msig
	}
	msg := ethereum.CallMsg{
		From:      common.HexToAddress("0x0000000000000000000000000000000000000000"),
		To:        &addr,
		Gas:       0,
		GasPrice:  nil,
		GasFeeCap: nil,
		GasTipCap: nil,
		Data:      calldata,
		Value:     nil,
	}
	argInfo.mimeType = mimeType
	argInfo.calldata = "0x" + common.Bytes2Hex(calldata)
	return msg, argInfo, nil
}

// parseArgument parses a [TYPE!]VALUE string into an abi.Type. The type will be auto-detected if TYPE not provided
func (client *Client) parseArgument(s string, nsChain string) (abi.Type, string, interface{}, error) {
	ss := strings.Split(s, "!")
	if len(ss) > 2 {
		return abi.Type{}, "", nil, &Web3Error{http.StatusBadRequest, "argument wrong format: " + s}
	}

	var v interface{}
	if len(ss) == 2 {
		switch ss[0] {
		case "uint256":
			b := new(big.Int)
			n, ok := b.SetString(ss[1], 0)
			if !ok {
				return abi.Type{}, "uint256", nil, &Web3Error{http.StatusBadRequest, "argument is not a number: " + s}
			}
			v = n
		case "bytes32":
			if !has0xPrefix(ss[1]) || !isHex(ss[1][2:]) {
				return abi.Type{}, "bytes32", nil, &Web3Error{http.StatusBadRequest, "argument is not a valid hex string: " + s}
			}
			v = common.HexToHash(ss[1])
		case "address":
			addr, _, err := client.getAddressFromNameService(nsChain, ss[1])
			if err != nil {
				return abi.Type{}, "address", nil, err
			}
			v = addr
		case "bytes":
			if !has0xPrefix(ss[1]) || !isHex(ss[1][2:]) {
				return abi.Type{}, "bytes", nil, &Web3Error{http.StatusBadRequest, "argument is not a valid hex string: " + s}
			}
			v = common.FromHex(ss[1])
		case "string":
			v = ss[1]
		case "bool":
			{
				if ss[1] == "0" {
					v = false
				}
				v = true
			}
		default:
			return abi.Type{}, "", nil, &Web3Error{http.StatusBadRequest, "unknown type: " + ss[0]}
		}
		ty, _ := abi.NewType(ss[0], "", nil)
		return ty, ss[0], v, nil
	}

	n := new(big.Int)
	n, success := n.SetString(ss[0], 10)
	if success {
		// treat it as uint256
		ty, _ := abi.NewType("uint256", "", nil)
		return ty, "uint256", n, nil
	}

	if has0xPrefix(ss[0]) && isHex(ss[0][2:]) {
		if len(ss[0]) == 40+2 {
			v = common.HexToAddress(ss[0])
			ty, _ := abi.NewType("address", "", nil)
			return ty, "address", v, nil
		} else if len(ss[0]) == 64+2 {
			v = common.HexToHash(ss[0])
			ty, _ := abi.NewType("bytes32", "", nil)
			return ty, "bytes32", v, nil
		} else {
			v = common.FromHex(ss[0][2:])
			ty, _ := abi.NewType("bytes", "", nil)
			return ty, "bytes", v, nil
		}
	}

	// parse as domain name
	addr, _, err := client.getAddressFromNameService(nsChain, ss[0])
	if err == nil {
		ty, _ := abi.NewType("address", "", nil)
		return ty, "address", addr, nil
	}
	return abi.Type{}, "", nil, err
}

func checkReturnType(web3Url *Web3URL) error {
	parsedUrl, err := url.Parse(web3Url.Url)
	if err != nil {
		return err
	}
	parsedQuery, err := url.ParseQuery(parsedUrl.RawQuery)
	if err != nil {
		return err
	}

	termReturnTypesURL := parsedQuery["returnTypes"]
	termReturnsURL := parsedQuery["returns"]
	// attribute `returnTypes` is an alias of `returns`, for compatibility concern
	// duplicate returns are prohibited
	if len(termReturnsURL) > 0 && len(termReturnTypesURL) > 0 || len(termReturnsURL) > 2 || len(termReturnTypesURL) > 2 {
		// cannot parse a full url, early exit
		return &Web3Error{http.StatusBadRequest, "Duplicate return attribute"}
	}
	// here should only one string is meaningful
	var rType string
	if len(termReturnsURL) == 1 {
		rType = termReturnsURL[0]
	} else if len(termReturnTypesURL) == 1 {
		rType = termReturnTypesURL[0]
	}
	if web3Url.ReturnType == "" {
		if rType != "" {
			web3Url.ReturnType = rType
		}
	} else {
		if rType != "" && rType != web3Url.ReturnType {
			return &Web3Error{http.StatusBadRequest, "Conflict return types"}
		}
	}
	return nil
}

// parseOutput parses the bytes into actual values according to the returnTypes string
func parseOutput(output []byte, userTypes string) ([]interface{}, error) {
	returnTypes := "(bytes)"
	if userTypes == "()" {
		return []interface{}{"0x" + common.Bytes2Hex(output)}, nil
	} else if userTypes != "" {
		returnTypes = userTypes
	}
	returnArgs := strings.Split(strings.Trim(returnTypes, "()"), ",")
	var argsArray abi.Arguments
	for _, arg := range returnArgs {
		ty, err := abi.NewType(arg, "", nil)
		if err != nil {
			return nil, &Web3Error{http.StatusBadRequest, err.Error()}
		}
		argsArray = append(argsArray, abi.Argument{Name: "", Type: ty, Indexed: false})
	}
	var res []interface{}
	res, err := argsArray.UnpackValues(output)
	if err != nil {
		return nil, &Web3Error{http.StatusBadRequest, err.Error()}
	}
	if userTypes != "" {
		for i, arg := range argsArray {
			// get the type of the return value
			res[i] = toJSON(arg.Type, res[i])
		}
	}
	return res, nil
}
