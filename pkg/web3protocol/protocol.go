package web3protocol

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

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



type Web3URL struct {
	Url         string         // The actual url string "web3://...."
	Contract    common.Address // actual address
	NSChain     string         // chain where the name service is running
	TargetChain string         // chain where the contract is deployed
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

func (client *Client) fetchUrl(url string) (fetchedUrl FetchedWeb3Url, err error) {
	// Parse the URL
	parsedUrl, err := client.parseUrl(url)
	if err != nil {
		return
	}

	// Execute it
	fetchedUrl, err = client.fetchParsedUrl(parsedUrl)

	return
}

func (client *Client) parseUrl(url string) (web3Url Web3URL, err error) {
	web3Url.Url = url

	// Must start with web3://
	if len(url) < len("web3:/") || url[:len("web3:/")] != "web3:/" {
		return web3Url, &Web3Error{http.StatusBadRequest, "web3:/ prefix missing"}
	}
	path := url[len("web3:/"):]

	var contract string
	ss := strings.Split(path, "/")
	contract = ss[1]
	web3Url.RawPath = path[len(ss[1])+1:]
	// split raw contract part, with "->" (contract return sign)
	// example /quark.eth:3->(uint256, bool)
	sr := strings.Split(ss[1], "->")
	if len(sr) > 2 {
		return web3Url, &Web3Error{http.StatusBadRequest, "web3Url can only have one '->'"}
	} else if len(sr) == 2 {
		if !strings.HasPrefix(sr[1], "(") || !strings.HasSuffix(sr[1], ")") {
			return web3Url, &Web3Error{http.StatusBadRequest, "invalid return type: " + sr[1]}
		}
		contract = sr[0]
		web3Url.ReturnType = sr[1]
	}
	// sr[0] means all part before a potential symbol "->", split it to get chainId
	st := strings.Split(sr[0], ":")
	if len(st) > 2 {
		return web3Url, &Web3Error{http.StatusBadRequest, "too many chainID to parse in: " + sr[0]}
	} else if len(st) == 2 {
		contract = st[0]
		web3Url.NSChain = st[1]
		// check if chainID is valid, against cached config(can stem from a config file)
		_, ok := client.Config.ChainConfigs[web3Url.NSChain]
		if !ok {
			// check if chainName is valid
			chainId, ok := client.Config.Name2Chain[strings.ToLower(web3Url.NSChain)]
			if !ok {
				return web3Url, &Web3Error{http.StatusBadRequest, "unsupported chain: " + web3Url.NSChain}
			}
			web3Url.NSChain = chainId
		}
	}

	// after spliting from "->" and ":", var contact shall be a pure name service or a hex address
	if common.IsHexAddress(contract) {
		web3Url.Contract = common.HexToAddress(contract)
		web3Url.TargetChain = web3Url.NSChain
		web3Url.NSType = "Address"
	} else {
		// a meaningful name waiting being processed
		ss := strings.Split(contract, ".")
		if len(ss) <= 1 {
			return web3Url, &Web3Error{http.StatusBadRequest, "unsupported contract name: " + contract}
		}
		suffix := ss[len(ss)-1]
		// check whether a suffix we are familar
		chainId, ok := client.Config.NSDefaultChains[suffix]
		if !ok {
			return web3Url, &Web3Error{http.StatusBadRequest, "unsupported domain name suffix: " + suffix}
		}
		if web3Url.NSChain == "" {
			web3Url.NSChain = chainId
		}
		var addr common.Address
		var targetChain string
		var hit bool
		cacheKey := web3Url.NSChain + ":" + contract
		if client.nameAddrCache != nil {
			addr, targetChain, hit = client.nameAddrCache.get(cacheKey)
		}
		if !hit {
			var err error
			addr, targetChain, err = client.getAddressFromNameServiceWebHandler(web3Url.NSChain, contract)
			if err != nil {
				return web3Url, err
			}
			if client.nameAddrCache != nil {
				client.nameAddrCache.add(cacheKey, addr, targetChain)
			}
		}
		web3Url.Contract = addr
		web3Url.TargetChain = targetChain

		chainInfo, ok := client.Config.ChainConfigs[web3Url.NSChain]
		if !ok {
			return web3Url, &Web3Error{http.StatusBadRequest, "unsupported chain: " + web3Url.NSChain}
		}
		nsInfo, ok := chainInfo.NSConfig[suffix]
		if !ok {
			return web3Url, &Web3Error{http.StatusBadRequest, "unsupported suffix: " + suffix}
		}
		if nsInfo.NSType == 1 {
			web3Url.NSType = "W3NS"
		} else if nsInfo.NSType == 2 {
			web3Url.NSType = "ENS"
		} else {
			web3Url.NSType = "Others"
		}
	}

	web3Url.Arguments = ss[2:]

	if web3Url.NSChain == "" {
		web3Url.NSChain = "1" // Was client.Config.DefaultChain
	}
	if web3Url.TargetChain == "" {
		web3Url.TargetChain = web3Url.NSChain
	}
	return web3Url, nil
}

func (client *Client) fetchParsedUrl(web3Url Web3URL) (fetchedWeb3Url FetchedWeb3Url, err error) {
	fetchedWeb3Url = FetchedWeb3Url{
		ParsedUrl: web3Url,
	}

	_, ok := client.Config.ChainConfigs[web3Url.TargetChain]
	if !ok {
		return fetchedWeb3Url, &Web3Error{http.StatusBadRequest, fmt.Sprintf("unsupported chain id: %v", web3Url.TargetChain)}
	}
	err = checkReturnType(&web3Url)
	if err != nil {
		return
	}
	log.Infof("Parsed web3Url: %+v", web3Url)
	
	resolveMode := checkResolveMode(web3Url)
	
	log.Info("contract: ", web3Url.Contract, " resolveMode: ", ResolveText[resolveMode])

	var bs []byte
	if resolveMode == ResolveModeResourceRequests {
		spliterIdx := strings.Index(p[1:], "/")
		path := p[spliterIdx+1:]
		if len(req.URL.RawQuery) > 0 {
			path += "?" + req.URL.RawQuery
		}
		bs, er = handleEIP5219(w, web3Url.Contract, web3Url.TargetChain, path)
		if er != nil {
			respondWithErrorPage(w, &Web3Error{http.StatusBadRequest, er.Error()})
			return
		}
	} else {
		var mimeType string
		if resolveMode == ResolveModeManual {
			undecoded := req.RequestURI
			if useSubdomain {
				web3Url.RawPath = undecoded
			} else {
				web3Url.RawPath = undecoded[strings.Index(undecoded[1:], "/")+1:]
			}
			log.Printf("web3Url.RawPath = %s", web3Url.RawPath)
			bs, mimeType, err = handleManualMode(w, web3Url)
		} else {
			bs, mimeType, err = handleAutoMode(w, web3Url)
		}
		if err.HasError() {
			respondWithErrorPage(w, err)
			return
		}
		if len(bs) == 0 {
			respondWithErrorPage(w, &Web3Error{http.StatusBadRequest, "no such contract or method"})
			return
		}
		res, err := parseOutput(bs, web3Url.ReturnType)
		if err.HasError() {
			respondWithErrorPage(w, err)
			return
		}
		e := render(w, req, web3Url.ReturnType, mimeType, res)
		if e != nil {
			respondWithErrorPage(w, &Web3Error{http.StatusBadRequest, e.Error()})
			return
		}
	}

	if len(*dbToken) > 0 {
		stats(len(bs), req.RemoteAddr, web3Url.TargetChain, web3Url.NSType, path, h)
	}
}












func handleManualMode(w http.ResponseWriter, web3Url Web3URL) ([]byte, string, Web3Error) {
	var mimeType string
	ss := strings.Split(web3Url.RawPath, ".")
	if len(ss) > 1 {
		mimeType = mime.TypeByExtension("." + ss[len(ss)-1])
		log.Info("type: ", mimeType)
	}
	calldata := []byte(web3Url.RawPath)
	log.Info("calldata (manual): ", "0x"+hex.EncodeToString(calldata))
	addWeb3Header(w, "Calldata", "0x"+hex.EncodeToString(calldata))
	bs, werr := callContract(web3Url.Contract, web3Url.TargetChain, calldata)
	if werr.HasError() {
		return nil, "", werr
	}
	return bs, mimeType, NoWeb3Error
}

func handleAutoMode(w http.ResponseWriter, web3Url Web3URL) ([]byte, string, Web3Error) {
	msg, argInfo, err := parseArguments(web3Url.TargetChain, web3Url.Contract, web3Url.Arguments)
	addWeb3Header(w, "Method-Signature", argInfo.methodSignature)
	addWeb3Header(w, "Calldata", argInfo.calldata)
	if err.HasError() {
		log.Infof("Cannot parse message: %v\n", err)
		return nil, "", err
	}
	client, linkErr := ethclient.Dial(config.ChainConfigs[web3Url.TargetChain].RPC)
	if linkErr != nil {
		log.Info("Dial failed: ", linkErr.Error())
		return nil, "", &Web3Error{http.StatusNotFound, linkErr.Error()}
	}
	defer client.Close()
	bs, e := client.CallContract(context.Background(), msg, nil)
	if e != nil {
		log.Info("Call Contract failed ", e.Error())
		return nil, "", &Web3Error{http.StatusNotFound, e.Error()}
	}
	log.Info("return data len: ", len(bs))
	log.Debug("return data: 0x", hex.EncodeToString(bs))

	return bs, argInfo.mimeType, err
}

func addWeb3Header(w http.ResponseWriter, header string, value string) {
	w.Header().Add("Web3-"+header, value)
}

func respondWithErrorPage(w http.ResponseWriter, err Web3Error) {
	w.WriteHeader(err.code)
	_, e := fmt.Fprintf(w, "<html><h1>%d: %s</h1>%v<html/>", err.code, http.StatusText(err.code), err.Error())
	if e != nil {
		log.Errorf("Cannot write error page: %v\n", e)
		return
	}
}

func checkResolveMode(web3Url Web3URL) int {
	msg, _, err := parseArguments("", web3Url.Contract, []string{"resolveMode"})
	if err.HasError() {
		panic(err)
	}
	client, _ := ethclient.Dial(config.ChainConfigs[web3Url.TargetChain].RPC)
	defer client.Close()
	bs, e := client.CallContract(context.Background(), msg, nil)
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
func parseArguments(nameServiceChain string, addr common.Address, args []string) (ethereum.CallMsg, ArgInfo, error) {
	msig := "("
	mimeType := ""
	var arguments abi.Arguments = make([]abi.Argument, 0)
	values := make([]interface{}, 0)
	for i := 1; i < len(args); i++ {
		if len(args[i]) == 0 {
			continue
		}
		ty, typeStr, value, err := parseArgument(args[i], nameServiceChain)
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
func parseArgument(s string, nsChain string) (abi.Type, string, interface{}, Web3Error) {
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
			addr, _, err := getAddressFromNameService(nsChain, ss[1])
			if err.HasError() {
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
		return ty, ss[0], v, NoWeb3Error
	}

	n := new(big.Int)
	n, success := n.SetString(ss[0], 10)
	if success {
		// treat it as uint256
		ty, _ := abi.NewType("uint256", "", nil)
		return ty, "uint256", n, NoWeb3Error
	}

	if has0xPrefix(ss[0]) && isHex(ss[0][2:]) {
		if len(ss[0]) == 40+2 {
			v = common.HexToAddress(ss[0])
			ty, _ := abi.NewType("address", "", nil)
			return ty, "address", v, NoWeb3Error
		} else if len(ss[0]) == 64+2 {
			v = common.HexToHash(ss[0])
			ty, _ := abi.NewType("bytes32", "", nil)
			return ty, "bytes32", v, NoWeb3Error
		} else {
			v = common.FromHex(ss[0][2:])
			ty, _ := abi.NewType("bytes", "", nil)
			return ty, "bytes", v, NoWeb3Error
		}
	}

	// parse as domain name
	addr, _, err := getAddressFromNameService(nsChain, ss[0])
	if !err.HasError() {
		ty, _ := abi.NewType("address", "", nil)
		return ty, "address", addr, NoWeb3Error
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
	if termReturnsURL != "" && termReturnTypesURL != "" {
		// cannot parse a full url, early exit
		return &Web3Error{http.StatusBadRequest, "Duplicate return attribute"}
	}
	// here should only one string is meaningful
	var rType string
	if termReturnsURL != "" {
		rType = termReturnsURL
	} else {
		rType = termReturnTypesURL
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
