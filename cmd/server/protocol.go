package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"mime"
	"net"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Web3URL struct {
	Contract    common.Address // actual address
	NSChain     string         // chain where the name service is running
	TargetChain string         // chain where the contract is deployed
	RawPath     string         // All after contract name
	Arguments   []string       // arguments to call
	ReturnType  string         // return type
	NSType      string
}

const (
	SimpleNameService NameServiceType = iota
	Web3QNameService
	EthereumNameService
)

const (
	ResolveModeAuto = iota
	ResolveModeManual
	ResolveModeResourceRequests
)

var ResolveText = map[int]string{
	ResolveModeAuto:             "auto",
	ResolveModeManual:           "manual",
	ResolveModeResourceRequests: "5219",
}

var nsTypeMapping = map[string]NameServiceType{
	"W3NS": Web3QNameService,
	"ENS":  EthereumNameService,
	"SNS":  SimpleNameService,
}

func handle(w http.ResponseWriter, req *http.Request) {
	h := req.Host
	path := req.URL.Path
	// ban ico request
	if path == "/favicon.ico" {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", config.CORS)
	if strings.HasPrefix(h, "ordinals.btc.") {
		handleOrdinals(w, req, path)
		return
	}
	p, er := handleSubdomain(h, path)
	if er != nil {
		respondWithErrorPage(w, Web3Error{http.StatusBadRequest, er.Error()})
		return
	}
	if p == "/" {
		http.Redirect(w, req, config.HomePage, http.StatusFound)
		return
	}
	w3url, err := parseWeb3URL(p)
	if err.HasError() {
		respondWithErrorPage(w, err)
		return
	}
	_, ok := config.ChainConfigs[w3url.TargetChain]
	if !ok {
		respondWithErrorPage(w, Web3Error{http.StatusBadRequest, fmt.Sprintf("unsupported chain id: %v", w3url.TargetChain)})
		return
	}
	err = checkReturnType(w, req, &w3url)
	if err.HasError() {
		respondWithErrorPage(w, err)
		return
	}
	log.Infof("Parsed web3url: %+v", w3url)
	if w3url.ReturnType == "" {
		addWeb3Header(w, "Return-Type", "(bytes)")
	} else {
		addWeb3Header(w, "Return-Type", w3url.ReturnType)
	}
	addWeb3Header(w, "Contract-Address", w3url.Contract.Hex())
	addWeb3Header(w, "Target-ChainId", w3url.TargetChain)
	addWeb3Header(w, "NameService-ChainId", w3url.NSChain)
	resolveMode := checkResolveMode(w3url)
	addWeb3Header(w, "Resolve-Mode", ResolveText[resolveMode])
	log.Info("contract: ", w3url.Contract, " resolveMode: ", ResolveText[resolveMode])

	var bs []byte
	if resolveMode == ResolveModeResourceRequests {
		path := strings.Split(p, "/request")[1]
		if len(req.URL.RawQuery) > 0 {
			path += "?" + req.URL.RawQuery
		}
		bs, er = handleEIP5219(w, w3url.Contract, w3url.TargetChain, path)
		if er != nil {
			respondWithErrorPage(w, Web3Error{http.StatusBadRequest, er.Error()})
			return
		}
	} else {
		var mimeType string
		if resolveMode == ResolveModeManual {
			bs, mimeType, err = handleManualMode(w, w3url)
		} else {
			bs, mimeType, err = handleAutoMode(w, w3url)
		}
		if err.HasError() {
			respondWithErrorPage(w, err)
			return
		}
		if len(bs) == 0 {
			respondWithErrorPage(w, Web3Error{http.StatusBadRequest, "no such contract or method"})
			return
		}
		res, err := parseOutput(bs, w3url.ReturnType)
		if err.HasError() {
			respondWithErrorPage(w, err)
			return
		}
		e := render(w, req, w3url.ReturnType, mimeType, res)
		if e != nil {
			respondWithErrorPage(w, Web3Error{http.StatusBadRequest, e.Error()})
			return
		}
	}

	if len(*dbToken) > 0 {
		stats(len(bs), req.RemoteAddr, w3url.TargetChain, w3url.NSType, path, h)
	}
}

func render(w http.ResponseWriter, req *http.Request, returnType, mimeType string, content []interface{}) error {
	// returns > mime.type > mime.content > .ext
	if returnType != "" {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(content)
		if err != nil {
			return err
		}
		return nil
	}
	var mmc string
	mmt := req.URL.Query().Get("mime.type")
	if mmt != "" {
		mmc = mime.TypeByExtension("." + mmt)
	}
	if mmc == "" {
		mmc = req.URL.Query().Get("mime.content")
	}
	if mmc != "" {
		mimeType = mmc
	}
	if mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
	}
	_, e := w.Write(content[0].([]byte))
	if e != nil {
		return e
	}
	return nil
}

// process request with contract info in subdomain:
// e.g.,
// 0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io
// quark.w3q.w3q-g.w3link.io
func handleSubdomain(host string, path string) (string, error) {
	log.Info(host + path)
	if strings.Index(host, ":") > 0 {
		host = host[0:strings.Index(host, ":")]
	}
	if net.ParseIP(host) != nil {
		// ban ip addresses
		return "", fmt.Errorf("invalid subdomain")
	}
	pieces := strings.Split(host, ".")
	l := len(pieces)
	if l > 5 {
		log.Info("subdomain too long")
		return "", fmt.Errorf("invalid subdomain")
	}
	p := path
	if l <= 2 {
		// back compatible with hosted dweb files
		if strings.HasSuffix(strings.Split(path, "/")[1], ".w3q") {
			p = strings.Replace(path, ".w3q/", ".w3q:w3q-g/", 1)
		}
	}
	if l == 3 {
		if len(config.DefaultChain) == 0 {
			return "", fmt.Errorf("default chain is not specified")
		}
		if common.IsHexAddress(pieces[0]) {
			//e.g. 0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io/name?returns=(string)
			p = "/" + pieces[0] + ":" + config.DefaultChain + path
		} else {
			//e.g. quark.w3eth.io
			suffix, err := getDefaultNSSuffix()
			if err != nil {
				log.Info(err.Error())
				return "", fmt.Errorf("invalid subdomain")
			}
			name := pieces[0] + "." + suffix
			// back compatible with hosted dweb files
			if !strings.Contains(path, "/"+name+"/") {
				p = "/" + name + path
			}
		}
	}
	// e.g. 0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.sep.w3link.io
	if l == 4 {
		if !common.IsHexAddress(pieces[0]) {
			log.Info("invalid contract address")
			return "", fmt.Errorf("invalid subdomain")
		}
		full := strings.Join(pieces[0:2], ":")
		pp := strings.Split(path, "/")
		if strings.HasSuffix(pp[1], ".w3q") || strings.HasSuffix(pp[1], ".eth") {
			p = strings.Replace(path, pp[1], full, 1)
		} else {
			p = "/" + full + path
		}
	}
	//e.g.quark.w3q.w3q-g.w3link.io
	if l == 5 {
		if len(config.DefaultChain) > 0 {
			log.Info("no tld should be provided when default chain is specified")
			return "", fmt.Errorf("invalid subdomain")
		}
		name := strings.Join(pieces[0:2], ".")
		full := name + ":" + pieces[2]
		if strings.Index(path, "/"+name+"/") == 0 {
			// append chain short name to hosted dweb files
			p = strings.Replace(path, "/"+name+"/", "/"+full+"/", 1)
		} else if !strings.Contains(path, "/"+name+"/") {
			p = "/" + full + path
		}
	}
	log.Info("=>", p)
	return p, nil
}

// parseWeb3URL parse input path into Web3URL struct
func parseWeb3URL(path string) (Web3URL, Web3Error) {
	var w Web3URL
	var contract string
	ss := strings.Split(path, "/")
	contract = ss[1]
	w.RawPath = path[len(ss[1])+1:]
	// split raw contract part, with "->" (contract return sign)
	// example /quark.eth:3->(uint256, bool)
	sr := strings.Split(ss[1], "->")
	if len(sr) > 2 {
		return w, Web3Error{http.StatusBadRequest, "web3url can only have one '->'"}
	} else if len(sr) == 2 {
		if !strings.HasPrefix(sr[1], "(") || !strings.HasSuffix(sr[1], ")") {
			return w, Web3Error{http.StatusBadRequest, "invalid return type: " + sr[1]}
		}
		contract = sr[0]
		w.ReturnType = sr[1]
	}
	// sr[0] means all part before a potential symbol "->", split it to get chainId
	st := strings.Split(sr[0], ":")
	if len(st) > 2 {
		return w, Web3Error{http.StatusBadRequest, "too many chainID to parse in: " + sr[0]}
	} else if len(st) == 2 {
		contract = st[0]
		w.NSChain = st[1]
		// check if chainID is valid, against cached config(can stem from a config file)
		_, ok := config.ChainConfigs[w.NSChain]
		if !ok {
			// check if chainName is valid
			chainId, ok := config.Name2Chain[strings.ToLower(w.NSChain)]
			if !ok {
				return w, Web3Error{http.StatusBadRequest, "unsupported chain: " + w.NSChain}
			}
			w.NSChain = chainId
		}
	}

	// after spliting from "->" and ":", var contact shall be a pure name service or a hex address
	if common.IsHexAddress(contract) {
		w.Contract = common.HexToAddress(contract)
		w.TargetChain = w.NSChain
		w.NSType = "Address"
	} else {
		// a meaningful name waiting being processed
		ss := strings.Split(contract, ".")
		if len(ss) <= 1 {
			return w, Web3Error{http.StatusBadRequest, "unsupported contract name: " + contract}
		}
		suffix := ss[len(ss)-1]
		// check whether a suffix we are familar
		chainId, ok := config.NSDefaultChains[suffix]
		if !ok {
			return w, Web3Error{http.StatusBadRequest, "unsupported domain name suffix: " + suffix}
		}
		if w.NSChain == "" {
			w.NSChain = chainId
		}
		var addr common.Address
		var targetChain string
		var hit bool
		cacheKey := w.NSChain + ":" + contract
		if nameAddrCache != nil {
			addr, targetChain, hit = nameAddrCache.get(cacheKey)
		}
		if !hit {
			var err Web3Error
			addr, targetChain, err = getAddressFromNameServiceWebHandler(w.NSChain, contract)
			if err.HasError() {
				return w, err
			}
			if nameAddrCache != nil {
				nameAddrCache.add(cacheKey, addr, targetChain)
			}
		}
		w.Contract = addr
		w.TargetChain = targetChain

		chainInfo, ok := config.ChainConfigs[w.NSChain]
		if !ok {
			return w, Web3Error{http.StatusBadRequest, "unsupported chain: " + w.NSChain}
		}
		nsInfo, ok := chainInfo.NSConfig[suffix]
		if !ok {
			return w, Web3Error{http.StatusBadRequest, "unsupported suffix: " + suffix}
		}
		if nsInfo.NSType == 1 {
			w.NSType = "W3NS"
		} else if nsInfo.NSType == 2 {
			w.NSType = "ENS"
		} else {
			w.NSType = "Others"
		}
	}

	w.Arguments = ss[2:]

	if w.NSChain == "" {
		w.NSChain = config.DefaultChain
	}
	if w.TargetChain == "" {
		w.TargetChain = w.NSChain
	}
	return w, NoWeb3Error
}
func handleManualMode(w http.ResponseWriter, w3url Web3URL) ([]byte, string, Web3Error) {
	var mimeType string
	ss := strings.Split(w3url.RawPath, ".")
	if len(ss) > 1 {
		mimeType = mime.TypeByExtension("." + ss[len(ss)-1])
		log.Info("type: ", mimeType)
	}
	calldata := []byte(w3url.RawPath)
	log.Info("calldata (manual): ", "0x"+hex.EncodeToString(calldata))
	addWeb3Header(w, "Calldata", "0x"+hex.EncodeToString(calldata))
	bs, werr := callContract(w3url.Contract, w3url.TargetChain, calldata)
	if werr.HasError() {
		return nil, "", werr
	}
	return bs, mimeType, NoWeb3Error
}

func handleAutoMode(w http.ResponseWriter, w3url Web3URL) ([]byte, string, Web3Error) {
	msg, argInfo, err := parseArguments(w3url.TargetChain, w3url.Contract, w3url.Arguments)
	addWeb3Header(w, "Method-Signature", argInfo.methodSignature)
	addWeb3Header(w, "Calldata", argInfo.calldata)
	if err.HasError() {
		log.Infof("Cannot parse message: %v\n", err)
		return nil, "", err
	}
	client, linkErr := ethclient.Dial(config.ChainConfigs[w3url.TargetChain].RPC)
	if linkErr != nil {
		log.Info("Dial failed: ", linkErr.Error())
		return nil, "", Web3Error{http.StatusNotFound, linkErr.Error()}
	}
	defer client.Close()
	bs, e := client.CallContract(context.Background(), msg, nil)
	if e != nil {
		log.Info("Call Contract failed ", e.Error())
		return nil, "", Web3Error{http.StatusNotFound, e.Error()}
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

func checkResolveMode(w3url Web3URL) int {
	msg, _, err := parseArguments("", w3url.Contract, []string{"resolveMode"})
	if err.HasError() {
		panic(err)
	}
	client, _ := ethclient.Dial(config.ChainConfigs[w3url.TargetChain].RPC)
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
func parseArguments(nameServiceChain string, addr common.Address, args []string) (ethereum.CallMsg, ArgInfo, Web3Error) {
	msig := "("
	mimeType := ""
	var arguments abi.Arguments = make([]abi.Argument, 0)
	values := make([]interface{}, 0)
	for i := 1; i < len(args); i++ {
		if len(args[i]) == 0 {
			continue
		}
		ty, typeStr, value, err := parseArgument(args[i], nameServiceChain)
		if err.HasError() {
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
		return ethereum.CallMsg{}, ArgInfo{}, Web3Error{http.StatusBadRequest, err.Error()}
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
	return msg, argInfo, NoWeb3Error
}

// parseArgument parses a [TYPE!]VALUE string into an abi.Type. The type will be auto-detected if TYPE not provided
func parseArgument(s string, nsChain string) (abi.Type, string, interface{}, Web3Error) {
	ss := strings.Split(s, "!")
	if len(ss) > 2 {
		return abi.Type{}, "", nil, Web3Error{http.StatusBadRequest, "argument wrong format: " + s}
	}

	var v interface{}
	if len(ss) == 2 {
		switch ss[0] {
		case "uint256":
			b := new(big.Int)
			n, ok := b.SetString(ss[1], 0)
			if !ok {
				return abi.Type{}, "uint256", nil, Web3Error{http.StatusBadRequest, "argument is not a number: " + s}
			}
			v = n
		case "bytes32":
			if !has0xPrefix(ss[1]) || !isHex(ss[1][2:]) {
				return abi.Type{}, "bytes32", nil, Web3Error{http.StatusBadRequest, "argument is not a valid hex string: " + s}
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
				return abi.Type{}, "bytes", nil, Web3Error{http.StatusBadRequest, "argument is not a valid hex string: " + s}
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
			return abi.Type{}, "", nil, Web3Error{http.StatusBadRequest, "unknown type: " + ss[0]}
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

func checkReturnType(w http.ResponseWriter, req *http.Request, w3url *Web3URL) Web3Error {
	termReturnTypesURL := req.URL.Query().Get("returnTypes")
	termReturnsURL := req.URL.Query().Get("returns")
	// attribute `returnTypes` is an alias of `returns`, for compatibility concern
	// duplicate returns are prohibited
	if termReturnsURL != "" && termReturnTypesURL != "" {
		// cannot parse a full url, early exit
		return Web3Error{http.StatusBadRequest, "Duplicate return attribute"}
	}
	// here should only one string is meaningful
	var rType string
	if termReturnsURL != "" {
		rType = termReturnsURL
	} else {
		rType = termReturnTypesURL
	}
	if w3url.ReturnType == "" {
		if rType != "" {
			w3url.ReturnType = rType
		}
	} else {
		if rType != "" && rType != w3url.ReturnType {
			return Web3Error{http.StatusBadRequest, "Conflict return types"}
		}
	}
	return Web3Error{}
}

// parseOutput parses the bytes into actual values according to the returnTypes string
func parseOutput(output []byte, userTypes string) ([]interface{}, Web3Error) {
	returnTypes := "(bytes)"
	if userTypes == "()" {
		return []interface{}{"0x" + common.Bytes2Hex(output)}, NoWeb3Error
	} else if userTypes != "" {
		returnTypes = userTypes
	}
	returnArgs := strings.Split(strings.Trim(returnTypes, "()"), ",")
	var argsArray abi.Arguments
	for _, arg := range returnArgs {
		ty, err := abi.NewType(arg, "", nil)
		if err != nil {
			return nil, Web3Error{http.StatusBadRequest, err.Error()}
		}
		argsArray = append(argsArray, abi.Argument{Name: "", Type: ty, Indexed: false})
	}
	var res []interface{}
	res, err := argsArray.UnpackValues(output)
	if err != nil {
		return nil, Web3Error{http.StatusBadRequest, err.Error()}
	}
	if userTypes != "" {
		for i, arg := range argsArray {
			// get the type of the return value
			res[i] = toJSON(arg.Type, res[i])
		}
	}
	return res, NoWeb3Error
}
