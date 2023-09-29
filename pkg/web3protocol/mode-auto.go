package web3protocol

import(
	"strings"
	"mime"
	"net/http"
	"math/big"
	"net/url"
	// "fmt"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func (client *Client) parseAutoModeUrl(web3Url *Web3URL, urlMainParts map[string]string) (err error) {
	// Special case : No path : we call empty calldata
	if urlMainParts["pathname"] == "" {
		web3Url.ContractCallMode = ContractCallModeCalldata
		web3Url.Calldata = []byte{}
		return
	}

	pathnameParts := strings.Split(urlMainParts["pathname"], "/")
	if len(pathnameParts) < 3 {
		return &Web3Error{http.StatusBadRequest, "Pathname in auto mode is invalid"}
	}

	// Get method name
	web3Url.ContractCallMode = ContractCallModeMethod
	web3Url.MethodName = pathnameParts[1]

	// Resolver for domain name in args : 
	// We use the chain from the initial lookup (erc-6821 allows use to switch chain)
	domainNameResolverChainId := web3Url.ChainId
	if web3Url.HostDomainNameResolverChainId > 0 {
		domainNameResolverChainId = web3Url.HostDomainNameResolverChainId
	}

	for _, pathnamePart := range pathnameParts[2:] {
		abiType, _, value, err := client.parseArgument(pathnamePart, domainNameResolverChainId)
		if err != nil {
			return err
		}
		web3Url.MethodArgs = append(web3Url.MethodArgs, abiType)
		web3Url.MethodArgValues = append(web3Url.MethodArgValues, value)
	}

	// Get the mime type to use
	lastPathnamePartParts := strings.Split(pathnameParts[len(pathnameParts) - 1], ".")
	if len(lastPathnamePartParts) > 1 {
		// If no mime type is found, this will return empty string
		web3Url.FirstValueAsBytesMimeType = mime.TypeByExtension("." + lastPathnamePartParts[len(lastPathnamePartParts) - 1])
	}

	// Return: By default bytes
	web3Url.ContractReturnProcessing = ContractReturnProcessingFirstValueAsBytes
	// Check if there is a returns def specified
	err = checkReturnType(web3Url, urlMainParts)
	if err != nil {
		return
	}

	// _, _, err = client.parseArguments(web3Url.ChainId, web3Url.ContractAddress, web3Url.Arguments)

	// if err != nil {
	// 	log.Infof("Cannot parse message: %v\n", err)
	// 	return
	// }

	// err = checkReturnType(web3Url)
	// if err != nil {
	// 	return
	// }

	// ethClient, linkErr := ethclient.Dial(client.Config.ChainConfigs[web3Url.ChainId].RPC)
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
// 	msg, argInfo, err := parseArguments(web3Url.ChainId, web3Url.Contract, web3Url.Arguments)
// 	addWeb3Header(w, "Method-Signature", argInfo.methodSignature)
// 	addWeb3Header(w, "Calldata", argInfo.calldata)
// 	if err.HasError() {
// 		log.Infof("Cannot parse message: %v\n", err)
// 		return nil, "", err
// 	}
// 	client, linkErr := ethclient.Dial(config.ChainConfigs[web3Url.ChainId].RPC)
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




// parseArguments parses a [METHOD_NAME, ARG0, ARG1, ...] string array into an ethereum message with provided address, and return the mime type if end with type extension
func (client *Client) parseArguments(nameServiceChain int, addr common.Address, args []string) (ethereum.CallMsg, ArgInfo, error) {
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
func (client *Client) parseArgument(s string, nsChain int) (abi.Type, string, interface{}, error) {
	ss := strings.Split(s, "!")
	if len(ss) > 2 {
		return abi.Type{}, "", nil, &Web3Error{http.StatusBadRequest, "Argument wrong format: " + s}
	}

	var v interface{}
	if len(ss) == 2 {
		switch ss[0] {
		case "uint256":
			b := new(big.Int)
			n, ok := b.SetString(ss[1], 0)
			if !ok {
				return abi.Type{}, "uint256", nil, &Web3Error{http.StatusBadRequest, "Argument is not a number: " + ss[1]}
			}
			if n.Cmp(new(big.Int)) == -1 {
				return abi.Type{}, "uint256", nil, &Web3Error{http.StatusBadRequest, "Number is negative: " + ss[1]}
			}
			v = n
		case "bytes32":
			if !has0xPrefix(ss[1]) || !isHex(ss[1][2:]) || len(ss[1][2:]) != 64 {
				return abi.Type{}, "bytes32", nil, &Web3Error{http.StatusBadRequest, "Argument is not a valid hex string: " + ss[1]}
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
				return abi.Type{}, "bytes", nil, &Web3Error{http.StatusBadRequest, "Argument is not a valid hex string: " + ss[1]}
			}
			v = common.FromHex(ss[1])
		case "string":
			v = ss[1]
			// URI-percent-encoding decoding
			decodedV, err := url.PathUnescape(v.(string))
			if err != nil  {
				return abi.Type{}, "string", nil, &Web3Error{http.StatusBadRequest, "Unable to URI-percent decode: " + ss[1]}
			}
			v = decodedV
		// case "bool":
		// 	{
		// 		if ss[1] == "0" {
		// 			v = false
		// 		}
		// 		v = true
		// 	}
		default:
			return abi.Type{}, "", nil, &Web3Error{http.StatusBadRequest, "Unknown type: " + ss[0]}
		}
		ty, _ := abi.NewType(ss[0], "", nil)
		return ty, ss[0], v, nil
	}

	n := new(big.Int)
	n, success := n.SetString(ss[0], 10)
	if success {
		// Check that positive
		if n.Cmp(new(big.Int)) == -1 {
			return abi.Type{}, "uint256", nil, &Web3Error{http.StatusBadRequest, "Number is negative: " + ss[0]}
		}
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

func checkReturnType(web3Url *Web3URL, urlMainParts map[string]string) error {
	
	parsedQuery, err := url.ParseQuery(urlMainParts["searchParams"])
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

	// No rType? We exit here
	if rType == "" {
		return nil
	}

	// Parse the returnType definition
	if len(rType) < 2 {
		return &Web3Error{http.StatusBadRequest, "Invalid returns attribute"}
	}
	if string(rType[0]) != "(" || string(rType[len(rType) - 1]) != ")" {
		return &Web3Error{http.StatusBadRequest, "Invalid returns attribute"}
	}

	// Ok at this stage we know we are going to return JSON-encoded vars
	web3Url.ContractReturnProcessing = ContractReturnProcessingJsonEncodeValues

	// Remove parenthesis
	rType = rType[1:len(rType) - 1]
	// If rType is now empty, we default to bytes32
	if rType == "" {
		rType = "bytes32"
	}
	// Do the types parsing
	rTypeParts := strings.Split(rType, ",")
	web3Url.MethodReturn = []abi.Type{}
	for _, rTypePart := range rTypeParts {
		abiType, err := abi.NewType(rTypePart, "", nil)
		if err != nil {
			return &Web3Error{http.StatusBadRequest, "Invalid type: " + rTypePart}
		}
		web3Url.MethodReturn = append(web3Url.MethodReturn, abiType)
	}

	return nil
}
