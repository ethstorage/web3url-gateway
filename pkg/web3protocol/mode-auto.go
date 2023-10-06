package web3protocol

import(
    "strings"
    "mime"
    "net/http"
    "math/big"
    "net/url"
    "regexp"
    // "fmt"

    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
)

func (client *Client) parseAutoModeUrl(web3Url *Web3URL, urlMainParts map[string]string) (err error) {
    // Special case : No path : we call empty calldata
    if urlMainParts["pathname"] == "" {
        web3Url.ContractCallMode = ContractCallModeCalldata
        web3Url.Calldata = []byte{}
        web3Url.ContractReturnProcessing = ContractReturnProcessingABIEncodedBytes
        return
    }

    pathnameParts := strings.Split(urlMainParts["pathname"], "/")

    // Get method name
    methodName := pathnameParts[1]
    if methodName == "" {
        return &Web3Error{http.StatusBadRequest, "Missing method name"}
    }
    validMethodName, err := regexp.MatchString("^[a-zA-Z$_][a-zA-Z0-9$_]*$", methodName)
    if err != nil {
        return err
    }
    if validMethodName == false {
        return &Web3Error{http.StatusBadRequest, "Invalid method name"}
    }
    web3Url.ContractCallMode = ContractCallModeMethod
    web3Url.MethodName = methodName

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

    // Return processing: By default ABI-encoded bytes
    web3Url.ContractReturnProcessing = ContractReturnProcessingABIEncodedBytes
    
    // Process the ?returns / ?returnTypes query
    parsedQuery, err := url.ParseQuery(urlMainParts["searchParams"])
    if err != nil {
        return err
    }
    returnTypesValue := parsedQuery["returnTypes"]
    returnsValue := parsedQuery["returns"]
    if len(returnsValue) > 0 && len(returnTypesValue) > 0 || len(returnsValue) >= 2 || len(returnTypesValue) >= 2 {
        return &Web3Error{http.StatusBadRequest, "Duplicate return attribute"}
    }
    var rType string
    if len(returnsValue) == 1 {
        rType = returnsValue[0]
    } else if len(returnTypesValue) == 1 {
        rType = returnTypesValue[0]
    }

    if rType != "" {
        if len(rType) < 2 {
            return &Web3Error{http.StatusBadRequest, "Invalid returns attribute"}
        }
        if string(rType[0]) != "(" || string(rType[len(rType) - 1]) != ")" {
            return &Web3Error{http.StatusBadRequest, "Invalid returns attribute"}
        }

        if rType == "()" {
            // We will return the raw bytes, JSON encoded
            web3Url.ContractReturnProcessing = ContractReturnProcessingRawBytesJsonEncoded
        } else {
            // Ok at this stage we know we are going to return JSON-encoded vars
            web3Url.ContractReturnProcessing = ContractReturnProcessingJsonEncodeValues

            // Remove parenthesis
            rType = rType[1:len(rType) - 1]

            // Do the types parsing
            rTypeParts := strings.Split(rType, ",")
            web3Url.JsonEncodedValueTypes = []abi.Type{}
            for _, rTypePart := range rTypeParts {
                abiType, err := abi.NewType(rTypePart, "", nil)
                if err != nil {
                    return &Web3Error{http.StatusBadRequest, "Invalid type: " + rTypePart}
                }
                web3Url.JsonEncodedValueTypes = append(web3Url.JsonEncodedValueTypes, abiType)
            }
        }
    }

    // If we are still returning decoded ABI-encoded bytes,
    // Get the mime type to use, from an argument
    if web3Url.ContractReturnProcessing == ContractReturnProcessingABIEncodedBytes && len(pathnameParts) >= 3 /** At least an argument */ {
        lastPathnamePartParts := strings.Split(pathnameParts[len(pathnameParts) - 1], ".")
        if len(lastPathnamePartParts) > 1 {
            // If no mime type is found, this will return empty string
            web3Url.DecodedABIEncodedBytesMimeType = mime.TypeByExtension("." + lastPathnamePartParts[len(lastPathnamePartParts) - 1])
        }
    }

    return
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
        //  {
        //      if ss[1] == "0" {
        //          v = false
        //      }
        //      v = true
        //  }
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

