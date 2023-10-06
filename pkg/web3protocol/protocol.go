package web3protocol

import (
    "strconv"
    "encoding/json"
    "fmt"
    "errors"
    "net/http"
    "strings"
    "time"
    "regexp"

    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
)

type Client struct {
    Config Config
    nameAddrCache *localCache
}

type DomainNameService string
const (
    DomainNameServiceENS = "ens"
    DomainNameServiceW3NS = "w3ns"
)

type ResolveMode string
const (
    ResolveModeAuto = "auto"
    ResolveModeManual = "manual"
    ResolveModeResourceRequests = "resourceRequest"
)

type ContractCallMode string
const (
    ContractCallModeCalldata = "calldata"
    ContractCallModeMethod = "method"
)

type ContractReturnProcessing string
const (
    // Expect the whole returned data to be ABI-encoded bytes. Decode.
    ContractReturnProcessingABIEncodedBytes = "decodeABIEncodedBytes"
    // JSON-encode the raw bytes of the returned data
    ContractReturnProcessingRawBytesJsonEncoded = "jsonEncodeRawBytes"
    // JSON-encode the different return values
    ContractReturnProcessingJsonEncodeValues = "jsonEncodeValues"
    // Expect a string as first return value, parse it as a dataUrl
    // ContractReturnProcessingDataUrl = "dataUrl" // To implement
    // Expect a return following the erc5219 spec, will decode it using this spec
    ContractReturnProcessingDecodeErc5219Request = "decodeErc5219Request"
)

// This contains a web3:// URL parsed and ready to call the main smartcontract
type Web3URL struct {
    // The actual url string "web3://...."
    Url string

    // If the host was a domain name, what domain name service was used?
    HostDomainNameResolver DomainNameService
    // Chain of the name resolution service
    HostDomainNameResolverChainId int

    // The contract address (after optional domain name resolution) that is going to be called,
    // and its chain location
    ContractAddress common.Address // actual address
    ChainId int

    // The ERC-4804 resolve mode
    ResolveMode ResolveMode

    // How do we call the smartcontract
    // 'calldata' : We use a raw calldata
    // 'method': We use the specified method and method parameters
    ContractCallMode ContractCallMode
    // Attributes for ContractCallModeCalldata
    Calldata []byte
    // Attributes for ContractCallModeMethod
    MethodName string
    MethodArgs []abi.Type
    MethodArgValues []interface{}

    // How to process the return of the contract. See enum for doc
    ContractReturnProcessing ContractReturnProcessing
    // In case of contractReturnProcessing being decodeABIEncodedBytes,
    // this will set the mime type to return
    DecodedABIEncodedBytesMimeType string
    // In case of ContractReturnProcessing being jsonEncodeValues,
    // this will tell us how to ABI-decode the returned data
    JsonEncodedValueTypes []abi.Type
}

// This contains the result of a web3:// URL call : the parsed URL, the raw contract return,
// and the bytes output, HTTP code and headers for the browser.
type FetchedWeb3URL struct {
    // The web3 URL, parsed
    ParsedUrl *Web3URL

    // The raw data returned by the contract
    ContractReturn []byte

    // The processed output, to be returned by the browser
    Output []byte
    // The HTTP code to be returned by the browser
    HttpCode int
    // The HTTP headers to be returned by the browser
    HttpHeaders map[string]string
}


/**
 * You'll need to instantiate a client to make calls.
 */
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

/**
 * The main function of the package.
 * For a given full web3:// url ("web3://xxxx"), returns a structure containing
 * the bytes output and the HTTP code and headers, as well as plenty of informations on
 * how the processing was done.
 */
func (client *Client) FetchUrl(url string) (fetchedUrl FetchedWeb3URL, err error) {
    // Parse the URL
    parsedUrl, err := client.ParseUrl(url)
    if err != nil {
        return
    }

    // Fetch the contract return data
    contractReturn, err := client.FetchContractReturn(&parsedUrl)
    if err != nil {
        return
    }

    // Finally, process the returned data
    fetchedUrl, err = client.ProcessContractReturn(&parsedUrl, contractReturn)
    if err != nil {
        return
    }

    return
}

/**
 * Step 1 : Parse the URL and determine how we are going to call the main contract.
 */
func (client *Client) ParseUrl(url string) (web3Url Web3URL, err error) {
    web3Url.Url = url

    // Parse the main structure of the URL
    web3UrlRegexp, err := regexp.Compile(`^(?P<protocol>[^:]+):\/\/(?P<hostname>[^:\/?]+)(:(?P<chainId>[1-9][0-9]*))?(?P<path>(?P<pathname>\/[^?]*)?([?](?P<searchParams>.*))?)?$`)
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

    // Protocol name: 1 name and alias supported
    if urlMainParts["protocol"] != "web3" && urlMainParts["protocol"] != "w3" {
        return web3Url, &Web3Error{http.StatusBadRequest, "Protocol name is invalid"}
    }

    // Default chain is ethereum mainnet
    // Check if we were explicitely asked to go to another chain
    web3Url.ChainId = 1
    if len(urlMainParts["chainId"]) > 0 {
        chainId, err := strconv.Atoi(urlMainParts["chainId"])
        if err != nil {
            // Regexp should always get us valid numbers, but we could enter here if overflow
            return web3Url, &Web3Error{http.StatusBadRequest, fmt.Sprintf("Unsupported chain %v", urlMainParts["chainId"])}
        }
        web3Url.ChainId = chainId
    }

    // Check that we support the chain
    _, ok := client.Config.ChainConfigs[web3Url.ChainId]
    if !ok {
        return web3Url, &Web3Error{http.StatusBadRequest, fmt.Sprintf("Unsupported chain %v", web3Url.ChainId)}
    }

    // Main hostname : We determine if we need hostname resolution, and do it
    if common.IsHexAddress(urlMainParts["hostname"]) {
        web3Url.ContractAddress = common.HexToAddress(urlMainParts["hostname"])
    } else {
        // Determine name suffix
        hostnameParts := strings.Split(urlMainParts["hostname"], ".")
        if len(hostnameParts) <= 1 {
            return web3Url, &Web3Error{http.StatusBadRequest, "Invalid contract address"}
        }
        nameServiceSuffix := hostnameParts[len(hostnameParts) - 1]
        domainNameWithoutSuffix := strings.Join(hostnameParts[0:len(hostnameParts) - 1], ".")

        if domainNameWithoutSuffix == "" {
            return web3Url, &Web3Error{http.StatusBadRequest, "Invalid domain name"}
        }

        // If the chain id was not explicitely requested on the URL, we will use the 
        // "default home" chain id of the name resolution service 
        // (e.g. 1 for .eth, 333 for w3q) as the target chain
        if len(urlMainParts["chainId"]) == 0 {
            NSDefaultChainId := client.Config.NSDefaultChains[nameServiceSuffix]
            if NSDefaultChainId == 0 {
                return web3Url, &Web3Error{http.StatusBadRequest, "Unsupported domain name service suffix: " + nameServiceSuffix}
            }
            web3Url.ChainId = NSDefaultChainId
        }

        // We will use a nameservice in the current target chain
        web3Url.HostDomainNameResolverChainId = web3Url.ChainId

        chainInfo, _ := client.Config.ChainConfigs[web3Url.HostDomainNameResolverChainId]
        nsInfo, ok := chainInfo.NSConfig[nameServiceSuffix]
        if !ok {
            return web3Url, &Web3Error{http.StatusBadRequest, "Unsupported domain name service suffix: " + nameServiceSuffix}
        }
        web3Url.HostDomainNameResolver = nsInfo.NSType

        // Make the domaine name resolution, cache it
        var addr common.Address
        var targetChain int
        var hit bool
        cacheKey := fmt.Sprintf("%v:%v", web3Url.HostDomainNameResolverChainId, urlMainParts["hostname"])
        if client.nameAddrCache != nil {
            addr, targetChain, hit = client.nameAddrCache.get(cacheKey)
        }
        if !hit {
            var err error
            addr, targetChain, err = client.getAddressFromNameServiceWebHandler(web3Url.HostDomainNameResolverChainId, urlMainParts["hostname"])
            if err != nil {
                return web3Url, err
            }
            if client.nameAddrCache != nil {
                client.nameAddrCache.add(cacheKey, addr, targetChain)
            }
        }
        web3Url.ContractAddress = addr
        if targetChain > 0 {
            web3Url.ChainId = targetChain
        }

        _, ok = client.Config.ChainConfigs[web3Url.ChainId]
        if !ok {
            return web3Url, &Web3Error{http.StatusBadRequest, fmt.Sprintf("unsupported chain id: %v", web3Url.ChainId)}
        }
    }

    // Determine the web3 mode
    // 3 modes:
    // - Auto : we parse the path and arguments and send them
    // - Manual : we forward all the path & arguments as calldata
    // - ResourceRequest : we parse the path and arguments and send them
    // Call the resolveMode in the contract
    resolveModeCalldata, err := methodCallToCalldata("resolveMode", []abi.Type{}, []interface{}{})
    if err != nil {
        return
    }
    resolveModeReturn, err := client.callContract(web3Url.ContractAddress, web3Url.ChainId, resolveModeCalldata)
    // Auto : exact match or empty bytes32 value or empty value (method does not exist or return nothing)
    // or execution reverted
    if len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "6175746f00000000000000000000000000000000000000000000000000000000" || 
        len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "0000000000000000000000000000000000000000000000000000000000000000" || 
        len(resolveModeReturn) == 0 ||
        err != nil {
        web3Url.ResolveMode = ResolveModeAuto
    // Manual : exact match
    } else if len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "6d616e75616c0000000000000000000000000000000000000000000000000000" {
        web3Url.ResolveMode = ResolveModeManual
    // ResourceRequest : exact match
    } else if len(resolveModeReturn) == 32 && common.Bytes2Hex(resolveModeReturn) == "3532313900000000000000000000000000000000000000000000000000000000" {
        web3Url.ResolveMode = ResolveModeResourceRequests
    // Other cases (method returning non recognized value) : throw an error
    } else {
        return web3Url, &Web3Error{http.StatusBadRequest, "Unsupported resolve mode"}
    }

    // Then process the resolve-mode-specific parts
    if web3Url.ResolveMode == ResolveModeManual {
        err = client.parseManualModeUrl(&web3Url, urlMainParts)
    } else if web3Url.ResolveMode == ResolveModeAuto {
        err = client.parseAutoModeUrl(&web3Url, urlMainParts)
    } else if web3Url.ResolveMode == ResolveModeResourceRequests {
        err = client.parseResourceRequestModeUrl(&web3Url, urlMainParts)
    } 
    if err != nil {
        return
    }

    return
}

/**
 * Step 2: Make the call to the main contract.
 */
func (client *Client) FetchContractReturn(web3Url *Web3URL) (contractReturn []byte, err error) {
    var calldata []byte

    // Contract call is specified with method and arguments, deduce the calldata from it
    if web3Url.ContractCallMode == ContractCallModeMethod {
        // Compute the calldata
        calldata, err = methodCallToCalldata(web3Url.MethodName, web3Url.MethodArgs, web3Url.MethodArgValues)
        if err != nil {
            return contractReturn, err
        }

    // Contract call is specified with calldata directly
    } else if web3Url.ContractCallMode == ContractCallModeCalldata {
        calldata = web3Url.Calldata

    // Empty field: This should not happen
    } else {
        err = errors.New("ContractCallMode is empty")
    }

    // Do the contract call
    contractReturn, err = client.callContract(web3Url.ContractAddress, web3Url.ChainId, calldata)
    if err != nil {
      return
    }

    if len(contractReturn) == 0 {
        return contractReturn, &Web3Error{http.StatusNotFound, "The contract returned no data (\"0x\").\n\nThis could be due to any of the following:\n  - The contract does not have the requested function,\n  - The parameters passed to the contract function may be invalid, or\n  - The address is not a contract."}
    }

    return
}

/**
 * Step 3 : Process the data returned by the main contract.
 */
func (client *Client) ProcessContractReturn(web3Url *Web3URL, contractReturn []byte) (fetchedWeb3Url FetchedWeb3URL, err error) {
    // Init the maps
    fetchedWeb3Url.HttpHeaders = map[string]string{}

    if web3Url.ContractReturnProcessing == "" {
        err = errors.New("Missing ContractReturnProcessing field");
        return
    }

    // Returned data is ABI-encoded bytes: We decode them and return them
    if web3Url.ContractReturnProcessing == ContractReturnProcessingABIEncodedBytes {
        bytesType, _ := abi.NewType("bytes", "", nil)
        argsArguments := abi.Arguments{
            abi.Argument{Name: "", Type: bytesType, Indexed: false},
        }

        // Decode the ABI bytes
        unpackedValues, err := argsArguments.UnpackValues(contractReturn)
        if err != nil {
            return fetchedWeb3Url, &Web3Error{http.StatusBadRequest, "Unable to parse contract output"}
        }
        fetchedWeb3Url.Output = unpackedValues[0].([]byte)
        fetchedWeb3Url.HttpCode = 200

        // If a MIME type was hinted, inject it
        if web3Url.DecodedABIEncodedBytesMimeType != "" {
            fetchedWeb3Url.HttpHeaders["Content-Type"] = web3Url.DecodedABIEncodedBytesMimeType;
        }

    // We JSON encode the raw bytes of the returned data
    } else if web3Url.ContractReturnProcessing == ContractReturnProcessingRawBytesJsonEncoded {
        jsonEncodedOutput, err := json.Marshal([]string{fmt.Sprintf("0x%x", contractReturn)})
        if err != nil {
            return fetchedWeb3Url, err
        }
        fetchedWeb3Url.Output = jsonEncodedOutput
        fetchedWeb3Url.HttpCode = 200
        fetchedWeb3Url.HttpHeaders["Content-Type"] = "application/json";

    // Having a contract return signature, we ABI-decode it and return the result JSON-encoded
    } else if web3Url.ContractReturnProcessing == ContractReturnProcessingJsonEncodeValues {
        argsArguments := abi.Arguments{}
        for _, jsonEncodedValueType := range web3Url.JsonEncodedValueTypes {
            argsArguments = append(argsArguments, abi.Argument{Name: "", Type: jsonEncodedValueType, Indexed: false})
        }

        // Decode the ABI data
        unpackedValues, err := argsArguments.UnpackValues(contractReturn)
        if err != nil {
            return fetchedWeb3Url, &Web3Error{http.StatusBadRequest, "Unable to parse contract output"}
        }

        // Format the data
        formattedValues := make([]interface{}, 0)
        for i, arg := range argsArguments {
            // get the type of the return value
            formattedValue, err := toJSON(arg.Type, unpackedValues[i])
            if err != nil {
                return fetchedWeb3Url, err
            }
            formattedValues = append(formattedValues, formattedValue)
        }

        // JSON encode the data
        jsonEncodedOutput, err := json.Marshal(formattedValues)
        if err != nil {
            return fetchedWeb3Url, err
        }
        fetchedWeb3Url.Output = jsonEncodedOutput
        fetchedWeb3Url.HttpCode = 200
        fetchedWeb3Url.HttpHeaders["Content-Type"] = "application/json";

    // The returned data come from contract implementing ERC5219, process it
    } else if web3Url.ContractReturnProcessing == ContractReturnProcessingDecodeErc5219Request {
        fetchedWeb3Url, err = client.ProcessResourceRequestContractReturn(web3Url, contractReturn)
    }

    return
}
