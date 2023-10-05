package web3protocol

import (
    "context"
    "strconv"
    // "encoding/hex"
    // "encoding/json"
    "fmt"
    // "net"
    "net/http"
    "strings"
    "time"
    "regexp"

    log "github.com/sirupsen/logrus"

    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/ethclient"
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
    ContractReturnProcessingErc5219 = "erc5219"
)

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
// fmt.Println("%+v\n", urlMainParts)

    if urlMainParts["protocol"] != "web3" {
        return web3Url, &Web3Error{http.StatusBadRequest, "Protocol name is invalid"}
    }


// var contract string
// ss := strings.Split(path, "/")
// contract = ss[1]
// web3Url.RawPath = path[len(ss[1])+1:]

    // sr[0] means all part before a potential symbol "->", split it to get chainId


    //  contract = st[0]
    //  web3Url.HostDomainNameResolverChainId = st[1]

    //  // check if chainID is valid, against cached config(can stem from a config file)
    //  _, ok := client.Config.ChainConfigs[web3Url.HostDomainNameResolverChainId]
    //  if !ok {
    //      // check if chainName is valid
    //      chainId, ok := client.Config.Name2Chain[strings.ToLower(web3Url.HostDomainNameResolverChainId)]
    //      if !ok {
    //          return web3Url, &Web3Error{http.StatusBadRequest, "unsupported chain: " + web3Url.HostDomainNameResolverChainId}
    //      }
    //      web3Url.HostDomainNameResolverChainId = chainId
    //  }
    // }

    // Default chain is ethereum mainnet
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

    // after spliting from "->" and ":", var contact shall be a pure name service or a hex address
    if common.IsHexAddress(urlMainParts["hostname"]) {
        web3Url.ContractAddress = common.HexToAddress(urlMainParts["hostname"])
    } else {
        // Determine name suffix
        ss := strings.Split(urlMainParts["hostname"], ".")
        if len(ss) <= 1 {
            return web3Url, &Web3Error{http.StatusBadRequest, "Invalid contract address"}
        }
        nameServiceSuffix := ss[len(ss)-1]

        // We will use a nameservice in the current target chain
        web3Url.HostDomainNameResolverChainId = web3Url.ChainId

        chainInfo, _ := client.Config.ChainConfigs[web3Url.HostDomainNameResolverChainId]
        nsInfo, ok := chainInfo.NSConfig[nameServiceSuffix]
        if !ok {
            return web3Url, &Web3Error{http.StatusBadRequest, "Unsupported domain name service suffix: " + nameServiceSuffix}
        }

        // TODO change
        web3Url.HostDomainNameResolver = nsInfo.NSType

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
    // - 5219 : we parse the path and arguments and send them
    web3Url.ResolveMode = client.checkResolveMode(web3Url)

    if web3Url.ResolveMode == ResolveModeManual {
        // undecoded := req.RequestURI
        // if useSubdomain {
        //  web3Url.RawPath = undecoded
        // } else {
        //  web3Url.RawPath = undecoded[strings.Index(undecoded[1:], "/")+1:]
        // }
        err = client.parseManualModeUrl(&web3Url, urlMainParts)
    } else if web3Url.ResolveMode == ResolveModeAuto {
        err = client.parseAutoModeUrl(&web3Url, urlMainParts)
    } else if web3Url.ResolveMode == ResolveModeResourceRequests {
        // spliterIdx := strings.Index(p[1:], "/")
        // path := p[spliterIdx+1:]
        // if len(req.URL.RawQuery) > 0 {
        //  path += "?" + req.URL.RawQuery
        // }
        // bs, er = handleEIP5219(w, web3Url.Contract, web3Url.ChainId, path)
        // if er != nil {
        //  respondWithErrorPage(w, &Web3Error{http.StatusBadRequest, er.Error()})
        //  return
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
    //  return web3Url, err
    // }
    // var mimeType string
    // err = render(w, req, web3Url.ReturnType, mimeType, res)
    // if err != nil {
    //  return
    // }

    return
}








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
    msg, _, err := client.parseArguments(0, web3Url.ContractAddress, []string{"resolveMode"})
    if err != nil {
        panic(err)
    }
    ethClient, _ := ethclient.Dial(client.Config.ChainConfigs[web3Url.ChainId].RPC)
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
