package web3protocol

import (
    "context"
    "net/http"
    "strings"
    "fmt"
    "mime"

    "github.com/ethereum/go-ethereum"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/ethclient"
    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/crypto"
    log "github.com/sirupsen/logrus"
    "golang.org/x/net/idna"

    "golang.org/x/crypto/sha3"
)

type ArgInfo struct {
    methodSignature string
    mimeType        string
    calldata        string
}

var (
    EmptyString  = strings.Repeat("0", 62) + "20" + strings.Repeat("0", 64)
    EmptyAddress = strings.Repeat("0", 64)

    p = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false))
)

// Normalize normalizes a name according to the ENS rules
func Normalize(input string) (output string, err error) {
    output, err = p.ToUnicode(input)
    if err != nil {
        return
    }
    // If the name started with a period then ToUnicode() removes it, but we want to keep it
    if strings.HasPrefix(input, ".") && !strings.HasPrefix(output, ".") {
        output = "." + output
    }
    return
}

// LabelHash generates a simple hash for a piece of a name.
func LabelHash(label string) (hash [32]byte, err error) {
    normalizedLabel, err := Normalize(label)
    if err != nil {
        return
    }

    sha := sha3.NewLegacyKeccak256()
    if _, err = sha.Write([]byte(normalizedLabel)); err != nil {
        return
    }
    sha.Sum(hash[:0])
    return
}

// NameHash generates a hash from a name that can be used to
// look up the name in ENS
func NameHash(name string) (hash [32]byte, err error) {
    if name == "" {
        return
    }
    normalizedName, err := Normalize(name)
    if err != nil {
        return
    }
    parts := strings.Split(normalizedName, ".")
    for i := len(parts) - 1; i >= 0; i-- {
        if hash, err = nameHashPart(hash, parts[i]); err != nil {
            return
        }
    }
    return
}

func nameHashPart(currentHash [32]byte, name string) (hash [32]byte, err error) {
    sha := sha3.NewLegacyKeccak256()
    if _, err = sha.Write(currentHash[:]); err != nil {
        return
    }
    nameSha := sha3.NewLegacyKeccak256()
    if _, err = nameSha.Write([]byte(name)); err != nil {
        return
    }
    nameHash := nameSha.Sum(nil)
    if _, err = sha.Write(nameHash); err != nil {
        return
    }
    sha.Sum(hash[:0])
    return
}

// If the read is failed, the address will be read with the `addr` record
func (client *Client) getAddressFromNameService(nameServiceChain int, nameWithSuffix string) (common.Address, int, error) {
    if common.IsHexAddress(nameWithSuffix) {
        return common.HexToAddress(nameWithSuffix), 0, nil
    }

    // Not an address? It now has to have a dot to be a domain name, or it is just an invalid address
    if len(strings.Split(nameWithSuffix, ".")) == 1 {
    	return common.Address{}, 0, &Web3Error{http.StatusBadRequest, "Unrecognized address"}
    }

    nsInfo, rpc, we := client.getConfigs(nameServiceChain, nameWithSuffix)
    if we != nil {
        return common.Address{}, 0, we
    }
    ethClient, err := ethclient.Dial(rpc)
    if err != nil {
        log.Debug(err)
        return common.Address{}, 0, &Web3Error{http.StatusInternalServerError, "internal server error"}
    }
    defer ethClient.Close()

    nameHash, _ := NameHash(nameWithSuffix)
    node := common.BytesToHash(nameHash[:]).Hex()
    log.Debug("node: ", node)
    resolver, e := client.getResolver(ethClient, common.HexToAddress(nsInfo.NSAddr), node, nameServiceChain, nameWithSuffix)
    if e != nil {
        return common.Address{}, 0, e
    }
    return client.resolve(ethClient, nameServiceChain, resolver, []string{"addr", "bytes32!" + node})
}

// When webHandler is True, the address will be read with specific webHandler field first;
// If the read is failed, the address will be read with the `addr` record
func (client *Client) getAddressFromNameServiceWebHandler(nameServiceChain int, nameWithSuffix string) (common.Address, int, error) {
    if common.IsHexAddress(nameWithSuffix) {
        return common.HexToAddress(nameWithSuffix), 0, nil
    }
    nsInfo, rpc, we := client.getConfigs(nameServiceChain, nameWithSuffix)
    if we != nil {
        return common.Address{}, 0, we
    }
    ethClient, err := ethclient.Dial(rpc)
    if err != nil {
        log.Debug(err)
        return common.Address{}, 0, &Web3Error{http.StatusInternalServerError, "internal server error"}
    }
    defer ethClient.Close()

    nameHash, _ := NameHash(nameWithSuffix)
    node := common.BytesToHash(nameHash[:]).Hex()
    log.Debug("node: ", node)
    resolver, e := client.getResolver(ethClient, common.HexToAddress(nsInfo.NSAddr), node, nameServiceChain, nameWithSuffix)
    if e != nil {
        return common.Address{}, 0, e
    }
    var args []string
    var returnTp string
    if nsInfo.NSType == DomainNameServiceW3NS {
        args = []string{"webHandler", "bytes32!" + node}
        returnTp = "(address)"
    } else if nsInfo.NSType == DomainNameServiceENS {
        args = []string{"text", "bytes32!" + node, "string!contentcontract"}
        returnTp = "(string)"
    }
    msg, _, e := client.parseArguments(nameServiceChain, resolver, args)
    if e != nil {
        return common.Address{}, 0, e
    }
    bs, we := handleCallContract(*ethClient, msg)
    if we != nil {
        return common.Address{}, 0, we
    }
    if common.Bytes2Hex(bs) != EmptyString {
        res, we := parseOutput(bs, returnTp)
        if we == nil {
            return client.parseChainSpecificAddress(res[0].(string))
        }
    }
    return client.resolve(ethClient, nameServiceChain, resolver, []string{"addr", "bytes32!" + node})
}

func (client *Client) resolve(ethClient *ethclient.Client, nameServiceChain int, resolver common.Address, args []string) (common.Address, int, error) {
    msg, _, e := client.parseArguments(nameServiceChain, resolver, args)
    if e != nil {
        return common.Address{}, 0, e
    }
    bs, err := ethClient.CallContract(context.Background(), msg, nil)
    if err != nil || common.Bytes2Hex(bs) == EmptyAddress {
        log.Infof("Cannot get address: %v\n", err)
        return common.Address{}, 0, &Web3Error{http.StatusNotFound, err.Error()}
    }
    res, e := parseOutput(bs, "address")
    if e != nil {
        return common.Address{}, 0, e
    }
    return client.parseChainSpecificAddress(res[0].(string))
}

func (client *Client) getResolver(ethClient *ethclient.Client, nsAddr common.Address, node string, nameServiceChain int, nameWithSuffix string) (common.Address, error) {
    msg, _, e := client.parseArguments(nameServiceChain, nsAddr,
        []string{"resolver", "bytes32!" + node})
    if e != nil {
        return common.Address{}, e
    }
    bs, e := handleCallContract(*ethClient, msg)
    if e != nil {
        return common.Address{}, e
    }
    if common.Bytes2Hex(bs) == EmptyAddress {
        return common.Address{}, &Web3Error{http.StatusNotFound, "Cannot resolve domain name"}
    }
    log.Debug("resolver: ", common.BytesToAddress(bs).String())
    return common.BytesToAddress(bs), nil
}

func (client *Client) getConfigs(nameServiceChain int, nameWithSuffix string) (NameServiceInfo, string, error) {
    ss := strings.Split(nameWithSuffix, ".")
    if len(ss) <= 1 {
        return NameServiceInfo{}, "", &Web3Error{http.StatusBadRequest, "invalid domain name: " + nameWithSuffix}
    }
    suffix := ss[len(ss)-1]
    chainInfo, ok := client.Config.ChainConfigs[nameServiceChain]
    if !ok {
        return NameServiceInfo{}, "", &Web3Error{http.StatusBadRequest, fmt.Sprintf("unsupported chain: %v", nameServiceChain)}
    }
    nsInfo, ok := chainInfo.NSConfig[suffix]
    if !ok {
        return NameServiceInfo{}, "", &Web3Error{http.StatusBadRequest, "Unsupported domain name suffix: " + suffix}
    }
    return nsInfo, chainInfo.RPC, nil
}

// support chainSpecificAddress from EIP-3770
func (client *Client) parseChainSpecificAddress(addr string) (common.Address, int, error) {
    if common.IsHexAddress(addr) {
        return common.HexToAddress(addr), 0, nil
    }
    ss := strings.Split(addr, ":")
    if len(ss) != 2 {
        return common.Address{}, 0, &Web3Error{http.StatusBadRequest, "invalid contract address from name service: " + addr}
    }
    chainName := ss[0]
    chainId, ok := client.Config.Name2Chain[strings.ToLower(chainName)]
    if !ok {
        return common.Address{}, 0, &Web3Error{http.StatusBadRequest, "unsupported chain short name from name service: " + addr}
    }
    if !common.IsHexAddress(ss[1]) {
        return common.Address{}, 0, &Web3Error{http.StatusBadRequest, "invalid contract address from name service: " + addr}
    }
    return common.HexToAddress(ss[1]), chainId, nil
}


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
            res[i], _ = toJSON(arg.Type, res[i])
        }
    }
    return res, nil
}
