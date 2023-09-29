package web3protocol

import (
    "context"
    "net/http"
    "strings"
    "fmt"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/ethclient"
    log "github.com/sirupsen/logrus"
    "golang.org/x/net/idna"

    "golang.org/x/crypto/sha3"
)

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
