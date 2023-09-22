package main

// import (
// 	"context"
// 	"net/http"
// 	"strings"

// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/ethclient"
// 	log "github.com/sirupsen/logrus"
// 	"golang.org/x/net/idna"

// 	"golang.org/x/crypto/sha3"

// 	"github.com/ethstorage/web3url-gateway/pkg/web3protocol"
// )

// var (
// 	EmptyString  = strings.Repeat("0", 62) + "20" + strings.Repeat("0", 64)
// 	EmptyAddress = strings.Repeat("0", 64)

// 	p = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.Transitional(false))
// )

// // Normalize normalizes a name according to the ENS rules
// func Normalize(input string) (output string, err error) {
// 	output, err = p.ToUnicode(input)
// 	if err != nil {
// 		return
// 	}
// 	// If the name started with a period then ToUnicode() removes it, but we want to keep it
// 	if strings.HasPrefix(input, ".") && !strings.HasPrefix(output, ".") {
// 		output = "." + output
// 	}
// 	return
// }

// // LabelHash generates a simple hash for a piece of a name.
// func LabelHash(label string) (hash [32]byte, err error) {
// 	normalizedLabel, err := Normalize(label)
// 	if err != nil {
// 		return
// 	}

// 	sha := sha3.NewLegacyKeccak256()
// 	if _, err = sha.Write([]byte(normalizedLabel)); err != nil {
// 		return
// 	}
// 	sha.Sum(hash[:0])
// 	return
// }

// // NameHash generates a hash from a name that can be used to
// // look up the name in ENS
// func NameHash(name string) (hash [32]byte, err error) {
// 	if name == "" {
// 		return
// 	}
// 	normalizedName, err := Normalize(name)
// 	if err != nil {
// 		return
// 	}
// 	parts := strings.Split(normalizedName, ".")
// 	for i := len(parts) - 1; i >= 0; i-- {
// 		if hash, err = nameHashPart(hash, parts[i]); err != nil {
// 			return
// 		}
// 	}
// 	return
// }

// func nameHashPart(currentHash [32]byte, name string) (hash [32]byte, err error) {
// 	sha := sha3.NewLegacyKeccak256()
// 	if _, err = sha.Write(currentHash[:]); err != nil {
// 		return
// 	}
// 	nameSha := sha3.NewLegacyKeccak256()
// 	if _, err = nameSha.Write([]byte(name)); err != nil {
// 		return
// 	}
// 	nameHash := nameSha.Sum(nil)
// 	if _, err = sha.Write(nameHash); err != nil {
// 		return
// 	}
// 	sha.Sum(hash[:0])
// 	return
// }

// // If the read is failed, the address will be read with the `addr` record
// func getAddressFromNameService(nameServiceChain string, nameWithSuffix string) (common.Address, string, Web3Error) {
// 	if common.IsHexAddress(nameWithSuffix) {
// 		return common.HexToAddress(nameWithSuffix), "", NoWeb3Error
// 	}
// 	nsInfo, rpc, we := getConfigs(nameServiceChain, nameWithSuffix)
// 	if we.HasError() {
// 		return common.Address{}, "", we
// 	}
// 	client, err := ethclient.Dial(rpc)
// 	if err != nil {
// 		log.Debug(err)
// 		return common.Address{}, "", Web3Error{http.StatusInternalServerError, "internal server error"}
// 	}
// 	defer client.Close()

// 	nameHash, _ := NameHash(nameWithSuffix)
// 	node := common.BytesToHash(nameHash[:]).Hex()
// 	log.Debug("node: ", node)
// 	resolver, e := getResolver(client, common.HexToAddress(nsInfo.NSAddr), node, nameServiceChain, nameWithSuffix)
// 	if e.HasError() {
// 		return common.Address{}, "", e
// 	}
// 	return resolve(client, nameServiceChain, resolver, []string{"addr", "bytes32!" + node})

// 	// // fallback to simple name service
// 	// args := []string{"pointers", "bytes32!" + common.BytesToHash(common.RightPadBytes([]byte(nameWithSuffix[:len(nameWithSuffix)-4]), 32)).Hex()}
// 	// return resolve(client, nameServiceChain, common.HexToAddress(nsInfo.NSAddr), args)
// }

// // When webHandler is True, the address will be read with specific webHandler field first;
// // If the read is failed, the address will be read with the `addr` record
// func getAddressFromNameServiceWebHandler(nameServiceChain string, nameWithSuffix string) (common.Address, string, Web3Error) {
// 	if common.IsHexAddress(nameWithSuffix) {
// 		return common.HexToAddress(nameWithSuffix), "", NoWeb3Error
// 	}
// 	nsInfo, rpc, we := getConfigs(nameServiceChain, nameWithSuffix)
// 	if we.HasError() {
// 		return common.Address{}, "", we
// 	}
// 	client, err := ethclient.Dial(rpc)
// 	if err != nil {
// 		log.Debug(err)
// 		return common.Address{}, "", Web3Error{http.StatusInternalServerError, "internal server error"}
// 	}
// 	defer client.Close()

// 	nameHash, _ := NameHash(nameWithSuffix)
// 	node := common.BytesToHash(nameHash[:]).Hex()
// 	log.Debug("node: ", node)
// 	resolver, e := getResolver(client, common.HexToAddress(nsInfo.NSAddr), node, nameServiceChain, nameWithSuffix)
// 	if e.HasError() {
// 		return common.Address{}, "", e
// 	}
// 	var args []string
// 	var returnTp string
// 	if nsInfo.NSType == web3protocol.DomainNameResolverW3NS {
// 		args = []string{"webHandler", "bytes32!" + node}
// 		returnTp = "(address)"
// 	} else {
// 		args = []string{"text", "bytes32!" + node, "string!contentcontract"}
// 		returnTp = "(string)"
// 	}
// 	msg, _, e := parseArguments(nameServiceChain, resolver, args)
// 	if e.HasError() {
// 		return common.Address{}, "", e
// 	}
// 	bs, we := handleCallContract(*client, msg)
// 	if we.HasError() {
// 		return common.Address{}, "", we
// 	}
// 	if common.Bytes2Hex(bs) != EmptyString {
// 		res, we := parseOutput(bs, returnTp)
// 		if !we.HasError() {
// 			return parseChainSpecificAddress(res[0].(string))
// 		}
// 	}
// 	return resolve(client, nameServiceChain, resolver, []string{"addr", "bytes32!" + node})

// 	// // fallback to simple name service
// 	// args := []string{"pointers", "bytes32!" + common.BytesToHash(common.RightPadBytes([]byte(nameWithSuffix[:len(nameWithSuffix)-4]), 32)).Hex()}
// 	// return resolve(client, nameServiceChain, common.HexToAddress(nsInfo.NSAddr), args)
// }

// func resolve(client *ethclient.Client, nameServiceChain string, resolver common.Address, args []string) (common.Address, string, Web3Error) {
// 	msg, _, e := parseArguments(nameServiceChain, resolver, args)
// 	if e.HasError() {
// 		return common.Address{}, "", e
// 	}
// 	bs, err := client.CallContract(context.Background(), msg, nil)
// 	if err != nil || common.Bytes2Hex(bs) == EmptyAddress {
// 		log.Infof("Cannot get address: %v\n", err)
// 		return common.Address{}, "", Web3Error{http.StatusNotFound, err.Error()}
// 	}
// 	res, e := parseOutput(bs, "address")
// 	if e.HasError() {
// 		return common.Address{}, "", e
// 	}
// 	return parseChainSpecificAddress(res[0].(string))
// }

// func getResolver(client *ethclient.Client, nsAddr common.Address, node, nameServiceChain, nameWithSuffix string) (common.Address, Web3Error) {
// 	msg, _, e := parseArguments(nameServiceChain, nsAddr,
// 		[]string{"resolver", "bytes32!" + node})
// 	if e.HasError() {
// 		return common.Address{}, e
// 	}
// 	bs, e := handleCallContract(*client, msg)
// 	if e.HasError() {
// 		return common.Address{}, e
// 	}
// 	if common.Bytes2Hex(bs) == EmptyAddress {
// 		return common.Address{}, Web3Error{http.StatusBadRequest, "Cannot get resolver for " + nameWithSuffix}
// 	}
// 	log.Debug("resolver: ", common.BytesToAddress(bs).String())
// 	return common.BytesToAddress(bs), NoWeb3Error
// }

// func getConfigs(nameServiceChain, nameWithSuffix string) (web3protocol.NameServiceInfo, string, Web3Error) {
// 	ss := strings.Split(nameWithSuffix, ".")
// 	if len(ss) <= 1 {
// 		return web3protocol.NameServiceInfo{}, "", Web3Error{http.StatusBadRequest, "invalid domain name: " + nameWithSuffix}
// 	}
// 	suffix := ss[len(ss)-1]
// 	chainInfo, ok := config.ChainConfigs[nameServiceChain]
// 	if !ok {
// 		return web3protocol.NameServiceInfo{}, "", Web3Error{http.StatusBadRequest, "unsupported chain: " + nameServiceChain}
// 	}
// 	nsInfo, ok := chainInfo.NSConfig[suffix]
// 	if !ok {
// 		return web3protocol.NameServiceInfo{}, "", Web3Error{http.StatusBadRequest, "unsupported suffix: " + suffix}
// 	}
// 	return nsInfo, chainInfo.RPC, NoWeb3Error
// }

// // support chainSpecificAddress from EIP-3770
// func parseChainSpecificAddress(addr string) (common.Address, string, Web3Error) {
// 	if common.IsHexAddress(addr) {
// 		return common.HexToAddress(addr), "", NoWeb3Error
// 	}
// 	ss := strings.Split(addr, ":")
// 	if len(ss) != 2 {
// 		return common.Address{}, "", Web3Error{http.StatusBadRequest, "invalid contract address from name service: " + addr}
// 	}
// 	chainName := ss[0]
// 	chainId, ok := config.Name2Chain[strings.ToLower(chainName)]
// 	if !ok {
// 		return common.Address{}, "", Web3Error{http.StatusBadRequest, "unsupported chain short name from name service: " + addr}
// 	}
// 	if !common.IsHexAddress(ss[1]) {
// 		return common.Address{}, "", Web3Error{http.StatusBadRequest, "invalid contract address from name service: " + addr}
// 	}
// 	return common.HexToAddress(ss[1]), chainId, NoWeb3Error
// }
