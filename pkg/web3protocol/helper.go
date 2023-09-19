package web3protocol

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/naoina/toml"
	log "github.com/sirupsen/logrus"
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








type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type stringFlags struct {
	set   bool
	value string
}

type ArgInfo struct {
	methodSignature string
	mimeType        string
	calldata        string
}

func (sf *stringFlags) String() string {
	return sf.value
}

func (sf *stringFlags) Set(value string) error {
	sf.value = value
	sf.set = true
	return nil
}

var NoWeb3Error = Web3Error{}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// isHexCharacter returns bool of c being a valid hexadecimal.
func isHexCharacter(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// isHex validates whether each byte is valid hexadecimal string.
func isHex(str string) bool {
	if len(str)%2 != 0 {
		return false
	}
	for _, c := range []byte(str) {
		if !isHexCharacter(c) {
			return false
		}
	}
	return true
}

// convert the value to json string recursively, use "0x" hex string for bytes, use string for numbers
func toJSON(arg abi.Type, value interface{}) interface{} {
	switch arg.T {
	case abi.IntTy, abi.UintTy, abi.FixedPointTy, abi.AddressTy:
		return fmt.Sprintf("%v", value)
	case abi.BytesTy, abi.FixedBytesTy, abi.HashTy:
		return fmt.Sprintf("0x%x", value)
	case abi.SliceTy, abi.ArrayTy:
		ty, _ := abi.NewType(arg.Elem.String(), "", nil)
		tv := make([]interface{}, 0)
		rv := reflect.ValueOf(value)
		for i := 0; i < rv.Len(); i++ {
			tv = append(tv, toJSON(ty, rv.Index(i).Interface()))
		}
		return tv
	default:
		return value
	}
}

func callContract(contract common.Address, chain string, calldata []byte, config Config) ([]byte, error) {
	msg := ethereum.CallMsg{
		From:      common.HexToAddress("0x0000000000000000000000000000000000000000"),
		To:        &contract,
		Gas:       0,
		GasPrice:  nil,
		GasFeeCap: nil,
		GasTipCap: nil,
		Data:      calldata,
		Value:     nil,
	}
	client, linkErr := ethclient.Dial(config.ChainConfigs[chain].RPC)
	if linkErr != nil {
		log.Info("Dial failed: ", linkErr.Error())
		return nil, &Web3Error{http.StatusNotFound, linkErr.Error()}
	}
	defer client.Close()
	bs, err := handleCallContract(*client, msg)
	if err != nil {
		return nil, err
	}
	log.Info("return data len: ", len(bs))
	log.Debug("return data: 0x", hex.EncodeToString(bs))
	return bs, nil
}

func handleCallContract(client ethclient.Client, msg ethereum.CallMsg) ([]byte, error) {
	bs, err := client.CallContract(context.Background(), msg, nil)
	if err != nil {
		if err.Error() == "execution reverted" {
			return nil, &Web3Error{http.StatusBadRequest, err.Error()}
		} else {
			log.Debug(err)
			return nil, &Web3Error{http.StatusInternalServerError, "internal server error"}
		}
	}
	return bs, nil
}

func getDefaultNSSuffix(config Config) (string, error) {
	chainConfig := config.ChainConfigs["1"] // Previously config.DefaultChain
	// use first ns config as default
	for suffix := range chainConfig.NSConfig {
		return suffix, nil
	}
	return "", fmt.Errorf("cannot find ns config for default chain %v", "1") // Previously config.DefaultChain
}

func getChainById(chainId string, config Config) string {
	for k, v := range config.Name2Chain {
		if chainId == v {
			return k
		}
	}
	return chainId
}
