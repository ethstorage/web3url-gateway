package web3protocol

import (
    "context"
    "fmt"
    "net/http"
    "reflect"
    "errors"

    "github.com/ethereum/go-ethereum"
    "github.com/ethereum/go-ethereum/accounts/abi"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/ethclient"
    "github.com/ethereum/go-ethereum/crypto"
    log "github.com/sirupsen/logrus"
)



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
func toJSON(arg abi.Type, value interface{}) (result interface{}, err error) {
    switch arg.T {
        case abi.StringTy:
            result = value

        case abi.IntTy, abi.UintTy, abi.FixedPointTy, abi.AddressTy:
            result = fmt.Sprintf("%v", value)

        case abi.BytesTy, abi.FixedBytesTy, abi.HashTy:
            result = fmt.Sprintf("0x%x", value)

        case abi.SliceTy, abi.ArrayTy:
            ty, _ := abi.NewType(arg.Elem.String(), "", nil)
            result = make([]interface{}, 0)
            rv := reflect.ValueOf(value)
            for i := 0; i < rv.Len(); i++ {
                subResult, err := toJSON(ty, rv.Index(i).Interface())
                if err != nil {
                    return result, err
                }
                result = append(result.([]interface{}), subResult)
            }

        default:
            err = errors.New(fmt.Sprintf("Unsupported type: 0x%x", arg.T));
    }

    return
}


// For a method signature and the actual arguments, generate the calldata
func methodCallToCalldata(methodName string, methodArgTypes []abi.Type, methodArgValues []interface{}) (calldata []byte, err error) {
    // ABI-encode the arguments
    abiArguments := abi.Arguments{}
    for _, methodArgType := range methodArgTypes {
        abiArguments = append(abiArguments, abi.Argument{Type: methodArgType})
    }
    calldataArgumentsPart, err := abiArguments.Pack(methodArgValues...)
    if err != nil {
        return
    }

    // Determine method signature
    methodSignature := methodName + "("
    for i, methodArgType := range methodArgTypes {
        methodSignature += methodArgType.String()
        if i < len(methodArgTypes) - 1 {
            methodSignature += ","
        }
    }
    methodSignature += ")"
    methodSignatureHash := crypto.Keccak256Hash([]byte(methodSignature))

    // Compute the calldata
    calldata = append(methodSignatureHash[0:4], calldataArgumentsPart...)

    return
}

// Call a contract with calldata
func (client *Client) callContract(contract common.Address, chain int, calldata []byte) (contractReturn []byte, err error) {
    // Prepare the ethereum message to send
    callMessage := ethereum.CallMsg{
        From:      common.HexToAddress("0x0000000000000000000000000000000000000000"),
        To:        &contract,
        Gas:       0,
        GasPrice:  nil,
        GasFeeCap: nil,
        GasTipCap: nil,
        Data:      calldata,
        Value:     nil,
    }

    // Create connection
    ethClient, err := ethclient.Dial(client.Config.ChainConfigs[chain].RPC)
    if err != nil {
        return contractReturn, &Web3Error{http.StatusBadRequest, err.Error()}
    }
    defer ethClient.Close()

    // Do the contract call
    contractReturn, err = handleCallContract(*ethClient, callMessage)
    if err != nil {
        return contractReturn, &Web3Error{http.StatusNotFound, err.Error()}
    }

    return
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

