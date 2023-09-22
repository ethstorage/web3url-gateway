package main

import (
	// "encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	// "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	// log "github.com/sirupsen/logrus"
)

// https://ordinals.btc.w3link.io/txid/83997e2cfad159dd6f1fde263d0dbca88879e747c6ccf2b7fcfc0f5638c17511i0
//
//	or
//
// https://ordinals.btc.w3link.io/number/351686
func handleOrdinals(w http.ResponseWriter, req *http.Request, path string) {
	temp := strings.Split(path, "/")
	if len(temp) != 3 || (temp[1] != "txid" && temp[1] != "number") {
		respondWithErrorPage(w, Web3Error{http.StatusBadRequest, "invalid ordinals query"})
		return
	}
	ocontent, otype, oerr := getInscription(temp[2])
	if oerr != nil {
		respondWithErrorPage(w, Web3Error{http.StatusBadRequest, oerr.Error()})
		return
	}
	if otype != "" {
		w.Header().Set("Content-Type", otype)
	}
	_, e := w.Write(ocontent)
	if e != nil {
		respondWithErrorPage(w, Web3Error{http.StatusBadRequest, e.Error()})
		return
	}

	if len(*dbToken) > 0 {
		stats(len(ocontent), req.RemoteAddr, "Bitcoin", "ordinals", path, req.Host)
	}
}

func getInscription(idOrNumber string) ([]byte, string, error) {
	url := fmt.Sprintf("https://api.hiro.so/ordinals/v1/inscriptions/%s/content", idOrNumber)
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	mimeType := http.DetectContentType(bytes)
	return bytes, mimeType, nil
}

type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// https://eips.ethereum.org/assets/eip-5219/IDecentralizedApp.sol
// path e.g., /request/asdf/1234?abc=567&foo=bar

func handleEIP5219(w http.ResponseWriter, contract common.Address, chain, path string) ([]byte, error) {
	// strings, _ := abi.NewType("string[]", "", nil)
	// kvs, _ := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
	// 	{Name: "key", Type: "string"},
	// 	{Name: "value", Type: "string"},
	// })
	// args := abi.Arguments{
	// 	{Type: strings},
	// 	{Type: kvs},
	// }
	// resource, params, err := extractUrl(path)
	// if err != nil {
	// 	return nil, err
	// }
	// values := []interface{}{resource, params}
	// dataField, err := args.Pack(values...)
	// if err != nil {
	// 	return nil, err
	// }
	// //sig of request(string[], KeyValue[])
	// calldata := append(common.Hex2Bytes("1374c460"), dataField...)
	// addWeb3Header(w, "Calldata", "0x"+hex.EncodeToString(calldata))
	// bs, werr := callContract(contract, chain, calldata)
	// if werr.HasError() {
	// 	return nil, fmt.Errorf("call contract err %v", werr.Error())
	// }
	// uint_16, _ := abi.NewType("uint16", "", nil)
	// string_, _ := abi.NewType("string", "", nil)
	// returnArgs := abi.Arguments{
	// 	{Type: uint_16},
	// 	{Type: string_},
	// 	{Type: kvs},
	// }
	// res, err := returnArgs.UnpackValues(bs)
	// if err != nil {
	// 	return nil, err
	// }
	// statusCode, ok := res[0].(uint16)
	// if !ok {
	// 	err := fmt.Errorf("invalid statusCode(uint16) %v", res[0])
	// 	return nil, err
	// }
	// log.Info("statusCode ", statusCode)
	// body, ok := res[1].(string)
	// if !ok {
	// 	err := fmt.Errorf("invalid body(string) %v", res[1])
	// 	return nil, err
	// }
	// log.Debug("body ", body)
	// headers, ok := res[2].([]struct {
	// 	Key   string `json:"key"`
	// 	Value string `json:"value"`
	// })
	// if !ok {
	// 	err := fmt.Errorf("invalid headers %v", res[2])
	// 	return nil, err
	// }
	// for _, h := range headers {
	// 	log.Info("header ", h)
	// 	w.Header().Set(h.Key, h.Value)
	// }
	// _, err = w.Write([]byte(body))
	// if err != nil {
	// 	return nil, err
	// }
	// w.WriteHeader(int(statusCode))
	// return bs, nil
	return []byte{}, nil
}

func extractUrl(input string) ([]string, []KeyValue, error) {
	u, err := url.Parse(input)
	if err != nil {
		return nil, nil, errors.New("invalid url")
	}

	pathSegments := strings.Split(u.Path, "/")
	if len(pathSegments) <= 1 {
		return nil, nil, errors.New("invalid url")
	}
	pathSegments = pathSegments[1:]

	values := u.Query()
	kvs := make([]KeyValue, 0)
	for k, v := range values {
		if len(v) > 0 {
			kvs = append(kvs, KeyValue{k, v[0]})
		}
	}
	return pathSegments, kvs, nil
}
