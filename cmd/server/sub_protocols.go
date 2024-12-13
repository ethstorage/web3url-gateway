package main

import (
	"fmt"
	"io"
	"errors"
	"net/http"
	"strings"

	"github.com/web3-protocol/web3protocol-go"
)

// https://ordinals.btc.w3link.io/txid/83997e2cfad159dd6f1fde263d0dbca88879e747c6ccf2b7fcfc0f5638c17511i0
//
//	or
//
// https://ordinals.btc.w3link.io/number/351686
func handleOrdinals(w http.ResponseWriter, req *http.Request, path string) {
	temp := strings.Split(path, "/")
	if len(temp) != 3 || (temp[1] != "txid" && temp[1] != "number") {
		respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: errors.New("invalid ordinals query")})
		return
	}
	ocontent, otype, oerr := getInscription(temp[2])
	if oerr != nil {
		respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: oerr})
		return
	}
	if otype != "" {
		w.Header().Set("Content-Type", otype)
	}
	_, e := w.Write(ocontent)
	if e != nil {
		respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: e})
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