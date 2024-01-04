package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"strconv"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum/common"

	"github.com/web3-protocol/web3protocol-go"
)


func handle(w http.ResponseWriter, req *http.Request) {
	h := req.Host

	path := req.URL.EscapedPath()
	w.Header().Set("Access-Control-Allow-Origin", config.CORS)
	if strings.HasPrefix(h, "ordinals.btc.") {
		handleOrdinals(w, req, path)
		return
	}

	// Convert the subdomain and path to a web3:// URL (without "web3:/" prefix and the query)
	p, _, er := handleSubdomain(h, path)
	if er != nil {
		respondWithErrorPage(w, &web3protocol.ErrorWithHttpCode{http.StatusBadRequest, er.Error()})
		return
	}
	if p == "/" {
		http.Redirect(w, req, config.HomePage, http.StatusFound)
		return
	}

	// Make it a full web3 URL
	web3Url := "web3:/" + p
	if len(req.URL.RawQuery) > 0 {
		web3Url += "?" + req.URL.RawQuery
	}

	// Fetch the web3 URL
	fetchedWeb3Url, err := web3protocolClient.FetchUrl(web3Url)
	if err != nil {
		respondWithErrorPage(w, err)
		return
	}
	
	// Send the HTTP headers returned by the protocol
	for httpHeaderName, httpHeaderValue := range fetchedWeb3Url.HttpHeaders {
		w.Header().Set(httpHeaderName, httpHeaderValue)
	}
	// Golang HTTP server has a weird default : if we don't explicitely add a content-type header,
	// it will add his own Content-Type: text/xml; charset=utf-8
	if w.Header().Get("Content-Type") == "" {
		// Best thing would be to remove the content-type header, but looks like we can 
		// only set it to empty. This code looks weird but it works.
		w.Header().Set("Content-Type", "")
	}

	// Add some debug headers
	parsedWeb3Url := fetchedWeb3Url.ParsedUrl
	if parsedWeb3Url.HostDomainNameResolver != "" {
		w.Header().Set("Web3-Host-Domain-Name-Resolver", string(parsedWeb3Url.HostDomainNameResolver))
		w.Header().Set("Web3-Host-Domain-Name-Resolver-Chain", fmt.Sprintf("%d", parsedWeb3Url.HostDomainNameResolverChainId))
	}
	w.Header().Set("Web3-Contract-Address", parsedWeb3Url.ContractAddress.String())
	w.Header().Set("Web3-Chain-Id", fmt.Sprintf("%d", parsedWeb3Url.ChainId))
	w.Header().Set("Web3-Resolve-Mode", string(parsedWeb3Url.ResolveMode))
	w.Header().Set("Web3-Contract-Call-Mode", string(parsedWeb3Url.ContractCallMode))
	calldata, _ := parsedWeb3Url.ComputeCalldata()
	w.Header().Set("Web3-Calldata", fmt.Sprintf("0x%x", calldata))
	if parsedWeb3Url.ContractCallMode == web3protocol.ContractCallModeMethod {
		w.Header().Set("Web3-Mode-Auto-Method", parsedWeb3Url.MethodName)
		methodArgTypes := []string{}
		for _, methodArgType := range parsedWeb3Url.MethodArgs {
			methodArgTypes = append(methodArgTypes, methodArgType.String())
		}
		w.Header().Set("Web3-Mode-Auto-Method-Arg-Types", strings.Join(methodArgTypes, ","))
		formattedMethodArgValues := make([]interface{}, 0)
		for i, methodArgValue := range parsedWeb3Url.MethodArgValues {
			formattedValue, err := web3protocol.JsonEncodeAbiTypeValue(parsedWeb3Url.MethodArgs[i], methodArgValue)
			if err != nil {
				respondWithErrorPage(w, err)
				return
			}
			formattedMethodArgValues = append(formattedMethodArgValues, formattedValue)
		}
		jsonEncodedMethodArgValues, err := json.Marshal(formattedMethodArgValues)
		if err != nil {
			respondWithErrorPage(w, err)
			return
		}
		w.Header().Set("Web3-Mode-Auto-Method-Arg-Values", string(jsonEncodedMethodArgValues))
	}
	w.Header().Set("Web3-Contract-Return-Processing", string(parsedWeb3Url.ContractReturnProcessing))
	if parsedWeb3Url.ContractReturnProcessing == web3protocol.ContractReturnProcessingDecodeABIEncodedBytes {
		w.Header().Set("Web3-Decoded-ABI-Encoded-Bytes-Mime-Type", parsedWeb3Url.DecodedABIEncodedBytesMimeType)
	} else if parsedWeb3Url.ContractReturnProcessing == web3protocol.ContractReturnProcessingJsonEncodeValues {
		valueTypes := []string{}
		for _, valueType := range parsedWeb3Url.JsonEncodedValueTypes {
			valueTypes = append(valueTypes, valueType.String())
		}
		w.Header().Set("Web3-Json-Encoded-Value-Types", strings.Join(valueTypes, ","))
	}

	// Send the HTTP code
	w.WriteHeader(fetchedWeb3Url.HttpCode)

	// Send the output
	// We receive it chunk by chunk from web3protocol-go. Usually there is only a single chunk.
	outputDataLength := 0
	buf := make([]byte, 8 * 1024 * 1024)
	for {
		// Fetch data from web3protocol-go
		n, err := fetchedWeb3Url.Output.Read(buf)
		if err != nil && err != io.EOF {
			respondWithErrorPage(w, &web3protocol.ErrorWithHttpCode{http.StatusBadRequest, err.Error()})
			return
		}
		outputDataLength += n
		if n == 0 {
			break
		}

		// Feed the data to the HTTP client
		_, err = w.Write(buf[:n])
		if  err != nil {
			respondWithErrorPage(w, &web3protocol.ErrorWithHttpCode{http.StatusBadRequest, err.Error()})
			return
		}

		// Flush it so that it gets sent right away, as a chunk
		// (This is still an HTTP 1.1 server, so it's using Transfer-encoding: chunked)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	// Stats
	if len(*dbToken) > 0 {
		stats(outputDataLength, req.RemoteAddr, fmt.Sprintf("%d", parsedWeb3Url.ChainId), fmt.Sprintf("%v", parsedWeb3Url.HostDomainNameResolver), path, h)
	}
}

func respondWithErrorPage(w http.ResponseWriter, err error) {
	httpCode := 400
	switch err.(type) {
		case *web3protocol.ErrorWithHttpCode:
			httpCode = err.(*web3protocol.ErrorWithHttpCode).HttpCode	
	}

	w.WriteHeader(httpCode)
	_, e := fmt.Fprintf(w, "<html><h1>%d: %s</h1>%v<html/>", httpCode, http.StatusText(httpCode), err.Error())
	if e != nil {
		log.Errorf("Cannot write error page: %v\n", e)
		return
	}
}

// process request with contract info in subdomain:
// e.g.,
// 0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io
// quark.w3q.w3q-g.w3link.io
func handleSubdomain(host string, path string) (p string, useSubdomain bool, err error) {
	log.Info(host + path)

	// Remove port from end of host
	if strings.Index(host, ":") > 0 {
		host = host[0:strings.Index(host, ":")]
	}
	// Do not authorize being called with an IP address
	if net.ParseIP(host) != nil {
		return "", false, fmt.Errorf("invalid subdomain")
	}

	hostParts := strings.Split(host, ".")
	hostPartsCount := len(hostParts)
	if hostPartsCount > 5 {
		log.Info("subdomain too long")
		return "", false, fmt.Errorf("invalid subdomain")
	}
	
	p = path

	// https://[gateway-host].[gateway-tld]/[web3-hex-address | web3-host]
	// Examples:
	// https://localhost/quark.w3q/index.txt -> web3://quark.w3q/index.txt
	// https://w3eth.io/quark.w3q/index.txt -> web3://quark.w3q/index.txt
	// https://w3bnb.io/0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699/index.txt (with defaultChain = 56) -> web3://0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699:56/index.txt
	if hostPartsCount <= 2 {
		pathParts := strings.Split(p, "/")
		// If no chain id, and we have a defaultChain : set it
		if len(strings.Split(pathParts[1], ":")) == 1 && config.DefaultChain > 1 {
			pathParts[1] = pathParts[1] + ":" + strconv.Itoa(config.DefaultChain)
		}
		// Hostname: If [host]:[chain-short-name] then [host]:[chain-id]
		pathParts[1] = hostChangeChainShortNameToId(pathParts[1])
		p = strings.Join(pathParts, "/")

		// back compatible with hosted dweb files
		if strings.HasSuffix(strings.Split(p, "/")[1], ".w3q") {
			p = strings.Replace(p, ".w3q/", ".w3q:3334/", 1)
		}
	}

	// https://[web3-hex-address | web3-host-name].[gateway-host].[gateway-tld]
	// These URLs require a default chain specified in config. Examples, with default chain id == 1:
	// https://quark.w3eth.io/index.txt -> web3://quark.eth/index.txt ("eth" deduced as 
	//   the default domain name service TLD from config)
	// https://0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699.w3eth.io/index.txt -> 
	//   web3://0x90560AD4A95147a00Ef17A3cC48b4Ef337a5E699:1/index.txt
	if hostPartsCount == 3 {
		if config.DefaultChain == 0 {
			return "", false, fmt.Errorf("default chain is not specified")
		}
		if common.IsHexAddress(hostParts[0]) {
			//e.g. 0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io/name?returns=(string)
			p = "/" + hostParts[0] + ":" + strconv.Itoa(config.DefaultChain) + path
		} else {
			//e.g. quark.w3eth.io
			suffix, err := getDefaultNSSuffix()
			if err != nil {
				log.Info(err.Error())
				return "", false, fmt.Errorf("invalid subdomain")
			}
			name := hostParts[0] + "." + suffix

			// back compatible with hosted dweb files
			if !strings.Contains(path, "/"+name+"/") {
				p = "/" + name + path
			}
		}
		useSubdomain = true
	}

	// https://[web3-hex-address].[web3-chain-id | web3-chain-shortname].[gateway-host].[gateway-tld]
	// Examples:
	// https://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.11155111.w3link.io/index.txt -> web3://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5:11155111/index.txt
	// https://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.sep.w3link.io/index.txt -> web3://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5:11155111/index.txt
	if hostPartsCount == 4 {
		if !common.IsHexAddress(hostParts[0]) {
			log.Info("invalid contract address")
			return "", false, fmt.Errorf("invalid subdomain")
		}

		// Hostname: If [host]:[chain-short-name] then [host]:[chain-id]
		full := hostChangeChainShortNameToId(hostParts[0] + ":" + hostParts[1])

		pp := strings.Split(path, "/")
		if strings.HasSuffix(pp[1], ".w3q") || strings.HasSuffix(pp[1], ".eth") {
			p = strings.Replace(path, pp[1], full, 1)
		} else {
			p = "/" + full + path
		}
		useSubdomain = true
	}

	// https://[web3-host-name].[web3-host-tld].[web3-chain-id | web3-chain-shortname].[gateway-host].[gateway-tld]
	// Examples:
	// https://quark.w3q.3334.w3link.io/index.txt -> web3://quark.w3q:3334/index.txt
	// https://quark.w3q.w3q-g.w3link.io/index.txt -> web3://quark.w3q:3334/index.txt
	if hostPartsCount == 5 {
		if config.DefaultChain > 0 {
			log.Info("no tld should be provided when default chain is specified")
			return "", false, fmt.Errorf("invalid subdomain")
		}

		name := hostParts[0] + "." + hostParts[1]
		// Hostname: If [host]:[chain-short-name] then [host]:[chain-id]
		full := hostChangeChainShortNameToId(name + ":" + hostParts[2])

		if strings.Index(path, "/"+name+"/") == 0 {
			// append chain short name to hosted dweb files
			p = strings.Replace(path, "/"+name+"/", "/"+full+"/", 1)
		} else if !strings.Contains(path, "/"+name+"/") {
			p = "/" + full + path
		}
		useSubdomain = true
	}
	log.Info("=>", p)

	return p, useSubdomain, nil
}
