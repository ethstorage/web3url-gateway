package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"strconv"

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
	_, e := w.Write(fetchedWeb3Url.Output)
	if e != nil {
		respondWithErrorPage(w, &web3protocol.ErrorWithHttpCode{http.StatusBadRequest, er.Error()})
		return
	}

	// Stats
	if len(*dbToken) > 0 {
		stats(len(fetchedWeb3Url.Output), req.RemoteAddr, fmt.Sprintf("%d", parsedWeb3Url.ChainId), fmt.Sprintf("%v", parsedWeb3Url.HostDomainNameResolver), path, h)
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
func handleSubdomain(host string, path string) (string, bool, error) {
	log.Info(host + path)
	if strings.Index(host, ":") > 0 {
		host = host[0:strings.Index(host, ":")]
	}
	if net.ParseIP(host) != nil {
		// ban ip addresses
		return "", false, fmt.Errorf("invalid subdomain")
	}
	pieces := strings.Split(host, ".")
	l := len(pieces)
	if l > 5 {
		log.Info("subdomain too long")
		return "", false, fmt.Errorf("invalid subdomain")
	}
	var useSubdomain bool
	p := path
	if l <= 2 {
		// If /xxxx:[chainShortName]/, replace chainShortName by chain id
		pathParts := strings.Split(p, "/")
		secondPathPartParts := strings.Split(pathParts[1], ":")
		if len(secondPathPartParts) == 2 {
			if chainId, ok := config.Name2Chain[secondPathPartParts[1]]; ok {
				pathParts[1] = secondPathPartParts[0] + ":" + fmt.Sprintf("%d", chainId)
				p = strings.Join(pathParts, "/")
			}
		}
		// back compatible with hosted dweb files
		if strings.HasSuffix(strings.Split(p, "/")[1], ".w3q") {
			p = strings.Replace(p, ".w3q/", ".w3q:3334/", 1)
		}
	}
	if l == 3 {
		if config.DefaultChain == 0 {
			return "", false, fmt.Errorf("default chain is not specified")
		}
		if common.IsHexAddress(pieces[0]) {
			//e.g. 0xe9e7cea3dedca5984780bafc599bd69add087d56.w3bnb.io/name?returns=(string)
			p = "/" + pieces[0] + ":" + strconv.Itoa(config.DefaultChain) + path
		} else {
			//e.g. quark.w3eth.io
			suffix, err := getDefaultNSSuffix()
			if err != nil {
				log.Info(err.Error())
				return "", false, fmt.Errorf("invalid subdomain")
			}
			name := pieces[0] + "." + suffix
			// back compatible with hosted dweb files
			if !strings.Contains(path, "/"+name+"/") {
				p = "/" + name + path
			}
		}
		useSubdomain = true
	}
	// e.g. 0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.sep.w3link.io
	if l == 4 {
		if !common.IsHexAddress(pieces[0]) {
			log.Info("invalid contract address")
			return "", false, fmt.Errorf("invalid subdomain")
		}
		name := pieces[0]
		var chainId string
		if _, ok := config.Name2Chain[pieces[1]]; ok {
			chainId = fmt.Sprintf("%d", config.Name2Chain[pieces[1]])
		} else {
			chainId = pieces[1]
		}
		full := name + ":" + chainId
		pp := strings.Split(path, "/")
		if strings.HasSuffix(pp[1], ".w3q") || strings.HasSuffix(pp[1], ".eth") {
			p = strings.Replace(path, pp[1], full, 1)
		} else {
			p = "/" + full + path
		}
		useSubdomain = true
	}
	//e.g. quark.w3q.w3q-g.w3link.io, quark.w3q.3334.w3link.io
	if l == 5 {
		if config.DefaultChain > 0 {
			log.Info("no tld should be provided when default chain is specified")
			return "", false, fmt.Errorf("invalid subdomain")
		}
		name := strings.Join(pieces[0:2], ".")
		var chainId string
		if _, ok := config.Name2Chain[pieces[2]]; ok {
			chainId = fmt.Sprintf("%d", config.Name2Chain[pieces[2]])
		} else {
			chainId = pieces[2]
		}
		full := name + ":" + chainId
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
