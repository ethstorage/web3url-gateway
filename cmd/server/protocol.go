package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum/common"

	"github.com/web3-protocol/web3protocol-go"
)

// We act as a proxy implementing part of the standard HTTP cache spec
// When we receive a request, we first check if we have the page in cache.
type PageCacheKey struct {
	// The web3 URL
	Web3Url string
	// In standard HTTP, the cache key also includes the request headers values specified
	// in the Vary response header.
	// Here, we only take into account the "Accept-Encoding" header, because we know the
	// others headers have no effect on the response.
	AcceptEncodingHeader string
}
type PageCacheEntryType string

const (
	// The cache entry is for standard HTTP caching (ETag, etc.)
	PageCacheEntryTypeHttpCaching PageCacheEntryType = "httpCaching"
	// The cache entry is for a URL that was marked as immutable in the configuration
	PageCacheEntryTypeImmutableUrl PageCacheEntryType = "immutableUrl"
)

type PageCacheEntry struct {
	// The type of the cache entry
	Type PageCacheEntryType

	// The ETag of the cached data
	ETag string

	// The cached data
	HttpCode    int
	HttpHeaders map[string]string
	Body        []byte

	// The time at which the cache entry was created
	CreationTime time.Time
}

func handle(w http.ResponseWriter, req *http.Request) {

	h := req.Host

	if cname, err := net.LookupCNAME(h); err == nil {
		log.Infof("cname is ---> %s", cname)
		if strings.HasSuffix(cname, ".") {
			h = cname[:len(cname)-1]
			w.Header().Set("Web3-CNAME", cname)
		}

	}

	path := req.URL.EscapedPath()
	w.Header().Set("Access-Control-Allow-Origin", config.CORS)
	if strings.HasPrefix(h, "ordinals.btc.") {
		handleOrdinals(w, req, path)
		return
	}

	// Convert the subdomain and path to a web3:// URL (without "web3:/" prefix and the query)
	p, _, er := handleSubdomain(h, path)
	if er != nil {
		log.Errorf("%s%s => Error converting subdomain: %s", h, req.URL.String(), er)
		respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: er})
		return
	}
	// Make it a full web3 URL
	web3Url := "web3:/" + p
	if len(req.URL.RawQuery) > 0 {
		web3Url += "?" + req.URL.RawQuery
	}
	log.Infof("%s%s => %s", h, req.URL.String(), web3Url)

	if p == "/" {
		http.Redirect(w, req, config.HomePage, http.StatusFound)
		return
	}

	// Get a map[string]string of the HTTP headers
	reqHttpHeaders := make(map[string]string)
	for headerName, headerValues := range req.Header {
		reqHttpHeaders[headerName] = strings.Join(headerValues, ", ")
	}

	// Check if the page is in cache
	pageCacheKey := PageCacheKey{
		Web3Url:              web3Url,
		AcceptEncodingHeader: req.Header.Get("Accept-Encoding"),
	}
	cacheEntry, cacheEntryPresent := pageCache.Get(pageCacheKey)
	// If the cache enry is present and is an immutable URL, we can return it right away
	if cacheEntryPresent && cacheEntry.Type == PageCacheEntryTypeImmutableUrl {
		// Send the HTTP headers returned by the protocol
		for httpHeaderName, httpHeaderValue := range cacheEntry.HttpHeaders {
			w.Header().Set(httpHeaderName, httpHeaderValue)
		}
		// Add a extra header indicating that it was served from cache
		w.Header().Set("Web3urlgateway-Cache-Status", "hit")
		w.Header().Set("Age", fmt.Sprintf("%d", int(time.Since(cacheEntry.CreationTime).Seconds())))
		// Golang HTTP server has a weird default : if we don't explicitely add a content-type header,
		// it will add his own Content-Type: text/xml; charset=utf-8
		if w.Header().Get("Content-Type") == "" {
			// Best thing would be to remove the content-type header, but looks like we can
			// only set it to empty. This code looks weird but it works.
			w.Header().Set("Content-Type", "")
		}
		// Send the HTTP code
		w.WriteHeader(cacheEntry.HttpCode)
		// Send the output
		_, err := w.Write(cacheEntry.Body)
		if err != nil {
			respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err})
			return
		}
		return
	}
	// If the client does not have a cache invalidation header, and
	// we have this URL cached, we inject its caching headers to the request given to the
	// web3protocol client
	cacheInvalidationHeadersSetFromCache := false
	if req.Header.Get("If-None-Match") == "" && cacheEntryPresent && cacheEntry.Type == PageCacheEntryTypeHttpCaching {
		reqHttpHeaders["If-None-Match"] = cacheEntry.ETag
		cacheInvalidationHeadersSetFromCache = true
	}

	// Fetch the web3 URL
	fetchedWeb3Url, err := web3protocolClient.FetchUrl(web3Url, reqHttpHeaders)
	if err != nil {
		respondWithErrorPage(w, err)
		return
	}

	// If cache invalidation headers where set from cache, and the response is 304, we can return
	// the cached page
	if cacheInvalidationHeadersSetFromCache && fetchedWeb3Url.HttpCode == 304 {
		// Send the HTTP headers returned by the protocol
		for httpHeaderName, httpHeaderValue := range cacheEntry.HttpHeaders {
			w.Header().Set(httpHeaderName, httpHeaderValue)
		}
		// Add a extra header indicating that it was served from cache
		w.Header().Set("Web3urlgateway-Cache-Status", "hit")
		w.Header().Set("Age", fmt.Sprintf("%d", int(time.Since(cacheEntry.CreationTime).Seconds())))
		// Golang HTTP server has a weird default : if we don't explicitely add a content-type header,
		// it will add his own Content-Type: text/xml; charset=utf-8
		if w.Header().Get("Content-Type") == "" {
			// Best thing would be to remove the content-type header, but looks like we can
			// only set it to empty. This code looks weird but it works.
			w.Header().Set("Content-Type", "")
		}
		// Send the HTTP code
		w.WriteHeader(cacheEntry.HttpCode)
		// Send the output
		_, err = w.Write(cacheEntry.Body)
		if err != nil {
			respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err})
			return
		}
		return
	}

	// Send the HTTP headers returned by the protocol
	for httpHeaderName, httpHeaderValue := range fetchedWeb3Url.HttpHeaders {
		w.Header().Set(httpHeaderName, httpHeaderValue)
	}
	// Add a extra header indicating that it was not served from cache
	w.Header().Set("Web3urlgateway-Cache-Status", "miss")
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

	// Determine if we should cache the page
	var willCacheResponseAsType PageCacheEntryType
	var cacheResponse bytes.Buffer
	cacheResponseWriter := bufio.NewWriter(&cacheResponse)
	if config.PageCache.Enabled && fetchedWeb3Url.HttpCode == 200 {
		// Check if the URL is marked as immutable
		for _, immutableUrlRegexp := range config.PageCache.ImmutableUrlRegexps {
			if matched, _ := regexp.MatchString(immutableUrlRegexp, web3Url); matched {
				willCacheResponseAsType = PageCacheEntryTypeImmutableUrl
				break
			}
		}
		// If the URL is not immutable, we check if we should cache it as a standard HTTP cache
		if willCacheResponseAsType == "" && w.Header().Get("ETag") != "" {
			willCacheResponseAsType = PageCacheEntryTypeHttpCaching
		}
	}

	// Send the output
	// We receive it chunk by chunk from web3protocol-go. Usually there is only a single chunk.
	outputDataLength := 0
	buf := make([]byte, 8*1024*1024)
	for {
		// Fetch data from web3protocol-go
		n, err := fetchedWeb3Url.Output.Read(buf)
		if err != nil && err != io.EOF {
			respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err})
			return
		}
		if n == 0 {
			break
		}

		// If the content type is text/html, we do some processing on the data
		// - patching the fetch() JS function so that it works with web3:// URLs
		// - Handling <a> links to absolute web3:// URLs
		if strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			n = patchHTMLFile(buf, n, w.Header().Get("Content-Encoding"))
		}

		// Update the total output data length
		outputDataLength += n

		// Feed the data to the HTTP client
		_, err = w.Write(buf[:n])
		if err != nil {
			respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err})
			return
		}

		// Feed the data to the cache, if enabled
		// If output data length is above the limit, we don't cache
		if willCacheResponseAsType != "" && outputDataLength > config.PageCache.MaxEntrySize {
			willCacheResponseAsType = ""
		}
		if willCacheResponseAsType != "" {
			_, err = cacheResponseWriter.Write(buf[:n])
			if err != nil {
				respondWithErrorPage(w, &web3protocol.Web3ProtocolError{HttpCode: http.StatusServiceUnavailable, Err: err})
				return
			}
		}

		// Flush it so that it gets sent right away, as a chunk
		// (This is still an HTTP 1.1 server, so it's using Transfer-encoding: chunked)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	// Save the cache entry
	if willCacheResponseAsType != "" {
		cacheResponseWriter.Flush()

		newCacheEntry := PageCacheEntry{
			Type:         willCacheResponseAsType,
			HttpCode:     fetchedWeb3Url.HttpCode,
			HttpHeaders:  make(map[string]string),
			Body:         cacheResponse.Bytes(),
			CreationTime: time.Now(),
		}
		if willCacheResponseAsType == PageCacheEntryTypeHttpCaching {
			newCacheEntry.ETag = w.Header().Get("ETag")
		}
		for httpHeaderName, httpHeaderValue := range fetchedWeb3Url.HttpHeaders {
			newCacheEntry.HttpHeaders[httpHeaderName] = httpHeaderValue
		}

		// Add the cache entry
		pageCache.Add(pageCacheKey, newCacheEntry)

		logFields := log.Fields{
			"domain":       "web3urlGateway",
			"vary-headers": pageCacheKey.AcceptEncodingHeader,
			"type":         string(willCacheResponseAsType),
			"size":         len(newCacheEntry.Body),
		}
		if willCacheResponseAsType == PageCacheEntryTypeHttpCaching {
			logFields["etag"] = newCacheEntry.ETag
		}
		log.WithFields(logFields).Infof("Added page cache entry for %s", web3Url)
		// If we know we will not cache this page, and we got a HTTP code different than 304 (Not modified),
		// and if there was previously a cache entry of type PageCacheEntryTypeHttpCaching,
		// we remove it from the cache
	} else if fetchedWeb3Url.HttpCode != 304 && cacheEntryPresent && cacheEntry.Type == PageCacheEntryTypeHttpCaching {
		pageCache.Remove(pageCacheKey)
		log.WithFields(log.Fields{
			"domain":       "web3urlGateway",
			"vary-headers": req.Header.Get("Accept-Encoding"),
			"type":         string(PageCacheEntryTypeHttpCaching),
			"etag":         cacheEntry.ETag,
		}).Infof("Removed page cache entry for %s", web3Url)
	}

	// Stats
	if len(*dbToken) > 0 {
		stats(outputDataLength, req.RemoteAddr, fmt.Sprintf("%d", parsedWeb3Url.ChainId), fmt.Sprintf("%v", parsedWeb3Url.HostDomainNameResolver), path, h)
	}
}

func respondWithErrorPage(w http.ResponseWriter, err error) {
	log.Errorf("Error: %v", err)
	httpCode := http.StatusBadRequest // Default to 400
	if web3Err, ok := err.(*web3protocol.Web3ProtocolError); ok {
		httpCode = web3Err.HttpCode
	}
	// reset Content-Type to avoid "superfluous response.WriteHeader call"
	w.Header().Set("Content-Type", "")
	w.WriteHeader(httpCode)

	escapedErrorMessage := html.EscapeString(err.Error())
	_, writeErr := fmt.Fprintf(w, "<html><head><title>Error</title></head><body><h1>%d: %s</h1><p>%s</p></body></html>",
		httpCode, http.StatusText(httpCode), escapedErrorMessage)
	if writeErr != nil {
		log.Errorf("Cannot write error page: %v", writeErr)
	}
}

// process request with contract info in subdomain:
// e.g.,
// https://0x2b51a751d3c7d3554e28dc72c3b032e5f56aa656.w3eth.io/view/2
// web3url.eth.1.w3link.io
func handleSubdomain(host string, path string) (p string, useSubdomain bool, err error) {
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
	if hostPartsCount > 6 {
		log.Info("subdomain too long")
		return "", false, fmt.Errorf("invalid subdomain")
	}

	p = path

	// https://[gateway-host].[gateway-tld]/[web3-hex-address | web3-host]
	// Examples:
	// https://w3link.io/usdc.eth/balanceOf/vitalik.eth?returns=(uint256) -> web3://usdc.eth:1/balanceOf/vitalik.eth?returns=(uint256)
	// https://0x2f7696d4284358a2e8fdb4df772dad60c2c8fbad.3333.w3link.io/hello.txt -> web3://0x2f7696d4284358a2e8fdb4df772dad60c2c8fbad:3333/hello.txt
	if hostPartsCount <= 2 {
		pathParts := strings.Split(p, "/")
		// If no chain id, and we have a defaultChain : set it
		if len(strings.Split(pathParts[1], ":")) == 1 && config.DefaultChain > 1 {
			pathParts[1] = pathParts[1] + ":" + strconv.Itoa(config.DefaultChain)
		}
		// Hostname: If [host]:[chain-short-name] then [host]:[chain-id]
		pathParts[1] = hostChangeChainShortNameToId(pathParts[1])
		p = strings.Join(pathParts, "/")
	}

	// https://[web3-hex-address | web3-host-name].[gateway-host].[gateway-tld]
	// These URLs require a default chain specified in config. Examples, with default chain id == 1:
	// https://terraformnavigator.w3eth.io/view/2 -> web3://terraformnavigator.eth/view/2
	// ("eth" deduced as the default domain name service TLD from config)
	// https://0x2b51a751d3c7d3554e28dc72c3b032e5f56aa656.w3eth.io/view/2 ->
	//   web3://0x2b51a751d3c7d3554e28dc72c3b032e5f56aa656:1/view/2
	if hostPartsCount == 3 {
		if config.DefaultChain == 0 {
			return "", false, fmt.Errorf("default chain is not specified")
		}
		if common.IsHexAddress(hostParts[0]) {
			//e.g. https://0x2b51a751d3c7d3554e28dc72c3b032e5f56aa656.w3eth.io/view/2
			p = "/" + hostParts[0] + ":" + strconv.Itoa(config.DefaultChain) + path
		} else {
			//e.g. https://terraformnavigator.w3eth.io/view/2
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
	// https://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.11155111.w3link.io/name?returns=(string) ->
	// 	web3://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5:11155111/name?returns=(string)
	// https://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5.sep.w3link.io/name?returns=(string)->
	// 	web3://0x9616fd0f0afc5d39c518289d1c1189a50bde94f5:11155111/name?returns=(string)
	if hostPartsCount == 4 {
		if !common.IsHexAddress(hostParts[0]) {
			log.Info("invalid contract address")
			return "", false, fmt.Errorf("invalid subdomain")
		}

		// Hostname: If [host]:[chain-short-name] then [host]:[chain-id]
		full := hostChangeChainShortNameToId(hostParts[0] + ":" + hostParts[1])
		p = "/" + full + path
		useSubdomain = true
	}

	// https://[web3-host-name].[web3-host-tld].[web3-chain-id | web3-chain-shortname].[gateway-host].[gateway-tld]
	// Examples:
	// https://usdc.eth.1.web3gateway.dev/balanceOf/vitalik.eth?returns=(uint256)
	//  -> web3://usdc.eth:1/balanceOf/vitalik.eth?returns=(uint256)
	// https://usdc.eth.eth.web3gateway.dev/balanceOf/vitalik.eth?returns=(uint256)
	//  -> web3://usdc.eth:eth/balanceOf/vitalik.eth?returns=(uint256)
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

	// https://[web3-host-subdomain].[web3-host-name].[web3-host-tld].[web3-chain-id | web3-chain-shortname].[gateway-host].[gateway-tld]
	// Examples:
	// https://dblog.dblog.eth.11155111.w3link.io/ -> web3://dblog.dblog.eth:11155111/
	if hostPartsCount == 6 {
		if config.DefaultChain > 0 {
			log.Info("no tld should be provided when default chain is specified")
			return "", false, fmt.Errorf("invalid subdomain")
		}

		name := hostParts[0] + "." + hostParts[1] + "." + hostParts[2]
		// Hostname: If [host]:[chain-short-name] then [host]:[chain-id]
		full := hostChangeChainShortNameToId(name + ":" + hostParts[3])

		if strings.Index(path, "/"+name+"/") == 0 {
			// append chain short name to hosted dweb files
			p = strings.Replace(path, "/"+name+"/", "/"+full+"/", 1)
		} else if !strings.Contains(path, "/"+name+"/") {
			p = "/" + full + path
		}
		useSubdomain = true
	}

	return p, useSubdomain, nil
}

// If the content type is text/html, we do some processing on the data
// - patching the fetch() JS function so that it works with web3:// URLs
// - Handling <a> links to absolute web3:// URLs
// This is not 100% perfect:
// - This will fail if the content is compressed and spread over several chunks (should be rare)
//
//go:embed html.patch
var htmlPatch []byte

func patchHTMLFile(buf []byte, n int, contentEncoding string) int {
	// Create a new buffer of length n, and copy the data into it
	alteredBuf := make([]byte, n)
	copy(alteredBuf, buf[:n])

	// If contentEncoding is "gzip", then first decompress the data
	if contentEncoding == "gzip" {
		gzipReader, err := gzip.NewReader(bytes.NewReader(alteredBuf))
		if err != nil {
			log.Infof("patchHtmlFile: Cannot initiate gzip decompression: %v\n", err)
			return n
		}
		alteredBuf, err = ioutil.ReadAll(gzipReader)
		if err != nil {
			log.Infof("patchHtmlFile: Cannot decompress gzip data (likely spread over several chunks): %v\n", err)
			return n
		}
	}

	// Look for the "<body>" tag (which might have attributes), and insert the patch right after it
	// Find the "<body" tag
	bodyTagIndex := strings.Index(strings.ToLower(string(alteredBuf)), "<body")
	if bodyTagIndex == -1 {
		return n
	}
	// Find the closing '>' of the body tag
	closingTagIndex := strings.Index(string(alteredBuf[bodyTagIndex:]), ">")
	if closingTagIndex == -1 {
		return n
	}	
	// Calculate the actual position of the closing '>' in the full buffer
	closingTagIndex += bodyTagIndex + 1
	// Insert the patch right after the closing '>' of the body tag
	alteredBuf = append(
		alteredBuf[:closingTagIndex],
		append(htmlPatch, alteredBuf[closingTagIndex:len(alteredBuf)]...)...)

	// If contentEncoding is "gzip", then recompress the data
	if contentEncoding == "gzip" {
		var compressedBuf bytes.Buffer
		gzipWriter := gzip.NewWriter(&compressedBuf)
		gzipWriter.Write(alteredBuf)
		gzipWriter.Close()
		alteredBuf = compressedBuf.Bytes()
	}

	// Finally: copy the altered data back into the original buffer and update n
	copy(buf, alteredBuf)
	n = len(alteredBuf)

	return n
}
