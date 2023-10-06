package web3protocol

import (
    "net/url"
    "strings"
    "net/http"
    "fmt"

    "github.com/ethereum/go-ethereum/accounts/abi"
)

// Step 1 : Process the web3:// url
func (client *Client) parseResourceRequestModeUrl(web3Url *Web3URL, urlMainParts map[string]string) (err error) {

    // For this mode, we call a specific function
    web3Url.ContractCallMode = ContractCallModeMethod
    web3Url.MethodName = "request"
    // Input types
    stringArrayType, _ := abi.NewType("string[]", "", nil)
    keyValueStructArrayType, _ := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
        {Name: "key", Type: "string"},
        {Name: "value", Type: "string"},
    })
    web3Url.MethodArgs = []abi.Type{
        stringArrayType,
        keyValueStructArrayType,
    }

    // Extract the values we will feed to the contract
    argValues := make([]interface{}, 0)
    
    // Process path
    pathnameParts := strings.Split(urlMainParts["pathname"], "/")
    pathnamePartsToSend := pathnameParts[1:]
    // Remove empty strings at the end (e.g. /boo///)
    for len(pathnamePartsToSend) > 0 && pathnamePartsToSend[len(pathnamePartsToSend) - 1] == "" {
        pathnamePartsToSend = pathnamePartsToSend[:len(pathnamePartsToSend) - 1]
    }
    // Now URI-percent-decode the parts
    for i, _ := range pathnamePartsToSend {
        decodedPart, err := url.PathUnescape(pathnamePartsToSend[i])
        if err != nil  {
            return &Web3Error{http.StatusBadRequest, "Unable to URI-percent decode: " + pathnamePartsToSend[i]}
        }
        pathnamePartsToSend[i] = decodedPart
    }
    argValues = append(argValues, pathnamePartsToSend)
    
    // Process query
    params := []struct{
        Key string
        Value string}{}
    parsedQuery, err := url.ParseQuery(urlMainParts["searchParams"])
    if err != nil {
        return err
    }
    for keyName, values := range parsedQuery {
        for _, value := range values {
            params = append(params, struct{
                Key string
                Value string}{
                Key: keyName,
                Value: value,
            })
        }
    }
    argValues = append(argValues, params)
    web3Url.MethodArgValues = argValues

    // Contract return processing will be custom
    web3Url.ContractReturnProcessing = ContractReturnProcessingDecodeErc5219Request

    return
}

// Step 3 : We have the contract return, process it
func (client *Client) ProcessResourceRequestContractReturn(web3Url *Web3URL, contractReturn []byte) (fetchedWeb3Url FetchedWeb3URL, err error) {
    // Init the maps
    fetchedWeb3Url.HttpHeaders = map[string]string{}

    // Preparing the ABI data structure with which we will decode the contract output
    uint16Type, _ := abi.NewType("uint16", "", nil)
    stringType, _ := abi.NewType("string", "", nil)
    keyValueStructArrayType, _ := abi.NewType("tuple[]", "", []abi.ArgumentMarshaling{
        {Name: "key", Type: "string"},
        {Name: "value", Type: "string"},
    })
    returnDataArgTypes := abi.Arguments{
        {Type: uint16Type},
        {Type: stringType},
        {Type: keyValueStructArrayType},
    }

    // Decode the ABI data
    unpackedValues, err := returnDataArgTypes.UnpackValues(contractReturn)
    if err != nil {
        return fetchedWeb3Url, &Web3Error{http.StatusBadRequest, "Unable to parse contract output"}
    }

    // Assign the decoded data to the right slots
    // HTTP code
    httpCode, ok := unpackedValues[0].(uint16)
    if !ok {
        err = fmt.Errorf("invalid statusCode(uint16) %v", unpackedValues[0])
        return fetchedWeb3Url, err
    }
    fetchedWeb3Url.HttpCode = int(httpCode)
    // Body
    body, ok := unpackedValues[1].(string)
    if !ok {
        err = fmt.Errorf("invalid body(string) %v", unpackedValues[1])
        return fetchedWeb3Url, err
    }
    fetchedWeb3Url.Output = []byte(body)
    // Headers
    headers, ok := unpackedValues[2].([]struct{
        Key string `json:"key"`
        Value string `json:"value"`})
    if !ok {
        err = fmt.Errorf("invalid headers %v", unpackedValues[2])
        return fetchedWeb3Url, err
    }
    for _, header := range headers {
        fetchedWeb3Url.HttpHeaders[header.Key] = header.Value
    }

    return
}
