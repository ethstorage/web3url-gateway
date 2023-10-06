package web3protocol

import(
    "strings"
    "mime"
)

func (client *Client) parseManualModeUrl(web3Url *Web3URL, urlMainParts map[string]string) (err error) {
    // Path must be at least "/"
    path := urlMainParts["path"]
    if(len(path) == 0) {
        path = "/"
    }

    web3Url.ContractCallMode = ContractCallModeCalldata
    web3Url.Calldata = []byte(path)
    web3Url.ContractReturnProcessing = ContractReturnProcessingABIEncodedBytes

    // Default MIME type is text/html
    web3Url.DecodedABIEncodedBytesMimeType = "text/html"
    // The path can contain an extension, which will override the mime type to use
    pathnameParts := strings.Split(urlMainParts["pathname"], ".")
    if len(pathnameParts) > 1 {
        // If no mime type is found, this will return empty string
        web3Url.DecodedABIEncodedBytesMimeType = mime.TypeByExtension("." + pathnameParts[len(pathnameParts) - 1])
    }

    return
}
