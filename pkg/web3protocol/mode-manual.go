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
	web3Url.ContractReturnProcessing = ContractReturnProcessingFirstValueAsBytes

	// Default MIME type is text/html
	web3Url.FirstValueAsBytesMimeType = "text/html"
	// The path can contain an extension, which will override the mime type to use
	pathnameParts := strings.Split(urlMainParts["pathname"], ".")
	if len(pathnameParts) > 1 {
		// If no mime type is found, this will return empty string
		web3Url.FirstValueAsBytesMimeType = mime.TypeByExtension("." + pathnameParts[len(pathnameParts) - 1])
	}

	return
}


// func handleManualMode(web3Url Web3URL) ([]byte, string, error) {
// 	var mimeType string
// 	ss := strings.Split(web3Url.RawPath, ".")
// 	if len(ss) > 1 {
// 		mimeType = mime.TypeByExtension("." + ss[len(ss)-1])
// 		log.Info("type: ", mimeType)
// 	}
// 	calldata := []byte(web3Url.RawPath)
// 	log.Info("calldata (manual): ", "0x"+hex.EncodeToString(calldata))
// 	addWeb3Header(w, "Calldata", "0x"+hex.EncodeToString(calldata))
// 	bs, werr := callContract(web3Url.Contract, web3Url.ChainId, calldata)
// 	if werr.HasError() {
// 		return nil, "", werr
// 	}
// 	return bs, mimeType, nil
// }