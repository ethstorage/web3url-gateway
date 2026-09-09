package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Response bodies are streamed through a small pooled buffer, so a body now
// routinely arrives in several reads. These tests drive the real handler
// against a mocked JSON-RPC node; nothing leaves the machine.

const testChainId = 31337

var resolveModeSelector = "0x" + hex.EncodeToString(crypto.Keccak256([]byte("resolveMode()"))[:4])

// abiEncodeBytes ABI-encodes payload as a single `bytes` return value.
func abiEncodeBytes(payload []byte) string {
	var b bytes.Buffer
	word := func(v int) {
		var w [32]byte
		for i, n := 31, v; i >= 0 && n > 0; i, n = i-1, n>>8 {
			w[i] = byte(n & 0xff)
		}
		b.Write(w[:])
	}
	word(32) // offset of the bytes value
	word(len(payload))
	b.Write(payload)
	if pad := len(payload) % 32; pad != 0 {
		b.Write(make([]byte, 32-pad))
	}
	return "0x" + hex.EncodeToString(b.Bytes())
}

// gatewayServingBody returns a gateway whose test chain answers every contract
// call with payload. An empty resolveMode() return selects "auto" mode.
func gatewayServingBody(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	encoded := abiEncodeBytes(payload)

	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Id json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &req)

		result := encoded
		if bytes.Contains(body, []byte(resolveModeSelector+`"`)) {
			result = "0x"
		}
		if len(req.Id) == 0 {
			req.Id = json.RawMessage("1")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%q}`, req.Id, result)
	}))
	t.Cleanup(rpc.Close)

	config.ChainConfigs[testChainId] = ChainConfig{ChainID: testChainId, RPC: rpc.URL, SystemRPC: rpc.URL}
	initWeb3protocolClient()
	t.Cleanup(func() {
		delete(config.ChainConfigs, testChainId)
		initWeb3protocolClient()
	})

	gw := httptest.NewServer(http.HandlerFunc(handle))
	t.Cleanup(gw.Close)
	return gw
}

// fetchBody asks the gateway for path and returns the response body.
func fetchBody(t *testing.T, gw *httptest.Server, path string) []byte {
	t.Helper()
	req, err := http.NewRequest("GET", gw.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = fmt.Sprintf("0x1e9796fa683cbdaa29b5fd5267febed6d4b9124b.%d.w3link.io", testChainId)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	return body
}

// A body several buffers long must arrive byte for byte. The pattern makes a
// lost, reordered or duplicated read show up as a mismatch, not just a length
// change -- the read buffer is pooled and reused, so stale content would show.
func TestResponseBodyStreamsIntact(t *testing.T) {
	payload := make([]byte, 5*responseBufferSize+1234)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	got := fetchBody(t, gatewayServingBody(t, payload), "/data/1?mime.type=bin")

	if !bytes.Equal(got, payload) {
		t.Errorf("body mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// Patchable content is accumulated before being patched, so a link straddling a
// read boundary is still rewritten and the javascript patch is injected once.
// Patching each read on its own would miss the link and inject nothing.
func TestPatchableBodySpanningReadsIsPatchedAsOneDocument(t *testing.T) {
	head := "<html><body>"
	link := `<a href="web3://0x1e9796FA683cBDaA29B5fD5267FebED6D4b9124b:1/assets/x">l</a>`
	// Start the link 20 bytes before the first read boundary, so it is cut in two.
	doc := head + strings.Repeat("y", responseBufferSize-len(head)-20) + link +
		strings.Repeat("z", 2*responseBufferSize) + "</body></html>"

	got := fetchBody(t, gatewayServingBody(t, []byte(doc)), "/page/1?mime.type=html")

	if bytes.Contains(got, []byte("web3://0x1e9796")) {
		t.Error("link straddling a read boundary was not rewritten")
	}
	if !bytes.Contains(got, []byte(".w3link.io/assets/x")) {
		t.Error("rewritten link does not point at the gateway host")
	}
	if n := bytes.Count(got, htmlPatch); n != 1 {
		t.Errorf("html.patch injected %d times, want exactly 1", n)
	}
	if !bytes.HasSuffix(got, []byte("</body></html>")) {
		t.Error("document was truncated")
	}
}

// Past the accumulation limit the body is served unpatched rather than held in
// memory, and it must still arrive complete.
func TestOversizedPatchableBodyIsServedComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates twice the patchable-body limit")
	}
	doc := "<html><body>" + strings.Repeat("y", maxPatchableBodySize) + "</body></html>"

	got := fetchBody(t, gatewayServingBody(t, []byte(doc)), "/page/1?mime.type=html")

	// The patched prefix carries the injected patch; the remainder is untouched.
	if want := len(doc) + len(htmlPatch); len(got) != want {
		t.Errorf("got %d bytes, want %d", len(got), want)
	}
	if !bytes.HasSuffix(got, []byte("</body></html>")) {
		t.Error("document was truncated")
	}
}

// The incident behind this change was a burst of requests to contracts
// returning nothing: the read buffer was allocated before the body size was
// known, so an empty response still cost 8 MiB in the gateway plus 8 MiB in
// web3protocol-go's SharedOutputReader, which mirrors the size we pass it.
func TestEmptyResponseDoesNotAllocatePerRequestBuffers(t *testing.T) {
	gw := gatewayServingBody(t, nil)
	fetchBody(t, gw, "/warmup?mime.type=bin") // fill the caches and the buffer pool

	const requests = 5
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < requests; i++ {
		if body := fetchBody(t, gw, fmt.Sprintf("/empty/%d?mime.type=bin", i)); len(body) != 0 {
			t.Fatalf("got %d bytes, want an empty body", len(body))
		}
	}
	runtime.ReadMemStats(&after)

	// Generous: the whole request path, mock RPC included, is well under this.
	perRequest := (after.TotalAlloc - before.TotalAlloc) / requests
	if perRequest > 1024*1024 {
		t.Errorf("%d bytes allocated per empty response, want well under 1 MiB", perRequest)
	}
}
