package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"testing"
)

// patchTestDoc builds an HTML document of approximately size bytes containing
// numLinks <a href="web3://..."> tags.
func patchTestDoc(size int, numLinks int) []byte {
	var b bytes.Buffer
	b.WriteString("<html><head><title>t</title></head><body>\n")
	for i := 0; i < numLinks; i++ {
		fmt.Fprintf(&b, `<a href="web3://0x1e9796FA683cBDaA29B5fD5267FebED6D4b9124b:1/assets/%d">l%d</a>`+"\n", i, i)
	}
	filler := strings.Repeat("x", 1024)
	for b.Len() < size-64 {
		b.WriteString("<p>")
		b.WriteString(filler)
		b.WriteString("</p>\n")
	}
	b.WriteString("</body></html>")
	return b.Bytes()
}

// TestPatchTextFileGrowsBeyondInputBuffer is the regression test for the
// out-of-bounds panic: patchTextFile used to write its result back into the
// caller's buffer and return the *expanded* length, so `w.Write(buf[:n])`
// panicked whenever the patch pushed the content past the buffer capacity.
// The threshold was cap(buf) - len(htmlPatch), reachable by any page that
// nearly fills the read buffer.
func TestPatchTextFileGrowsBeyondInputBuffer(t *testing.T) {
	for _, bufSize := range []int{64 * 1024, 256 * 1024} {
		t.Run(fmt.Sprintf("%dKiB", bufSize/1024), func(t *testing.T) {
			// A page that leaves less room than the patch needs.
			doc := patchTestDoc(bufSize-1024, 0)
			buf := make([]byte, bufSize)
			n := copy(buf, doc)

			got := patchTextFile(buf[:n], "text/html", "", "w3link.io")

			if len(got) <= bufSize {
				t.Fatalf("test is not exercising the overflow: len=%d, buffer=%d", len(got), bufSize)
			}
			if want := n + len(htmlPatch); len(got) != want {
				t.Errorf("len(got)=%d, want %d", len(got), want)
			}
			// The caller writes the returned slice directly; this used to panic.
			var sink bytes.Buffer
			if _, err := sink.Write(got); err != nil {
				t.Fatalf("write: %v", err)
			}
			if !bytes.Contains(got, []byte("</body></html>")) {
				t.Error("document was truncated: closing tags are gone")
			}
		})
	}
}

// TestPatchTextFileDoesNotMutateInput pins the new contract: the input slice is
// read-only, so the caller's read buffer stays intact and reusable.
func TestPatchTextFileDoesNotMutateInput(t *testing.T) {
	doc := patchTestDoc(8*1024, 5)
	input := make([]byte, len(doc))
	copy(input, doc)

	patchTextFile(input, "text/html", "", "w3link.io")

	if !bytes.Equal(input, doc) {
		t.Error("patchTextFile modified its input slice")
	}
}

func TestPatchTextFileRewritesWeb3Urls(t *testing.T) {
	doc := patchTestDoc(4*1024, 3)
	got := patchTextFile(doc, "text/html", "", "w3link.io")

	if bytes.Contains(got, []byte("web3://0x1e9796")) {
		t.Error("web3:// link was not rewritten")
	}
	if !bytes.Contains(got, []byte(".w3link.io/assets/0")) {
		t.Error("rewritten link does not point at the gateway host")
	}
	if !bytes.Contains(got, htmlPatch) {
		t.Error("html.patch was not injected")
	}
}

func TestPatchTextFileGzipRoundTrip(t *testing.T) {
	doc := patchTestDoc(16*1024, 3)

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	zw.Write(doc)
	zw.Close()

	got := patchTextFile(compressed.Bytes(), "text/html", "gzip", "w3link.io")

	zr, err := gzip.NewReader(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("result is not valid gzip: %v", err)
	}
	decompressed, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Contains(decompressed, htmlPatch) {
		t.Error("html.patch was not injected into the gzip payload")
	}
	if bytes.Contains(decompressed, []byte("web3://0x1e9796")) {
		t.Error("web3:// link was not rewritten in the gzip payload")
	}
}

// Content that cannot be patched is returned unchanged, in its original
// encoding -- not the decompressed intermediate.
func TestPatchTextFilePassesThroughUnpatchable(t *testing.T) {
	noBody := []byte("<html><head><title>t</title></head></html>")
	if got := patchTextFile(noBody, "text/html", "", "w3link.io"); !bytes.Equal(got, noBody) {
		t.Errorf("no <body> tag: got %q, want it unchanged", got)
	}

	notGzip := []byte("<html><body>plain</body></html>")
	if got := patchTextFile(notGzip, "text/html", "gzip", "w3link.io"); !bytes.Equal(got, notGzip) {
		t.Errorf("undecompressable gzip: got %q, want the original bytes back", got)
	}
}
