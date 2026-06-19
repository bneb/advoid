/*
Package main implements the ahead-of-time blocklist compiler for Advoid.

It fetches the StevenBlack unified hosts file over HTTP, parses out target
domains, computes their 64-bit FNV-1a hashes in DNS wire format (so they
match what the engine sees in incoming UDP packets), and emits blocklist.ll —
a single LLVM switch statement mapping hash → blocked/allowed.

The switch-statement-as-hash-table thing is the idea I'm happiest with.
Instead of loading a blocklist at runtime and building a hash table, the
Go compiler does all the work at build time and LLVM turns the switch into
jump tables. The lookup is a single computed branch. The tradeoff is you
have to recompile to update the blocklist, but the hot path has nothing
to allocate, probe, or chase pointers through.

The -local flag converts a text blocklist file (one domain per line) into
a binary hashes file the engine reads at startup with open/read/close.
*/
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const blocklistURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
const fnvPrime = uint64(0x100000001b3)
const fnvOffset = uint64(0xcbf29ce484222325)

// safelist contains critical infrastructure domains that must never be blocked,
// protecting the system from denial-of-service if the upstream list is compromised.
var safelist = []string{
	"localhost",
	"github.com",
	"raw.githubusercontent.com",
	"apple.com",
	"icloud.com",
}

// hashLabel applies the FNV-1a hash algorithm to a single domain label.
// It iterates byte-by-byte, mutating the 64-bit hash state.
func hashLabel(hash uint64, label string) uint64 {
	hash ^= uint64(len(label))
	hash *= fnvPrime
	for i := 0; i < len(label); i++ {
		hash ^= uint64(label[i])
		hash *= fnvPrime
	}
	return hash
}

// hashWire computes the FNV-1a hash of a full domain string formatted
// identically to a DNS QNAME wire format.
func hashWire(domain string) uint64 {
	hash := fnvOffset
	for {
		idx := strings.IndexByte(domain, '.')
		if idx == -1 {
			hash = hashLabel(hash, domain)
			break
		}
		hash = hashLabel(hash, domain[:idx])
		domain = domain[idx+1:]
	}
	hash ^= 0
	hash *= fnvPrime
	return hash
}

// parseLine extracts the target domain from a StevenBlack host file line.
// It returns an empty string if the line is a comment or invalid.
func parseLine(line string) string {
	if !strings.HasPrefix(line, "0.0.0.0") {
		return ""
	}
	parts := strings.Fields(line)
	if len(parts) < 2 || parts[1] == "0.0.0.0" {
		return ""
	}
	return parts[1]
}

// fetchStream executes an HTTP GET request to retrieve the blocklist.
func fetchStream() (io.ReadCloser, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(blocklistURL)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// processStream iterates over the fetched blocklist, extracting valid domains
// and computing their unique 64-bit FNV-1a hashes into a map, while ignoring safely-listed domains.
func processStream(r io.Reader) map[uint64]struct{} {
	hashes := make(map[uint64]struct{})
	
	safeHashes := make(map[uint64]struct{})
	for _, safeDomain := range safelist {
		safeHashes[hashWire(safeDomain)] = struct{}{}
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		domain := parseLine(scanner.Text())
		if domain != "" {
			hash := hashWire(domain)
			if _, isSafe := safeHashes[hash]; !isSafe {
				hashes[hash] = struct{}{}
			}
		}
	}
	return hashes
}

// writeIR outputs the LLVM Intermediate Representation file containing
// the monolithic switch statement for O(1) branch lookups.
func writeIR(hashes map[uint64]struct{}, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	writeIRHeader(w)
	
	for h := range hashes {
		w.WriteString(fmt.Sprintf("    i64 %d, label %%block\n", int64(h)))
	}
	
	writeIRFooter(w)
	return w.Flush()
}

func writeIRHeader(w *bufio.Writer) {
	w.WriteString("; Auto-generated LLVM IR Blocklist\n")
	w.WriteString("target datalayout = \"e-m:o-i64:64-i128:128-n32:64-S128\"\n")
	w.WriteString("target triple = \"arm64-apple-macosx\"\n\n")
	w.WriteString("define i1 @is_blocked(i64 %hash) {\nentry:\n")
	w.WriteString("  switch i64 %hash, label %allow [\n")
}

func writeIRFooter(w *bufio.Writer) {
	w.WriteString("  ]\n\nblock:\n  ret i1 1\n\nallow:\n  ret i1 0\n}\n")
}

// processLocalFile reads a text blocklist file (one domain per line),
// computes wire-format FNV-1a hashes for each domain, and writes them
// as a binary file suitable for runtime loading by the Advoid engine.
func processLocalFile(inputPath, outputPath string) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	var hashes []uint64
	seen := make(map[uint64]struct{})
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hash := hashWire(line)
		if _, exists := seen[hash]; !exists {
			seen[hash] = struct{}{}
			hashes = append(hashes, hash)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write count as little-endian u64, then each hash
	if err := binary.Write(out, binary.LittleEndian, uint64(len(hashes))); err != nil {
		return err
	}
	for _, h := range hashes {
		if err := binary.Write(out, binary.LittleEndian, h); err != nil {
			return err
		}
	}
	fmt.Printf("Wrote %d local domain hashes to %s\n", len(hashes), outputPath)
	return nil
}

func main() {
	localPath := flag.String("local", "", "Path to a local blocklist text file to convert to binary hashes")
	localOutput := flag.String("output", "blocklist.local.hashes", "Output path for binary hashes (used with -local)")
	flag.Parse()

	// Local mode: convert text blocklist to binary hashes for runtime engine loading
	if *localPath != "" {
		if err := processLocalFile(*localPath, *localOutput); err != nil {
			panic(err)
		}
		return
	}

	// Default mode: fetch StevenBlack list and generate blocklist.ll (AOT compilation)
	body, err := fetchStream()
	if err != nil {
		panic(err)
	}
	defer body.Close()

	hashes := processStream(body)
	if err := writeIR(hashes, "blocklist.ll"); err != nil {
		panic(err)
	}
}
