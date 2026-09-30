package main

import (
	"strings"
	"testing"
)

func TestHashLabel(t *testing.T) {
	h := hashLabel(fnvOffset, "google")
	if h == 0 {
		t.Fatal("Expected non-zero hash for 'google'")
	}
}

func TestHashWire(t *testing.T) {
	h1 := hashWire("google.com")
	h2 := hashWire("google.com")
	if h1 != h2 {
		t.Fatal("Hash is not deterministic")
	}
	h3 := hashWire("apple.com")
	if h1 == h3 {
		t.Fatal("Hash collision on google.com and apple.com")
	}
}

// hashWire must match what the engine computes over the QNAME bytes it reads off
// the wire: each label prefixed by its length, terminated by a zero byte.
func TestHashWireMatchesWireFormat(t *testing.T) {
	wire := []byte{6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}
	h := fnvOffset
	for _, b := range wire {
		h ^= uint64(b)
		h *= fnvPrime
	}
	if got := hashWire("google.com"); got != h {
		t.Fatalf("hashWire disagrees with wire-format hashing: got %d want %d", got, h)
	}
}

func TestParseLine(t *testing.T) {
	valid := "0.0.0.0 doubleclick.net"
	res := parseLine(valid)
	if res != "doubleclick.net" {
		t.Fatalf("Expected doubleclick.net, got %s", res)
	}

	invalid := "# This is a comment"
	res = parseLine(invalid)
	if res != "" {
		t.Fatalf("Expected empty string, got %s", res)
	}

	localhost := "0.0.0.0 0.0.0.0"
	res = parseLine(localhost)
	if res != "" {
		t.Fatalf("Expected empty string, got %s", res)
	}
}

func TestProcessStream(t *testing.T) {
	input := `
# Header
0.0.0.0 ads.google.com
0.0.0.0 github.com
0.0.0.0 tracking.com
`
	hashes, err := processStream(strings.NewReader(input))
	if err != nil {
		t.Fatalf("processStream returned error: %v", err)
	}

	if len(hashes) != 2 {
		t.Fatalf("Expected 2 hashes (ads.google.com, tracking.com), got %d", len(hashes))
	}

	safeHash := hashWire("github.com")
	if _, exists := hashes[safeHash]; exists {
		t.Fatal("github.com was included despite being on the safelist")
	}
}

// The safelist must protect subdomains too. Protecting only the apex let real
// telemetry hosts such as securemetrics.apple.com through.
func TestSafelistCoversSubdomains(t *testing.T) {
	blocked := []string{
		"securemetrics.apple.com",
		"metrics.apple.com",
		"gateway.icloud.com",
		"gist.github.com",
		"raw.githubusercontent.com",
		"foo.localhost",
		"apple.com",
		"github.com",
	}
	for _, d := range blocked {
		if !isSafelisted(d) {
			t.Errorf("isSafelisted(%q) = false, want true", d)
		}
	}

	allowed := []string{
		"notapple.com",       // suffix must respect the label boundary
		"apple.com.evil.net", // safelist entry appears mid-name
		"evilapple.com",
		"example.com",
		"myicloud.com",
		// sibling, not a subdomain: only raw.githubusercontent.com is safelisted
		"objects.githubusercontent.com",
	}
	for _, d := range allowed {
		if isSafelisted(d) {
			t.Errorf("isSafelisted(%q) = true, want false", d)
		}
	}
}

func TestProcessStreamDropsSafelistedSubdomains(t *testing.T) {
	input := `
0.0.0.0 securemetrics.apple.com
0.0.0.0 metrics.apple.com
0.0.0.0 ads.example.com
`
	hashes, err := processStream(strings.NewReader(input))
	if err != nil {
		t.Fatalf("processStream returned error: %v", err)
	}
	if len(hashes) != 1 {
		t.Fatalf("expected only ads.example.com to survive, got %d entries", len(hashes))
	}
	if _, ok := hashes[hashWire("ads.example.com")]; !ok {
		t.Fatal("ads.example.com should have been kept")
	}
}

// Two distinct domains that hash to the same 64-bit value must fail the build
// rather than silently block the wrong name. hashFn is stubbed so a collision is
// guaranteed, which exercises the real detection path in processStream.
func TestProcessStreamDetectsCollisions(t *testing.T) {
	orig := hashFn
	defer func() { hashFn = orig }()
	hashFn = func(string) uint64 { return 42 } // every domain collides

	input := "0.0.0.0 first.example\n0.0.0.0 second.example\n"
	_, err := processStream(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected a collision error, got nil")
	}
	if !strings.Contains(err.Error(), "collision") {
		t.Fatalf("error should mention collision, got: %v", err)
	}
	if !strings.Contains(err.Error(), "first.example") || !strings.Contains(err.Error(), "second.example") {
		t.Fatalf("error should name both domains, got: %v", err)
	}
}

// A repeated identical domain is not a collision.
func TestProcessStreamAllowsDuplicateDomains(t *testing.T) {
	input := "0.0.0.0 ads.example.com\n0.0.0.0 ads.example.com\n"
	hashes, err := processStream(strings.NewReader(input))
	if err != nil {
		t.Fatalf("duplicates must not be an error: %v", err)
	}
	if len(hashes) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(hashes))
	}
}

func TestProcessStreamEmptyInputIsNotAnError(t *testing.T) {
	hashes, err := processStream(strings.NewReader("# nothing here\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hashes) != 0 {
		t.Fatalf("expected no hashes, got %d", len(hashes))
	}
}
