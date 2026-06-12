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
	r := strings.NewReader(input)
	hashes := processStream(r)

	if len(hashes) != 2 {
		t.Fatalf("Expected 2 hashes (ads.google.com, tracking.com), got %d", len(hashes))
	}

	safeHash := hashWire("github.com")
	if _, exists := hashes[safeHash]; exists {
		t.Fatal("github.com was included despite being on the safelist")
	}
}
