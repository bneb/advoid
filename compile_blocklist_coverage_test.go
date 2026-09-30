package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- writeIR: the reproducible-output guarantee lives here -------------------

func TestWriteIRIsSortedAndReproducible(t *testing.T) {
	// Unsorted input: map iteration order is random, so the emitted file must be
	// sorted for two runs over the same set to agree byte for byte.
	hashes := map[uint64]struct{}{
		42: {}, 7: {}, 4294967296: {}, 18446744073709551615: {}, 123456789: {},
	}
	dir := t.TempDir()
	a := filepath.Join(dir, "a.ll")
	b := filepath.Join(dir, "b.ll")

	for _, path := range []string{a, b} {
		if err := writeIR(hashes, path); err != nil {
			t.Fatalf("writeIR(%s): %v", path, err)
		}
	}

	first, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("writeIR output is not reproducible across runs")
	}

	body := string(first)
	for _, want := range []string{
		"define i1 @is_blocked(i64 %hash) {",
		"switch i64 %hash, label %allow [",
		"ret i1 1",
		"ret i1 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("generated IR missing %q", want)
		}
	}
}

func TestWriteIREmitsEveryCaseAsSignedDecimal(t *testing.T) {
	// Hashes above 2^63 must round-trip through int64 the same way the original
	// compiler did, or the engine's switch will not match the hashed domain.
	hashes := map[uint64]struct{}{18446744073709551615: {}, 1: {}}
	path := filepath.Join(t.TempDir(), "x.ll")
	if err := writeIR(hashes, path); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "i64 -1, label %block") {
		t.Fatalf("expected the max uint64 to be emitted as -1; got:\n%s", body)
	}
}

// --- processLocalFile: the custom-blocklist artefact ------------------------

func TestProcessLocalFileFiltersSafelistAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "list.txt")
	out := filepath.Join(dir, "list.hashes")

	content := strings.Join([]string{
		"# comment",
		"",
		"ads.example.com",
		"ads.example.com",   // duplicate
		"apple.com",         // safelisted apex
		"metrics.apple.com", // safelisted subdomain
		"tracker.example.net",
	}, "\n")
	if err := os.WriteFile(in, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := processLocalFile(in, out); err != nil {
		t.Fatalf("processLocalFile: %v", err)
	}

	got := readHashes(t, out)
	if len(got) != 2 {
		t.Fatalf("expected 2 hashes (duplicates and safelist entries dropped), got %d: %v", len(got), got)
	}
	want := map[uint64]bool{hashWire("ads.example.com"): true, hashWire("tracker.example.net"): true}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected hash %d (safe=%v)", h, want[h])
		}
	}
}

func TestProcessLocalFileDetectsCollisions(t *testing.T) {
	// A colliding pair must fail the build rather than silently block the wrong
	// domain. Force the collision through the same seam the compiler uses.
	orig := hashFn
	defer func() { hashFn = orig }()
	hashFn = func(string) uint64 { return 99 }

	dir := t.TempDir()
	in := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(in, []byte("a.example\nb.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := processLocalFile(in, filepath.Join(dir, "out.hashes"))
	if err == nil {
		t.Fatal("expected a collision error, got nil")
	}
	if !strings.Contains(err.Error(), "collision") {
		t.Fatalf("error should mention collision, got: %v", err)
	}
}

func TestProcessLocalFileToleratesDuplicates(t *testing.T) {
	orig := hashFn
	defer func() { hashFn = orig }()
	hashFn = func(string) uint64 { return 5 }

	dir := t.TempDir()
	in := filepath.Join(dir, "list.txt")
	// Only the SAME domain repeated: distinct names sharing a hash is a genuine
	// collision and must still be rejected.
	if err := os.WriteFile(in, []byte("a.example\na.example\na.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := processLocalFile(in, filepath.Join(dir, "out.hashes")); err != nil {
		t.Fatalf("identical domains repeated must not be a collision: %v", err)
	}
}

func TestProcessLocalFileWarnsPastEngineCap(t *testing.T) {
	// The engine caps @local_hashes at 1024 entries. Silently truncating the
	// user's custom list is worse than saying so.
	var sb strings.Builder
	for i := 0; i < maxLocalHashes+10; i++ {
		sb.WriteString("d")
		sb.WriteString(strings.Repeat("x", i%50+1))
		sb.WriteString(".example\n")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(in, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := processLocalFile(in, filepath.Join(dir, "out.hashes")); err != nil {
		t.Fatalf("over-cap list should still be written: %v", err)
	}
}

// --- processStream: parsing and the minimum-count guard --------------------

func TestProcessStreamReturnsErrorOnScannerFailure(t *testing.T) {
	// A line longer than the scanner buffer must surface as an error rather than
	// a silently short blocklist.
	long := strings.Repeat("a", 2*1024*1024)
	if _, err := processStream(strings.NewReader("0.0.0.0 x.example\n" + long)); err == nil {
		t.Fatal("expected an error for an over-long line")
	}
}

func readHashes(t *testing.T, path string) []uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 8 {
		t.Fatalf("hash file too short: %d bytes", len(b))
	}
	var count uint64
	for i := 0; i < 8; i++ {
		count |= uint64(b[i]) << (8 * i)
	}
	out := make([]uint64, 0, count)
	for i := uint64(0); i < count; i++ {
		off := 8 + int(i)*8
		var v uint64
		for j := 0; j < 8; j++ {
			v |= uint64(b[off+j]) << (8 * j)
		}
		out = append(out, v)
	}
	return out
}
