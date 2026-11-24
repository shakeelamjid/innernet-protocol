// Independent UV10-1 format verifier (Go standard library, no Python imports).
// This verifies plaintext container framing and SHA-256, NOT OB80 authentication.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var mimePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,49}/[a-z0-9][a-z0-9.+-]{0,49}$`)
var tokenPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,39}$`)
var lowerHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

const maxHeader = 4096
const maxObject = 128 * 1024 * 1024

type Header struct {
	Version     string            `json:"version"`
	Kind        string            `json:"kind"`
	ContentType string            `json:"content_type"`
	Name        string            `json:"name"`
	Size        int64             `json:"size"`
	SHA256      string            `json:"sha256"`
	CreatedAt   int64             `json:"created_at"`
	StreamID    *string           `json:"stream_id"`
	Sequence    *int64            `json:"sequence"`
	Final       *bool             `json:"final"`
	Attributes  map[string]string `json:"attributes"`
}

func verify(path string) (Header, error) {
	var h Header
	fi, err := os.Lstat(path)
	if err != nil {
		return h, err
	}
	if !fi.Mode().IsRegular() {
		return h, errors.New("not a regular source file")
	}
	f, err := os.Open(path)
	if err != nil {
		return h, err
	}
	defer f.Close()
	prefix := make([]byte, 8)
	if _, err = io.ReadFull(f, prefix); err != nil {
		return h, err
	}
	if string(prefix[:4]) != "UV10" {
		return h, errors.New("UV10 magic mismatch")
	}
	n := binary.BigEndian.Uint32(prefix[4:])
	if n < 2 || n > maxHeader {
		return h, errors.New("header length outside bound")
	}
	raw := make([]byte, n)
	if _, err = io.ReadFull(f, raw); err != nil {
		return h, err
	}
	// Reject missing or extra fields; Go's struct decoder alone permits missing keys.
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return h, err
	}
	required := []string{"version", "kind", "content_type", "name", "size", "sha256",
		"created_at", "stream_id", "sequence", "final", "attributes"}
	if len(fields) != len(required) {
		return h, errors.New("application header has missing or extra keys")
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return h, errors.New("missing required field")
		}
	}
	// Go's json.Unmarshal silently converts null into zero-values for scalar
	// fields. Python rejects these types; reject them before typed decoding.
	for _, key := range []string{"version", "kind", "content_type", "name", "size", "sha256", "created_at", "attributes"} {
		if string(fields[key]) == "null" {
			return h, errors.New("null in required UV10 field")
		}
	}
	for _, key := range []string{"size", "created_at", "sequence"} {
		if string(fields[key]) == "-0" {
			return h, errors.New("noncanonical negative zero")
		}
	}
	// Reject JSON whitespace, field reordering, and noncanonical encodings.
	// Python's encoder uses sorted keys, no spaces, and escaped non-ASCII.
	canonicalKeys := []string{"attributes", "content_type", "created_at", "final", "kind", "name", "sequence", "sha256", "size", "stream_id", "version"}
	canonical := []byte{'{'}
	for i, key := range canonicalKeys {
		if i > 0 {
			canonical = append(canonical, ',')
		}
		quoted, _ := json.Marshal(key)
		canonical = append(canonical, quoted...)
		canonical = append(canonical, ':')
		value := fields[key]
		// For every value, normalize JSON representation.
		var decoded interface{}
		valueDecoder := json.NewDecoder(strings.NewReader(string(value)))
		valueDecoder.UseNumber()
		if err = valueDecoder.Decode(&decoded); err != nil {
			return h, err
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			return h, err
		}
		// Match Python json.dumps(ensure_ascii=True, separators=(",",":"))
		// while preserving numbers and key ordering.
		item := strings.NewReplacer(`\u003c`, `<`, `\u003e`, `>`, `\u0026`, `&`).Replace(string(encoded))
		for _, runeValue := range item {
			if runeValue < 128 {
				canonical = append(canonical, byte(runeValue))
			} else if runeValue <= 0xffff {
				canonical = append(canonical, fmt.Sprintf(`\u%04x`, runeValue)...)
			} else {
				two := utf16.Encode([]rune{runeValue})
				for _, unit := range two {
					canonical = append(canonical, fmt.Sprintf(`\u%04x`, unit)...)
				}
			}
		}
	}
	canonical = append(canonical, '}')
	if string(raw) != string(canonical) {
		return h, errors.New("noncanonical UV10 header")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&h); err != nil {
		return h, err
	}
	if h.Version != "UV10-1" {
		return h, errors.New("unsupported version")
	}
	switch h.Kind {
	case "file", "message", "event", "stream-segment":
	default:
		return h, errors.New("invalid kind")
	}
	if h.Size < 0 || h.Size >= maxObject-int64(n)-8 || fi.Size() != 8+int64(n)+h.Size {
		return h, errors.New("invalid payload framing")
	}
	if len([]rune(h.Name)) < 1 || len([]rune(h.Name)) > 100 || h.Name == "." || h.Name == ".." ||
		strings.HasPrefix(h.Name, ".") || strings.ContainsAny(h.Name, `/\:`+"\x00") {
		return h, errors.New("invalid display name")
	}
	// Unicode scalar values are required for parity with the Python verifier.
	validText := func(value string) bool {
		if !utf8.ValidString(value) {
			return false
		}
		for _, cp := range value {
			if cp < 0x20 || cp == 0x7f || (cp >= 0xd800 && cp <= 0xdfff) {
				return false
			}
		}
		return true
	}
	if !validText(h.Name) {
		return h, errors.New("invalid display text")
	}
	if !mimePattern.MatchString(h.ContentType) {
		return h, errors.New("bad content type")
	}
	if len(h.Attributes) > 16 {
		return h, errors.New("too many attributes")
	}
	for k, v := range h.Attributes {
		if !tokenPattern.MatchString(k) || len([]rune(v)) > 160 || !validText(v) {
			return h, errors.New("invalid attribute")
		}
	}
	if h.CreatedAt < 0 {
		return h, errors.New("invalid creation time")
	}

	if h.Kind == "message" || h.Kind == "event" {
		if h.Size > 65536 {
			return h, errors.New("message too long")
		}
	}
	if h.Kind == "stream-segment" {
		if h.StreamID == nil || len(*h.StreamID) != 32 || h.Sequence == nil || *h.Sequence < 0 || *h.Sequence >= 8192 || h.Final == nil {
			return h, errors.New("invalid stream fields")
		}
		if !lowerHex32.MatchString(*h.StreamID) {
			return h, errors.New("invalid stream hex")
		}
	} else if h.StreamID != nil || h.Sequence != nil || h.Final != nil {
		return h, errors.New("unexpected stream fields")
	}
	if !lowerHex64.MatchString(h.SHA256) {
		return h, errors.New("bad digest")
	}
	expected, err := hex.DecodeString(h.SHA256)
	if err != nil || len(expected) != 32 {
		return h, errors.New("bad digest")
	}
	digest := sha256.New()
	var read int64
	if h.Kind == "message" || h.Kind == "event" {
		body := make([]byte, int(h.Size))
		if _, err = io.ReadFull(f, body); err != nil {
			return h, errors.New("truncated payload")
		}
		if !utf8.Valid(body) {
			return h, errors.New("message/event must be UTF-8")
		}
		if h.Kind == "event" && !json.Valid(body) {
			return h, errors.New("event must be valid JSON")
		}
		_, _ = digest.Write(body)
		read = int64(len(body))
	} else {
		read, err = io.CopyN(digest, f, h.Size)
	}
	if err != nil || read != h.Size {
		return h, errors.New("truncated payload")
	}
	if hex.EncodeToString(digest.Sum(nil)) != h.SHA256 {
		return h, errors.New("payload SHA-256 mismatch")
	}
	rest := make([]byte, 1)
	if n, err := f.Read(rest); n != 0 || err != io.EOF {
		return h, errors.New("unexpected trailing payload")
	}
	return h, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: uv10verify FILE.uv10")
		os.Exit(2)
	}
	h, err := verify(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result, _ := json.Marshal(map[string]interface{}{"status": "PASS", "version": h.Version, "kind": h.Kind, "sha256": h.SHA256, "bytes": h.Size})
	fmt.Println(string(result))
}
