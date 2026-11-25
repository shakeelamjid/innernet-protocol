// Independent IRM-1 DRAFT vector verifier (Go standard library only).
// Re-derives, without any Python code: the canonical JSON used for signing,
// the REG-1 / descriptor / rotation / PAY-1 ticket Ed25519 signatures, and the
// STO-1 Merkle root and inclusion proof (RFC 6962 tree + block-count commit).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"unicode/utf16"
)

const (
	registryDomain   = "INNERnet/REG-1/provider-registry\x00"
	rotationDomain   = "INNERnet/REG-1/registry-key-rotation\x00"
	descriptorDomain = "INNERnet/REG-1/provider-descriptor\x00"
	ticketDomain     = "INNERnet/PAY-1/service-ticket\x00"
	blockSize        = 1024
)

// canonical reproduces Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True).
func canonical(v any, buf *bytes.Buffer) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		if _, err := strconv.ParseInt(string(x), 10, 64); err != nil {
			return errors.New("non-integer number in signed payload")
		}
		buf.WriteString(string(x))
	case string:
		writeString(x, buf)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonical(e, buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(k, buf)
			buf.WriteByte(':')
			if err := canonical(x[k], buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON type %T", v)
	}
	return nil
}

// Python sorts str keys by code point; for the ASCII keys used here this equals byte order.
func lessUTF16(a, b string) bool { return a < b }

func writeString(s string, buf *bytes.Buffer) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 || r > 0x7e {
				if r > 0xffff {
					a, b := utf16.EncodeRune(r)
					fmt.Fprintf(buf, `\u%04x\u%04x`, a, b)
				} else {
					fmt.Fprintf(buf, `\u%04x`, r)
				}
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func mustHex(s any, n int, label string) []byte {
	str, ok := s.(string)
	if !ok {
		fail(label + ": not a string")
	}
	b, err := hex.DecodeString(str)
	if err != nil || (n > 0 && len(b) != n) {
		fail(label + ": bad hex")
	}
	return b
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "IRM1_VERIFY_FAIL:", msg)
	os.Exit(1)
}

func verifySig(domain string, payload any, pub []byte, sig []byte, label string) {
	var buf bytes.Buffer
	if err := canonical(payload, &buf); err != nil {
		fail(label + ": " + err.Error())
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), append([]byte(domain), buf.Bytes()...), sig) {
		fail(label + ": signature does not verify")
	}
	fmt.Println("OK", label)
}

// ---- STO-1 ----

func leaf(b []byte) []byte {
	h := sha256.Sum256(append([]byte("\x00STO-1"), b...))
	return h[:]
}
func node(l, r []byte) []byte {
	h := sha256.Sum256(append(append([]byte("\x01STO-1"), l...), r...))
	return h[:]
}
func commit(mth []byte, n int) []byte {
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, uint32(n))
	h := sha256.Sum256(append(append([]byte("\x02STO-1"), c...), mth...))
	return h[:]
}
func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}
func mth(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return node(mth(leaves[:k]), mth(leaves[k:]))
}

// RFC 9162 section 2.1.3.2 inclusion proof verification.
func inclusion(root []byte, n, index int, block []byte, path [][]byte) bool {
	if index < 0 || index >= n {
		return false
	}
	fn, sn := index, n-1
	r := leaf(block)
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = node(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = node(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(commit(r, n), root)
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: irm1verify <TEST_VECTORS_IRM1_DRAFT.json>")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err.Error())
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		fail("invalid JSON")
	}
	keys := v["keys"].(map[string]any)
	regPub := mustHex(keys["registry_public"], 32, "registry key")
	backupPub := mustHex(keys["registry_backup_public"], 32, "backup key")
	provPub := mustHex(keys["provider_public"], 32, "provider key")

	doc := v["registry_document"].(map[string]any)
	if !bytes.Equal(mustHex(doc["registry_key"], 32, "doc registry_key"), regPub) {
		fail("registry document key is not the pinned key")
	}
	verifySig(registryDomain, doc["payload"], regPub, mustHex(doc["signature"], 64, "registry sig"), "registry_document")

	rot := v["rotation_record"].(map[string]any)
	sigs := rot["signatures"].(map[string]any)
	verifySig(rotationDomain, rot["payload"], backupPub, mustHex(sigs["backup"], 64, "rotation backup sig"), "rotation_record/backup")
	verifySig(rotationDomain, rot["payload"], regPub, mustHex(sigs["old"], 64, "rotation old sig"), "rotation_record/old")

	desc := v["descriptor"].(map[string]any)
	entry := desc["payload"].(map[string]any)["provider"].(map[string]any)
	if !bytes.Equal(mustHex(entry["id"], 32, "descriptor id"), provPub) {
		fail("descriptor id is not the provider key")
	}
	verifySig(descriptorDomain, desc["payload"], provPub, mustHex(desc["signature"], 64, "descriptor sig"), "descriptor")

	tk := v["service_ticket"].(map[string]any)
	verifySig(ticketDomain, tk["payload"], provPub, mustHex(tk["signature"], 64, "ticket sig"), "service_ticket")

	sp := v["storage_proof"].(map[string]any)
	length, _ := strconv.Atoi(string(sp["chunk_length"].(json.Number)))
	var chunk []byte
	for i := 0; len(chunk) < length; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("IRM1-VECTOR-DATA/chunk/%d", i)))
		chunk = append(chunk, h[:]...)
	}
	chunk = chunk[:length]
	if hx := sha256.Sum256(chunk); hex.EncodeToString(hx[:]) != sp["chunk_sha256"] {
		fail("regenerated chunk hash mismatch")
	}
	var leaves [][]byte
	var blocks [][]byte
	for i := 0; i < len(chunk); i += blockSize {
		end := i + blockSize
		if end > len(chunk) {
			end = len(chunk)
		}
		blocks = append(blocks, chunk[i:end])
		leaves = append(leaves, leaf(chunk[i:end]))
	}
	root := commit(mth(leaves), len(leaves))
	count, _ := strconv.Atoi(string(sp["block_count"].(json.Number)))
	if count != len(leaves) || hex.EncodeToString(root) != sp["root"] {
		fail("independently computed STO-1 root differs from vector")
	}
	fmt.Println("OK storage_proof/root")
	ch := sp["challenge"].(map[string]any)
	idx, _ := strconv.Atoi(string(ch["block"].(json.Number)))
	if hx := sha256.Sum256(blocks[idx]); hex.EncodeToString(hx[:]) != sp["block_sha256"] {
		fail("challenge block hash mismatch")
	}
	var path [][]byte
	for _, p := range sp["path"].([]any) {
		path = append(path, mustHex(p, 32, "path element"))
	}
	if !inclusion(root, count, idx, blocks[idx], path) {
		fail("STO-1 inclusion proof does not verify")
	}
	fmt.Println("OK storage_proof/inclusion")
	fmt.Println("IRM1_VERIFY_PASS")
}
