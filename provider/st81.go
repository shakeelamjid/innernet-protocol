package main

// ST81: INNERnet's mutually authenticated, encrypted TCP session (RC5 core spec,
// "ST81 handshake"). A Go port of innernet2/stream_v080.py, byte-for-byte compatible:
//
//   responder -> S81H || server_ed25519 || challenge32                              (68)
//   initiator -> S81C || client_ed25519 || eph_x25519 || nonce32 || sig             (164)
//   responder -> S81S || server_ed25519 || eph_x25519 || nonce32 || snonce32 || sig (196)
//   keys      =  HKDF-SHA256(X25519, salt SHA256(challenge||hello||reply),
//                            info "INNERnet/ST80/key-schedule-v1\0", 64) -> C->S, S->C
//   frames    =  u32(len) || ChaCha20-Poly1305(u32(json_len) || JSON || body),
//                nonce u32(0)||u64(counter), AAD "C"/"S"||u64(counter)
//
// No downgrade to ST80. Everything that does not match closes the connection.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"innernetcorp.com/provider/internal/xcrypto/chacha20poly1305"
)

const (
	st81Challenge = "S81H"
	st81MagicC    = "S81C"
	st81Server    = "S81S"
	st81DomainC   = "INNERnet/ST80/client-auth\x00"
	st81DomainS   = "INNERnet/ST80/server-auth\x00"
	st81KeyInfo   = "INNERnet/ST80/key-schedule-v1\x00"
	st81MaxFrame  = 400_000
	st81MaxJSON   = 240_000
)

var errST81 = errors.New("st81")

func st81Err(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errST81, fmt.Sprintf(format, a...))
}

type st81Session struct {
	conn       net.Conn
	Peer       ed25519.PublicKey
	send, recv cipherAEAD
	sendN      uint64
	recvN      uint64
	sendTag    byte
	recvTag    byte
	Timeout    time.Duration
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func readFull(c net.Conn, n int, deadline time.Time) ([]byte, error) {
	_ = c.SetReadDeadline(deadline)
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, st81Err("peer closed or timed out during the frame: %v", err)
	}
	return buf, nil
}

func hkdfSHA256(secret, salt, info []byte, n int) []byte {
	prk := hmac.New(sha256.New, salt)
	prk.Write(secret)
	key := prk.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, key)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func st81Keys(eph *ecdh.PrivateKey, peer []byte, hello, reply []byte) (c2s, s2c []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, nil, st81Err("bad ephemeral public key")
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, nil, st81Err("bad ephemeral public key")
	}
	salt := sha256.Sum256(append(append([]byte{}, hello...), reply...))
	m := hkdfSHA256(shared, salt[:], []byte(st81KeyInfo), 64)
	return m[:32], m[32:], nil
}

func newST81Session(c net.Conn, peer []byte, sendKey, recvKey []byte, initiator bool) (*st81Session, error) {
	s, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	r, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	sess := &st81Session{conn: c, Peer: ed25519.PublicKey(append([]byte{}, peer...)), send: s, recv: r,
		sendTag: 'S', recvTag: 'C', Timeout: 15 * time.Second}
	if initiator {
		sess.sendTag, sess.recvTag = 'C', 'S'
	}
	return sess, nil
}

func nonceFor(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

func aadFor(tag byte, n uint64) []byte {
	aad := make([]byte, 9)
	aad[0] = tag
	binary.BigEndian.PutUint64(aad[1:], n)
	return aad
}

// Write sends one frame: a JSON object header and an optional raw body.
func (s *st81Session) Write(header any, body []byte) error {
	raw, err := canonicalJSON(header)
	if err != nil {
		return err
	}
	if len(raw) > st81MaxJSON || len(body)+len(raw)+4+16 > st81MaxFrame {
		return st81Err("outgoing frame exceeds fixed safety bound")
	}
	clear := make([]byte, 4, 4+len(raw)+len(body))
	binary.BigEndian.PutUint32(clear, uint32(len(raw)))
	clear = append(append(clear, raw...), body...)
	blob := s.send.Seal(nil, nonceFor(s.sendN), clear, aadFor(s.sendTag, s.sendN))
	frame := make([]byte, 4, 4+len(blob))
	binary.BigEndian.PutUint32(frame, uint32(len(blob)))
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.Timeout))
	if _, err := s.conn.Write(append(frame, blob...)); err != nil {
		return err
	}
	s.sendN++
	return nil
}

// Read returns the next frame's validated JSON header and raw body.
func (s *st81Session) Read() (map[string]any, []byte, error) {
	return s.readWithin(time.Now().Add(s.Timeout), st81MaxFrame)
}

func (s *st81Session) readWithin(deadline time.Time, limit int) (map[string]any, []byte, error) {
	head, err := readFull(s.conn, 4, deadline)
	if err != nil {
		return nil, nil, err
	}
	size := int(binary.BigEndian.Uint32(head))
	if size < 20 || size > min(st81MaxFrame, limit) {
		return nil, nil, st81Err("peer frame outside bound")
	}
	blob, err := readFull(s.conn, size, deadline)
	if err != nil {
		return nil, nil, err
	}
	clear, err := s.recv.Open(nil, nonceFor(s.recvN), blob, aadFor(s.recvTag, s.recvN))
	if err != nil {
		return nil, nil, st81Err("invalid frame AEAD or replayed counter")
	}
	s.recvN++
	if len(clear) < 4 {
		return nil, nil, st81Err("frame truncated")
	}
	n := int(binary.BigEndian.Uint32(clear))
	if n < 2 || n > st81MaxJSON || len(clear) < 4+n {
		return nil, nil, st81Err("invalid framed JSON length")
	}
	obj, err := strictJSONObject(clear[4 : 4+n])
	if err != nil {
		return nil, nil, st81Err("invalid JSON frame: %v", err)
	}
	return obj, clear[4+n:], nil
}

func (s *st81Session) Close() error { return s.conn.Close() }

// strictJSONObject parses a JSON object the way the Python reference does: no duplicate
// keys, no NaN/Infinity, integers within signed 64 bits, nesting depth at most 64.
func strictJSONObject(raw []byte) (map[string]any, error) {
	if err := checkJSONTokens(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("frame must contain a JSON object")
	}
	return obj, nil
}

func checkJSONTokens(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		obj    bool
		keys   map[string]bool
		expect bool // in an object: the next string token is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		isKey := top != nil && top.obj && top.expect
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack)+1 > 64 {
					return errors.New("JSON nesting exceeds limit")
				}
				if top != nil && top.obj {
					top.expect = true
				}
				stack = append(stack, &frame{obj: t == '{', keys: map[string]bool{}, expect: t == '{'})
			default:
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].expect = true
				}
			}
			continue
		case string:
			if isKey {
				if top.keys[t] {
					return errors.New("duplicate JSON object key")
				}
				top.keys[t] = true
				top.expect = false
				continue
			}
		case json.Number:
			s := string(t)
			if strings.ContainsAny(s, ".eE") {
				f, err := strconv.ParseFloat(s, 64)
				if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
					return errors.New("non-finite JSON float")
				}
			} else {
				if len(strings.TrimLeft(s, "-")) > 19 {
					return errors.New("JSON integer too long")
				}
				if _, err := strconv.ParseInt(s, 10, 64); err != nil {
					return errors.New("JSON integer outside signed 64-bit range")
				}
			}
		}
		if top != nil && top.obj {
			top.expect = true
		}
	}
}

// st81Dial connects as initiator and checks the responder is the pinned key.
func st81Dial(addr string, key ed25519.PrivateKey, pinned ed25519.PublicKey, timeout time.Duration) (*st81Session, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	s, err := st81Client(conn, key, pinned, timeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return s, nil
}

// st81Client runs the initiator side over an existing connection (TCP or a relayed stream).
func st81Client(conn net.Conn, key ed25519.PrivateKey, pinned ed25519.PublicKey, timeout time.Duration) (*st81Session, error) {
	if len(pinned) != 32 {
		return nil, st81Err("server pin must be 32 bytes")
	}
	deadline := time.Now().Add(timeout)
	challenge, err := readFull(conn, 68, deadline)
	if err != nil {
		return nil, err
	}
	if string(challenge[:4]) != st81Challenge || !bytes.Equal(challenge[4:36], pinned) {
		return nil, st81Err("invalid server challenge or pin")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	prefix := append(append(append([]byte(st81MagicC), key.Public().(ed25519.PublicKey)...), eph.PublicKey().Bytes()...), nonce...)
	sig := ed25519.Sign(key, append(append([]byte(st81DomainC), challenge...), prefix...))
	hello := append(append([]byte{}, prefix...), sig...)
	_ = conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}
	reply, err := readFull(conn, 196, deadline)
	if err != nil {
		return nil, err
	}
	if string(reply[:4]) != st81Server || !bytes.Equal(reply[4:36], pinned) || !bytes.Equal(reply[68:100], hello[68:100]) {
		return nil, st81Err("untrusted server identity or handshake nonce")
	}
	signed := append(append(append([]byte(st81DomainS), challenge...), hello...), reply[:132]...)
	if !ed25519.Verify(pinned, signed, reply[132:]) {
		return nil, st81Err("invalid server handshake signature")
	}
	c2s, s2c, err := st81Keys(eph, reply[36:68], append(append([]byte{}, challenge...), hello...), reply)
	if err != nil {
		return nil, err
	}
	sess, err := newST81Session(conn, pinned, c2s, s2c, true)
	if err != nil {
		return nil, err
	}
	if err := sess.Write(map[string]any{"handshake": "key-confirm-v1"}, nil); err != nil {
		return nil, err
	}
	ack, body, err := sess.readWithin(deadline, 512)
	if err != nil {
		return nil, err
	}
	if ack["handshake"] != "key-confirmed-v1" || len(ack) != 1 || len(body) != 0 {
		return nil, st81Err("missing authenticated server key confirmation")
	}
	_ = conn.SetDeadline(time.Time{})
	return sess, nil
}

// st81Accept runs the responder side. authorize decides which client keys may connect
// (nil: any key, as a public provider does; the key is still authenticated).
func st81Accept(conn net.Conn, identity ed25519.PrivateKey, authorize func(ed25519.PublicKey) bool) (*st81Session, error) {
	deadline := time.Now().Add(2 * time.Second)
	cnonce := make([]byte, 32)
	_, _ = rand.Read(cnonce)
	challenge := append(append([]byte(st81Challenge), identity.Public().(ed25519.PublicKey)...), cnonce...)
	_ = conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(challenge); err != nil {
		return nil, err
	}
	return st81AcceptAfterChallenge(conn, identity, authorize, challenge, deadline)
}

func st81AcceptAfterChallenge(conn net.Conn, identity ed25519.PrivateKey, authorize func(ed25519.PublicKey) bool,
	challenge []byte, deadline time.Time) (*st81Session, error) {
	hello, err := readFull(conn, 164, deadline)
	if err != nil {
		return nil, err
	}
	client := ed25519.PublicKey(append([]byte{}, hello[4:36]...))
	if string(hello[:4]) != st81MagicC || (authorize != nil && !authorize(client)) {
		return nil, st81Err("untrusted connecting identity")
	}
	if !ed25519.Verify(client, append(append([]byte(st81DomainC), challenge...), hello[:100]...), hello[100:]) {
		return nil, st81Err("invalid client handshake signature")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	snonce := make([]byte, 32)
	_, _ = rand.Read(snonce)
	prefix := append(append(append(append([]byte(st81Server), identity.Public().(ed25519.PublicKey)...),
		eph.PublicKey().Bytes()...), hello[68:100]...), snonce...)
	sig := ed25519.Sign(identity, append(append(append([]byte(st81DomainS), challenge...), hello...), prefix...))
	reply := append(append([]byte{}, prefix...), sig...)
	_ = conn.SetWriteDeadline(deadline)
	if _, err := conn.Write(reply); err != nil {
		return nil, err
	}
	c2s, s2c, err := st81Keys(eph, hello[36:68], append(append([]byte{}, challenge...), hello...), reply)
	if err != nil {
		return nil, err
	}
	sess, err := newST81Session(conn, client, s2c, c2s, false)
	if err != nil {
		return nil, err
	}
	first, body, err := sess.readWithin(deadline, 512)
	if err != nil {
		return nil, err
	}
	if first["handshake"] != "key-confirm-v1" || len(first) != 1 || len(body) != 0 {
		return nil, st81Err("client failed cryptographic key confirmation")
	}
	if err := sess.Write(map[string]any{"handshake": "key-confirmed-v1"}, nil); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return sess, nil
}
