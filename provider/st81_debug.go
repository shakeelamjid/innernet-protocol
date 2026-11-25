package main

// Hidden commands for cross-language conformance tests (Python reference <-> Go).
//   st81-echo ADDR          listen, print "<server key hex> <addr>", echo every frame back
//   st81-ping ADDR PINHEX   connect with a fresh key, send {"op":"ping"} + "hello", print the reply

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

func cmdST81Debug(cmd string, args []string) error {
	switch cmd {
	case "st81-echo":
		if len(args) != 1 {
			return errors.New("usage: st81-echo ADDR")
		}
		_, key, _ := ed25519.GenerateKey(nil)
		ln, err := net.Listen("tcp", args[0])
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(key.Public().(ed25519.PublicKey)), ln.Addr().String())
		for {
			c, err := ln.Accept()
			if err != nil {
				return err
			}
			go func(c net.Conn) {
				defer c.Close()
				s, err := st81Accept(c, key, nil)
				if err != nil {
					return
				}
				for {
					h, b, err := s.Read()
					if err != nil {
						return
					}
					h["peer"] = hex.EncodeToString(s.Peer)
					if s.Write(h, b) != nil {
						return
					}
				}
			}(c)
		}
	case "st81-ping":
		if len(args) != 2 {
			return errors.New("usage: st81-ping ADDR PINHEX")
		}
		pin, err := hex.DecodeString(args[1])
		if err != nil {
			return err
		}
		_, key, _ := ed25519.GenerateKey(nil)
		s, err := st81Dial(args[0], key, ed25519.PublicKey(pin), 5*time.Second)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.Write(map[string]any{"op": "ping", "n": 7}, []byte("hello")); err != nil {
			return err
		}
		h, b, err := s.Read()
		if err != nil {
			return err
		}
		out, _ := json.Marshal(map[string]any{"header": h, "body": string(b), "me": hex.EncodeToString(key.Public().(ed25519.PublicKey))})
		fmt.Println(string(out))
		return nil
	}
	return errors.New("unknown")
}
