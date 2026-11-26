package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The machine code links a browser to this machine. It stays the same until the owner runs
// `innernet-provider rekey`. Only its SHA-256 is sent to the registry, in a request signed by the
// machine key, so only this machine can set or change it. The code is not the machine key: it
// can add a passkey for the dashboard or open a waiting setup, but every listing and every payout
// change is still signed and confirmed on the machine.

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O, 1/I

func machineCodePath() string { return filepath.Join(home(), "machine-code") }

func newMachineCode() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	var s strings.Builder
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			s.WriteByte('-')
		}
		s.WriteByte(codeAlphabet[int(v)%len(codeAlphabet)]) // 256 is a multiple of 32: no bias
	}
	return s.String()
}

func codeHash(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// machineCode returns this machine's code and whether the registry already has it.
func machineCode() (code string, registered bool) {
	raw, err := os.ReadFile(machineCodePath())
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		code = strings.TrimSpace(lines[0])
		registered = len(lines) > 1 && strings.TrimSpace(lines[1]) == "registered"
		if len(code) == 19 {
			return code, registered
		}
	}
	return newMachineCode(), false
}

func saveMachineCode(code string, registered bool) error {
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return err
	}
	s := code + "\n"
	if registered {
		s += "registered\n"
	}
	return os.WriteFile(machineCodePath(), []byte(s), 0o600)
}

// ensureMachineCode makes sure the registry knows this machine's code; it returns the code.
func ensureMachineCode(registry string, priv ed25519.PrivateKey) (string, error) {
	code, registered := machineCode()
	if registered {
		return code, nil
	}
	if err := saveMachineCode(code, false); err != nil {
		return "", err
	}
	if _, err := signedIntent(registry, priv, "pairing-set", codeHash(code)); err != nil {
		return code, err
	}
	return code, saveMachineCode(code, true)
}

func cmdCode() error {
	code, registered := machineCode()
	if _, err := os.Stat(machineCodePath()); err != nil {
		return errors.New("this machine has no code yet: run innernet-provider start")
	}
	fmt.Println("Machine code:", bold(code))
	if !registered {
		fmt.Println(dim("Not registered yet; innernet-provider start registers it."))
	}
	fmt.Println(dim("Enter it at the claim page to add a passkey or continue setup. Keep it private;"))
	fmt.Println(dim("if someone else has seen it: innernet-provider rekey"))
	return nil
}

// cmdRekey replaces the machine code; the old one stops working at once.
func cmdRekey() error {
	c, err := loadConfig()
	reg := defaultRegistry
	if err == nil {
		reg = registryURL(c)
	}
	priv, err := loadKey()
	if err != nil {
		return err
	}
	code := newMachineCode()
	if _, err := signedIntent(reg, priv, "pairing-set", codeHash(code)); err != nil {
		return fmt.Errorf("the registry did not take the new code (the old one still works): %v", err)
	}
	if err := saveMachineCode(code, true); err != nil {
		return err
	}
	fmt.Println(green(markOK), "New machine code:", bold(code))
	fmt.Println(dim("The old code no longer works. Passkeys you added stay; remove one with innernet-provider passkeys remove NAME."))
	return nil
}
