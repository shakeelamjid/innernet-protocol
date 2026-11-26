package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildJob(t *testing.T) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "job.wasm")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = "testdata/wasmjob"
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build wasip1 test job: %v %s", err, b)
	}
	b, _ := os.ReadFile(out)
	return b
}

func TestWasmJobIsSandboxedAndDeterministic(t *testing.T) {
	wasm := buildJob(t)
	a := runWasm(context.Background(), wasm, []byte("hello"), nil, 7, 256, 20*time.Second)
	b := runWasm(context.Background(), wasm, []byte("hello"), nil, 7, 256, 20*time.Second)
	c := runWasm(context.Background(), wasm, []byte("hello"), nil, 8, 256, 20*time.Second)
	if a.Err != "" || !strings.HasPrefix(string(a.Output), "HELLO|") {
		t.Fatalf("%+v %s", a, a.Stderr)
	}
	if string(a.Output) != string(b.Output) {
		t.Fatal("same module, input and seed gave different output")
	}
	if string(a.Output) == string(c.Output) {
		t.Fatal("the seed does not reach the job's randomness")
	}
	if !strings.HasSuffix(string(a.Output), "|1767225600") {
		t.Fatalf("clock is not fixed: %s", a.Output)
	}
	f := runWasm(context.Background(), wasm, nil, []string{"files"}, 1, 256, 20*time.Second)
	if strings.TrimSpace(string(f.Output)) != "files: true" {
		t.Fatalf("job could read a file: %s", f.Output)
	}
	start := time.Now()
	s := runWasm(context.Background(), wasm, nil, []string{"spin"}, 1, 256, 2*time.Second)
	if s.Err == "" || time.Since(start) > 10*time.Second {
		t.Fatalf("endless job was not stopped: %+v", s)
	}
}

func TestLedgerHoldSettle(t *testing.T) {
	l := openLedger(t.TempDir())
	l.add("c", 1000)
	if err := l.hold("c", 1500); err == nil {
		t.Fatal("held more than the balance")
	}
	if err := l.hold("c", 800); err != nil {
		t.Fatal(err)
	}
	if bal := l.settle("c", 800, 300); bal != 700 {
		t.Fatal(bal)
	}
	if usdc(1234500) != "1.2345" || micro("3/2", "0.20") != 300000 || micro("90/3600", "0.36") != 9000 {
		t.Fatal(usdc(1234500), micro("3/2", "0.20"), micro("90/3600", "0.36"))
	}
}
