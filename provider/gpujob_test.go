package main

import (
	"encoding/binary"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func testDeno(t *testing.T) string {
	if p := findDeno(); p != "" {
		return p
	}
	t.Skip("deno not installed (set INNERNET_DENO)")
	return ""
}

func TestGPUProgramComputesAndIsSealed(t *testing.T) {
	deno := testDeno(t)
	t.Setenv("INNERNET_HOME", t.TempDir())
	prog, _ := os.ReadFile("testdata/gpujob/double.js")
	in := make([]byte, 4*100)
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint32(in[i*4:], math.Float32bits(float32(i)+0.5))
	}
	r := runGPUProgram(deno, prog, in, "js", nil, 256, 60*time.Second)
	if r.Err != "" || len(r.Output) != 400 {
		t.Fatalf("%+v %s", r, r.Stderr)
	}
	for i := 0; i < 100; i++ {
		if got := math.Float32frombits(binary.LittleEndian.Uint32(r.Output[i*4:])); got != 2*(float32(i)+0.5) {
			t.Fatalf("value %d: %v", i, got)
		}
	}
	p := runGPUProgram(deno, prog, nil, "js", []string{"probe"}, 256, 60*time.Second)
	if strings.Contains(string(p.Output), "open") || !strings.Contains(string(p.Output), "NotCapable") {
		t.Fatalf("sandbox let something through: %s %s", p.Output, p.Stderr)
	}
	t0 := time.Now()
	s := runGPUProgram(deno, prog, nil, "js", []string{"spin"}, 256, 2*time.Second)
	if !strings.Contains(s.Err, "time limit") || time.Since(t0) > 15*time.Second {
		t.Fatalf("endless program not stopped: %+v", s)
	}
}
