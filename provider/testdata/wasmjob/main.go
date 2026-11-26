// A WASI test job: upper-cases standard input, then prints a random number and the clock,
// so tests can check that the sandbox makes both deterministic. "spin" loops forever.
package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "spin" {
		for {
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "files" {
		_, err := os.ReadFile("/etc/passwd")
		fmt.Println("files:", err != nil)
		return
	}
	in, _ := io.ReadAll(os.Stdin)
	fmt.Printf("%s|%d|%d", bytes.ToUpper(in), rand.Uint64(), time.Now().Unix())
}
