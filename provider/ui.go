package main

// Terminal presentation: one consistent look for every command.
// Colours and the spinner only appear on a real terminal; NO_COLOR, a pipe or
// --json output gives plain text that scripts and agents can read.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	isTTY   = stdoutIsTerminal()
	colorOn = isTTY && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
)

func stdoutIsTerminal() bool {
	if os.Getenv("INNERNET_PLAIN") == "1" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func paint(code, s string) string {
	if !colorOn {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string  { return paint("1", s) }
func dim(s string) string   { return paint("2", s) }
func green(s string) string { return paint("32", s) }
func red(s string) string   { return paint("31", s) }
func amber(s string) string { return paint("33", s) }

const (
	markOK   = "✓"
	markFail = "✗"
	markWarn = "!"
	markWait = "●"
)

func networkLabel(n string) string {
	if n == "base" {
		return "mainnet"
	}
	return "testnet"
}

// banner is the opening line of every interactive command.
func banner(what, network string) {
	word := bold("INNERNET")
	if colorOn {
		word = paint("1;7", " INNERNET ")
	}
	fmt.Printf("\n %s  %s %s %s\n\n", word, what, dim(version), dim("· "+networkLabel(network)))
}

// stepper prints numbered steps: [2/6] Label   ✓ result
type stepper struct {
	n, total int
	label    string
	mu       sync.Mutex
	stop     chan struct{}
	done     chan struct{}
}

func newStepper(total int) *stepper { return &stepper{total: total} }

func (s *stepper) prefix() string {
	return fmt.Sprintf(" %s %-20s", dim(fmt.Sprintf("[%d/%d]", s.n, s.total)), s.label)
}

// begin starts a step; on a terminal a spinner turns until end/ok/fail is called.
func (s *stepper) begin(label string) {
	s.n++
	s.label = label
	if !isTTY {
		return
	}
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	go func(stop, done chan struct{}, pre string) {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		t := time.NewTicker(90 * time.Millisecond)
		defer t.Stop()
		defer close(done)
		for i := 0; ; i++ {
			s.mu.Lock()
			fmt.Printf("\r%s %s", pre, dim(frames[i%len(frames)]))
			s.mu.Unlock()
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}(s.stop, s.done, s.prefix())
}

func (s *stepper) end(mark, text string) {
	if s.stop != nil {
		close(s.stop)
		<-s.done
		s.stop = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isTTY {
		fmt.Print("\r\x1b[K")
	}
	fmt.Printf("%s %s %s\n", s.prefix(), mark, text)
}

func (s *stepper) ok(format string, a ...any)   { s.end(green(markOK), fmt.Sprintf(format, a...)) }
func (s *stepper) fail(format string, a ...any) { s.end(red(markFail), fmt.Sprintf(format, a...)) }
func (s *stepper) warn(format string, a ...any) { s.end(amber(markWarn), fmt.Sprintf(format, a...)) }

// note prints an indented line under the current step.
func note(format string, a ...any) {
	fmt.Printf("  %s %s\n", strings.Repeat(" ", 26), dim(fmt.Sprintf(format, a...)))
}

// box draws a titled summary with aligned rows.
func box(title string, rows [][2]string) {
	w := utf8.RuneCountInString(title) + 2
	kw := 0
	for _, r := range rows {
		kw = max(kw, utf8.RuneCountInString(r[0]))
	}
	for _, r := range rows {
		w = max(w, kw+3+utf8.RuneCountInString(stripANSI(r[1])))
	}
	line := strings.Repeat("─", w+2)
	fmt.Printf("\n ┌%s┐\n", line)
	fmt.Printf(" │ %s%s │\n", bold(title), strings.Repeat(" ", w-utf8.RuneCountInString(title)))
	fmt.Printf(" ├%s┤\n", line)
	for _, r := range rows {
		k := r[0] + strings.Repeat(" ", kw-utf8.RuneCountInString(r[0]))
		pad := w - kw - 3 - utf8.RuneCountInString(stripANSI(r[1]))
		fmt.Printf(" │ %s   %s%s │\n", dim(k), r[1], strings.Repeat(" ", max(0, pad)))
	}
	fmt.Printf(" └%s┘\n", line)
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			esc = true
		case esc && r == 'm':
			esc = false
		case !esc:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// bar renders a progress bar such as ███████░░░  70%.
func bar(done, total int64, width int) string {
	if total <= 0 {
		total = 1
	}
	f := int(float64(width) * float64(done) / float64(total))
	f = min(max(f, 0), width)
	return green(strings.Repeat("█", f)) + dim(strings.Repeat("░", width-f)) + fmt.Sprintf(" %3d%%", done*100/total)
}
