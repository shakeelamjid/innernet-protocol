package main

// Availability hours and machine type, both part of the signed offer.
//
// Hours are written the way people say them, in the machine's own time zone:
//   always
//   mon-fri 21:00-08:00, sat-sun 00:00-24:00
// A window that passes midnight belongs to the day it starts on. In the descriptor they
// become {"tz": "Asia/Karachi", "weekly": [[day, from_minute, to_minute], ...]} with
// day 0 = Monday and no window crossing midnight, which is easy for clients to check.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var dayNames = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

type window struct{ Day, From, To int } // minutes since midnight, From < To <= 1440

func parseHours(s string) ([]window, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "always" || s == "24/7" {
		return nil, nil
	}
	var out []window
	for _, part := range strings.Split(s, ",") {
		f := strings.Fields(part)
		if len(f) != 2 {
			return nil, fmt.Errorf("%q: write days then hours, e.g. mon-fri 21:00-08:00", strings.TrimSpace(part))
		}
		days, err := parseDays(f[0])
		if err != nil {
			return nil, err
		}
		span := strings.SplitN(f[1], "-", 2)
		if len(span) != 2 {
			return nil, fmt.Errorf("%q: hours look like 21:00-08:00", f[1])
		}
		from, err1 := parseClock(span[0])
		to, err2 := parseClock(span[1])
		if err1 != nil || err2 != nil || from == to || from == 1440 {
			return nil, fmt.Errorf("%q: hours look like 21:00-08:00", f[1])
		}
		for _, d := range days {
			if from < to {
				out = append(out, window{d, from, to})
			} else { // passes midnight
				out = append(out, window{d, from, 1440})
				if to > 0 {
					out = append(out, window{(d + 1) % 7, 0, to})
				}
			}
		}
	}
	return mergeWindows(out), nil
}

func parseDays(s string) ([]int, error) {
	idx := func(n string) int {
		for i, d := range dayNames {
			if strings.HasPrefix(n, d) {
				return i
			}
		}
		return -1
	}
	switch s {
	case "daily", "every", "all":
		return []int{0, 1, 2, 3, 4, 5, 6}, nil
	case "weekdays":
		return []int{0, 1, 2, 3, 4}, nil
	case "weekends":
		return []int{5, 6}, nil
	}
	if a, b, ok := strings.Cut(s, "-"); ok {
		i, j := idx(a), idx(b)
		if i < 0 || j < 0 {
			return nil, fmt.Errorf("%q: days are mon..sun", s)
		}
		var out []int
		for d := i; ; d = (d + 1) % 7 {
			out = append(out, d)
			if d == j {
				return out, nil
			}
		}
	}
	if i := idx(s); i >= 0 {
		return []int{i}, nil
	}
	return nil, fmt.Errorf("%q: days are mon..sun, weekdays, weekends or daily", s)
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		m = "0"
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, errors.New("bad time")
	}
	return hh*60 + mm, nil
}

func mergeWindows(ws []window) []window {
	sort.Slice(ws, func(i, j int) bool {
		if ws[i].Day != ws[j].Day {
			return ws[i].Day < ws[j].Day
		}
		return ws[i].From < ws[j].From
	})
	var out []window
	for _, w := range ws {
		if n := len(out); n > 0 && out[n-1].Day == w.Day && w.From <= out[n-1].To {
			out[n-1].To = max(out[n-1].To, w.To)
			continue
		}
		out = append(out, w)
	}
	return out
}

// weeklyMinutes is how many minutes a week the machine promises to be on.
func weeklyMinutes(ws []window) int {
	if ws == nil {
		return 7 * 1440
	}
	t := 0
	for _, w := range ws {
		t += w.To - w.From
	}
	return t
}

// availabilityEntry: weekly hours, optionally only on some days of the month, minus days off.
// Days off alone (always on otherwise) are written as every day of the month minus those days.
func availabilityEntry(hours, tz string, monthDays []int, skip []string) (map[string]any, error) {
	ws, err := parseHours(hours)
	if err != nil {
		return nil, err
	}
	if err := checkSchedule(monthDays, skip); err != nil {
		return nil, err
	}
	if ws == nil && len(monthDays) == 0 && len(skip) == 0 {
		return nil, nil // always on
	}
	av := map[string]any{"tz": tz}
	if ws != nil {
		weekly := make([]any, len(ws))
		for i, w := range ws {
			weekly[i] = []any{w.Day, w.From, w.To}
		}
		av["weekly"] = weekly
	}
	md := monthDays
	if ws == nil && len(md) == 0 {
		md = make([]int, 31) // only days off: every day of the month
		for i := range md {
			md[i] = i + 1
		}
	}
	if len(md) > 0 {
		out := make([]any, len(md))
		for i, d := range md {
			out[i] = d
		}
		av["monthdays"] = out
	}
	if len(skip) > 0 {
		out := make([]any, len(skip))
		for i, d := range skip {
			out[i] = d
		}
		av["skip"] = out
	}
	return av, nil
}

var reDate = regexp.MustCompile(`^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$`)

// checkSchedule: days of the month sorted, 1-31, no repeats; days off sorted YYYY-MM-DD, at most 64.
func checkSchedule(monthDays []int, skip []string) error {
	for i, d := range monthDays {
		if d < 1 || d > 31 || (i > 0 && d <= monthDays[i-1]) {
			return errors.New("days of the month: sorted, 1-31, no repeats")
		}
	}
	if len(skip) > 64 {
		return errors.New("days off: at most 64")
	}
	for i, d := range skip {
		if !reDate.MatchString(d) || (i > 0 && d <= skip[i-1]) {
			return errors.New("days off: sorted YYYY-MM-DD dates, no repeats")
		}
	}
	return nil
}

func describeHours(hours string) string {
	ws, err := parseHours(hours)
	if err != nil {
		return "invalid"
	}
	if ws == nil {
		return "always on"
	}
	return fmt.Sprintf("%s (%d h a week)", hours, weeklyMinutes(ws)/60)
}

// localTZ names this machine's time zone: an IANA name where the system has one,
// otherwise a fixed offset such as UTC+05:00.
func localTZ() string {
	if tz := os.Getenv("TZ"); tz != "" && !strings.HasPrefix(tz, ":") {
		return tz
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			return target[i+len("zoneinfo/"):]
		}
	}
	_, off := time.Now().Zone()
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, off/3600, off%3600/60)
}

// ---------- machine type ----------

// hasBattery reports a laptop. Best effort; false when it cannot tell.
func hasBattery() bool {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("pmset", "-g", "batt").Output()
		return err == nil && strings.Contains(string(out), "InternalBattery")
	case "linux":
		types, _ := filepath.Glob("/sys/class/power_supply/*/type")
		for _, p := range types {
			if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == "Battery" {
				return true
			}
		}
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-CimInstance Win32_Battery | Measure-Object).Count").Output()
		n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return err == nil && n > 0
	}
	return false
}

// machineClass: laptop (battery), server (the public address is on this machine itself,
// so no home router in between), otherwise desktop.
func machineClass(publicIP string) string {
	if hasBattery() {
		return "laptop"
	}
	if publicIP != "" && addressIsLocal(publicIP) {
		return "server"
	}
	return "desktop"
}

func addressIsLocal(ip string) bool {
	addrs, err := netInterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if strings.HasPrefix(a, ip+"/") || a == ip {
			return true
		}
	}
	return false
}

var netInterfaceAddrs = func() ([]string, error) {
	as, err := net.InterfaceAddrs()
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out, err
}
