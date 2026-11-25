//go:build !windows

package main

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func freeDiskGiB(path string) int {
	for p := path; p != "" && p != "/"; {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
		i := strings.LastIndex(p, "/")
		if i <= 0 {
			path = "/"
			break
		}
		p = p[:i]
	}
	var s syscall.Statfs_t
	if syscall.Statfs(path, &s) != nil {
		return 0
	}
	return int(uint64(s.Bavail) * uint64(s.Bsize) >> 30)
}

func totalMemoryMiB() int {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
		return int(v >> 20)
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, _ := strconv.Atoi(fields[1])
			return kb / 1024
		}
	}
	return 0
}
