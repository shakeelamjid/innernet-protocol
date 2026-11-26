package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The scheduler shares the machine between storage, CPU jobs, GPU jobs and the owner.
//
//   - Storage never waits for compute: chunk transfers have their own pool (stoSlots).
//   - Compute is admitted against a budget of CPU slots, GPUs and memory. The memory budget is
//     the machine's memory minus what the owner keeps for themselves.
//   - Waiting work is served fairly: the client with the fewest running jobs goes first, then the
//     longest waiting. No backfilling, so a large job is never starved by small ones.
//   - Each client has a cap on running jobs, the queue is bounded, and a full queue answers at
//     once with "busy" so the client can go to another provider.
//   - When the owner is using the machine (little memory actually free), new compute waits.
//   - Before an update restart the scheduler drains: no new compute, running work finishes.

type demand struct {
	Client string
	CPU    int
	GPU    int
	MemMiB int
}

type waiter struct {
	d     demand
	at    time.Time
	ready chan struct{}
	gone  bool
}

type scheduler struct {
	mu           sync.Mutex
	cpuTotal     int
	gpuTotal     int
	memTotal     int // MiB available to compute
	reserve      int // MiB the owner keeps
	cpuUsed      int
	gpuUsed      int
	memUsed      int
	running      map[string]int
	maxPerClient int
	maxQueue     int
	queue        []*waiter
	draining     bool
	freeMem      func() int // MiB actually free on the machine now (0 = unknown)
}

var errBusy = errors.New("busy")

func newScheduler(c *Config, machineMiB int) *scheduler {
	reserve := c.ReserveMiB
	if reserve <= 0 {
		reserve = 4096
		if c.Class == "server" {
			reserve = 1024
		}
	}
	mem := machineMiB - reserve
	if machineMiB <= 0 { // unknown (Windows): trust the configured limits
		mem = max(c.CPUs, 1)*c.MemMiB + 64<<10
	}
	gpus := 0
	if c.GPU {
		gpus = max(1, c.GPUs)
	}
	return &scheduler{cpuTotal: max(1, c.CPUs), gpuTotal: gpus, memTotal: max(0, mem), reserve: reserve,
		running: map[string]int{}, maxPerClient: orInt(c.PerClient, 2), maxQueue: 32, freeMem: cachedFreeMem()}
}

func (s *scheduler) fits(d demand) bool {
	if s.draining || s.cpuUsed+d.CPU > s.cpuTotal || s.gpuUsed+d.GPU > s.gpuTotal || s.memUsed+d.MemMiB > s.memTotal {
		return false
	}
	if s.running[d.Client] >= s.maxPerClient {
		return false
	}
	// The owner comes first: if the machine itself is short of memory, wait.
	if free := s.freeMem(); free > 0 && free-d.MemMiB < s.reserve/2 {
		return false
	}
	return true
}

func (s *scheduler) take(d demand) {
	s.cpuUsed += d.CPU
	s.gpuUsed += d.GPU
	s.memUsed += d.MemMiB
	s.running[d.Client]++
}

// acquire reserves resources for d, waiting at most wait. The returned release must be called once.
func (s *scheduler) acquire(ctx context.Context, d demand, wait time.Duration) (func(), error) {
	s.mu.Lock()
	if d.CPU > s.cpuTotal || d.GPU > s.gpuTotal || d.MemMiB > s.memTotal {
		s.mu.Unlock()
		return nil, fmt.Errorf("this job needs more than this provider offers (%d CPU, %d GPU, %d MiB)", s.cpuTotal, s.gpuTotal, s.memTotal)
	}
	if s.draining {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: provider is restarting for an update", errBusy)
	}
	if len(s.queue) == 0 && s.fits(d) {
		s.take(d)
		s.mu.Unlock()
		return s.releaser(d), nil
	}
	if len(s.queue) >= s.maxQueue || wait <= 0 {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %d waiting", errBusy, len(s.queue))
	}
	w := &waiter{d: d, at: time.Now(), ready: make(chan struct{})}
	s.queue = append(s.queue, w)
	s.mu.Unlock()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-w.ready:
		return s.releaser(d), nil
	case <-t.C:
	case <-ctx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-w.ready: // granted just as we gave up
		return s.releaser(d), nil
	default:
	}
	w.gone = true
	s.prune()
	return nil, fmt.Errorf("%w: waited %s", errBusy, wait.Round(time.Second))
}

func (s *scheduler) releaser(d demand) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.cpuUsed -= d.CPU
			s.gpuUsed -= d.GPU
			s.memUsed -= d.MemMiB
			if s.running[d.Client]--; s.running[d.Client] <= 0 {
				delete(s.running, d.Client)
			}
			s.dispatch()
			s.mu.Unlock()
		})
	}
}

func (s *scheduler) prune() {
	q := s.queue[:0]
	for _, w := range s.queue {
		if !w.gone {
			q = append(q, w)
		}
	}
	s.queue = q
}

// dispatch grants waiting work in fair order: fewest running for that client, then oldest.
func (s *scheduler) dispatch() {
	s.prune()
	for len(s.queue) > 0 {
		sort.SliceStable(s.queue, func(i, j int) bool {
			a, b := s.running[s.queue[i].d.Client], s.running[s.queue[j].d.Client]
			if a != b {
				return a < b
			}
			return s.queue[i].at.Before(s.queue[j].at)
		})
		granted := false
		for i, w := range s.queue {
			if s.running[w.d.Client] >= s.maxPerClient {
				continue // this client is at its cap; let the next client in
			}
			if !s.fits(w.d) {
				break // the first eligible waiter does not fit: wait for it (no backfilling)
			}
			s.take(w.d)
			close(w.ready)
			s.queue = append(s.queue[:i], s.queue[i+1:]...)
			granted = true
			break
		}
		if !granted {
			return
		}
	}
}

// kick re-checks the queue; called periodically because the owner's memory use changes by itself.
func (s *scheduler) kick() {
	s.mu.Lock()
	s.dispatch()
	s.mu.Unlock()
}

// drain stops new compute and waits until running compute has finished, at most limit.
func (s *scheduler) drain(limit time.Duration) {
	s.mu.Lock()
	s.draining = true
	for _, w := range s.queue {
		w.gone = true
	}
	s.prune()
	s.mu.Unlock()
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		s.mu.Lock()
		idle := s.cpuUsed == 0 && s.gpuUsed == 0
		s.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func (s *scheduler) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{"cpu_slots": int64(s.cpuTotal), "cpu_free": int64(s.cpuTotal - s.cpuUsed),
		"gpu_slots": int64(s.gpuTotal), "gpu_free": int64(s.gpuTotal - s.gpuUsed),
		"compute_mem_free_mib": int64(max(0, s.memTotal-s.memUsed)), "queued": int64(len(s.queue))}
}

// ---------- free memory on this machine ----------

func cachedFreeMem() func() int {
	var mu sync.Mutex
	var at time.Time
	var v int
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(at) > 5*time.Second {
			v, at = freeMemMiB(), time.Now()
		}
		return v
	}
}

// freeMemMiB is memory the system could hand out now (Linux MemAvailable; macOS free +
// inactive + purgeable pages). 0 when unknown.
func freeMemMiB() int {
	switch runtime.GOOS {
	case "linux":
		f, err := os.Open("/proc/meminfo")
		if err != nil {
			return 0
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 2 && fs[0] == "MemAvailable:" {
				kb, _ := strconv.Atoi(fs[1])
				return kb / 1024
			}
		}
	case "darwin":
		out, err := exec.Command("vm_stat").Output()
		if err != nil {
			return 0
		}
		return parseVMStat(string(out))
	}
	return 0
}

func parseVMStat(out string) int {
	page := 4096
	var pages int
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "page size of") {
			for _, f := range strings.Fields(line) {
				if n, err := strconv.Atoi(f); err == nil && n > 0 {
					page = n
				}
			}
			continue
		}
		name, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(name) {
		case "Pages free", "Pages inactive", "Pages speculative", "Pages purgeable":
			n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(val), "."))
			pages += n
		}
	}
	return pages * page >> 20
}
