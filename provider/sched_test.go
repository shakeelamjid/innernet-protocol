package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func testSched(cpu, gpu, mem, perClient int) *scheduler {
	s := newScheduler(&Config{CPUs: cpu, GPU: gpu > 0, GPUs: gpu, PerClient: perClient, ReserveMiB: 1}, mem+1)
	s.freeMem = func() int { return 0 } // unknown: only the budget counts
	return s
}

func TestSchedulerBudgetAndPerClientCap(t *testing.T) {
	s := testSched(2, 1, 4096, 1)
	r1, err := s.acquire(context.Background(), demand{Client: "a", CPU: 1, MemMiB: 1000}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.acquire(context.Background(), demand{Client: "a", CPU: 1, MemMiB: 100}, 0); !errors.Is(err, errBusy) {
		t.Fatal("client went over its cap of 1 running job")
	}
	r2, err := s.acquire(context.Background(), demand{Client: "b", GPU: 1, MemMiB: 3000}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.acquire(context.Background(), demand{Client: "c", CPU: 1, MemMiB: 200}, 0); !errors.Is(err, errBusy) {
		t.Fatal("memory budget was exceeded") // 1000 + 3000 + 200 > 4096
	}
	if _, err := s.acquire(context.Background(), demand{Client: "c", GPU: 2}, time.Second); err == nil || errors.Is(err, errBusy) {
		t.Fatal("a job bigger than the whole provider must be refused outright")
	}
	r1()
	r1() // releasing twice is harmless
	r2()
	if snap := s.snapshot(); snap["cpu_free"] != int64(2) || snap["gpu_free"] != int64(1) || snap["compute_mem_free_mib"] != int64(4096) {
		t.Fatal(snap)
	}
}

func TestSchedulerFairOrderNoStarvation(t *testing.T) {
	s := testSched(2, 0, 1<<20, 4)
	long, _ := s.acquire(context.Background(), demand{Client: "busy", CPU: 1}, 0) // runs all along
	defer long()
	hold, _ := s.acquire(context.Background(), demand{Client: "busy", CPU: 1}, 0)
	var mu sync.Mutex
	var order []string
	var wg sync.WaitGroup
	start := func(client string, delay time.Duration) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(delay)
			rel, err := s.acquire(context.Background(), demand{Client: client, CPU: 1}, 5*time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			order = append(order, client)
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			rel()
		}()
	}
	// "busy" keeps one job running: its next job, queued first, still goes after the other
	// clients' first jobs (fewest running first), then oldest first.
	start("busy", 0)
	start("x", 30*time.Millisecond)
	start("y", 60*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	hold()
	wg.Wait()
	if len(order) != 3 || order[0] != "x" || order[1] != "y" || order[2] != "busy" {
		t.Fatalf("order %v", order)
	}
}

func TestSchedulerOwnerFirstAndDrain(t *testing.T) {
	s := testSched(4, 0, 8192, 4)
	s.reserve = 4096
	free := 3000
	s.freeMem = func() int { return free }
	if _, err := s.acquire(context.Background(), demand{Client: "a", CPU: 1, MemMiB: 1024}, 0); !errors.Is(err, errBusy) {
		t.Fatal("started compute while the owner was short of memory")
	}
	done := make(chan error, 1)
	go func() {
		rel, err := s.acquire(context.Background(), demand{Client: "a", CPU: 1, MemMiB: 1024}, 3*time.Second)
		if rel != nil {
			defer rel()
		}
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	free = 12000 // the owner closed their apps
	s.kick()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rel, _ := s.acquire(context.Background(), demand{Client: "b", CPU: 1}, 0)
	go func() { time.Sleep(200 * time.Millisecond); rel() }()
	t0 := time.Now()
	s.drain(5 * time.Second)
	if time.Since(t0) < 150*time.Millisecond {
		t.Fatal("drain did not wait for running work")
	}
	if _, err := s.acquire(context.Background(), demand{Client: "c", CPU: 1}, time.Second); !errors.Is(err, errBusy) {
		t.Fatal("new work admitted while draining")
	}
}

func TestParseVMStat(t *testing.T) {
	out := `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               10000.
Pages active:                            500000.
Pages inactive:                           20000.
Pages speculative:                         2000.
Pages purgeable:                           1000.`
	if got := parseVMStat(out); got != (33000*16384)>>20 {
		t.Fatal(got)
	}
}
