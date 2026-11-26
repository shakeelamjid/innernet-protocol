package main

import (
	"encoding/json"
	"testing"
)

func TestAvailabilityWithMonthDaysAndDaysOff(t *testing.T) {
	av, err := availabilityEntry("mon-fri 21:00-08:00", "Asia/Karachi", []int{1, 2, 15}, []string{"2026-12-25"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(av)
	want := `{"monthdays":[1,2,15],"skip":["2026-12-25"],"tz":"Asia/Karachi","weekly":[[0,1260,1440],[1,0,480],[1,1260,1440],[2,0,480],[2,1260,1440],[3,0,480],[3,1260,1440],[4,0,480],[4,1260,1440],[5,0,480]]}`
	if string(raw) != want {
		t.Fatalf("got %s", raw)
	}
	only, _ := availabilityEntry("always", "UTC", nil, []string{"2027-01-01"})
	if md := only["monthdays"].([]any); len(md) != 31 || only["weekly"] != nil {
		t.Fatalf("days off alone: %v", only)
	}
	if a, _ := availabilityEntry("always", "UTC", nil, nil); a != nil {
		t.Fatal("always on must have no availability")
	}
	for _, bad := range []struct {
		md   []int
		skip []string
	}{{[]int{0}, nil}, {[]int{3, 1}, nil}, {nil, []string{"25/12/2026"}}, {nil, []string{"2027-01-02", "2027-01-01"}}} {
		if _, err := availabilityEntry("always", "UTC", bad.md, bad.skip); err == nil {
			t.Fatalf("accepted %v %v", bad.md, bad.skip)
		}
	}
}
