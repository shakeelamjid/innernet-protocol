package main

import "testing"

func TestParseMacGPUs(t *testing.T) {
	out := `{"SPDisplaysDataType":[{"_name":"Apple M1 Pro","sppci_model":"Apple M1 Pro","sppci_cores":"16",
	 "spdisplays_vendor":"sppci_vendor_Apple","spdisplays_mtlgpufamilysupport":"spdisplays_metal3"}]}`
	g := parseMacGPUs(out, 16384)
	if len(g) != 1 || g[0].Vendor != "Apple" || g[0].Model != "Apple M1 Pro" || g[0].Cores != 16 || g[0].VRAMMiB != 16384 || g[0].API != "metal" {
		t.Fatalf("%+v", g)
	}
	intel := parseMacGPUs(`{"SPDisplaysDataType":[{"sppci_model":"Intel Iris Plus Graphics","spdisplays_vendor":"Intel","spdisplays_vram_shared":"1536 MB"}]}`, 8192)
	if intel[0].API != "none" || intel[0].VRAMMiB != 1536 {
		t.Fatalf("%+v", intel)
	}
}

func TestParseNvidiaAndBest(t *testing.T) {
	g := clean(parseNvidiaSMI("NVIDIA GeForce RTX 4090, 24564, 550.54.14\nNVIDIA GeForce RTX 4090, 24564, 550.54.14\nNVIDIA T400, 2048, 550.54.14\n"))
	best, n, ok := bestGPU(g)
	if !ok || n != 2 || best.Model != "NVIDIA GeForce RTX 4090" || best.VRAMMiB != 24564 || best.API != "cuda" {
		t.Fatalf("%+v %d", best, n)
	}
	if s := gpuSummary(g); s != "2 × NVIDIA GeForce RTX 4090" {
		t.Fatal(s)
	}
}

func TestParseLspciAndWindowsSkipVirtual(t *testing.T) {
	g := clean(parseLspci(`00:02.0 "VGA compatible controller" "ASPEED Technology, Inc." "ASPEED Graphics Family" -r41 "" ""
01:00.0 "3D controller" "NVIDIA Corporation" "GA100 [A100 PCIe 40GB]" -ra1 "NVIDIA Corporation" "Device 145f"`))
	if len(g) != 1 || g[0].Vendor != "NVIDIA" || g[0].API != "none" {
		t.Fatalf("%+v", g) // no nvidia-smi means no driver: listed but not rentable
	}
	w := clean(parseWinVideo(`[{"Name":"Microsoft Basic Display Adapter","AdapterCompatibility":"(Standard display types)","AdapterRAM":0},
	{"Name":"AMD Radeon RX 7900 XTX","AdapterCompatibility":"Advanced Micro Devices, Inc.","AdapterRAM":4293918720,"DriverVersion":"31.0.24027.1012"}]`))
	if len(w) != 1 || w[0].Vendor != "AMD" || w[0].VRAMMiB != 0 {
		t.Fatalf("%+v", w)
	}
	if _, _, ok := bestGPU(w); ok {
		t.Fatal("a display-only GPU must not be rentable")
	}
}

func TestGPUDescriptor(t *testing.T) {
	c := &Config{Name: "m", Region: "asia-south", Host: "203.0.113.7", Port: 9443, Network: "base-sepolia",
		Payout: "0x" + "ab12" + "00000000000000000000000000000000000000"[:36], Prices: defaultPrices()}
	if err := c.setGPU(parseNvidiaSMI("NVIDIA L4, 23034, 550.0\n"), 2); err == nil {
		t.Fatal("offered more GPUs than the machine has")
	}
	if err := c.setGPU(parseNvidiaSMI("NVIDIA L4, 23034, 550.0\n"), 1); err != nil {
		t.Fatal(err)
	}
	if err := c.validate(true); err != nil {
		t.Fatal(err)
	}
	e := c.descriptorEntry("00")
	hw := e["hardware"].(map[string]any)
	if hw["gpu_model"] != "NVIDIA L4" || hw["gpu_api"] != "cuda" || hw["gpu_vram_mib"] != 23034 {
		t.Fatalf("%v", hw)
	}
	if e["limits"].(map[string]any)["GPU-1"].(map[string]any)["max_gpus"] != 1 {
		t.Fatalf("%v", e["limits"])
	}
}
