package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// gpuInfo is one graphics processor the machine found. API is the native interface WebGPU jobs
// run through: cuda (NVIDIA driver present; WebGPU uses Vulkan or DirectX on it), metal (Apple),
// vulkan (Linux), directx (Windows), rocm/oneapi, or none (no working driver).
type gpuInfo struct {
	Vendor  string `json:"vendor"`
	Model   string `json:"model"`
	VRAMMiB int    `json:"vram_mib,omitempty"` // Apple: the shared (unified) memory
	Cores   int    `json:"cores,omitempty"`
	API     string `json:"api,omitempty"`
	Driver  string `json:"driver,omitempty"`
}

var reHWText = regexp.MustCompile(`[^A-Za-z0-9 ()._+/,-]`)

func hwText(s string) string {
	s = strings.TrimSpace(reHWText.ReplaceAllString(s, ""))
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// run gives a hardware tool 5 seconds; a missing or slow tool just means "not found".
func runTool(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// detectGPUs asks the tools each system already ships with. Nothing is installed.
func detectGPUs() []gpuInfo {
	if v := os.Getenv("INNERNET_TEST_GPUS"); v != "" { // tests: pretend this machine has these GPUs
		var g []gpuInfo
		_ = json.Unmarshal([]byte(v), &g)
		return g
	}
	var g []gpuInfo
	switch runtime.GOOS {
	case "darwin":
		g = parseMacGPUs(runTool("system_profiler", "-json", "SPDisplaysDataType"), totalMemoryMiB())
	case "linux":
		g = parseNvidiaSMI(runTool("nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"))
		if len(g) == 0 {
			g = parseLspci(runTool("lspci", "-mm"))
		}
	case "windows":
		g = parseNvidiaSMI(runTool("nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"))
		if len(g) == 0 {
			g = parseWinVideo(runTool("powershell", "-NoProfile", "-Command",
				"Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,AdapterRAM,DriverVersion | ConvertTo-Json"))
		}
	}
	return clean(g)
}

// clean drops virtual and server-console adapters and caps the list.
func clean(in []gpuInfo) []gpuInfo {
	var out []gpuInfo
	for _, x := range in {
		x.Vendor, x.Model, x.Driver = hwText(x.Vendor), hwText(x.Model), hwText(x.Driver)
		low := strings.ToLower(x.Vendor + " " + x.Model)
		if x.Model == "" || x.Vendor == "" {
			continue
		}
		skip := false
		for _, v := range []string{"basic display", "basic render", "vmware", "virtualbox", "cirrus", "aspeed", "matrox",
			"llvmpipe", "qxl", "virtio", "hyper-v", "parallels", "remote display", "bochs"} {
			if strings.Contains(low, v) {
				skip = true
			}
		}
		if !skip {
			out = append(out, x)
		}
		if len(out) == 16 {
			break
		}
	}
	return out
}

func parseNvidiaSMI(out string) []gpuInfo {
	var g []gpuInfo
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, ",")
		if len(f) < 3 {
			continue
		}
		mem, _ := strconv.Atoi(strings.TrimSpace(f[1]))
		g = append(g, gpuInfo{Vendor: "NVIDIA", Model: strings.TrimSpace(f[0]), VRAMMiB: mem, API: "cuda",
			Driver: strings.TrimSpace(f[2])})
	}
	return g
}

func parseMacGPUs(out string, memMiB int) []gpuInfo {
	var doc struct {
		Displays []map[string]any `json:"SPDisplaysDataType"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return nil
	}
	var g []gpuInfo
	for _, d := range doc.Displays {
		model, _ := d["sppci_model"].(string)
		vendor, _ := d["spdisplays_vendor"].(string)
		x := gpuInfo{Model: model, API: "metal"}
		switch {
		case strings.Contains(strings.ToLower(vendor), "apple") || strings.HasPrefix(model, "Apple"):
			x.Vendor, x.VRAMMiB = "Apple", memMiB // unified memory: the GPU can use most of it
		case strings.Contains(strings.ToLower(vendor), "amd") || strings.Contains(strings.ToLower(vendor), "ati"):
			x.Vendor = "AMD"
		case strings.Contains(strings.ToLower(vendor), "intel"):
			x.Vendor = "Intel"
		case strings.Contains(strings.ToLower(vendor), "nvidia"):
			x.Vendor = "NVIDIA"
		default:
			x.Vendor = strings.TrimPrefix(vendor, "sppci_vendor_")
		}
		if c, ok := d["sppci_cores"].(string); ok {
			x.Cores, _ = strconv.Atoi(c)
		}
		for _, k := range []string{"spdisplays_vram", "spdisplays_vram_shared"} {
			if v, ok := d[k].(string); ok && x.VRAMMiB == 0 {
				x.VRAMMiB = parseSize(v)
			}
		}
		g = append(g, x)
	}
	return g
}

// parseSize reads "8 GB", "1536 MB".
func parseSize(s string) int {
	f := strings.Fields(s)
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return 0
	}
	if strings.HasPrefix(strings.ToUpper(f[1]), "G") {
		return n * 1024
	}
	return n
}

var reLspci = regexp.MustCompile(`"([^"]*)"`)

// parseLspci reads `lspci -mm`: slot "class" "vendor" "device" ... Only graphics and 3D controllers.
func parseLspci(out string) []gpuInfo {
	var g []gpuInfo
	for _, line := range strings.Split(out, "\n") {
		q := reLspci.FindAllStringSubmatch(line, -1)
		if len(q) < 3 {
			continue
		}
		class := strings.ToLower(q[0][1])
		if !strings.Contains(class, "vga") && !strings.Contains(class, "3d") && !strings.Contains(class, "display") {
			continue
		}
		vendor, model := q[1][1], q[2][1]
		x := gpuInfo{Model: model, API: "none"}
		lv := strings.ToLower(vendor)
		switch {
		case strings.Contains(lv, "nvidia"):
			x.Vendor = "NVIDIA" // no nvidia-smi: the driver is missing, so CUDA cannot run yet
		case strings.Contains(lv, "amd") || strings.Contains(lv, "ati"):
			x.Vendor, x.API = "AMD", "vulkan"
		case strings.Contains(lv, "intel"):
			x.Vendor, x.API = "Intel", "vulkan"
		default:
			x.Vendor = vendor
		}
		g = append(g, x)
	}
	return g
}

func parseWinVideo(out string) []gpuInfo {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	if !strings.HasPrefix(out, "[") {
		out = "[" + out + "]"
	}
	var rows []struct {
		Name    string `json:"Name"`
		Maker   string `json:"AdapterCompatibility"`
		RAM     int64  `json:"AdapterRAM"`
		Version string `json:"DriverVersion"`
	}
	if json.Unmarshal([]byte(out), &rows) != nil {
		return nil
	}
	var g []gpuInfo
	for _, r := range rows {
		x := gpuInfo{Model: r.Name, Driver: r.Version, API: "directx"}
		lm := strings.ToLower(r.Maker + " " + r.Name)
		switch {
		case strings.Contains(lm, "nvidia"):
			x.Vendor = "NVIDIA"
		case strings.Contains(lm, "amd") || strings.Contains(lm, "advanced micro") || strings.Contains(lm, "radeon"):
			x.Vendor = "AMD"
		case strings.Contains(lm, "intel"):
			x.Vendor = "Intel"
		default:
			x.Vendor = r.Maker
		}
		if r.RAM > 0 && r.RAM < 0xFFF00000 { // Windows caps this at 4 GiB; leave larger cards unknown
			x.VRAMMiB = int(r.RAM >> 20)
		}
		g = append(g, x)
	}
	return g
}

// bestGPU is the GPU to rent out: one jobs can use, with the most memory. Same rule as the registry.
func bestGPU(gpus []gpuInfo) (gpuInfo, int, bool) {
	var best gpuInfo
	found := false
	for _, g := range gpus {
		if g.API == "" || g.API == "none" {
			continue
		}
		if !found || g.VRAMMiB > best.VRAMMiB || (g.VRAMMiB == best.VRAMMiB && g.Cores > best.Cores) {
			best, found = g, true
		}
	}
	n := 0
	for _, g := range gpus {
		if found && g.Model == best.Model {
			n++
		}
	}
	return best, n, found
}

func gpuSummary(gpus []gpuInfo) string {
	if len(gpus) == 0 {
		return "no GPU"
	}
	g, n, ok := bestGPU(gpus)
	if !ok {
		return gpus[0].Model + " (display only)"
	}
	s := g.Model
	if n > 1 {
		s = strconv.Itoa(n) + " × " + s
	}
	if g.Cores > 0 {
		s += " " + strconv.Itoa(g.Cores) + "-core"
	}
	return s
}
