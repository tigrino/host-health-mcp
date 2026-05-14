// Package pressure implements tool 4.15: PSI averages from
// /proc/pressure/{cpu,io,memory}. Hosts without PSI support return
// null for each block.
package pressure

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"
)

// Data is the response data for tool pressure. Mirrors PressureData in
// doc/schema-draft.yaml.
type Data struct {
	CPU         *Metric `json:"cpu"`
	IOSome      *Metric `json:"io_some"`
	IOFull      *Metric `json:"io_full"`
	MemorySome  *Metric `json:"memory_some"`
	MemoryFull  *Metric `json:"memory_full"`
}

// Metric is one row of /proc/pressure/*.
type Metric struct {
	Avg10   float64 `json:"avg10"`
	Avg60   float64 `json:"avg60"`
	Avg300  float64 `json:"avg300"`
	TotalUs int64   `json:"total_us"`
}

// Tool is the registered tool.
type Tool struct{}

// New returns a new tool instance.
func New() *Tool { return &Tool{} }

// Name returns the tool name.
func (*Tool) Name() string { return "pressure" }

// DefaultTTL is short; PSI moves fast under load.
func (*Tool) DefaultTTL() time.Duration { return 15 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 1 * time.Second }

// Handle reads /proc/pressure/{cpu,io,memory} and returns the parsed
// rows. A null block is reported when the kernel lacks PSI support.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{}
	d.CPU = readSome("/proc/pressure/cpu")
	d.IOSome, d.IOFull = readSomeFull("/proc/pressure/io")
	d.MemorySome, d.MemoryFull = readSomeFull("/proc/pressure/memory")
	return d, nil, nil
}

// readSome reads a single-row file (CPU has only "some").
func readSome(path string) *Metric {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "some ") {
			return parsePressureLine(line)
		}
	}
	return nil
}

// readSomeFull reads io/memory which has both "some" and "full" rows.
func readSomeFull(path string) (*Metric, *Metric) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var some, full *Metric
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "some "):
			some = parsePressureLine(line)
		case strings.HasPrefix(line, "full "):
			full = parsePressureLine(line)
		}
	}
	return some, full
}

func parsePressureLine(line string) *Metric {
	// Format: "some avg10=0.00 avg60=0.00 avg300=0.00 total=1234"
	m := &Metric{}
	for _, field := range strings.Fields(line)[1:] {
		eq := strings.IndexByte(field, '=')
		if eq <= 0 {
			continue
		}
		key := field[:eq]
		val := field[eq+1:]
		switch key {
		case "avg10":
			m.Avg10, _ = strconv.ParseFloat(val, 64)
		case "avg60":
			m.Avg60, _ = strconv.ParseFloat(val, 64)
		case "avg300":
			m.Avg300, _ = strconv.ParseFloat(val, 64)
		case "total":
			m.TotalUs, _ = strconv.ParseInt(val, 10, 64)
		}
	}
	return m
}
