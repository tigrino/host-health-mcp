// Package sensors implements tool 4.17: hwmon readings - per-chip
// temperatures, fan RPMs, voltages. Walks /sys/class/hwmon entries
// in the daemon's own process (no helper required - hwmon is world-
// readable on Debian/Ubuntu).
package sensors

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Data is the response data for tool sensors.
type Data struct {
	Chips []Chip `json:"chips"`
}

// Chip is one hwmon device.
type Chip struct {
	Name    string   `json:"name"`
	Sensors []Sensor `json:"sensors"`
}

// Sensor is one reading on a chip.
type Sensor struct {
	Label    string   `json:"label"`
	Kind     string   `json:"kind"`
	Value    float64  `json:"value"`
	Critical *float64 `json:"critical,omitempty"`
}

// Tool is the registered tool.
type Tool struct{}

// New returns a new tool instance.
func New() *Tool { return &Tool{} }

// Name returns the tool name.
func (*Tool) Name() string { return "sensors" }

// DefaultTTL: temperatures move slowly relative to the inspection
// cadence.
func (*Tool) DefaultTTL() time.Duration { return 15 * time.Second }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 2 * time.Second }

// inputRE matches hwmon attribute names like temp1_input, fan2_input,
// in0_input. The prefix is the kind; the trailing digit (capture
// group 2) is the index used to find a matching _label, _crit.
var inputRE = regexp.MustCompile(`^(temp|fan|in)([0-9]+)_input$`)

// Handle walks /sys/class/hwmon. Hosts with no exposed sensors
// (typical for VMs) return an empty chips array.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	out := Data{Chips: []Chip{}}

	entries, err := os.ReadDir("/sys/class/hwmon")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil, nil
		}
		return nil, nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		chipDir := filepath.Join("/sys/class/hwmon", e.Name())
		name := readTrim(filepath.Join(chipDir, "name"))
		if name == "" {
			continue
		}
		chip := Chip{Name: name, Sensors: []Sensor{}}

		files, err := os.ReadDir(chipDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			m := inputRE.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			s, ok := readSensor(chipDir, m[1], m[2])
			if !ok {
				continue
			}
			chip.Sensors = append(chip.Sensors, s)
		}
		if len(chip.Sensors) > 0 {
			out.Chips = append(out.Chips, chip)
		}
	}
	return out, nil, nil
}

func readSensor(chipDir, kind, idx string) (Sensor, bool) {
	inputPath := filepath.Join(chipDir, kind+idx+"_input")
	raw := readTrim(inputPath)
	if raw == "" {
		return Sensor{}, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return Sensor{}, false
	}
	label := readTrim(filepath.Join(chipDir, kind+idx+"_label"))
	if label == "" {
		label = kind + idx
	}
	s := Sensor{Label: label}
	switch kind {
	case "temp":
		s.Kind = "temp_c"
		s.Value = v / 1000.0
	case "fan":
		s.Kind = "fan_rpm"
		s.Value = v
	case "in":
		s.Kind = "voltage_v"
		s.Value = v / 1000.0
	default:
		return Sensor{}, false
	}
	if c := readTrim(filepath.Join(chipDir, kind+idx+"_crit")); c != "" {
		if cv, err := strconv.ParseFloat(c, 64); err == nil {
			switch kind {
			case "temp":
				cv /= 1000.0
			case "in":
				cv /= 1000.0
			}
			s.Critical = &cv
		}
	}
	return s, true
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
