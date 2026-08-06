package capsplan

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPlanFor(t *testing.T) {
	tests := []struct {
		name         string
		tools        []string
		plugins      []string
		backends     []string
		wantBounding []string
		wantAmbient  []string
	}{
		{
			name:         "empty manifest grants only the helper's own CAP_CHOWN",
			wantBounding: []string{"CAP_CHOWN"},
			wantAmbient:  nil,
		},
		{
			// The defaulted backend list is smart+lvm+mdraid, so
			// CAP_SYS_RAWIO is granted and CAP_SYS_ADMIN is not. This
			// is the case the whole storage_backends mechanism exists
			// for: an operator who has not declared ZFS does not pay
			// CAP_SYS_ADMIN.
			name:         "storage without declared backends defaults conservatively",
			tools:        []string{"storage"},
			wantBounding: []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO"},
			wantAmbient:  []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO"},
		},
		{
			name:         "zfs alone grants CAP_SYS_ADMIN but not CAP_SYS_RAWIO",
			tools:        []string{"storage"},
			backends:     []string{"zfs"},
			wantBounding: []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"},
			wantAmbient:  []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"},
		},
		{
			name:         "smart alone grants CAP_SYS_RAWIO but not CAP_SYS_ADMIN",
			tools:        []string{"storage"},
			backends:     []string{"smart"},
			wantBounding: []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO"},
			wantAmbient:  []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_RAWIO"},
		},
		{
			name:         "btrfs needs CAP_SYS_ADMIN for an in-progress scrub",
			tools:        []string{"storage"},
			backends:     []string{"btrfs"},
			wantBounding: []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"},
			wantAmbient:  []string{"CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"},
		},
		{
			name:         "lvm and mdraid need no dangerous capability",
			tools:        []string{"storage"},
			backends:     []string{"lvm", "mdraid"},
			wantBounding: []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH"},
			wantAmbient:  []string{"CAP_DAC_READ_SEARCH"},
		},
		{
			name:         "security",
			tools:        []string{"security"},
			wantBounding: []string{"CAP_CHOWN", "CAP_AUDIT_CONTROL", "CAP_DAC_READ_SEARCH"},
			wantAmbient:  []string{"CAP_AUDIT_CONTROL", "CAP_DAC_READ_SEARCH"},
		},
		{
			name:         "firewall",
			tools:        []string{"firewall"},
			wantBounding: []string{"CAP_CHOWN", "CAP_NET_ADMIN"},
			wantAmbient:  []string{"CAP_NET_ADMIN"},
		},
		{
			name:         "firewall_lookup alone also grants CAP_NET_ADMIN",
			tools:        []string{"firewall_lookup"},
			wantBounding: []string{"CAP_CHOWN", "CAP_NET_ADMIN"},
			wantAmbient:  []string{"CAP_NET_ADMIN"},
		},
		{
			name:         "both firewall tools grant CAP_NET_ADMIN once",
			tools:        []string{"firewall", "firewall_lookup"},
			wantBounding: []string{"CAP_CHOWN", "CAP_NET_ADMIN"},
			wantAmbient:  []string{"CAP_NET_ADMIN"},
		},
		{
			name:         "workload plus wireguard",
			tools:        []string{"workload"},
			plugins:      []string{"wireguard"},
			wantBounding: []string{"CAP_CHOWN", "CAP_NET_ADMIN"},
			wantAmbient:  []string{"CAP_NET_ADMIN"},
		},
		{
			name:         "workload plus nginx_apache reads 0640 root:adm access logs",
			tools:        []string{"workload"},
			plugins:      []string{"nginx_apache"},
			wantBounding: []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH"},
			wantAmbient:  []string{"CAP_DAC_READ_SEARCH"},
		},
		{
			// A plugin listed without the workload tool enabled cannot
			// run, so it must not widen the bounding set.
			name:         "plugins without the workload tool grant nothing",
			plugins:      []string{"wireguard", "nginx_apache"},
			wantBounding: []string{"CAP_CHOWN"},
			wantAmbient:  nil,
		},
		{
			name:         "workload with no plugins grants nothing extra",
			tools:        []string{"workload"},
			wantBounding: []string{"CAP_CHOWN"},
			wantAmbient:  nil,
		},
		{
			name:     "everything at once",
			tools:    []string{"storage", "security", "workload", "firewall"},
			plugins:  []string{"wireguard", "nginx_apache"},
			backends: []string{"smart", "lvm", "mdraid", "zfs", "btrfs"},
			wantBounding: []string{
				"CAP_CHOWN", "CAP_AUDIT_CONTROL", "CAP_DAC_READ_SEARCH",
				"CAP_SYS_RAWIO", "CAP_SYS_ADMIN", "CAP_NET_ADMIN",
			},
			wantAmbient: []string{
				"CAP_AUDIT_CONTROL", "CAP_DAC_READ_SEARCH",
				"CAP_SYS_RAWIO", "CAP_SYS_ADMIN", "CAP_NET_ADMIN",
			},
		},
		{
			// Backends are only consulted when storage is enabled, so
			// declaring zfs on a host that does not run the tool must
			// not hand it CAP_SYS_ADMIN.
			name:         "declared backends without the storage tool grant nothing",
			backends:     []string{"zfs", "btrfs"},
			wantBounding: []string{"CAP_CHOWN"},
			wantAmbient:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := For(tc.tools, tc.plugins, tc.backends)
			if !reflect.DeepEqual(p.Bounding, tc.wantBounding) {
				t.Errorf("bounding:\n got %v\nwant %v", p.Bounding, tc.wantBounding)
			}
			if !reflect.DeepEqual(p.Ambient, tc.wantAmbient) {
				t.Errorf("ambient:\n got %v\nwant %v", p.Ambient, tc.wantAmbient)
			}
		})
	}
}

// CAP_CHOWN is the helper's own, used to chown its socket and runtime
// directory at startup. Leaking it into the ambient set would hand it
// to every tool the helper execs.
func TestAmbientNeverCarriesCapChown(t *testing.T) {
	p := For([]string{"storage", "security", "workload", "firewall"},
		[]string{"wireguard"}, []string{"smart", "zfs"})
	for _, c := range p.Ambient {
		if c == "CAP_CHOWN" {
			t.Fatalf("CAP_CHOWN leaked into the ambient set: %v", p.Ambient)
		}
	}
	if !Has(p.Bounding, "CAP_CHOWN") {
		t.Errorf("CAP_CHOWN must stay in the bounding set: %v", p.Bounding)
	}
}

func TestBackendDefaultNoteOnlyWhenStorageEnabled(t *testing.T) {
	withStorage := For([]string{"storage"}, nil, nil)
	if len(withStorage.Notes) != 1 || !strings.Contains(withStorage.Notes[0], "storage_backends absent") {
		t.Errorf("storage enabled and backends absent should say so once, got %v", withStorage.Notes)
	}
	// On a host that does not enable storage the defaulted list grants
	// nothing, so the line is noise in an unattended-upgrade report.
	without := For([]string{"manifest"}, nil, nil)
	if len(without.Notes) != 0 {
		t.Errorf("storage disabled should produce no defaulting note, got %v", without.Notes)
	}
}

func TestEmptyBackendListDefaultsRatherThanGrantingNothing(t *testing.T) {
	// `storage_backends: []` is the natural spelling for "none" and the
	// daemon's decoder accepts it. Treating it as "declared, empty"
	// would silently drop CAP_SYS_RAWIO on every smart host.
	p := For([]string{"storage"}, nil, []string{})
	if !reflect.DeepEqual(p.Backends, DefaultBackends) {
		t.Errorf("empty list should default, got %v", p.Backends)
	}
}

func TestUnknownNamesWarnButDoNotChangeCaps(t *testing.T) {
	p := For([]string{"storage", "storag"}, []string{"wiregaurd"}, []string{"zfs", "ceph"})
	joined := strings.Join(p.Warnings, "\n")
	for _, want := range []string{`"storag"`, `"wiregaurd"`, `"ceph"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings should name %s, got:\n%s", want, joined)
		}
	}
	// The typos must not have widened or narrowed the set.
	want := []string{"CAP_CHOWN", "CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"}
	if !reflect.DeepEqual(p.Bounding, want) {
		t.Errorf("bounding:\n got %v\nwant %v", p.Bounding, want)
	}
}

// The generator is regenerated on every configure and its output is
// compared across hosts by eye. A set that reshuffles on identical
// input produces a diff nobody can use.
func TestOrderIsStableAcrossRuns(t *testing.T) {
	tools := []string{"storage", "security", "firewall", "workload"}
	plugins := []string{"wireguard", "nginx_apache"}
	backends := []string{"smart", "zfs"}
	first := For(tools, plugins, backends)
	for i := 0; i < 50; i++ {
		got := For(tools, plugins, backends)
		if !reflect.DeepEqual(got.Bounding, first.Bounding) {
			t.Fatalf("run %d bounding differs:\n got %v\nwant %v", i, got.Bounding, first.Bounding)
		}
		if !reflect.DeepEqual(got.Ambient, first.Ambient) {
			t.Fatalf("run %d ambient differs:\n got %v\nwant %v", i, got.Ambient, first.Ambient)
		}
	}
}

// KnownPlugins decides which plugins can widen the capability set. It
// is hand-maintained, and build/workload-tags is the interface
// downstream packaging reads to decide what to compile in. A plugin
// added there and forgotten here compiles into the daemon and then
// silently lacks the capability it needs.
func TestKnownPluginsMatchWorkloadTags(t *testing.T) {
	f, err := os.Open(filepath.Join(repoRoot(t), "build", "workload-tags"))
	if err != nil {
		t.Fatalf("open workload-tags: %v", err)
	}
	defer f.Close()

	fromTags := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, ok := strings.CutPrefix(line, "wl_")
		if !ok {
			t.Errorf("workload-tags entry %q does not start with wl_", line)
			continue
		}
		fromTags[name] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read workload-tags: %v", err)
	}
	if len(fromTags) == 0 {
		t.Fatal("parsed no tags from build/workload-tags; the test is not proving anything")
	}
	if !reflect.DeepEqual(fromTags, KnownPlugins) {
		t.Errorf("knownPlugins and build/workload-tags disagree:\n tags %v\n code %v", fromTags, KnownPlugins)
	}
}

// repoRoot walks up to the directory holding doc/REQUIREMENTS.txt.
// Anchoring on a README would stop a level short: build/ has one too.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "doc", "REQUIREMENTS.txt")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no doc/REQUIREMENTS.txt above cwd)")
		}
		dir = parent
	}
}
