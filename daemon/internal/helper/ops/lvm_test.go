package ops

import "testing"

const fakeVGsJSON = `{
  "report": [
    {
      "vg": [
        { "vg_name": "vg0", "vg_size": "1099511627776", "vg_free": "549755813888" },
        { "vg_name": "vg-data", "vg_size": "10737418240", "vg_free": "0" }
      ]
    }
  ]
}`

const fakeLVsJSON = `{
  "report": [
    {
      "lv": [
        { "vg_name": "vg0", "lv_name": "root", "lv_size": "53687091200", "lv_health_status": "" },
        { "vg_name": "vg0", "lv_name": "swap", "lv_size": "8589934592", "lv_health_status": "partial" }
      ]
    }
  ]
}`

func TestParseVGs(t *testing.T) {
	var out LvmReportResult
	if err := parseVGs([]byte(fakeVGsJSON), &out); err != nil {
		t.Fatalf("parseVGs: %v", err)
	}
	if len(out.VGs) != 2 {
		t.Fatalf("len(VGs) = %d want 2", len(out.VGs))
	}
	if out.VGs[0].Name != "vg0" || out.VGs[0].SizeB != 1099511627776 || out.VGs[0].FreeB != 549755813888 {
		t.Errorf("vg0 mismatch: %+v", out.VGs[0])
	}
	if out.VGs[1].Name != "vg-data" || out.VGs[1].FreeB != 0 {
		t.Errorf("vg-data mismatch: %+v", out.VGs[1])
	}
}

func TestParseLVs(t *testing.T) {
	var out LvmReportResult
	if err := parseLVs([]byte(fakeLVsJSON), &out); err != nil {
		t.Fatalf("parseLVs: %v", err)
	}
	if len(out.LVs) != 2 {
		t.Fatalf("len(LVs) = %d want 2", len(out.LVs))
	}
	if out.LVs[0].HealthStatus != nil {
		t.Errorf("empty lv_health_status should be nil, got %+v", out.LVs[0].HealthStatus)
	}
	if out.LVs[1].HealthStatus == nil || *out.LVs[1].HealthStatus != "partial" {
		t.Errorf("lv swap health_status: got %+v want 'partial'", out.LVs[1].HealthStatus)
	}
}
