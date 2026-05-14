// Package certs implements tool 4.6: subject, issuer, not_after,
// days_remaining for each manifest-declared cert path; renewal_unit
// when paired with the manifest's cert_renewal_units list.
package certs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Data is the response data for tool certs.
type Data struct {
	Certs []CertEntry `json:"certs"`
}

// CertEntry mirrors the schema.
type CertEntry struct {
	Path           string    `json:"path"`
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	NotAfter       time.Time `json:"not_after"`
	DaysRemaining  int       `json:"days_remaining"`
	RenewalUnit    *string   `json:"renewal_unit"`
}

// Tool is the registered tool.
type Tool struct {
	paths       []string
	renewalUnit []string // parallel to paths; "" if unknown
}

// New returns a new tool over the manifest-declared cert paths plus
// renewal units (parallel slices; the daemon's config loader pairs
// them).
func New(paths, renewalUnits []string) *Tool {
	p := make([]string, len(paths))
	copy(p, paths)
	ru := make([]string, len(paths))
	copy(ru, renewalUnits)
	return &Tool{paths: p, renewalUnit: ru}
}

// Name returns the tool name.
func (*Tool) Name() string { return "certs" }

// DefaultTTL: cert files change rarely.
func (*Tool) DefaultTTL() time.Duration { return 5 * time.Minute }

// DefaultTimeout caps the per-call duration.
func (*Tool) DefaultTimeout() time.Duration { return 3 * time.Second }

// Handle reads and parses each cert path. Individual parse failures
// drop that entry and surface a warning; the tool returns successfully
// with the partial set.
func (t *Tool) Handle(ctx context.Context, _ []byte) (any, []string, error) {
	d := Data{Certs: []CertEntry{}}
	var warnings []string

	now := time.Now()
	for i, p := range t.paths {
		entry, err := parseCertPath(p, now)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("certs: %s: %s", p, err.Error()))
			continue
		}
		if i < len(t.renewalUnit) && t.renewalUnit[i] != "" {
			ru := t.renewalUnit[i]
			entry.RenewalUnit = &ru
		}
		d.Certs = append(d.Certs, entry)
	}
	return d, warnings, nil
}

func parseCertPath(path string, now time.Time) (CertEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return CertEntry{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return CertEntry{}, fmt.Errorf("not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertEntry{}, err
	}
	return CertEntry{
		Path:          path,
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		NotAfter:      cert.NotAfter,
		DaysRemaining: int(cert.NotAfter.Sub(now).Hours() / 24),
	}, nil
}
