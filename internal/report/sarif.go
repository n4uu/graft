package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/scan"
)

// ruleText documents every signal for SARIF consumers (GitHub shows it in
// the code scanning alert).
var ruleText = map[string]string{
	"known_malicious":           "Version is listed in the known-malicious feed.",
	"security_holding":          "npm replaced the package with a security holding placeholder after confirming malware.",
	"dependency_malicious":      "Version adds a dependency that is known malicious or now an npm security placeholder.",
	"never_published":           "The registry has no record of this version ever existing.",
	"unpublished":               "Version was published and later removed from the registry.",
	"deprecated_security":       "Version is deprecated with a security or malware message.",
	"installed_mismatch":        "Installed package.json version differs from the lockfile: the package rewrote its own manifest.",
	"package_missing":           "The registry has no package by this name.",
	"trusted_publisher_dropped": "Previous version was published through npm trusted publishing (OIDC); this one with an account token.",
	"provenance_dropped":        "Previous version had a provenance attestation; this one has none.",
	"publisher_new":             "First version ever published by this account.",
	"githead_missing":           "Previous version recorded its git commit; this one doesn't.",
	"install_script_added":      "Version adds a preinstall/install/postinstall script.",
	"dependency_added":          "Version adds a dependency.",
	"young_dependency":          "Version adds a dependency that appeared on the registry shortly before.",
	"dependency_install_script": "Version adds a dependency that runs an install script.",
	"lookalike_name":            "Name resembles a widely used package.",
	"impersonation":             "Package copies a widely used package's description or repository without sharing any publisher with it.",
	"release_burst":             "Other release lines of the package were published in the same window.",
	"publisher_burst":           "The same account published new versions of several unrelated packages in your tree within minutes.",
	"obfuscated_code":           "Install-time or newly added code is machine-obfuscated.",
	"install_script_behaviour":  "Code run on install starts processes, uses the network, or reads credentials.",
	"self_tampering":            "Code run on install deletes itself or rewrites the package's package.json.",
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *struct {
			StartLine int `json:"startLine"`
		} `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

// SARIF writes findings at or above min as a SARIF 2.1.0 log, one result
// per locked package, located at its lockfile entry. GitHub code scanning
// ingests this directly (github/codeql-action/upload-sarif).
func SARIF(w io.Writer, r *scan.Result, min, version, root string) error {
	ids := make([]string, 0, len(ruleText))
	for id := range ruleText {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var rules []sarifRule
	for _, id := range ids {
		rules = append(rules, sarifRule{
			ID: id, ShortDescription: sarifText{ruleText[id]},
			HelpURI:    "https://github.com/n4uu/graft#signals",
			Properties: map[string]any{"tags": []string{"security", "supply-chain"}},
		})
	}
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{
		Name: "graft", InformationURI: "https://github.com/n4uu/graft", Version: version, Rules: rules,
	}}}

	for _, l := range r.Lockfiles {
		uri := l.Path
		if rel, err := filepath.Rel(root, l.Path); err == nil && !strings.HasPrefix(rel, "..") {
			uri = rel
		}
		uri = filepath.ToSlash(uri)
		for _, it := range l.Items {
			f := it.Finding
			if f == nil || len(f.Signals) == 0 || policy.LevelRank(f.Level) < policy.LevelRank(min) {
				continue
			}
			var lines []string
			for _, s := range f.Signals {
				lines = append(lines, fmt.Sprintf("%s (%+.1f): %s", s.ID, s.Points, s.Detail))
			}
			res := sarifResult{
				RuleID:  f.Signals[0].ID,
				Level:   sarifLevel(f.Level),
				Message: sarifText{fmt.Sprintf("%s is %s risk (score %.1f).\n%s", f.Spec(), f.Level, f.Score, strings.Join(lines, "\n"))},
				PartialFingerprints: map[string]string{
					"graft/v1": fingerprint(uri, f.Spec()),
				},
				Properties: map[string]any{"score": f.Score, "level": f.Level, "package": f.Name, "version": f.Version},
			}
			var loc sarifLocation
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			if it.Package.Line > 0 {
				loc.PhysicalLocation.Region = &struct {
					StartLine int `json:"startLine"`
				}{it.Package.Line}
			}
			res.Locations = []sarifLocation{loc}
			run.Results = append(run.Results, res)
		}
	}
	if run.Results == nil {
		run.Results = []sarifResult{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{run}})
}

func sarifLevel(l string) string {
	switch l {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:16])
}
