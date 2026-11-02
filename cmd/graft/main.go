// Command graft audits npm dependency trees for compromised releases: the
// kind where a stolen maintainer token grafts a new dependency, an install
// script or obfuscated code onto a package people already trust.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/n4uu/graft/internal/cacache"
	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/registry"
	"github.com/n4uu/graft/internal/report"
	"github.com/n4uu/graft/internal/scan"
	"github.com/n4uu/graft/internal/signals"
	"github.com/n4uu/graft/internal/tarball"
)

var version = "dev"

const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitError)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var code int
	var err error
	switch os.Args[1] {
	case "audit":
		code, err = run(ctx, "audit", os.Args[2:])
	case "sweep":
		code, err = run(ctx, "sweep", os.Args[2:])
	case "check":
		code, err = run(ctx, "check", os.Args[2:])
	case "policy":
		_, err = os.Stdout.Write(policy.DefaultYAML())
	case "version", "-version", "--version":
		fmt.Printf("graft %s\n", version)
	case "help", "-h", "-help", "--help":
		usage()
	default:
		usage()
		os.Exit(exitError)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "graft: %v\n", err)
		os.Exit(exitError)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprint(os.Stderr, `graft: find compromised releases in npm dependency trees

usage:
  graft audit [flags] [path...]        lockfiles under each path (default .): package-lock, yarn, pnpm
  graft sweep [flags] [path...]        incident response: audit + node_modules tampering + the npm cache
  graft check [flags] name@version...  evaluate specific versions, e.g. before an upgrade
  graft policy                         print the default policy (weights, thresholds, allowlists)
  graft version

exit status: 0 clean, 1 findings at or above -fail-on, 2 error.
run "graft audit -h" for flags.
`)
}

func run(ctx context.Context, mode string, args []string) (int, error) {
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	format := fs.String("format", "text", "text, json or sarif")
	out := fs.String("o", "", "write the report to this file instead of stdout")
	failOn := fs.String("fail-on", "high", "exit 1 if anything reaches this level: critical, high, medium, low, none (never)")
	min := fs.String("min", "medium", "lowest level shown in text and SARIF output")
	policyFile := fs.String("policy", "", "policy file overriding weights, thresholds or allowlists (see graft policy)")
	feedFile := fs.String("feed", "", "extra known-malicious feed (same format as the built-in one)")
	cacheDir := fs.String("cache", defaultCache(), "registry document cache (\"\" to disable)")
	ttl := fs.Duration("ttl", 6*time.Hour, "refetch cached registry documents older than this")
	offline := fs.Bool("offline", false, "use only cached registry documents")
	at := fs.String("at", "", "evaluate against the registry as of this RFC 3339 time (incident reconstruction)")
	deep := fs.Bool("deep", false, "download and inspect tarballs of suspicious versions")
	dev := fs.Bool("dev", true, "include devDependencies")
	workers := fs.Int("workers", 12, "parallel registry requests")
	reg := fs.String("registry", "https://registry.npmjs.org/", "registry URL")
	verbose := fs.Bool("v", false, "show publish details and references")
	npmCache := fs.String("npm-cache", cacache.DefaultDir(), "npm _cacache directory to read (sweep)")
	fs.Parse(args)

	if policy.LevelRank(*failOn) < 0 || policy.LevelRank(*min) < 0 {
		return exitError, fmt.Errorf("levels are critical, high, medium, low, none")
	}

	pol := policy.Default()
	if *policyFile != "" {
		p, err := policy.Load(*policyFile)
		if err != nil {
			return exitError, err
		}
		pol = p
	}
	if *feedFile != "" {
		if err := pol.LoadFeed(*feedFile); err != nil {
			return exitError, err
		}
	}

	rc := registry.New(*cacheDir, *offline)
	rc.Base = *reg
	rc.TTL = *ttl
	rc.Token = os.Getenv("NPM_TOKEN")
	ev := &signals.Evaluator{Registry: rc, Policy: pol, Deep: *deep}
	if *deep {
		ev.Inspect = tarball.Inspector(rc, pol)
	}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return exitError, fmt.Errorf("-at: %w", err)
		}
		ev.At = t
	}

	var res *scan.Result
	switch mode {
	case "check":
		if fs.NArg() == 0 {
			return exitError, fmt.Errorf("usage: graft check name@version...")
		}
		var specs [][2]string
		for _, a := range fs.Args() {
			name, ver, ok := splitSpec(a)
			if !ok {
				return exitError, fmt.Errorf("%q: want name@version", a)
			}
			specs = append(specs, [2]string{name, ver})
		}
		res = &scan.Result{Checked: ev.EvaluateAll(ctx, specs, *workers)}
		*min = "none"
	default:
		paths := fs.Args()
		if len(paths) == 0 {
			paths = []string{"."}
		}
		opts := scan.Options{Dev: *dev, Workers: *workers}
		if mode == "sweep" {
			opts.NodeModules = true
			opts.NpmCache = *npmCache
		}
		var err error
		res, err = scan.Run(ctx, ev, paths, opts)
		if err != nil {
			return exitError, err
		}
		if len(res.Lockfiles) == 0 && len(res.Cache) == 0 {
			res.Notes = append(res.Notes, "no lockfiles found (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml)")
		}
	}
	if rc.Requests > 0 || rc.Hits > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("registry: %d documents fetched, %d from cache", rc.Requests, rc.Hits))
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return exitError, err
		}
		defer f.Close()
		w = f
	}
	wd, _ := os.Getwd()
	var err error
	switch *format {
	case "text":
		report.Text(w, res, *min, *verbose)
	case "json":
		err = report.JSON(w, res)
	case "sarif":
		err = report.SARIF(w, res, *min, version, wd)
	default:
		return exitError, fmt.Errorf("unknown -format %q", *format)
	}
	if err != nil {
		return exitError, err
	}

	if *failOn != "none" && policy.LevelRank(report.Worst(res)) >= policy.LevelRank(*failOn) {
		return exitFindings, nil
	}
	return exitOK, nil
}

func splitSpec(s string) (string, string, bool) {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return "", "", false
	}
	return s[:at], s[at+1:], true
}

func defaultCache() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "graft")
}
