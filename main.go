package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"infralens/internal/ai"
	awsDiscovery "infralens/internal/aws"
	"infralens/internal/cleanup"
	"infralens/internal/demo"
	"infralens/internal/engine"
	"infralens/internal/history"
	"infralens/internal/importer"
	"infralens/internal/llm"
	"infralens/internal/report"
	"infralens/internal/settings"
)

// Exit codes are part of the CI contract.
const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitPolicy = 3 // a --fail-on-* threshold was exceeded
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

const usage = `InfraLens: read-only AWS inventory, waste and Shadow IT report.

Usage:
  infralens scan [flags]          scan one or more profiles
  infralens diff OLD.json NEW.json  compare two saved scans
  infralens report [--context FILE] SCAN.json [OUT.html]  rebuild the report from a saved scan
  infralens explain SCAN.json QUERY  show why a resource got its verdict and what the check cannot see
  infralens audit --client NAME [scan flags]   scan and write a client-ready audit pack
  infralens audit --from SCAN.json --client NAME   build the pack from a saved scan
  infralens demo --out DIR                write a synthetic example (no AWS access) to look at
  infralens version                       print the version
  infralens cleanup SCAN.json --out DIR   generate reviewable cleanup scripts (nothing is run)
  infralens progress OLD.json NEW.json    before/after: what was resolved, what is still open
  infralens serve                         local web app: scan, map, reports, notes, model settings (loopback only, port 8765)
  infralens shortcut [--desktop|--remove] add or remove a launcher (menu entry or .command) for serve
  infralens llm show|set|test             choose the language model and where its key comes from
  infralens ai SCAN.json                  a validated reading of a scan, or --q "question"
  infralens policy [--services a,b]   print the minimal read-only IAM policy for the checks
  infralens doctor --profile P        check which parts of a scan will work with these credentials
  infralens checks                list available checks

Exit codes: 0 ok, 1 error, 2 usage, 3 policy threshold exceeded.

scan flags:
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(exitUsage)
	}
	switch os.Args[1] {
	case "checks":
		for _, sc := range awsDiscovery.Scanners() {
			scope := "regional"
			if sc.Global != nil {
				scope = "account"
			}
			fmt.Printf("%-11s %-9s %s\n", sc.Name, scope, sc.Desc)
		}
	case "diff":
		os.Exit(runDiff(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("infralens", version)
	case "demo":
		os.Exit(runDemo(os.Args[2:]))
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "shortcut":
		os.Exit(runShortcut(os.Args[2:]))
	case "llm":
		os.Exit(runLLM(os.Args[2:]))
	case "ai":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		os.Exit(runAICmd(ctx, os.Args[2:]))
	case "cleanup":
		os.Exit(runCleanup(os.Args[2:]))
	case "progress":
		os.Exit(runProgress(os.Args[2:]))
	case "policy":
		os.Exit(runPolicy(os.Args[2:]))
	case "doctor":
		f := newScanFlags()
		if err := f.fs.Parse(os.Args[2:]); err != nil {
			os.Exit(exitUsage)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		os.Exit(runDoctor(ctx, f))
	case "audit":
		f := newScanFlags()
		addAuditFlags(f)
		if err := f.fs.Parse(os.Args[2:]); err != nil {
			os.Exit(exitUsage)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		os.Exit(runAudit(ctx, f))
	case "report":
		os.Exit(runReport(os.Args[2:]))
	case "explain":
		os.Exit(runExplain(os.Args[2:]))
	case "scan":
		f := newScanFlags()
		if err := f.fs.Parse(os.Args[2:]); err != nil {
			os.Exit(exitUsage)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		os.Exit(runScanAll(ctx, f))
	default:
		printUsage()
		os.Exit(exitUsage)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, usage)
	f := newScanFlags()
	f.fs.SetOutput(os.Stderr)
	f.fs.PrintDefaults()
}

type scanFlags struct {
	fs             *flag.FlagSet
	profile        string
	allProfiles    bool
	regions        string
	services       string
	skip           string
	configPath     string
	htmlOut        string
	jsonOut        string
	ssoLogin       bool
	concurrency    int
	useAI          bool
	aiModel        string
	yes            bool
	historyDir     string
	noHistory      bool
	contextPath    string
	baseline       string
	keep           int
	failOnWaste    float64
	failOnNewWaste float64
	apiLog         string
	noBlast        bool
	noAllocate     bool
	tfstate        string
	prowler        string

	// audit
	client     string
	consultant string
	logoPath   string
	anonymize  bool
	outDir     string
	fromPath   string
	withAI     bool

	// progress, when set, receives one line per stage; the web app shows them.
	progress func(string)
	// savedAs is filled with the history path of the scan that was written.
	savedAs string
}

func (f *scanFlags) say(format string, a ...any) {
	if f.progress != nil {
		f.progress(fmt.Sprintf(format, a...))
	}
}

// addAuditFlags registers the flags that only `audit` uses.
func addAuditFlags(f *scanFlags) {
	fs := f.fs
	fs.StringVar(&f.client, "client", "", "client name shown on the document")
	fs.StringVar(&f.consultant, "consultant", "", "who prepared it (shown on the document)")
	fs.StringVar(&f.logoPath, "logo", "", "PNG/JPEG/SVG logo (max 256 KiB) embedded in the document")
	fs.BoolVar(&f.anonymize, "anonymize", false, "replace names, IDs and the account number with aliases; the raw report and scan are then NOT written to the output directory")
	fs.StringVar(&f.outDir, "out", "audit", "output directory")
	fs.StringVar(&f.fromPath, "from", "", "build the audit from a saved scan instead of scanning")
	fs.BoolVar(&f.withAI, "ai-reading", false, "add an AI-assisted reading to the document (uses the model chosen with `infralens llm set`)")
}

func newScanFlags() *scanFlags {
	f := &scanFlags{fs: flag.NewFlagSet("scan", flag.ContinueOnError)}
	fs := f.fs
	fs.StringVar(&f.profile, "profile", os.Getenv("AWS_PROFILE"), "AWS profile(s), comma-separated (default: AWS_PROFILE or the default chain)")
	fs.BoolVar(&f.allProfiles, "all-profiles", false, "scan every profile in ~/.aws/config")
	fs.StringVar(&f.regions, "regions", "", "comma-separated regions (default: all enabled regions)")
	fs.StringVar(&f.services, "services", "", "run only these checks (see `infralens checks`)")
	fs.StringVar(&f.skip, "skip", "", "skip these checks")
	fs.StringVar(&f.configPath, "config", "", "JSON file with threshold overrides")
	fs.StringVar(&f.htmlOut, "html", "report.html", "HTML report path (with several profiles: the profile name is added)")
	fs.StringVar(&f.jsonOut, "json", "", "also write the scan result as JSON (same naming rule)")
	fs.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` first")
	fs.IntVar(&f.concurrency, "concurrency", 4, "regions scanned in parallel")
	fs.BoolVar(&f.useAI, "ai", false, "send a MASKED inventory to Gemini for an extra audit (needs GEMINI_API_KEY)")
	fs.StringVar(&f.aiModel, "ai-model", os.Getenv("INFRALENS_GEMINI_MODEL"), "Gemini model (default "+ai.DefaultModel+")")
	fs.BoolVar(&f.yes, "yes", false, "do not ask for confirmation before sending data to the AI")
	fs.StringVar(&f.historyDir, "history-dir", "", "where scans are kept (default ~/.infralens)")
	fs.BoolVar(&f.noHistory, "no-history", false, "neither read nor write scan history")
	fs.StringVar(&f.prowler, "prowler-json", "", "Prowler JSON output file(s), comma-separated; failed checks become security findings")
	fs.StringVar(&f.tfstate, "tfstate", "", "Terraform state to read, comma-separated: a file, a directory or s3://bucket[/prefix]; state is read only when named")
	fs.BoolVar(&f.noAllocate, "no-allocate", false, "do not read usage types from Cost Explorer (saves a few $0.01 API requests; costs fall back to catalogue estimates)")
	fs.BoolVar(&f.noBlast, "no-blast", false, "skip dependency lookups (Route53, CloudFront, route tables, consumers) for waste candidates")
	fs.StringVar(&f.apiLog, "api-log", "", "write every AWS API call (JSON lines) to this file")
	fs.StringVar(&f.contextPath, "context", "", "JSON file with what you know and the scan cannot: planned migrations, intentionally idle resources")
	fs.StringVar(&f.baseline, "baseline", "", "compare with this saved scan instead of the latest one")
	fs.IntVar(&f.keep, "keep", 100, "scans kept per account (0 = all)")
	fs.Float64Var(&f.failOnWaste, "fail-on-waste", 0, "exit 3 if estimated monthly waste exceeds this amount (USD, 0 = off)")
	fs.Float64Var(&f.failOnNewWaste, "fail-on-new-waste", 0, "exit 3 if waste that appeared since the baseline exceeds this amount (USD, 0 = off)")
	return f
}

type outcome struct {
	profile string
	res     *engine.ScanResult
	err     error
	policy  []string
}

// runScanAll scans each profile in turn. One failing account does not stop
// the others, but it does make the exit code non-zero.
func runScanAll(ctx context.Context, f *scanFlags) int {
	profiles := splitCSV(f.profile)
	if f.allProfiles {
		all, err := awsDiscovery.ListProfiles()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot read AWS profiles:", err)
			return exitError
		}
		profiles = all
	}
	if len(profiles) == 0 {
		profiles = []string{""} // default credential chain
	}
	if f.baseline != "" && len(profiles) > 1 {
		fmt.Fprintln(os.Stderr, "error: --baseline names one file and cannot be used with several profiles")
		return exitUsage
	}

	var outs []outcome
	for _, p := range profiles {
		if ctx.Err() != nil {
			break
		}
		if len(profiles) > 1 {
			fmt.Fprintf(os.Stderr, "\n=== profile %s ===\n", p)
		}
		res, policy, err := scanProfile(ctx, f, p, len(profiles) > 1)
		outs = append(outs, outcome{p, res, err, policy})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error (%s): %v\n", p, err)
		}
	}

	if len(outs) > 1 {
		printPortfolio(outs)
	}
	code := exitOK
	for _, o := range outs {
		switch {
		case o.err != nil:
			code = exitError
		case len(o.policy) > 0 && code == exitOK:
			code = exitPolicy
		}
		for _, m := range o.policy {
			fmt.Fprintf(os.Stderr, "POLICY (%s): %s\n", o.profile, m)
		}
	}
	return code
}

func scanProfile(ctx context.Context, f *scanFlags, profile string, multi bool) (*engine.ScanResult, []string, error) {
	scanners, err := awsDiscovery.SelectScanners(splitCSV(f.services), splitCSV(f.skip))
	if err != nil {
		return nil, nil, err
	}
	th, err := awsDiscovery.LoadThresholds(f.configPath)
	if err != nil {
		return nil, nil, err
	}
	owner, err := engine.LoadContext(f.contextPath)
	if err != nil {
		return nil, nil, err
	}
	dc := awsDiscovery.NewDiscoveryClient(profile, f.concurrency)
	dc.Scanners, dc.Th = scanners, th
	if f.apiLog != "" {
		lf, err := os.OpenFile(f.apiLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("api log: %w", err)
		}
		defer lf.Close()
		dc.Log = awsDiscovery.NewAPILog(lf, profile)
	}
	if f.ssoLogin {
		if err := dc.RunSSOLogin(ctx); err != nil {
			return nil, nil, err
		}
	}

	account, err := dc.AccountID(ctx)
	if n := dc.CredentialNote(); n != "" {
		fmt.Fprintln(os.Stderr, "[i]", n)
	}
	if err != nil {
		hint := "check the credentials"
		if strings.Contains(err.Error(), "SSO") {
			cmd := "aws sso login"
			if profile != "" {
				cmd += " --profile " + profile
			}
			// The AWS CLI can keep working on cached role credentials after the
			// SSO token itself is gone; this tool refreshes the token itself.
			hint = "the SSO token has expired and cannot be refreshed; run `" + cmd + "` (the aws CLI may still answer from its own cache)"
		}
		return nil, nil, fmt.Errorf("cannot identify the account: %s: %w", hint, err)
	}

	regions := splitCSV(f.regions)
	if len(regions) == 0 {
		if regions, err = dc.GetActiveRegions(ctx); err != nil {
			return nil, nil, fmt.Errorf("cannot list regions (%w); pass --regions", err)
		}
	}

	names := make([]string, len(scanners))
	for i, sc := range scanners {
		names[i] = sc.Name
	}
	fmt.Fprintf(os.Stderr, "account %s: scanning %d region(s), checks: %s\n", account, len(regions), strings.Join(names, ","))
	f.say("account %s: scanning %d region(s) with %d checks", account, len(regions), len(names))
	start := time.Now()
	out := dc.ScanAll(ctx, regions)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	f.say("inventory done: %d resources, %d findings from AWS services", len(out.Nodes), len(out.Findings))
	warnings := append([]string(nil), out.Warnings...)
	if !f.noBlast {
		warnings = append(warnings, dc.EnrichBlast(ctx, out.Nodes)...)
	}
	costs, err := dc.GetServiceCosts(ctx)
	if err != nil {
		warnings = append(warnings, "cost-explorer: "+oneLine(err.Error()))
	}

	res := engine.ScanResult{
		Timestamp: time.Now().UTC(), Profile: profile, Account: account, Regions: regions,
		Nodes: out.Nodes, Edges: out.Edges, Commitments: out.Commitments, ServiceCosts: costs.Services, Warnings: warnings,
		Skipped:       out.Skipped,
		Findings:      out.Findings,
		TotalPrevCost: costs.PrevTotal, TotalCurrCost: costs.CurrTotal,
	}
	res.Checks = names
	res.IdleWindowDays = th.IdleWindowDays
	costMap := awsDiscovery.CostServiceMap(scanners)

	// Infrastructure as code: state files only when asked for (they are
	// sensitive), CloudFormation stacks whenever the check ran.
	var tf awsDiscovery.TerraformResult
	if specs := splitCSV(f.tfstate); len(specs) > 0 {
		tf = dc.LoadTerraformState(ctx, specs)
	}
	iacSources := append([]string(nil), tf.Sources...)
	if out.Stacks > 0 {
		iacSources = append(iacSources, fmt.Sprintf("cloudformation: %d stack(s) in %d region(s)", out.Stacks, len(regions)))
	}
	iacNotes := append([]string(nil), tf.Notes...)
	if len(splitCSV(f.tfstate)) == 0 {
		if hint := stateBucketHint(res.Nodes); hint != "" {
			iacNotes = append(iacNotes, hint)
		}
	}
	engine.JoinIaC(&res, append(append([]engine.IaCRef(nil), out.IaCRefs...), tf.Refs...), iacSources, tf.Files, out.Stacks, iacNotes)

	for _, pf := range splitCSV(f.prowler) {
		fh, err := os.Open(pf)
		if err != nil {
			res.Warnings = append(res.Warnings, "prowler: "+err.Error())
			continue
		}
		fs, perr := importer.ParseProwler(fh)
		fh.Close()
		if perr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("prowler: %s: %v", pf, perr))
			continue
		}
		res.Findings = append(res.Findings, fs...)
	}

	if !f.noAllocate {
		if lines, month, err := dc.GetUsageLines(ctx); err != nil {
			res.Warnings = append(res.Warnings, "cost-allocation: "+oneLine(err.Error()))
		} else {
			engine.Allocate(&res, lines)
			res.Ledger.Month = month
			res.Findings = append(res.Findings, engine.LedgerFindings(&res)...)
		}
	}
	engine.Finalize(&res, costMap)
	// The owner's notes are applied after detection and change only how a
	// finding is presented and counted. Totals are recomputed afterwards.
	res.Warnings = append(res.Warnings, owner.Apply(&res, time.Now())...)
	engine.Finalize(&res, costMap)
	res.Summary = report.LocalSummary(res)

	// Diff against the baseline before saving, so a scan is never compared with itself.
	base := f.historyDir
	if base == "" && !f.noHistory {
		if base, err = history.DefaultBase(); err != nil {
			res.Warnings = append(res.Warnings, "history disabled: "+err.Error())
			f.noHistory = true
		}
	}
	var baselineFile string
	var prev engine.ScanResult
	havePrev := false
	switch {
	case f.baseline != "":
		if prev, err = history.Read(f.baseline); err != nil {
			return nil, nil, fmt.Errorf("baseline: %w", err)
		}
		baselineFile, havePrev = f.baseline, true
	case !f.noHistory:
		p, r, err := history.Latest(base, res)
		switch {
		case err == nil:
			prev, baselineFile, havePrev = r, p, true
		case !errors.Is(err, history.ErrNone):
			res.Warnings = append(res.Warnings, "history: "+oneLine(err.Error()))
		}
	}
	if havePrev {
		d := engine.Compare(prev, res)
		d.BaselineFile = baselineFile
		res.Diff = &d
	}

	if f.useAI {
		if text, err := runAI(ctx, f, res); err != nil {
			res.Warnings = append(res.Warnings, "ai: "+oneLine(err.Error()))
		} else {
			res.AIAnalysis = text
		}
	}

	f.say("analysis done: %d findings, estimated waste %s/month", len(res.Findings), engine.Money(res.TotalWaste))
	calls, blocked := dc.Log.Counts()
	fmt.Fprintf(os.Stderr, "[i] %d read-only API calls, %d blocked\n", calls, blocked)
	report.PrintCLI(res)
	if f.htmlOut != "" {
		htmlPath := perProfile(f.htmlOut, profile, multi)
		if err := report.GenerateHTML(res, htmlPath); err != nil {
			return nil, nil, fmt.Errorf("write report: %w", err)
		}
		fmt.Printf("\n[+] report: %s (%s)\n", htmlPath, time.Since(start).Round(time.Second))
	} else {
		fmt.Printf("\n[+] scanned in %s\n", time.Since(start).Round(time.Second))
	}
	if f.jsonOut != "" {
		jp := perProfile(f.jsonOut, profile, multi)
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(jp, b, 0o600); err != nil {
			return nil, nil, fmt.Errorf("write json: %w", err)
		}
		fmt.Printf("[+] json:   %s\n", jp)
	}
	if !f.noHistory {
		if path, err := history.Save(base, res, f.keep); err != nil {
			fmt.Fprintln(os.Stderr, "warning: scan not saved to history:", err)
		} else {
			fmt.Printf("[+] saved:  %s\n", path)
			f.savedAs = path
			f.say("saved")
		}
	}

	return &res, evaluatePolicy(f, res), nil
}

// evaluatePolicy turns the --fail-on-* flags into violations.
func evaluatePolicy(f *scanFlags, res engine.ScanResult) []string {
	var v []string
	if f.failOnWaste > 0 && res.TotalWaste > f.failOnWaste {
		v = append(v, fmt.Sprintf("estimated waste $%.2f/month exceeds --fail-on-waste $%.2f", res.TotalWaste, f.failOnWaste))
	}
	if f.failOnNewWaste > 0 {
		switch {
		case res.Diff == nil:
			// No baseline means the first run: nothing is "new", so do not fail.
		case res.Diff.NewWasteCost > f.failOnNewWaste:
			v = append(v, fmt.Sprintf("new waste $%.2f/month since %s exceeds --fail-on-new-waste $%.2f",
				res.Diff.NewWasteCost, res.Diff.Baseline.Local().Format("2006-01-02"), f.failOnNewWaste))
		}
	}
	return v
}

func printPortfolio(outs []outcome) {
	fmt.Println("\n==================== PORTFOLIO ====================")
	fmt.Printf("%-22s %-14s %9s %9s %12s %12s\n", "profile", "account", "resources", "waste#", "waste $/mo", "est. $/mo")
	var tw, tc float64
	var tr, tn int
	sort.Slice(outs, func(i, j int) bool { return outs[i].profile < outs[j].profile })
	for _, o := range outs {
		if o.err != nil || o.res == nil {
			fmt.Printf("%-22s FAILED: %s\n", o.profile, truncate(oneLine(o.err.Error()), 60))
			continue
		}
		r := o.res
		fmt.Printf("%-22s %-14s %9d %9d %12.2f %12.2f\n", o.profile, r.Account, r.TotalLive, r.WasteCount, r.TotalWaste, r.EstimatedTCO)
		tr += r.TotalLive
		tn += r.WasteCount
		tw += r.TotalWaste
		tc += r.EstimatedTCO
	}
	fmt.Printf("%-22s %-14s %9d %9d %12.2f %12.2f\n", "TOTAL", "", tr, tn, tw, tc)
}

func runDiff(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: infralens diff OLD.json NEW.json")
		return exitUsage
	}
	a, err := history.Read(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	b, err := history.Read(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	if a.Account != "" && b.Account != "" && a.Account != b.Account {
		fmt.Fprintf(os.Stderr, "warning: scans are of different accounts (%s, %s)\n", a.Account, b.Account)
	}
	report.PrintDiff(engine.Compare(a, b))
	return exitOK
}

// runExplain prints the basis of a verdict for resources matching QUERY
// (exact id, or case-insensitive substring of name/id).
func runExplain(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: infralens explain SCAN.json QUERY")
		return exitUsage
	}
	res, err := history.Read(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	q := strings.ToLower(args[1])
	var hits []engine.ResourceNode
	for _, n := range res.Nodes {
		if n.ID == args[1] {
			hits = []engine.ResourceNode{n}
			break
		}
		if strings.Contains(strings.ToLower(n.Name), q) || strings.Contains(strings.ToLower(n.ID), q) {
			hits = append(hits, n)
		}
	}
	if len(hits) == 0 {
		fmt.Fprintf(os.Stderr, "nothing matches %q\n", args[1])
		return exitError
	}
	if len(hits) > 5 {
		fmt.Fprintf(os.Stderr, "%d matches, showing the first 5; refine the query\n", len(hits))
		hits = hits[:5]
	}
	for i, n := range hits {
		if i > 0 {
			fmt.Println(strings.Repeat("-", 60))
		}
		printExplain(n, res)
	}
	return exitOK
}

func printExplain(n engine.ResourceNode, res engine.ScanResult) {
	fmt.Printf("%s\n", n.Name)
	fmt.Printf("  id:        %s\n  type:      %s\n  region:    %s\n", n.ID, n.Type, n.Region)
	verdict := string(n.Status)
	if n.Confidence != "" {
		verdict += " (" + string(n.Confidence) + " confidence)"
	}
	fmt.Printf("  verdict:   %s\n", verdict)
	if n.WasteReason != "" {
		fmt.Printf("  reason:    %s\n", n.WasteReason)
	}
	src := n.CostSource
	if src == "" {
		src = "n/a"
	}
	fmt.Printf("  cost:      $%.2f/month (%s)\n", n.MonthlyCost, src)
	if len(n.Evidence) > 0 {
		fmt.Println("  evidence:")
		for _, e := range n.Evidence {
			fmt.Println("    -", e)
		}
	}
	if cs := awsDiscovery.Caveats(n.Type); len(cs) > 0 {
		fmt.Println("  what this check cannot see:")
		for _, c := range cs {
			fmt.Println("    -", c)
		}
	}
	var rel []string
	for _, e := range res.Edges {
		if e.Source == n.ID {
			rel = append(rel, fmt.Sprintf("%s -> %s", e.Label, e.Target))
		} else if e.Target == n.ID {
			rel = append(rel, fmt.Sprintf("%s <- %s", e.Label, e.Source))
		}
	}
	if len(rel) > 0 {
		fmt.Printf("  connections (%d):\n", len(rel))
		for i, r := range rel {
			if i == 6 {
				fmt.Printf("    ... and %d more\n", len(rel)-6)
				break
			}
			fmt.Println("    -", r)
		}
	}
	if len(res.Warnings) > 0 {
		fmt.Printf("  note: this scan had %d warning(s); checks that failed are not reflected above\n", len(res.Warnings))
	}
}

// runReport re-renders the HTML from a saved scan; no AWS access needed.
// With --context the owner's notes are applied first, so findings can be
// acknowledged and the report regenerated without scanning again.
func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	ctxPath := fs.String("context", "", "JSON file with owner notes (see `scan --context`)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return exitUsage
	}
	pos := fs.Args()
	if len(pos) < 1 || len(pos) > 2 {
		fmt.Fprintln(os.Stderr, "usage: infralens report [--context FILE] SCAN.json [OUT.html]")
		return exitUsage
	}
	res, err := history.Read(pos[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	owner, err := engine.LoadContext(*ctxPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	// Derived findings, owners and cross-checks are recomputed so that an old
	// scan benefits from newer rules without scanning again.
	engine.Finalize(&res, res.TypeServices)
	reapplyContext(&res, owner)
	out := "report.html"
	if len(pos) == 2 {
		out = pos[1]
	}
	if err := report.GenerateHTML(res, out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	fmt.Println("[+] report:", out)
	return exitOK
}

// runDemo writes a complete example from invented data: scan, report, audit
// document, findings and a cleanup pack. It touches no AWS account.
func runDemo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	out := fs.String("out", "demo", "output directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	now := time.Now()
	res := demo.Scan(now)
	res.Summary = report.LocalSummary(res)
	write := func(name string, b []byte) bool {
		p := filepath.Join(*out, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return false
		}
		fmt.Println("[+]", p)
		return true
	}
	js, _ := json.MarshalIndent(res, "", "  ")
	if !write("scan.json", js) {
		return exitError
	}
	html, err := report.RenderHTML(res)
	if err != nil || !write("report.html", []byte(html)) {
		return exitError
	}
	opts := report.AuditOptions{Client: "Northwind Retail (example)", Consultant: "Example Consulting", Version: version, Now: now}
	doc, err := report.RenderAudit(res, opts)
	if err != nil || !write("audit.html", []byte(doc)) {
		return exitError
	}
	csvb, err := report.FindingsCSV(res, opts)
	if err != nil || !write("findings.csv", csvb) {
		return exitError
	}
	for _, f := range cleanup.Generate(res, cleanup.Options{Now: now}) {
		dir := filepath.Join(*out, "cleanup")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		if err := os.WriteFile(filepath.Join(dir, f.Name), []byte(f.Content), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
	}
	fmt.Println("[+]", filepath.Join(*out, "cleanup/"))
	fmt.Println("[i] all data in this example is invented")
	return exitOK
}

// runCleanup writes the cleanup pack. It only writes text files.
func runCleanup(args []string) int {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	out := fs.String("out", "cleanup", "output directory")
	minConf := fs.String("min-confidence", "medium", "lowest confidence to include: high | medium | low")
	ctxPath := fs.String("context", "", "owner notes; acknowledged candidates are skipped")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: infralens cleanup [--out DIR] [--min-confidence medium] [--context FILE] SCAN.json")
		return exitUsage
	}
	switch *minConf {
	case "high", "medium", "low":
	default:
		fmt.Fprintln(os.Stderr, "error: --min-confidence must be high, medium or low")
		return exitUsage
	}
	res, err := history.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	owner, err := engine.LoadContext(*ctxPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	reapplyContext(&res, owner)
	if err := os.MkdirAll(*out, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	files := cleanup.Generate(res, cleanup.Options{MinConfidence: engine.Confidence(*minConf), Now: time.Now()})
	n := 0
	for _, f := range files {
		// 0600, not executable: a script is read first and run deliberately with `bash file`.
		if err := os.WriteFile(filepath.Join(*out, f.Name), []byte(f.Content), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		if strings.HasSuffix(f.Name, ".sh") {
			n++
		}
	}
	fmt.Printf("[+] %d script(s) and README.md in %s\n", n, *out)
	fmt.Println("[i] nothing has been run; each script is a dry run until you set DRY_RUN=0")
	return exitOK
}

// runProgress compares two scans of the same account.
func runProgress(args []string) int {
	fs := flag.NewFlagSet("progress", flag.ContinueOnError)
	client := fs.String("client", "", "client name for the document")
	consultant := fs.String("consultant", "", "who prepared it")
	out := fs.String("out", "progress.html", "output file")
	anon := fs.Bool("anonymize", false, "replace names and IDs with aliases")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: infralens progress [--client NAME] [--out FILE] OLD.json NEW.json")
		return exitUsage
	}
	old, err := history.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	cur, err := history.Read(fs.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	if !cur.Timestamp.After(old.Timestamp) {
		fmt.Fprintln(os.Stderr, "warning: the second scan is not newer than the first; check the argument order")
	}
	html, err := report.RenderProgress(old, cur, report.ProgressOptions{
		Client: *client, Consultant: *consultant, Anonymize: *anon, Version: version, Now: time.Now(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	if err := os.WriteFile(*out, []byte(html), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	p := report.CompareProgress(old, cur)
	fmt.Printf("resolved: %d (est. $%.2f/month) · still open: %d ($%.2f) · new: %d ($%.2f)\n",
		len(p.Resolved), p.ResolvedCost, len(p.Open), p.OpenCost, len(p.New), p.NewCost)
	fmt.Println("[+]", *out)
	return exitOK
}

var stateBucketName = regexp.MustCompile(`(?i)(tfstate|terraform[-_]?state|tf[-_]?state|terraform)`)

// stateBucketHint says, without reading anything, that a bucket looks like
// Terraform state, so the user can decide to point the tool at it.
func stateBucketHint(nodes []engine.ResourceNode) string {
	var names []string
	for _, n := range nodes {
		if n.Type == "aws_s3_bucket" && stateBucketName.MatchString(n.Name) {
			names = append(names, n.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return fmt.Sprintf("bucket %s looks like Terraform state; IaC coverage is unverified until it is read: --tfstate s3://%s", names[0], names[0])
}

// runPolicy prints the minimal IAM policy. Output is JSON on stdout so it can
// be piped straight into `aws iam create-policy`.
func runPolicy(args []string) int {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	services := fs.String("services", "", "limit to these checks")
	skip := fs.String("skip", "", "leave out these checks")
	noBlast := fs.Bool("no-blast", false, "leave out dependency lookups (Route53, CloudFront, route tables)")
	withWatch := fs.Bool("watch", false, "also include what the live Problem Monitor needs")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	sel, err := awsDiscovery.SelectScanners(splitCSV(*services), splitCSV(*skip))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}
	acts, err := awsDiscovery.Policy(sel, !*noBlast)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	if *withWatch {
		seen := map[string]bool{}
		for _, a := range acts {
			seen[a] = true
		}
		for _, a := range awsDiscovery.WatchActions {
			if !seen[a] {
				acts = append(acts, a)
			}
		}
		sort.Strings(acts)
	}
	doc, err := awsDiscovery.PolicyDocument(acts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	fmt.Println(string(doc))
	fmt.Fprintf(os.Stderr, "[i] %d read-only actions (Describe*/List*/Get* only). No write permission is requested.\n", len(acts))
	return exitOK
}

// runDoctor probes access per check, in one region, and says what will be missing.
func runDoctor(ctx context.Context, f *scanFlags) int {
	scanners, err := awsDiscovery.SelectScanners(splitCSV(f.services), splitCSV(f.skip))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}
	region := "eu-north-1"
	if r := splitCSV(f.regions); len(r) > 0 {
		region = r[0]
	}
	dc := awsDiscovery.NewDiscoveryClient(f.profile, f.concurrency)
	dc.Scanners = scanners
	results := dc.Doctor(ctx, region)
	for _, r := range results {
		mark := "ok  "
		if !r.OK {
			mark = "FAIL"
		}
		fmt.Printf("%s  %-14s %s\n", mark, r.Name, r.Scope)
		for _, p := range r.Problems {
			fmt.Printf("        %s\n", p)
		}
	}
	ok, failed, _ := awsDiscovery.DoctorSummary(results)
	fmt.Printf("\n%d ok, %d with problems (probed in %s; regional checks behave the same elsewhere unless a policy is region-scoped).\n", ok, failed, region)
	if failed > 0 {
		fmt.Println("A failing check will appear as a warning and its findings will be missing from the report.")
		return exitPolicy
	}
	return exitOK
}

// runAudit scans (or loads a saved scan) and writes the audit pack:
// audit.html (the document), findings.csv, and unless --anonymize the
// interactive report.html and scan.json. Files are private to the user.
func runAudit(ctx context.Context, f *scanFlags) int {
	if f.client == "" {
		fmt.Fprintln(os.Stderr, "error: --client is required (it is printed on the document)")
		return exitUsage
	}
	logo := ""
	if f.logoPath != "" {
		b, err := os.ReadFile(f.logoPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		if logo, err = report.LogoFromBytes(b); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitUsage
		}
	}
	if err := os.MkdirAll(f.outDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}

	var res engine.ScanResult
	if f.fromPath != "" {
		r, err := history.Read(f.fromPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		owner, err := engine.LoadContext(f.contextPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		reapplyContext(&r, owner)
		res = r
	} else {
		profiles := splitCSV(f.profile)
		if len(profiles) > 1 || f.allProfiles {
			fmt.Fprintln(os.Stderr, "error: audit covers one account; run it once per profile with its own --out")
			return exitUsage
		}
		profile := ""
		if len(profiles) == 1 {
			profile = profiles[0]
		}
		if f.anonymize {
			f.htmlOut, f.jsonOut = "", "" // raw artefacts stay out of a shareable directory
		} else {
			f.htmlOut = filepath.Join(f.outDir, "report.html")
			f.jsonOut = filepath.Join(f.outDir, "scan.json")
		}
		r, policy, err := scanProfile(ctx, f, profile, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		for _, m := range policy {
			fmt.Fprintf(os.Stderr, "POLICY: %s\n", m)
		}
		res = *r
	}

	opts := report.AuditOptions{
		Client: f.client, Consultant: f.consultant, Anonymize: f.anonymize,
		LogoDataURI: logo, Version: version, Now: time.Now(),
	}
	if f.withAI {
		if r, err := aiReading(ctx, res, f.yes, os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "warning: no AI reading:", err)
		} else {
			opts.AI = r
		}
	}
	doc, err := report.RenderAudit(res, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	csvb, err := report.FindingsCSV(res, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	write := func(name string, b []byte) bool {
		p := filepath.Join(f.outDir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return false
		}
		fmt.Println("[+]", p)
		return true
	}
	if !write("audit.html", []byte(doc)) || !write("findings.csv", csvb) {
		return exitError
	}
	if f.fromPath != "" && !f.anonymize {
		if h, err := report.RenderHTML(res); err == nil {
			write("report.html", []byte(h))
		}
	}
	if f.anonymize {
		fmt.Println("[i] identifiers are anonymised; raw data stays in your scan history, not in this directory")
	}
	return exitOK
}

// reapplyContext puts the owner's notes onto a saved scan. Notes from an
// earlier run must not linger, so it starts from the raw findings.
func reapplyContext(res *engine.ScanResult, owner engine.Context) {
	if len(owner.Notes) == 0 {
		return
	}
	for i := range res.Nodes {
		res.Nodes[i].Ack = nil
	}
	for i := range res.Commitments {
		res.Commitments[i].Ack = nil
	}
	for _, w := range owner.Apply(res, time.Now()) {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	engine.Finalize(res, res.TypeServices)
	res.Summary = report.LocalSummary(*res)
}

// reorderFlags moves flags in front of positional arguments so that
// `report scan.json out.html --context c.json` works like the flags-first form.
func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

// perProfile inserts the profile name before the extension when several
// profiles share one output flag.
func perProfile(path, profile string, multi bool) string {
	if !multi || profile == "" {
		return path
	}
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + "-" + profile + ext
}

// runAI sends a masked payload after the user has seen what leaves the machine.
func runAI(ctx context.Context, f *scanFlags, res engine.ScanResult) (string, error) {
	cli, err := ai.NewClient(f.aiModel)
	if err != nil {
		return "", err
	}
	m := ai.NewMasker()
	prompt, err := ai.Prompt(m.Mask(res))
	if err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "\nAI audit: %d bytes will be sent to Gemini (%s).\n", len(prompt), cli.Model)
	fmt.Fprintln(os.Stderr, "Identifiers are replaced by aliases; names, tags, ARNs, IPs and account IDs are not sent. Sample:")
	for i, line := range strings.Split(prompt[strings.Index(prompt, "{"):], "\n") {
		if i == 12 {
			fmt.Fprintln(os.Stderr, "  ...")
			break
		}
		fmt.Fprintln(os.Stderr, "  "+line)
	}
	if !f.yes && !confirm("Send? [y/N] ") {
		return "", fmt.Errorf("not sent (declined or non-interactive without --yes)")
	}
	text, err := cli.Analyze(ctx, prompt)
	if err != nil {
		return "", err
	}
	return m.Unmask(text), nil
}

func confirm(q string) bool {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fmt.Fprint(os.Stderr, q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---- language model ---------------------------------------------------------

func openStore(dir string) (*settings.Store, error) {
	if dir == "" {
		d, err := settings.DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	return settings.NewStore(dir), nil
}

func runLLM(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: infralens llm show | set [flags] | test")
		return exitUsage
	}
	fs := flag.NewFlagSet("llm "+args[0], flag.ContinueOnError)
	dir := fs.String("settings-dir", "", "settings directory (default ~/.infralens)")
	provider := fs.String("provider", "", "gemini | openai | anthropic | ollama | openai-compatible | bedrock")
	model := fs.String("model", "", "model name (a default is used when empty)")
	baseURL := fs.String("base-url", "", "endpoint for ollama or an OpenAI-compatible server")
	keyEnv := fs.String("key-env", "", "name of an environment variable that holds the API key")
	keyName := fs.String("key-name", "", "store a key under this name; the key is read from standard input, never from a flag")
	profile := fs.String("profile", "", "AWS profile (bedrock)")
	region := fs.String("region", "", "AWS region (bedrock)")
	language := fs.String("language", "", "language of the generated text, e.g. English or Russian")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	store, err := openStore(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	st, err := store.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	switch args[0] {
	case "show":
		l := st.LLM
		if l.Provider == "" {
			fmt.Println("no language model is configured; use: infralens llm set --provider ...")
			return exitOK
		}
		fmt.Printf("provider : %s\nmodel    : %s\nendpoint : %s\nlanguage : %s\n", l.Provider, firstNonEmpty(l.Model, "(default)"), firstNonEmpty(l.BaseURL, "(default)"), firstNonEmpty(l.Language, "English"))
		ref := firstNonEmpty(l.KeyRef, "(none)")
		state := ""
		if strings.HasPrefix(l.KeyRef, "secret:") {
			state = " (stored)"
			if !store.HasSecret(strings.TrimPrefix(l.KeyRef, "secret:")) {
				state = " (NOT stored)"
			}
		} else if strings.HasPrefix(l.KeyRef, "env:") {
			state = " (set)"
			if os.Getenv(strings.TrimPrefix(l.KeyRef, "env:")) == "" {
				state = " (NOT set in this shell)"
			}
		}
		fmt.Printf("key      : %s%s\n", ref, state)
		return exitOK
	case "set":
		l := st.LLM
		if *provider != "" {
			l.Provider = *provider
		}
		if *model != "" {
			l.Model = *model
		}
		if *baseURL != "" {
			l.BaseURL = *baseURL
		}
		if *profile != "" {
			l.Profile = *profile
		}
		if *region != "" {
			l.Region = *region
		}
		if *language != "" {
			l.Language = *language
		}
		switch {
		case *keyEnv != "":
			l.KeyRef = "env:" + *keyEnv
		case *keyName != "":
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			key := strings.TrimSpace(line)
			if key == "" {
				fmt.Fprintln(os.Stderr, "error: no key on standard input")
				return exitUsage
			}
			if err := store.SetSecret(*keyName, key); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return exitError
			}
			l.KeyRef = "secret:" + *keyName
		}
		st.LLM = l
		if err := store.Save(st); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		fmt.Println("[+] saved")
		return exitOK
	case "test":
		p, err := llm.New(st.LLM, store, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		out, err := p.Complete(ctx, "Reply with the single word: ok", "ping")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		where := "remote"
		if p.Local() {
			where = "local"
		}
		fmt.Printf("%s (%s) answered: %s\n", p.Name(), where, truncate(oneLine(out), 60))
		return exitOK
	}
	fmt.Fprintln(os.Stderr, "usage: infralens llm show | set [flags] | test")
	return exitUsage
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// consent shows what is about to leave the machine and asks. A model running
// on this machine needs none; --yes skips the question, not the display.
func consent(p llm.Provider, system, user string, yes bool, in io.Reader) bool {
	size := len(system) + len(user)
	if p.Local() {
		fmt.Fprintf(os.Stderr, "[i] %s runs on this machine; %d bytes of facts are given to it\n", p.Name(), size)
		return true
	}
	fmt.Fprintf(os.Stderr, "\nAbout to send %d bytes to %s.\nIt is findings and totals with names, account numbers and ARNs removed. Sample of the facts:\n", size, p.Name())
	lines := strings.Split(user, "\n")
	for i, l := range lines {
		if i == 14 {
			fmt.Fprintln(os.Stderr, "  ...")
			break
		}
		fmt.Fprintln(os.Stderr, "  "+truncate(l, 140))
	}
	if yes {
		return true
	}
	st, err := os.Stdin.Stat()
	if f, ok := in.(*os.File); ok && f == os.Stdin && (err != nil || st.Mode()&os.ModeCharDevice == 0) {
		fmt.Fprintln(os.Stderr, "not sent: not interactive and --yes was not given")
		return false
	}
	fmt.Fprint(os.Stderr, "Send? [y/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

// aiReading produces a validated narrative for the audit document.
func aiReading(ctx context.Context, res engine.ScanResult, yes bool, in io.Reader) (*report.AIReading, error) {
	store, err := openStore("")
	if err != nil {
		return nil, err
	}
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	p, err := llm.New(st.LLM, store, nil)
	if err != nil {
		return nil, err
	}
	facts := llm.BuildFacts(res, 60)
	sys, usr := llm.NarrativePrompt(facts, st.LLM.Language)
	if !consent(p, sys, usr, yes, in) {
		return nil, fmt.Errorf("declined")
	}
	n, ck, err := llm.GenerateNarrative(ctx, p, facts, st.LLM.Language)
	if err != nil {
		return nil, err
	}
	for _, note := range ck.Notes {
		fmt.Fprintln(os.Stderr, "[ai]", note)
	}
	return &report.AIReading{Model: p.Name(), Narrative: n, DroppedAny: ck.DroppedSentences + ck.DroppedIDs}, nil
}

// runAICmd prints a validated reading of a saved scan, or answers a question.
func runAICmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("ai", flag.ContinueOnError)
	dir := fs.String("settings-dir", "", "settings directory")
	question := fs.String("q", "", "ask a question about the scan instead of asking for a reading")
	yes := fs.Bool("yes", false, "send without asking")
	asJSON := fs.Bool("json", false, "print the validated result as JSON")
	ctxPath := fs.String("context", "", "owner notes to apply first")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: infralens ai [--q QUESTION] [--yes] [--json] SCAN.json")
		return exitUsage
	}
	res, err := history.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	owner, err := engine.LoadContext(*ctxPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	engine.Finalize(&res, res.TypeServices)
	reapplyContext(&res, owner)
	store, err := openStore(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	st, err := store.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	p, err := llm.New(st.LLM, store, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	facts := llm.BuildFacts(res, 60)
	titles := map[string]string{}
	for _, f := range res.Findings {
		titles[f.ID] = f.Title
	}
	if *question != "" {
		sys, usr := llm.AskPrompt(facts, *question, st.LLM.Language)
		if !consent(p, sys, usr, *yes, os.Stdin) {
			return exitError
		}
		a, ck, err := llm.Ask(ctx, p, facts, *question, st.LLM.Language)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitError
		}
		if *asJSON {
			b, _ := json.MarshalIndent(map[string]any{"answer": a, "checked": ck}, "", "  ")
			fmt.Println(string(b))
			return exitOK
		}
		fmt.Println(a.Answer)
		for _, id := range a.FindingIDs {
			fmt.Printf("  - %s: %s\n", id, titles[id])
		}
		if ck.DroppedSentences+ck.DroppedIDs > 0 {
			fmt.Fprintf(os.Stderr, "[ai] %d statement(s) removed during validation\n", ck.DroppedSentences+ck.DroppedIDs)
		}
		return exitOK
	}
	sys, usr := llm.NarrativePrompt(facts, st.LLM.Language)
	if !consent(p, sys, usr, *yes, os.Stdin) {
		return exitError
	}
	n, ck, err := llm.GenerateNarrative(ctx, p, facts, st.LLM.Language)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"narrative": n, "checked": ck, "model": p.Name()}, "", "  ")
		fmt.Println(string(b))
		return exitOK
	}
	fmt.Println(n.Headline)
	fmt.Println()
	for _, para := range n.Paragraphs {
		fmt.Println(para)
		fmt.Println()
	}
	for i, a := range n.Actions {
		fmt.Printf("%d. %s\n   %s\n", i+1, titles[a.FindingID], a.Why)
	}
	fmt.Fprintf(os.Stderr, "\n[ai] written by %s; %d statement(s) removed during validation\n", p.Name(), ck.DroppedSentences+ck.DroppedIDs)
	return exitOK
}
