package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"infralens/internal/engine"
)

//go:embed template.html
var htmlTemplate string

//go:embed assets/cytoscape.min.js
var cytoscapeJS string

//go:embed assets/app.js
var appJS string

//go:embed assets/style.css
var styleCSS string

// RenderHTML produces a single self-contained page. The data is injected
// as JSON; json.Marshal escapes <, > and & so it cannot close the script tag.
func RenderHTML(res engine.ScanResult) (string, error) {
	data, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	// The audit document travels inside the page so an offline file can still
	// produce it. A failure only removes the button's content.
	auditJSON := []byte(`""`)
	if doc, err := RenderAudit(res, AuditOptions{}); err == nil {
		if b, err := json.Marshal(doc); err == nil {
			auditJSON = b
		}
	}
	// NewReplacer does one pass, so substituted text is never rescanned.
	r := strings.NewReplacer(
		"__STYLE__", styleCSS,
		"__CYTOSCAPE__", cytoscapeJS,
		"__APP__", appJS,
		"__INFRALENS_DATA__", string(data),
		"__AUDIT__", string(auditJSON),
	)
	return r.Replace(htmlTemplate), nil
}

func GenerateHTML(res engine.ScanResult, outputPath string) error {
	html, err := RenderHTML(res)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, []byte(html), 0o644)
}

func PrintCLI(res engine.ScanResult) {
	fmt.Println("\n==================================================")
	fmt.Println("                 INFRALENS REPORT                 ")
	fmt.Println("==================================================")
	fmt.Printf("AWS Profile               : %s\n", res.Profile)
	fmt.Printf("Scanned Regions           : %d\n", len(res.Regions))
	fmt.Printf("Resources Found           : %d\n", res.TotalLive)
	fmt.Printf("No IaC marker (Shadow IT) : %d\n", res.ShadowCount)
	fmt.Printf("Waste Candidates          : %d (need owner confirmation)\n", res.WasteCount)
	fmt.Printf("Candidate Waste (est.)    : $%.2f/month\n", res.TotalWaste)
	if res.AckedCount > 0 {
		fmt.Printf("Acknowledged (not counted): %d, $%.2f/month\n", res.AckedCount, res.AckedWaste)
	}
	fmt.Printf("Estimated Monthly Cost    : $%.2f (list prices)\n", res.EstimatedTCO)
	if res.TotalCurrCost > 0 || res.TotalPrevCost > 0 {
		fmt.Printf("Cost Explorer             : $%.2f prev month, $%.2f this month\n", res.TotalPrevCost, res.TotalCurrCost)
	}
	fmt.Println("--------------------------------------------------")

	waste := []engine.ResourceNode{}
	for _, n := range res.Nodes {
		if n.Status == engine.StatusOrphanWaste {
			waste = append(waste, n)
		}
	}
	sort.Slice(waste, func(i, j int) bool { return waste[i].MonthlyCost > waste[j].MonthlyCost })
	if len(waste) > 0 {
		fmt.Println("Top waste:")
	}
	for i, n := range waste {
		if i == 5 {
			fmt.Printf("  ... and %d more (see report)\n", len(waste)-5)
			break
		}
		fmt.Printf("  $%7.2f  %-18s %s (%s) [%s]\n", n.MonthlyCost, n.Type, n.Name, n.Region, n.Confidence)
	}
	printCommitments(res.Commitments)
	if res.Diff != nil {
		PrintDiff(*res.Diff)
	}
	if len(res.Warnings) > 0 {
		fmt.Printf("\n%d warning(s), results may be incomplete:\n", len(res.Warnings))
		for i, w := range res.Warnings {
			if i == 5 {
				fmt.Printf("  ... and %d more (see report)\n", len(res.Warnings)-5)
				break
			}
			fmt.Println("  -", w)
		}
	}
}

// PrintDiff writes a compact change list.
func PrintDiff(d engine.Diff) {
	fmt.Printf("\nChanges since %s:\n", d.Baseline.Local().Format("2006-01-02 15:04"))
	if d.Empty() {
		fmt.Println("  no material changes")
	}
	list := func(title string, cs []engine.Change, limit int, line func(engine.Change) string) {
		if len(cs) == 0 {
			return
		}
		fmt.Printf("  %s (%d):\n", title, len(cs))
		for i, c := range cs {
			if i == limit {
				fmt.Printf("    ... and %d more\n", len(cs)-limit)
				break
			}
			fmt.Println("    " + line(c))
		}
	}
	list("new", d.Added, 8, func(c engine.Change) string {
		return fmt.Sprintf("+ $%7.2f  %-20s %s (%s)", c.CostTo, c.Type, c.Name, c.Region)
	})
	list("gone", d.Removed, 8, func(c engine.Change) string {
		return fmt.Sprintf("- $%7.2f  %-20s %s (%s)", c.CostFrom, c.Type, c.Name, c.Region)
	})
	list("changed", d.Changed, 8, func(c engine.Change) string {
		if c.Kind == engine.ChangeStatus {
			return fmt.Sprintf("~ %-20s %s: %s -> %s", c.Type, c.Name, c.From, c.To)
		}
		return fmt.Sprintf("~ %-20s %s: $%.2f -> $%.2f", c.Type, c.Name, c.CostFrom, c.CostTo)
	})
	fmt.Printf("  est. cost delta: %+.2f/month, waste delta: %+.2f/month, new waste: $%.2f/month\n",
		d.DeltaCost, d.DeltaWaste, d.NewWasteCost)
	for _, n := range d.Notes {
		fmt.Println("  note:", n)
	}
}

// printCommitments shows only what needs a human decision; the full list is
// in the report. Suggestions are printed as questions tied to plans.
func printCommitments(cs []engine.Commitment) {
	var asks []engine.Commitment
	for _, c := range cs {
		if len(c.Suggestions) > 0 && c.Ack == nil {
			asks = append(asks, c)
		}
	}
	if len(asks) == 0 {
		return
	}
	fmt.Printf("\nDecisions that depend on your plans (%d):\n", len(asks))
	for _, c := range asks {
		label := c.Service
		if c.Kind != "coverage" {
			label += " · " + c.Detail
		}
		fmt.Printf("  - %s\n", label)
		for _, f := range c.Facts {
			fmt.Printf("      %s\n", f)
		}
	}
	fmt.Println("  Record a plan with --context so these stop prompting; see README.")
}
