package report

import (
	"strings"
	"testing"

	"infralens/internal/engine"
)

func TestRenderHTMLIsInertAndSelfContained(t *testing.T) {
	res := engine.ScanResult{
		Profile: "p",
		Nodes: []engine.ResourceNode{{
			ID: "i-1", Name: `</script><script>alert(1)</script>`, Type: "aws_instance",
			Tags: map[string]string{"x": `"><img src=x onerror=alert(1)>`},
		}},
		AIAnalysis: "</script><b>",
	}
	html, err := RenderHTML(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "__INFRALENS_DATA__") || strings.Contains(html, "__CYTOSCAPE__") {
		t.Fatal("placeholder left in output")
	}
	if strings.Contains(html, "<script>alert(1)") {
		t.Fatal("data broke out of the script tag")
	}
	// template has four script blocks: cytoscape, data, app, embedded audit. Anything more
	// would mean the injected data (or an asset) closed a tag early.
	if got := strings.Count(html, "</script>"); got != 4 {
		t.Fatalf("expected exactly the four script closers of the template, got %d", got)
	}
	if strings.Contains(html, "https://cdnjs") || strings.Contains(html, `src="http`) {
		t.Fatal("report must not load anything from the network")
	}
}

func TestLocalSummary(t *testing.T) {
	res := engine.ScanResult{
		Regions: []string{"eu-west-1"},
		Nodes: []engine.ResourceNode{
			{ID: "vol-1", Name: "v", Type: "aws_ebs_volume", Status: engine.StatusOrphanWaste, MonthlyCost: 8,
				WasteReason: "Unattached EBS volume", Confidence: engine.ConfHigh},
			{ID: "i-1", Type: "aws_instance", Status: engine.StatusShadowIT},
		},
	}
	engine.Finalize(&res, nil)
	s := LocalSummary(res)
	for _, want := range []string{"$8.00", "Unattached EBS volume", "snapshot each unattached volume", "Shadow IT"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
}
