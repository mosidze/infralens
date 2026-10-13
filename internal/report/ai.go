package report

import (
	"bytes"
	"html/template"
	"time"

	"infralens/internal/engine"
	"infralens/internal/llm"
)

// AIReport is a stand-alone document of the model's reading of one scan, with
// an optional question and answer. It is separate from the audit so it can be
// produced, reviewed and discarded on its own.
type AIReport struct {
	Model     string
	Question  string
	Answer    *llm.Answer
	Narrative *llm.Narrative
	Removed   int
	Account   string
	Taken     time.Time
	Made      time.Time
}

type aiRef struct {
	Title, Severity, Pillar, Why string
}

var aiTmpl = template.Must(template.New("ai").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI analysis</title>
<style>
:root{--bg:#fff;--fg:#1c2330;--mut:#667085;--line:#d9dee7;--warn:#fff7e0;--warnb:#e5c36b}
@media (prefers-color-scheme:dark){:root{--bg:#10141c;--fg:#e6e9ef;--mut:#98a2b3;--line:#2a3140;--warn:#2b2410;--warnb:#7a6420}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:32px 20px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin-top:28px}
.mut{color:var(--mut);font-size:14px}
.caveat{background:var(--warn);border:1px solid var(--warnb);border-radius:8px;padding:12px 14px;margin:18px 0;font-size:14px}
.q{border-left:3px solid var(--line);padding-left:12px;color:var(--mut)}
ol{padding-left:20px}li{margin:10px 0}
.sev{display:inline-block;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border:1px solid var(--line);border-radius:4px;padding:0 6px;margin-right:6px}
@media print{main{max-width:none}}
</style></head><body><main>
<h1>AI analysis</h1>
<div class="mut">Account {{.Account}} · scan of {{.Taken.Format "2006-01-02 15:04"}} UTC · written {{.Made.Format "2006-01-02 15:04"}} UTC</div>
<div class="caveat"><b>Written by a language model ({{.Model}}), not by an auditor.</b>
It was given only findings and totals with names removed. Amounts and finding references were checked against the scan{{if .Removed}}; {{.Removed}} statement(s) that did not check out were removed{{end}}.
It cannot know your plans. Treat it as a reading aid: the findings in the audit are the record.</div>
{{if .Question}}<h2>Question</h2><p class="q">{{.Question}}</p>{{end}}
{{if .Answer}}<h2>Answer</h2><p>{{.Answer.Answer}}</p>
{{if .Refs}}<h2>Findings it refers to</h2><ul>{{range .Refs}}<li><span class="sev">{{.Severity}}</span>{{.Title}} <span class="mut">· {{.Pillar}}</span></li>{{end}}</ul>{{end}}{{end}}
{{if .Narrative}}
{{if .Narrative.Headline}}<h2>Reading</h2><p><b>{{.Narrative.Headline}}</b></p>{{end}}
{{range .Narrative.Paragraphs}}<p>{{.}}</p>{{end}}
{{if .Refs}}<h2>Suggested order of attention</h2><ol>{{range .Refs}}<li><span class="sev">{{.Severity}}</span><b>{{.Title}}</b> <span class="mut">{{.Why}}</span></li>{{end}}</ol>{{end}}
{{end}}
</main></body></html>`))

// RenderAIReport builds the document. Finding ids are resolved against the
// scan so a reader sees titles, not opaque ids.
func RenderAIReport(res engine.ScanResult, r AIReport) (string, error) {
	byID := map[string]engine.Finding{}
	for _, f := range res.Findings {
		byID[f.ID] = f
	}
	var refs []aiRef
	if r.Narrative != nil {
		for _, a := range r.Narrative.Actions {
			if f, ok := byID[a.FindingID]; ok {
				refs = append(refs, aiRef{f.Title, string(f.Severity), string(f.Pillar), a.Why})
			}
		}
	}
	if r.Answer != nil {
		for _, id := range r.Answer.FindingIDs {
			if f, ok := byID[id]; ok {
				refs = append(refs, aiRef{f.Title, string(f.Severity), string(f.Pillar), ""})
			}
		}
	}
	if r.Made.IsZero() {
		r.Made = time.Now()
	}
	data := struct {
		AIReport
		Refs []aiRef
	}{r, refs}
	var b bytes.Buffer
	if err := aiTmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
