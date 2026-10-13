package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const systemPrompt = `You help a consultant write a cloud infrastructure audit. You are given FACTS as JSON: findings and totals that a program has already computed and checked.

Rules, all of them binding:
1. Use only the facts. Never invent a finding, a number, a service, a resource, a person or a cause.
2. Any amount of money you write must be copied exactly from the facts. Do not add, subtract, convert or estimate amounts. If you are unsure, leave the amount out.
3. Refer to a finding by its "id". Every statement about a specific finding must carry its id in "finding_ids".
4. You cannot know the owner's plans (a migration, a shutdown, a resize). Never say a purchase or a deletion is right or wrong; give the condition under which it would be.
5. Do not repeat resource names; they were removed on purpose. Do not ask for them.
6. Write plainly, for a technical manager. No marketing language. No emoji.
7. Answer with one JSON object and nothing else.`

// Narrative is a short reading of the audit for the person who has to decide.
type Narrative struct {
	Headline   string   `json:"headline"`
	Paragraphs []string `json:"paragraphs"`
	Actions    []Action `json:"actions"`
}

type Action struct {
	FindingID string `json:"finding_id"`
	Why       string `json:"why"`
}

// Answer is a reply to a question about the scan.
type Answer struct {
	Answer     string   `json:"answer"`
	FindingIDs []string `json:"finding_ids"`
}

// Checked reports what validation removed, so the reader knows the text was
// edited and why.
type Checked struct {
	DroppedSentences int      `json:"dropped_sentences"`
	DroppedIDs       int      `json:"dropped_ids"`
	Notes            []string `json:"notes,omitempty"`
}

func lang(l string) string {
	if strings.TrimSpace(l) == "" {
		return "English"
	}
	return l
}

func factsJSON(f Facts) string {
	b, _ := json.MarshalIndent(f, "", " ")
	return string(b)
}

// NarrativePrompt returns the system and user messages, so a caller can show
// exactly what will be sent before it is sent.
func NarrativePrompt(f Facts, language string) (system, user string) {
	user = fmt.Sprintf("Language of the answer: %s.\n\nWrite a reading of this audit.\nJSON schema: {\"headline\": string (one sentence), \"paragraphs\": [string, ...] (2 to 4, each at most 70 words), \"actions\": [{\"finding_id\": string, \"why\": string}] (up to 5 most important findings, each \"why\" at most 30 words)}\n\nFACTS:\n%s", lang(language), factsJSON(f))
	return systemPrompt, user
}

func AskPrompt(f Facts, question, language string) (system, user string) {
	user = fmt.Sprintf("Language of the answer: %s.\n\nQuestion from the consultant: %s\n\nAnswer only from the facts. If the facts do not contain the answer, say so.\nJSON schema: {\"answer\": string (at most 120 words), \"finding_ids\": [string, ...]}\n\nFACTS:\n%s", lang(language), question, factsJSON(f))
	return systemPrompt, user
}

// extractJSON finds the first complete JSON object in a model's reply, which
// may be wrapped in prose or a code fence.
func extractJSON(s string) (string, error) {
	start := strings.Index(s, "{")
	if start < 0 {
		return "", fmt.Errorf("the model did not return JSON")
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && inStr:
			esc = true
		case c == '"':
			inStr = !inStr
		case !inStr && c == '{':
			depth++
		case !inStr && c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("the model's JSON is incomplete")
}

// splitSentences ends a sentence at . ! or ? only when whitespace or the end
// of the text follows, so a decimal point inside "$4,200.00" or "v2.1" does
// not cut a number in half.
func splitSentences(s string) []string {
	var out []string
	start := 0
	rs := []rune(s)
	for i, r := range rs {
		if r != '.' && r != '!' && r != '?' {
			continue
		}
		if i+1 < len(rs) && !isSpace(rs[i+1]) {
			continue
		}
		j := i + 1
		for j < len(rs) && isSpace(rs[j]) {
			j++
		}
		out = append(out, string(rs[start:j]))
		start = j
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}

func isSpace(r rune) bool { return r == ' ' || r == '\n' || r == '\t' || r == '\r' }

// cleanText removes sentences that quote an amount the facts do not contain.
// A model that was told to copy numbers and did not is not trusted with them.
func cleanText(text string, f Facts, ck *Checked) string {
	if !reMoneyIn.MatchString(text) {
		return text
	}
	var kept []string
	for _, s := range splitSentences(text) {
		ok := true
		for _, m := range reMoneyIn.FindAllStringSubmatch(s, -1) {
			v, err := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", ""), 64)
			if err != nil {
				continue
			}
			switch strings.ToLower(m[2]) {
			case "k":
				v *= 1000
			case "m":
				v *= 1e6
			}
			if !f.moneyAllowed(v) {
				ok = false
				ck.Notes = append(ck.Notes, "removed a sentence quoting "+strings.TrimSpace(m[0])+", which is not among the facts")
				break
			}
		}
		if ok {
			kept = append(kept, s)
		} else {
			ck.DroppedSentences++
		}
	}
	return strings.TrimSpace(strings.Join(kept, ""))
}

// GenerateNarrative asks the model and validates the answer.
func GenerateNarrative(ctx context.Context, p Provider, f Facts, language string) (Narrative, Checked, error) {
	sys, usr := NarrativePrompt(f, language)
	raw, err := p.Complete(ctx, sys, usr)
	if err != nil {
		return Narrative{}, Checked{}, err
	}
	return ParseNarrative(raw, f)
}

// ParseNarrative validates a model reply against the facts it was given.
func ParseNarrative(raw string, f Facts) (Narrative, Checked, error) {
	var n Narrative
	var ck Checked
	js, err := extractJSON(raw)
	if err != nil {
		return n, ck, err
	}
	if err := json.Unmarshal([]byte(js), &n); err != nil {
		return n, ck, fmt.Errorf("the model's JSON does not match the schema: %w", err)
	}
	n.Headline = cleanText(n.Headline, f, &ck)
	var paras []string
	for _, p := range n.Paragraphs {
		if t := cleanText(p, f, &ck); t != "" {
			paras = append(paras, t)
		}
	}
	n.Paragraphs = paras
	var acts []Action
	for _, a := range n.Actions {
		if !f.HasID(a.FindingID) {
			ck.DroppedIDs++
			ck.Notes = append(ck.Notes, "removed an action that cited a finding id which does not exist")
			continue
		}
		a.Why = cleanText(a.Why, f, &ck)
		acts = append(acts, a)
	}
	n.Actions = acts
	if n.Headline == "" && len(n.Paragraphs) == 0 {
		return n, ck, fmt.Errorf("nothing in the model's answer survived validation")
	}
	return n, ck, nil
}

// Ask answers a question about the scan, grounded in the facts.
func Ask(ctx context.Context, p Provider, f Facts, question, language string) (Answer, Checked, error) {
	sys, usr := AskPrompt(f, question, language)
	raw, err := p.Complete(ctx, sys, usr)
	if err != nil {
		return Answer{}, Checked{}, err
	}
	return ParseAnswer(raw, f)
}

func ParseAnswer(raw string, f Facts) (Answer, Checked, error) {
	var a Answer
	var ck Checked
	js, err := extractJSON(raw)
	if err != nil {
		return a, ck, err
	}
	if err := json.Unmarshal([]byte(js), &a); err != nil {
		return a, ck, fmt.Errorf("the model's JSON does not match the schema: %w", err)
	}
	a.Answer = cleanText(a.Answer, f, &ck)
	var ids []string
	for _, id := range a.FindingIDs {
		if f.HasID(id) {
			ids = append(ids, id)
		} else {
			ck.DroppedIDs++
		}
	}
	a.FindingIDs = ids
	if a.Answer == "" {
		return a, ck, fmt.Errorf("nothing in the model's answer survived validation")
	}
	return a, ck, nil
}
