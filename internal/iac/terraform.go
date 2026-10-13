// Package iac reads infrastructure-as-code state. A Terraform state file
// holds secrets next to the identifiers that are useful for an audit, so this
// package is written to keep the second and drop the first: values are read
// with a decoder, copied if they are on a short allow-list, and everything
// else is discarded without being stored or logged.
package iac

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"infralens/internal/engine"
)

// maxStateBytes bounds how much of one file is read.
const maxStateBytes = 256 << 20

// keep lists, per resource type, the dotted attribute paths that are copied
// out of the state. Everything not listed is dropped. A path through a
// nested block uses the first element of the block (Terraform's lists of one).
var keep = func() map[string]bool {
	m := map[string]bool{"id": true, "arn": true, "region": true}
	for k := range engine.DriftAttributes() {
		m[k] = true
	}
	return m
}()

type rawResource struct {
	Mode      string `json:"mode"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Module    string `json:"module"`
	Instances []struct {
		IndexKey   any            `json:"index_key"`
		Attributes map[string]any `json:"attributes"`
	} `json:"instances"`
}

// ParseState reads one Terraform state (format version 4) and returns the
// managed AWS resources of types the tool can match. origin names the file.
func ParseState(r io.Reader, origin string) ([]engine.IaCRef, error) {
	dec := json.NewDecoder(io.LimitReader(r, maxStateBytes))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: not a JSON document: %w", origin, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("%s: not a state file", origin)
	}
	var out []engine.IaCRef
	version := 0
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", origin, err)
		}
		key, _ := kt.(string)
		switch key {
		case "version":
			if err := dec.Decode(&version); err != nil {
				return nil, fmt.Errorf("%s: %w", origin, err)
			}
		case "resources":
			if version != 0 && version != 4 {
				return nil, fmt.Errorf("%s: state format version %d is not supported", origin, version)
			}
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				return nil, fmt.Errorf("%s: malformed resources", origin)
			}
			for dec.More() {
				var rr rawResource
				if err := dec.Decode(&rr); err != nil {
					return nil, fmt.Errorf("%s: %w", origin, err)
				}
				out = append(out, convert(rr, origin)...)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("%s: %w", origin, err)
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("%s: %w", origin, err)
			}
		}
	}
	if version != 4 {
		return nil, fmt.Errorf("%s: state format version %d is not supported (need 4)", origin, version)
	}
	return out, nil
}

func convert(rr rawResource, origin string) []engine.IaCRef {
	if rr.Mode != "managed" || !strings.HasPrefix(rr.Type, "aws_") {
		return nil
	}
	if _, ok := engine.IaCNodeType(rr.Type); !ok {
		return nil
	}
	var out []engine.IaCRef
	for _, in := range rr.Instances {
		ref := engine.IaCRef{
			Source: "terraform", Origin: origin, Type: rr.Type, Module: rr.Module,
			ID: str(in.Attributes["id"]), ARN: str(in.Attributes["arn"]), Region: str(in.Attributes["region"]),
			Attrs: map[string]string{},
		}
		if ref.ID == "" {
			continue
		}
		ref.Address = address(rr, in.IndexKey)
		for k := range keep {
			if k == "id" || k == "arn" || k == "region" {
				continue
			}
			if v, ok := lookup(in.Attributes, k); ok {
				ref.Attrs[k] = v
			}
		}
		out = append(out, ref)
	}
	return out
}

func address(rr rawResource, idx any) string {
	a := rr.Type + "." + rr.Name
	if rr.Module != "" {
		a = rr.Module + "." + a
	}
	switch v := idx.(type) {
	case nil:
	case string:
		a += `["` + v + `"]`
	case float64:
		a += "[" + strconv.Itoa(int(v)) + "]"
	}
	return a
}

// lookup resolves a dotted path, taking the first element of lists.
func lookup(attrs map[string]any, path string) (string, bool) {
	var cur any = attrs
	for _, p := range strings.Split(path, ".") {
		switch t := cur.(type) {
		case map[string]any:
			cur = t[p]
		case []any:
			if len(t) == 0 {
				return "", false
			}
			m, ok := t[0].(map[string]any)
			if !ok {
				return "", false
			}
			cur = m[p]
		default:
			return "", false
		}
		if cur == nil {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, v != ""
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
