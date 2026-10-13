package main

import (
	"reflect"
	"testing"
)

func TestReorderFlags(t *testing.T) {
	got := reorderFlags([]string{"scan.json", "out.html", "--context", "c.json"})
	want := []string{"--context", "c.json", "scan.json", "out.html"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	got = reorderFlags([]string{"--context=c.json", "scan.json"})
	if !reflect.DeepEqual(got, []string{"--context=c.json", "scan.json"}) {
		t.Fatalf("got %v", got)
	}
}
