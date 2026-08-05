package caddyaac

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExamples_Adapt(t *testing.T) {
	files, err := filepath.Glob("examples/*.Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example Caddyfiles found")
	}
	for _, f := range files {
		f := f
		t.Run(f, func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			adaptCaddyfile(t, string(b))
		})
	}
}
