package glob

import "testing"

func TestGlobToRegex(t *testing.T) {
	result := globToRegex("*.tasadar.net")
	if result != ".*\\.tasadar\\.net" {
		t.Errorf("Expected .*\\.tasadar\\.net, got %s", result)
	}
	result = globToRegex("*.tasadar.n?t")
	if result != ".*\\.tasadar\\.n.t" {
		t.Errorf("Expected .*\\.tasadar\\.n.t, got %s", result)
	}
	result = globToRegex("\\*.tasadar.net")
	if result != "\\*\\.tasadar\\.net" {
		t.Errorf("Expected \\*\\.tasadar\\.net, got %s", result)
	}
	result = globToRegex("\\*.tasadar.*")
	if result != "\\*\\.tasadar\\..*" {
		t.Errorf("Expected \\*\\.tasadar\\..*, got %s", result)
	}
}
