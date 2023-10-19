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

func TestGetListMatcher(t *testing.T) {
	listMatcher, err := GetListMatcher([]string{"*.tasadar.net", "*.tionis.dev", "*.test.tasadar.net", "!forbidden.tasadar.net"})
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	result := listMatcher("test.tasadar.net")
	if !result.Valid {
		t.Errorf("Expected valid result, got invalid")
	}
	if result.String != "*.tasadar.net" {
		t.Errorf("Expected *.tasadar.net, got %s", result.String)
	}
	result = listMatcher("forbidden.tasadar.net")
	if result.Valid {
		t.Errorf("Expected invalid result, got valid")
	}
	if result.String != "!forbidden.tasadar.net" {
		t.Errorf("Expected !forbidden.tasadar.net, got %s", result.String)
	}
	result = listMatcher("test.tionis.dev")
	if !result.Valid {
		t.Errorf("Expected valid result, got invalid")
	}
	if result.String != "*.tionis.dev" {
		t.Errorf("Expected *.tionis.dev, got %s", result.String)
	}
	result = listMatcher("this-is-a-test.net")
	if result.Valid {
		t.Errorf("Expected invalid result, got valid")
	}
	if result.String != "" {
		t.Errorf("Expected empty string, got %s", result.String)
	}
}
