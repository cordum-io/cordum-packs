package worker

import (
	"encoding/json"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPackManifest(t *testing.T) {
	data, err := os.ReadFile("../../pack/pack.yaml")
	if err != nil {
		t.Fatalf("read pack.yaml: %v", err)
	}
	var manifest struct {
		Metadata struct {
			ID      string `yaml:"id"`
			Version string `yaml:"version"`
			Title   string `yaml:"title"`
		} `yaml:"metadata"`
		Topics []struct {
			Name string `yaml:"name"`
		} `yaml:"topics"`
	}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse pack.yaml: %v", err)
	}
	if manifest.Metadata.ID == "" {
		t.Error("metadata.id is required")
	}
	if manifest.Metadata.Version == "" {
		t.Error("metadata.version is required")
	}
	if len(manifest.Topics) == 0 {
		t.Error("at least one topic is required")
	}
}

func TestSchemas(t *testing.T) {
	entries, err := os.ReadDir("../../pack/schemas")
	if err != nil {
		t.Skipf("no schemas dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile("../../pack/schemas/" + entry.Name())
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			var schema map[string]any
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatalf("invalid JSON schema: %v", err)
			}
			// Verify it looks like a JSON Schema
			if _, ok := schema["type"]; !ok {
				if _, ok := schema["properties"]; !ok {
					t.Error("schema should have 'type' or 'properties' field")
				}
			}
		})
	}
}
