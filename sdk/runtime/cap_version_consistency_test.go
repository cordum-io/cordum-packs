package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var (
	capModulePattern      = regexp.MustCompile(`(?m)^module\s+\S+$`)
	capRequireLinePattern = regexp.MustCompile(`(?m)^\s*(?:require\s+)?github\.com/cordum-io/cap/v2\s+(\S+?)\s*(?://.*)?$`)
	capReplaceLinePattern = regexp.MustCompile(`(?m)^\s*(?:replace\s+)?github\.com/cordum-io/cap/v2(?:\s+\S+)?\s*=>`)
	capStableTagPattern   = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
)

// transitiveOnlyPacks are packs that must never declare an explicit CAP
// requirement: they consume CAP purely through the local SDK module and the
// resolved module graph. Adding an explicit pin there would create a second,
// independently drifting version authority.
var transitiveOnlyPacks = map[string]bool{"webhooks": true}

type packGoMod struct {
	name    string
	content []byte
}

// checkPackCAPConsistency validates that the SDK pins one exact stable CAP
// tag with no replace directive, and that every sibling pack's explicit CAP
// requirement (where one exists) equals the SDK's version. Packs listed in
// transitiveOnlyPacks must not declare an explicit CAP requirement at all.
func checkPackCAPConsistency(sdkGoMod []byte, packs []packGoMod) []string {
	var problems []string

	sdkVersion := ""
	if !capModulePattern.Match(normalizeGoModEOL(sdkGoMod)) {
		problems = append(problems, "sdk/go.mod: malformed module file (missing module directive)")
	}
	sdkMatches := capRequireLinePattern.FindAllSubmatch(normalizeGoModEOL(sdkGoMod), -1)
	switch len(sdkMatches) {
	case 0:
		problems = append(problems, "sdk/go.mod: missing github.com/cordum-io/cap/v2 requirement")
	case 1:
		sdkVersion = string(sdkMatches[0][1])
		if !capStableTagPattern.MatchString(sdkVersion) {
			problems = append(problems, fmt.Sprintf("sdk/go.mod: CAP version %q is not an exact stable tag (pseudo-versions are forbidden)", sdkVersion))
		}
	default:
		problems = append(problems, "sdk/go.mod: duplicate github.com/cordum-io/cap/v2 requirements")
	}
	if capReplaceLinePattern.Match(normalizeGoModEOL(sdkGoMod)) {
		problems = append(problems, "sdk/go.mod: forbidden replace directive for github.com/cordum-io/cap/v2")
	}

	sorted := append([]packGoMod(nil), packs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })

	for _, pack := range sorted {
		label := "packs/" + pack.name + "/go.mod"
		if !capModulePattern.Match(normalizeGoModEOL(pack.content)) {
			problems = append(problems, label+": malformed module file (missing module directive)")
			continue
		}
		matches := capRequireLinePattern.FindAllSubmatch(normalizeGoModEOL(pack.content), -1)
		if capReplaceLinePattern.Match(normalizeGoModEOL(pack.content)) {
			problems = append(problems, label+": forbidden replace directive for github.com/cordum-io/cap/v2")
		}
		if len(matches) > 1 {
			problems = append(problems, label+": duplicate github.com/cordum-io/cap/v2 requirements")
			continue
		}
		if transitiveOnlyPacks[pack.name] {
			if len(matches) != 0 {
				problems = append(problems, label+": must stay transitive-only (no explicit CAP requirement)")
			}
			continue
		}
		if len(matches) == 0 {
			// No explicit CAP requirement: the pack resolves CAP through the
			// local SDK replace chain, which this check already pins.
			continue
		}
		version := string(matches[0][1])
		if !capStableTagPattern.MatchString(version) {
			problems = append(problems, fmt.Sprintf("%s: CAP version %q is not an exact stable tag (pseudo-versions are forbidden)", label, version))
			continue
		}
		if sdkVersion != "" && version != sdkVersion {
			problems = append(problems, fmt.Sprintf("%s: CAP version %s does not match the SDK's %s; promote every explicit pin atomically", label, version, sdkVersion))
		}
	}

	return problems
}

// discoverPackGoMods walks <packsRoot>/*/go.mod and returns the contents in
// deterministic name order. It uses filepath joins only, so it behaves
// identically with Windows and Unix path separators.
func discoverPackGoMods(packsRoot string) ([]packGoMod, error) {
	entries, err := os.ReadDir(packsRoot)
	if err != nil {
		return nil, err
	}
	var packs []packGoMod
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(packsRoot, entry.Name(), "go.mod")
		content, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		packs = append(packs, packGoMod{name: entry.Name(), content: content})
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].name < packs[j].name })
	return packs, nil
}

// normalizeGoModEOL strips carriage returns so line-anchored patterns behave
// identically on LF and CRLF (autocrlf) working trees.
func normalizeGoModEOL(data []byte) []byte {
	return []byte(strings.ReplaceAll(string(data), "\r\n", "\n"))
}

func sdkFixture(version string) []byte {
	return []byte("module github.com/cordum/cordum/sdk\n\ngo 1.25.9\n\nrequire (\n\tgithub.com/cordum-io/cap/v2 " + version + "\n\tgithub.com/nats-io/nats.go v1.49.0\n)\n")
}

func packFixture(version string) []byte {
	return []byte("module github.com/cordum/cordum-packs/packs/fixture\n\ngo 1.25.9\n\nrequire (\n\tgithub.com/cordum/cordum/sdk v0.2.0\n\tgithub.com/cordum-io/cap/v2 " + version + " // indirect\n)\n\nreplace github.com/cordum/cordum/sdk => ../../sdk\n")
}

func TestPackCAPConsistencyAcceptsAlignedPins(t *testing.T) {
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{
		{name: "alpha", content: packFixture("v2.17.0")},
		{name: "webhooks", content: []byte("module github.com/cordum/cordum-packs/packs/webhooks\n\ngo 1.25.9\n\nrequire github.com/cordum/cordum/sdk v0.2.0\n\nreplace github.com/cordum/cordum/sdk => ../../sdk\n")},
	})
	if len(problems) != 0 {
		t.Fatalf("aligned fixture reported problems: %v", problems)
	}
}

func TestPackCAPConsistencyDetectsVersionSkew(t *testing.T) {
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{
		{name: "alpha", content: packFixture("v2.14.0")},
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "does not match the SDK's v2.17.0") {
		t.Fatalf("problems = %v, want one skew problem", problems)
	}
}

func TestPackCAPConsistencyDetectsPseudoVersion(t *testing.T) {
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{
		{name: "alpha", content: packFixture("v2.16.2-0.20260722152314-e580c670d54a")},
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "not an exact stable tag") {
		t.Fatalf("problems = %v, want one pseudo-version problem", problems)
	}
}

func TestPackCAPConsistencyDetectsReplaceDirective(t *testing.T) {
	content := append(packFixture("v2.17.0"), []byte("\nreplace github.com/cordum-io/cap/v2 => ../../../cap\n")...)
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{{name: "alpha", content: content}})
	if len(problems) != 1 || !strings.Contains(problems[0], "forbidden replace directive") {
		t.Fatalf("problems = %v, want one replace problem", problems)
	}
}

func TestPackCAPConsistencyDetectsDuplicateRequirement(t *testing.T) {
	content := append(packFixture("v2.17.0"), []byte("\nrequire github.com/cordum-io/cap/v2 v2.17.0\n")...)
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{{name: "alpha", content: content}})
	if len(problems) != 1 || !strings.Contains(problems[0], "duplicate github.com/cordum-io/cap/v2 requirements") {
		t.Fatalf("problems = %v, want one duplicate problem", problems)
	}
}

func TestPackCAPConsistencyDetectsMalformedGoMod(t *testing.T) {
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{
		{name: "alpha", content: []byte("this is not a go.mod file\n")},
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "malformed module file") {
		t.Fatalf("problems = %v, want one malformed problem", problems)
	}
}

func TestPackCAPConsistencyAllowsMissingExplicitRequirement(t *testing.T) {
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{
		{name: "alpha", content: []byte("module github.com/cordum/cordum-packs/packs/alpha\n\ngo 1.25.9\n\nrequire github.com/cordum/cordum/sdk v0.2.0\n\nreplace github.com/cordum/cordum/sdk => ../../sdk\n")},
	})
	if len(problems) != 0 {
		t.Fatalf("missing explicit requirement should be tolerated for non transitive-only packs, got %v", problems)
	}
}

func TestPackCAPConsistencyRejectsExplicitPinInWebhooks(t *testing.T) {
	problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), []packGoMod{
		{name: "webhooks", content: packFixture("v2.17.0")},
	})
	if len(problems) != 1 || !strings.Contains(problems[0], "must stay transitive-only") {
		t.Fatalf("problems = %v, want one transitive-only problem", problems)
	}
}

func TestPackCAPConsistencyHandlesCRLFAndSeparators(t *testing.T) {
	dir := t.TempDir()
	packDir := filepath.Join(dir, "packs", "alpha")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatal(err)
	}
	crlf := strings.ReplaceAll(string(packFixture("v2.17.0")), "\n", "\r\n")
	if err := os.WriteFile(filepath.Join(packDir, "go.mod"), []byte(crlf), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, err := discoverPackGoMods(filepath.Join(dir, "packs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 1 || packs[0].name != "alpha" {
		t.Fatalf("discovered packs = %+v, want exactly alpha", packs)
	}
	if problems := checkPackCAPConsistency(sdkFixture("v2.17.0"), packs); len(problems) != 0 {
		t.Fatalf("CRLF fixture reported problems: %v", problems)
	}
}

func TestPackCAPConsistencyDiscoveryIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zeta", "alpha", "mid"} {
		packDir := filepath.Join(dir, name)
		if err := os.MkdirAll(packDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(packDir, "go.mod"), packFixture("v2.17.0"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	packs, err := discoverPackGoMods(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range packs {
		names = append(names, p.name)
	}
	if strings.Join(names, ",") != "alpha,mid,zeta" {
		t.Fatalf("discovery order = %v, want alphabetical", names)
	}
}

// TestRepositoryPackCAPConsistency runs the checker against the real
// repository: the SDK module plus every sibling pack module on disk.
func TestRepositoryPackCAPConsistency(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	sdkRoot := filepath.Clean(filepath.Join(filepath.Dir(current), ".."))
	sdkGoMod, err := os.ReadFile(filepath.Join(sdkRoot, "go.mod"))
	if err != nil {
		t.Fatalf("read sdk go.mod: %v", err)
	}
	packs, err := discoverPackGoMods(filepath.Join(sdkRoot, "..", "packs"))
	if err != nil {
		t.Fatalf("discover packs: %v", err)
	}
	if len(packs) == 0 {
		t.Fatal("no pack go.mod files discovered; walker or layout is broken")
	}
	if problems := checkPackCAPConsistency(sdkGoMod, packs); len(problems) != 0 {
		t.Fatalf("pack CAP version consistency problems:\n  %s", strings.Join(problems, "\n  "))
	}
}
