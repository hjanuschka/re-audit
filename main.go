package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type UnsafeBlock struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Context   string `json:"context"`
	BlockType string `json:"block_type"`
	IsNew     bool   `json:"is_new,omitempty"` // true if this is new in the diff
}

type SecurityPattern struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	PatternType string `json:"pattern_type"`
	Code        string `json:"code"`
	IsNew       bool   `json:"is_new,omitempty"`
}

type DependencyChange struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`
	ChangeType string `json:"change_type"`
}

type FileChange struct {
	Path       string `json:"path"`
	ChangeType string `json:"change_type"` // added, modified, deleted
	Additions  int    `json:"additions"`
	Deletions  int    `json:"deletions"`
}

type AuditReport struct {
	CrateName         string             `json:"crate_name"`
	Version           string             `json:"version"`
	FromRef           string             `json:"from_ref,omitempty"`
	ToRef             string             `json:"to_ref,omitempty"`
	UnsafeBlocks      []UnsafeBlock      `json:"unsafe_blocks"`
	SecurityPatterns  []SecurityPattern  `json:"security_patterns"`
	DependencyChanges []DependencyChange `json:"dependency_changes"`
	FileChanges       []FileChange       `json:"file_changes,omitempty"`
	TotalUnsafeLines  int                `json:"total_unsafe_lines"`
	FilesWithUnsafe   int                `json:"files_with_unsafe"`
	RiskAssessment    string             `json:"risk_assessment"`
	DiffStats         string             `json:"diff_stats,omitempty"`
}

var securityPatterns = map[string][]*regexp.Regexp{
	"fs": {
		regexp.MustCompile(`\bstd::fs\b`),
		regexp.MustCompile(`\buse\s+std::fs\b`),
		regexp.MustCompile(`\bfs::\w+`),
		regexp.MustCompile(`\bFile::`),
		regexp.MustCompile(`\bOpenOptions\b`),
		regexp.MustCompile(`\bread_to_string\b`),
		regexp.MustCompile(`\bwrite_all\b`),
	},
	"net": {
		regexp.MustCompile(`\bstd::net\b`),
		regexp.MustCompile(`\buse\s+std::net\b`),
		regexp.MustCompile(`\bTcpStream\b`),
		regexp.MustCompile(`\bTcpListener\b`),
		regexp.MustCompile(`\bUdpSocket\b`),
		regexp.MustCompile(`\bhyper::`),
		regexp.MustCompile(`\breqwest::`),
		regexp.MustCompile(`\btokio::net\b`),
	},
	"crypto": {
		regexp.MustCompile(`(?i)\bcrypto\b`),
		regexp.MustCompile(`(?i)\bcipher\b`),
		regexp.MustCompile(`(?i)\bencrypt\b`),
		regexp.MustCompile(`(?i)\bdecrypt\b`),
		regexp.MustCompile(`(?i)\b(sha|md5|blake)\d*\b`),
		regexp.MustCompile(`(?i)\baes\b`),
		regexp.MustCompile(`(?i)\brsa\b`),
		regexp.MustCompile(`(?i)\bhmac\b`),
	},
	"ffi": {
		regexp.MustCompile(`\bextern\s+"C"`),
		regexp.MustCompile(`#\[no_mangle\]`),
		regexp.MustCompile(`\bstd::ffi\b`),
		regexp.MustCompile(`\bCString\b`),
		regexp.MustCompile(`\bCStr\b`),
	},
	"env": {
		regexp.MustCompile(`\bstd::env\b`),
		regexp.MustCompile(`\benv::var\b`),
		regexp.MustCompile(`\bstd::process::Command\b`),
	},
	"raw_ptr": {
		regexp.MustCompile(`\*const\s+\w+`),
		regexp.MustCompile(`\*mut\s+\w+`),
		regexp.MustCompile(`\.as_ptr\(\)`),
		regexp.MustCompile(`\.as_mut_ptr\(\)`),
		regexp.MustCompile(`\bptr::\w+`),
	},
	"transmute": {
		regexp.MustCompile(`\btransmute\b`),
		regexp.MustCompile(`\btransmute_copy\b`),
		regexp.MustCompile(`\bfrom_raw_parts\b`),
		regexp.MustCompile(`\bfrom_raw_parts_mut\b`),
	},
}

var unsafePatterns = []struct {
	Pattern   *regexp.Regexp
	BlockType string
}{
	{regexp.MustCompile(`unsafe\s+fn\s+(\w+)`), "unsafe_fn"},
	{regexp.MustCompile(`unsafe\s+impl\b`), "unsafe_impl"},
	{regexp.MustCompile(`unsafe\s+trait\b`), "unsafe_trait"},
	{regexp.MustCompile(`unsafe\s*\{`), "unsafe_block"},
}

type Analyzer struct {
	repoPath string
	fromRef  string
	toRef    string
}

func NewAnalyzer(repoPath, fromRef, toRef string) *Analyzer {
	return &Analyzer{
		repoPath: repoPath,
		fromRef:  fromRef,
		toRef:    toRef,
	}
}

func (a *Analyzer) git(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = a.repoPath
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("git %v: %s", args, exitErr.Stderr)
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (a *Analyzer) getFileAtRef(ref, path string) (string, error) {
	return a.git("show", fmt.Sprintf("%s:%s", ref, path))
}

func (a *Analyzer) getChangedFiles() ([]FileChange, error) {
	if a.fromRef == "" || a.toRef == "" {
		return nil, nil
	}

	// Get diff stats
	out, err := a.git("diff", "--numstat", a.fromRef, a.toRef, "--", "*.rs", "Cargo.toml", "Cargo.lock")
	if err != nil {
		return nil, err
	}

	var changes []FileChange
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		var add, del int
		fmt.Sscanf(parts[0], "%d", &add)
		fmt.Sscanf(parts[1], "%d", &del)

		changeType := "modified"
		if add > 0 && del == 0 {
			changeType = "added"
		}

		changes = append(changes, FileChange{
			Path:       parts[2],
			ChangeType: changeType,
			Additions:  add,
			Deletions:  del,
		})
	}

	return changes, nil
}

func (a *Analyzer) getDiffStats() string {
	if a.fromRef == "" || a.toRef == "" {
		return ""
	}

	out, _ := a.git("diff", "--stat", a.fromRef, a.toRef, "--", "*.rs")
	lines := strings.Split(out, "\n")
	if len(lines) > 0 {
		return lines[len(lines)-1] // Summary line
	}
	return ""
}

func (a *Analyzer) getAddedLines() (map[string]map[int]bool, error) {
	if a.fromRef == "" || a.toRef == "" {
		return nil, nil
	}

	// Get unified diff to find which lines are new
	out, err := a.git("diff", "-U0", a.fromRef, a.toRef, "--", "*.rs")
	if err != nil {
		return nil, err
	}

	// Parse diff to find new lines
	added := make(map[string]map[int]bool)
	var currentFile string
	lineNumRe := regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			if added[currentFile] == nil {
				added[currentFile] = make(map[int]bool)
			}
		} else if strings.HasPrefix(line, "@@") && currentFile != "" {
			matches := lineNumRe.FindStringSubmatch(line)
			if matches != nil {
				var start, count int
				fmt.Sscanf(matches[1], "%d", &start)
				count = 1
				if matches[2] != "" {
					fmt.Sscanf(matches[2], "%d", &count)
				}
				for i := 0; i < count; i++ {
					added[currentFile][start+i] = true
				}
			}
		}
	}

	return added, nil
}

func (a *Analyzer) findRustFiles() ([]string, error) {
	var files []string
	err := filepath.WalkDir(a.repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "target" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".rs") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func (a *Analyzer) analyzeFile(filePath string, addedLines map[string]map[int]bool) ([]UnsafeBlock, []SecurityPattern, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	relPath, _ := filepath.Rel(a.repoPath, filePath)
	lines := strings.Split(string(content), "\n")
	isTestFile := strings.Contains(relPath, "/tests/") ||
		strings.HasSuffix(relPath, "_test.rs") ||
		strings.Contains(string(content), "#[cfg(test)]")

	fileAddedLines := addedLines[relPath]

	var unsafeBlocks []UnsafeBlock
	var secPatterns []SecurityPattern

	for lineNum, line := range lines {
		lineNum++ // 1-indexed
		stripped := strings.TrimSpace(line)

		if strings.HasPrefix(stripped, "//") {
			continue
		}

		isNew := fileAddedLines != nil && fileAddedLines[lineNum]

		// Check unsafe patterns
		for _, up := range unsafePatterns {
			if up.Pattern.MatchString(line) {
				start := max(0, lineNum-4)
				end := min(len(lines), lineNum+4)
				context := strings.Join(lines[start:end], "\n")

				file := relPath
				if isTestFile {
					file += " [TEST]"
				}

				unsafeBlocks = append(unsafeBlocks, UnsafeBlock{
					File:      file,
					Line:      lineNum,
					Context:   context,
					BlockType: up.BlockType,
					IsNew:     isNew,
				})
				break
			}
		}

		// Check security patterns
		for patternType, patterns := range securityPatterns {
			for _, p := range patterns {
				if p.MatchString(line) {
					file := relPath
					if isTestFile {
						file += " [TEST]"
					}

					code := stripped
					if len(code) > 200 {
						code = code[:200]
					}

					secPatterns = append(secPatterns, SecurityPattern{
						File:        file,
						Line:        lineNum,
						PatternType: patternType,
						Code:        code,
						IsNew:       isNew,
					})
					break
				}
			}
		}
	}

	return unsafeBlocks, secPatterns, nil
}

func (a *Analyzer) getCrateInfo() (name, version string) {
	cargoPath := filepath.Join(a.repoPath, "Cargo.toml")
	content, err := os.ReadFile(cargoPath)
	if err != nil {
		// Try workspace members
		entries, _ := os.ReadDir(a.repoPath)
		for _, e := range entries {
			if e.IsDir() {
				subCargo := filepath.Join(a.repoPath, e.Name(), "Cargo.toml")
				if c, err := os.ReadFile(subCargo); err == nil {
					content = c
					break
				}
			}
		}
	}

	nameRe := regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"`)
	versionRe := regexp.MustCompile(`(?m)^version\s*=\s*"([^"]+)"`)

	if m := nameRe.FindSubmatch(content); m != nil {
		name = string(m[1])
	} else {
		name = "unknown"
	}

	if m := versionRe.FindSubmatch(content); m != nil {
		version = string(m[1])
	} else {
		version = "unknown"
	}

	return
}

func (a *Analyzer) analyzeDependencies() []DependencyChange {
	if a.fromRef == "" {
		return nil
	}

	var changes []DependencyChange

	// Get current deps
	currentDeps := a.parseCargoDeps(filepath.Join(a.repoPath, "Cargo.toml"))

	// Get old deps via git show
	oldContent, err := a.getFileAtRef(a.fromRef, "Cargo.toml")
	if err != nil {
		return nil
	}

	oldDeps := a.parseCargoDepsContent(oldContent)

	// Compare
	allDeps := make(map[string]bool)
	for k := range currentDeps {
		allDeps[k] = true
	}
	for k := range oldDeps {
		allDeps[k] = true
	}

	for dep := range allDeps {
		oldVer := oldDeps[dep]
		newVer := currentDeps[dep]

		if oldVer == "" && newVer != "" {
			changes = append(changes, DependencyChange{Name: dep, NewVersion: newVer, ChangeType: "added"})
		} else if oldVer != "" && newVer == "" {
			changes = append(changes, DependencyChange{Name: dep, OldVersion: oldVer, ChangeType: "removed"})
		} else if oldVer != newVer {
			changes = append(changes, DependencyChange{Name: dep, OldVersion: oldVer, NewVersion: newVer, ChangeType: "updated"})
		}
	}

	return changes
}

func (a *Analyzer) parseCargoDeps(path string) map[string]string {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return a.parseCargoDepsContent(string(content))
}

func (a *Analyzer) parseCargoDepsContent(content string) map[string]string {
	deps := make(map[string]string)
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") && strings.Contains(strings.ToLower(line), "dependencies") {
			inDeps = true
			continue
		} else if strings.HasPrefix(line, "[") {
			inDeps = false
			continue
		}

		if inDeps && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			depName := strings.TrimSpace(parts[0])
			versionPart := strings.TrimSpace(parts[1])

			var version string
			if strings.HasPrefix(versionPart, `"`) {
				version = strings.Trim(versionPart, `"`)
			} else if strings.Contains(versionPart, "version") {
				re := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
				if m := re.FindStringSubmatch(versionPart); m != nil {
					version = m[1]
				}
			} else {
				version = "complex"
			}

			deps[depName] = version
		}
	}

	return deps
}

func (a *Analyzer) assessRisk(report *AuditReport) string {
	var factors []string

	// Count non-test unsafe (total and new)
	var prodUnsafe, testUnsafe, newProdUnsafe int
	for _, u := range report.UnsafeBlocks {
		if strings.Contains(u.File, "[TEST]") {
			testUnsafe++
		} else {
			prodUnsafe++
			if u.IsNew {
				newProdUnsafe++
			}
		}
	}

	if prodUnsafe == 0 {
		factors = append(factors, "✅ No unsafe code in production (ub-risk-0 candidate)")
	} else if prodUnsafe <= 5 {
		factors = append(factors, fmt.Sprintf("⚠️  %d unsafe blocks in production code", prodUnsafe))
	} else {
		factors = append(factors, fmt.Sprintf("🔴 %d unsafe blocks in production code - thorough review needed", prodUnsafe))
	}

	if newProdUnsafe > 0 {
		factors = append(factors, fmt.Sprintf("🆕 %d NEW unsafe blocks added in this diff", newProdUnsafe))
	}

	if testUnsafe > 0 {
		factors = append(factors, fmt.Sprintf("ℹ️  %d unsafe blocks in test code (less critical)", testUnsafe))
	}

	// Check security patterns
	patternTypes := make(map[string]bool)
	newPatternTypes := make(map[string]bool)
	for _, p := range report.SecurityPatterns {
		if !strings.Contains(p.File, "[TEST]") {
			patternTypes[p.PatternType] = true
			if p.IsNew {
				newPatternTypes[p.PatternType] = true
			}
		}
	}

	if patternTypes["fs"] {
		marker := "⚠️ "
		if newPatternTypes["fs"] {
			marker = "🆕 "
		}
		factors = append(factors, marker+"Filesystem access detected - verify safe-to-deploy")
	}
	if patternTypes["net"] {
		marker := "⚠️ "
		if newPatternTypes["net"] {
			marker = "🆕 "
		}
		factors = append(factors, marker+"Network access detected - verify safe-to-deploy")
	}
	if patternTypes["crypto"] {
		marker := "🔐"
		if newPatternTypes["crypto"] {
			marker = "🆕"
		}
		factors = append(factors, marker+" Crypto-related code detected - may need crypto-safe audit")
	}
	if patternTypes["ffi"] {
		marker := "⚠️ "
		if newPatternTypes["ffi"] {
			marker = "🆕 "
		}
		factors = append(factors, marker+"FFI usage detected - review boundary safety")
	}
	if patternTypes["transmute"] {
		marker := "🔴"
		if newPatternTypes["transmute"] {
			marker = "🆕"
		}
		factors = append(factors, marker+" Transmute usage detected - careful review needed")
	}

	// Dep changes
	if len(report.DependencyChanges) > 0 {
		var added, updated int
		for _, d := range report.DependencyChanges {
			if d.ChangeType == "added" {
				added++
			} else if d.ChangeType == "updated" {
				updated++
			}
		}
		if added > 0 {
			factors = append(factors, fmt.Sprintf("📦 %d new dependencies added - review their audits", added))
		}
		if updated > 0 {
			factors = append(factors, fmt.Sprintf("📦 %d dependencies updated", updated))
		}
	}

	return strings.Join(factors, "\n")
}

func (a *Analyzer) Analyze() (*AuditReport, error) {
	crateName, version := a.getCrateInfo()

	report := &AuditReport{
		CrateName: crateName,
		Version:   version,
		FromRef:   a.fromRef,
		ToRef:     a.toRef,
	}

	// Get added lines for diff highlighting
	addedLines, _ := a.getAddedLines()

	// Get file changes
	fileChanges, _ := a.getChangedFiles()
	report.FileChanges = fileChanges
	report.DiffStats = a.getDiffStats()

	files, err := a.findRustFiles()
	if err != nil {
		return nil, err
	}

	filesWithUnsafe := make(map[string]bool)

	for _, f := range files {
		unsafeBlocks, secPatterns, err := a.analyzeFile(f, addedLines)
		if err != nil {
			continue
		}

		report.UnsafeBlocks = append(report.UnsafeBlocks, unsafeBlocks...)
		report.SecurityPatterns = append(report.SecurityPatterns, secPatterns...)

		if len(unsafeBlocks) > 0 {
			filesWithUnsafe[f] = true
		}
	}

	report.TotalUnsafeLines = len(report.UnsafeBlocks)
	report.FilesWithUnsafe = len(filesWithUnsafe)
	report.DependencyChanges = a.analyzeDependencies()
	report.RiskAssessment = a.assessRisk(report)

	return report, nil
}

func generateMarkdown(report *AuditReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# 🔍 Audit Report: %s v%s\n\n", report.CrateName, report.Version))

	if report.FromRef != "" && report.ToRef != "" {
		sb.WriteString(fmt.Sprintf("**Comparing:** `%s` → `%s`\n\n", report.FromRef, report.ToRef))
	} else if report.FromRef != "" {
		sb.WriteString(fmt.Sprintf("**Delta from:** `%s`\n\n", report.FromRef))
	}

	if report.DiffStats != "" {
		sb.WriteString(fmt.Sprintf("**Diff stats:** %s\n\n", report.DiffStats))
	}

	// Count prod vs test, and new vs existing
	var prodUnsafe, testUnsafe, newProdUnsafe int
	for _, u := range report.UnsafeBlocks {
		if strings.Contains(u.File, "[TEST]") {
			testUnsafe++
		} else {
			prodUnsafe++
			if u.IsNew {
				newProdUnsafe++
			}
		}
	}

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Unsafe blocks (production) | %d |\n", prodUnsafe))
	if newProdUnsafe > 0 {
		sb.WriteString(fmt.Sprintf("| **NEW unsafe blocks** | **%d** |\n", newProdUnsafe))
	}
	sb.WriteString(fmt.Sprintf("| Unsafe blocks (tests) | %d |\n", testUnsafe))
	sb.WriteString(fmt.Sprintf("| Files with unsafe code | %d |\n", report.FilesWithUnsafe))
	sb.WriteString(fmt.Sprintf("| Security-relevant patterns | %d |\n", len(report.SecurityPatterns)))
	sb.WriteString(fmt.Sprintf("| Dependency changes | %d |\n", len(report.DependencyChanges)))
	sb.WriteString(fmt.Sprintf("| Files changed | %d |\n\n", len(report.FileChanges)))

	sb.WriteString("## Risk Assessment\n\n")
	sb.WriteString(report.RiskAssessment)
	sb.WriteString("\n\n")

	// Cargo-vet suggestions
	sb.WriteString("## Suggested cargo-vet Criteria\n\n")

	patternTypes := make(map[string]bool)
	for _, p := range report.SecurityPatterns {
		if !strings.Contains(p.File, "[TEST]") {
			patternTypes[p.PatternType] = true
		}
	}

	if prodUnsafe == 0 {
		sb.WriteString("- `ub-risk-0`: No unsafe code in production\n")
	} else if prodUnsafe <= 3 {
		sb.WriteString("- `ub-risk-1` or `ub-risk-2`: Limited unsafe code, review needed\n")
	} else {
		sb.WriteString("- `ub-risk-2` or `ub-risk-3`: Significant unsafe code present\n")
	}

	if !patternTypes["fs"] && !patternTypes["net"] {
		sb.WriteString("- `safe-to-deploy`: No filesystem or network access detected\n")
	} else {
		sb.WriteString("- `safe-to-run`: Filesystem/network access present, review scope\n")
	}

	if !patternTypes["crypto"] {
		sb.WriteString("- `does-not-implement-crypto`: No crypto implementations found\n")
	}
	sb.WriteString("\n")

	// NEW unsafe blocks first (most important for delta review)
	newUnsafe := make([]UnsafeBlock, 0)
	for _, block := range report.UnsafeBlocks {
		if block.IsNew && !strings.Contains(block.File, "[TEST]") {
			newUnsafe = append(newUnsafe, block)
		}
	}

	if len(newUnsafe) > 0 {
		sb.WriteString("## 🆕 NEW Unsafe Code (Review Priority)\n\n")
		sb.WriteString("These unsafe blocks were **added in this diff** and require careful review:\n\n")

		for _, block := range newUnsafe {
			sb.WriteString(fmt.Sprintf("### %s:%d (%s)\n", block.File, block.Line, block.BlockType))
			sb.WriteString("```rust\n")
			sb.WriteString(block.Context)
			sb.WriteString("\n```\n\n")
		}
	}

	// All unsafe blocks detail
	if prodUnsafe > 0 {
		sb.WriteString("## All Unsafe Code Locations (Production)\n\n")
		sb.WriteString("<details>\n<summary>Click to expand all unsafe code details</summary>\n\n")

		count := 0
		for _, block := range report.UnsafeBlocks {
			if strings.Contains(block.File, "[TEST]") {
				continue
			}
			if count >= 20 {
				break
			}

			marker := ""
			if block.IsNew {
				marker = " 🆕"
			}

			sb.WriteString(fmt.Sprintf("### %s:%d (%s)%s\n", block.File, block.Line, block.BlockType, marker))
			sb.WriteString("```rust\n")
			sb.WriteString(block.Context)
			sb.WriteString("\n```\n\n")
			count++
		}

		if prodUnsafe > 20 {
			sb.WriteString(fmt.Sprintf("*... and %d more*\n", prodUnsafe-20))
		}

		sb.WriteString("</details>\n\n")
	}

	// Security patterns
	prodPatterns := make([]SecurityPattern, 0)
	for _, p := range report.SecurityPatterns {
		if !strings.Contains(p.File, "[TEST]") {
			prodPatterns = append(prodPatterns, p)
		}
	}

	if len(prodPatterns) > 0 {
		sb.WriteString("## Security-Relevant Patterns\n\n")

		byType := make(map[string][]SecurityPattern)
		for _, p := range prodPatterns {
			byType[p.PatternType] = append(byType[p.PatternType], p)
		}

		types := make([]string, 0, len(byType))
		for t := range byType {
			types = append(types, t)
		}
		sort.Strings(types)

		for _, t := range types {
			patterns := byType[t]
			newCount := 0
			for _, p := range patterns {
				if p.IsNew {
					newCount++
				}
			}

			header := fmt.Sprintf("### %s (%d occurrences", strings.ToUpper(t), len(patterns))
			if newCount > 0 {
				header += fmt.Sprintf(", %d new", newCount)
			}
			header += ")\n\n"
			sb.WriteString(header)

			for i, p := range patterns {
				if i >= 10 {
					sb.WriteString(fmt.Sprintf("- *... and %d more*\n", len(patterns)-10))
					break
				}
				code := p.Code
				if len(code) > 80 {
					code = code[:80] + "..."
				}
				marker := ""
				if p.IsNew {
					marker = " 🆕"
				}
				sb.WriteString(fmt.Sprintf("- `%s:%d`: `%s`%s\n", p.File, p.Line, code, marker))
			}
			sb.WriteString("\n")
		}
	}

	// Dep changes
	if len(report.DependencyChanges) > 0 {
		sb.WriteString("## Dependency Changes\n\n")
		sb.WriteString("| Dependency | Change | Old Version | New Version |\n")
		sb.WriteString("|------------|--------|-------------|-------------|\n")
		for _, d := range report.DependencyChanges {
			old := d.OldVersion
			if old == "" {
				old = "-"
			}
			new := d.NewVersion
			if new == "" {
				new = "-"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", d.Name, d.ChangeType, old, new))
		}
		sb.WriteString("\n")
	}

	// File changes
	if len(report.FileChanges) > 0 {
		sb.WriteString("## Changed Files\n\n")
		sb.WriteString("<details>\n<summary>Click to expand file list</summary>\n\n")
		sb.WriteString("| File | +/- |\n")
		sb.WriteString("|------|-----|\n")
		for _, f := range report.FileChanges {
			sb.WriteString(fmt.Sprintf("| %s | +%d/-%d |\n", f.Path, f.Additions, f.Deletions))
		}
		sb.WriteString("\n</details>\n\n")
	}

	// Audit template
	sb.WriteString("## Audit Template\n\n")
	sb.WriteString("```toml\n")
	sb.WriteString(fmt.Sprintf("[[audits.%s]]\n", report.CrateName))
	sb.WriteString("who = \"Your Name <your.email@example.com>\"\n")
	sb.WriteString("criteria = [\"safe-to-deploy\", \"does-not-implement-crypto\"]  # Adjust based on review\n")
	if report.FromRef != "" {
		sb.WriteString(fmt.Sprintf("delta = \"%s -> %s\"\n", report.FromRef, report.Version))
	} else {
		sb.WriteString(fmt.Sprintf("version = \"%s\"\n", report.Version))
	}
	sb.WriteString("notes = \"Reviewed via re-audit tool\"\n")
	sb.WriteString("```\n\n")

	sb.WriteString("---\n*Generated by [re-audit](https://github.com/hjanuschka/re-audit)*\n")

	return sb.String()
}

func main() {
	repoPath := flag.String("repo", ".", "Path to the Rust repository")
	fromRef := flag.String("from", "", "Base commit/tag (current release)")
	toRef := flag.String("to", "HEAD", "Target commit/tag (next release)")
	format := flag.String("format", "markdown", "Output format: markdown or json")
	output := flag.String("output", "", "Output file (default: stdout)")

	flag.Parse()

	// Allow positional arg for repo path
	if flag.NArg() > 0 {
		*repoPath = flag.Arg(0)
	}

	analyzer := NewAnalyzer(*repoPath, *fromRef, *toRef)
	report, err := analyzer.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var out string
	if *format == "json" {
		data, _ := json.MarshalIndent(report, "", "  ")
		out = string(data)
	} else {
		out = generateMarkdown(report)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(out), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *output)
	} else {
		fmt.Print(out)
	}
}
