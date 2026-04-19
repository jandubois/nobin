package main

//go:generate go -C internal/confusables/gen run .

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/jandubois/nobin/version"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// parseCodePoint parses a Unicode code point from a hex string.
// Accepts "U+FEFF", "u+feff", "0xFEFF", "0xfeff", "FEFF", or "feff".
func parseCodePoint(s string) (rune, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "U+"), "u+")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid code point %q: expected hex like U+FEFF, 0xFEFF, or FEFF", s)
	}
	if n > unicode.MaxRune {
		return 0, fmt.Errorf("code point %q exceeds Unicode maximum (U+10FFFF)", s)
	}
	return rune(n), nil
}

// --- Types ---------------------------------------------------------------

// matchKind classifies a match so the post-scan skip filter can drop
// hits of one category without disturbing the others.
type matchKind int

const (
	matchRune       matchKind = iota // forbidden char or invalid UTF-8
	matchBase64                      // base64-encoded data run
	matchConfusable                  // Latin-confusable code point
	matchSummary                     // truncation summary (synthetic)
)

type match struct {
	Line   int
	Col    int
	Reason string
	Kind   matchKind
}

type fileResult struct {
	Path            string
	Matches         []match
	MatchCount      int // total matches (may exceed len(Matches) due to cap)
	Base64Count     int
	ConfusableCount int
}

type skippedEntry struct {
	Path   string
	Reason string
}

// --- Unicode detection ---------------------------------------------------

type scanOpts struct {
	allowBom    bool
	allowRunes  map[rune]bool
	blockBase64 int
	confusables *unicode.RangeTable // nil = disabled
}

// isForbidden returns true for characters that should not appear in source
// code: control characters (except tab/LF/CR), Unicode format characters
// (zero-width, bidi overrides), private-use area, and variation selectors.
func isForbidden(r rune, opts scanOpts) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	if opts.allowRunes[r] {
		return false
	}
	// Cc: C0 controls, DEL, C1 controls
	if unicode.IsControl(r) {
		return true
	}
	// Cf: zero-width chars, bidi overrides, BOM, soft hyphen, etc.
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	// Co: private use area (BMP + supplementary)
	if unicode.Is(unicode.Co, r) {
		return true
	}
	// Variation Selectors (category Mn — not caught by Cf or Cc).
	// Used by Glassworm malware to encode invisible payloads.
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	if r >= 0xE0100 && r <= 0xE01EF {
		return true
	}
	return false
}

// runeDescription returns a human-readable name for a forbidden character.
func runeDescription(r rune) string {
	if name, ok := knownNames[r]; ok {
		return name
	}
	switch {
	case r >= 0x01 && r <= 0x1F:
		return "CONTROL"
	case r == 0x7F:
		return "DELETE"
	case r >= 0x80 && r <= 0x9F:
		return "CONTROL"
	case r >= 0xFE00 && r <= 0xFE0F:
		return fmt.Sprintf("VARIATION SELECTOR-%d", r-0xFE00+1)
	case r >= 0xE0100 && r <= 0xE01EF:
		return fmt.Sprintf("VARIATION SELECTOR-%d", r-0xE0100+17)
	case unicode.Is(unicode.Co, r):
		return "PRIVATE USE"
	case unicode.Is(unicode.Cf, r):
		return "FORMAT"
	default:
		return "UNKNOWN"
	}
}

var knownNames = map[rune]string{
	0x00:   "NULL",
	0x07:   "BELL",
	0x08:   "BACKSPACE",
	0x0B:   "VERTICAL TAB",
	0x0C:   "FORM FEED",
	0x1B:   "ESCAPE",
	0x7F:   "DELETE",
	0x85:   "NEXT LINE",
	0xAD:   "SOFT HYPHEN",
	0x200B: "ZERO WIDTH SPACE",
	0x200C: "ZERO WIDTH NON-JOINER",
	0x200D: "ZERO WIDTH JOINER",
	0x200E: "LEFT-TO-RIGHT MARK",
	0x200F: "RIGHT-TO-LEFT MARK",
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2060: "WORD JOINER",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
	0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
}

func formatReason(r rune) string {
	return fmt.Sprintf("U+%04X %s", r, runeDescription(r))
}

// --- Base64 detection ----------------------------------------------------

// isBase64Char matches most of the standard base64 alphabet. The /
// character is intentionally excluded because it causes false positives
// on URLs and file paths.
func isBase64Char(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '+'
}

func isPureHex(s []byte) bool {
	for _, b := range s {
		if !((b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}

// isIdentifierLike reports whether s looks like a code identifier:
// alphabetic characters with at most one contiguous group of digits.
// Returns false if s contains non-alphanumeric characters (like +).
func isIdentifierLike(s []byte) bool {
	digitGroups := 0
	i := 0
	for i < len(s) {
		b := s[i]
		if b >= '0' && b <= '9' {
			digitGroups++
			if digitGroups > 1 {
				return false
			}
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		} else if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
			i++
		} else {
			return false
		}
	}
	return true
}

// scanBase64 finds contiguous runs of base64 characters that are at least
// minLen bytes long, not purely hexadecimal, and not identifier-like.
func scanBase64(data []byte, minLen int) []match {
	var matches []match
	lineNum := 1
	lineStart := 0

	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		line := data[lineStart:i]
		j := 0
		for j < len(line) {
			if !isBase64Char(line[j]) {
				j++
				continue
			}
			start := j
			for j < len(line) && isBase64Char(line[j]) {
				j++
			}
			run := line[start:j]
			if len(run) >= minLen && !isPureHex(run) && !isIdentifierLike(run) {
				matches = append(matches, match{
					Line:   lineNum,
					Col:    start + 1,
					Reason: fmt.Sprintf("base64-encoded data (%d chars)", len(run)),
				})
			}
		}
		lineNum++
		lineStart = i + 1
	}
	return matches
}

// --- File scanning -------------------------------------------------------

// maxMatchesPerFile caps the number of detailed matches stored per file.
// Beyond this limit, only the total count is tracked. This prevents
// multi-gigabyte allocations when scanning large binary files.
const maxMatchesPerFile = 20

// scanBytes checks content for forbidden characters and invalid UTF-8.
func scanBytes(data []byte, opts scanOpts) ([]match, int, int, int) {
	var matches []match
	total := 0
	base64Count := 0
	confusableCount := 0

	line := 1
	col := 1
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])

		hit := false
		if r == utf8.RuneError && size == 1 {
			hit = true
			if total < maxMatchesPerFile {
				matches = append(matches, match{
					Line:   line,
					Col:    col,
					Reason: fmt.Sprintf("0x%02X invalid UTF-8", data[i]),
					Kind:   matchRune,
				})
			}
		} else if r == 0xFEFF && i == 0 && opts.allowBom {
			// BOM at file start — explicitly allowed.
		} else if isForbidden(r, opts) {
			hit = true
			if total < maxMatchesPerFile {
				reason := formatReason(r)
				if r == 0xFEFF && i == 0 {
					reason = "U+FEFF BOM (byte order mark)"
				}
				matches = append(matches, match{
					Line:   line,
					Col:    col,
					Reason: reason,
					Kind:   matchRune,
				})
			}
		} else if opts.confusables != nil && !opts.allowRunes[r] && unicode.Is(opts.confusables, r) {
			hit = true
			confusableCount++
			if total < maxMatchesPerFile {
				matches = append(matches, match{
					Line:   line,
					Col:    col,
					Reason: fmt.Sprintf("U+%04X Latin confusable", r),
					Kind:   matchConfusable,
				})
			}
		}
		if hit {
			total++
		}

		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
		i += size
	}

	if opts.blockBase64 > 0 {
		for _, m := range scanBase64(data, opts.blockBase64) {
			total++
			base64Count++
			if total <= maxMatchesPerFile {
				m.Kind = matchBase64
				matches = append(matches, m)
			}
		}
	}

	// Append a summary if matches were truncated.
	if total > maxMatchesPerFile {
		matches = append(matches, match{
			Reason: fmt.Sprintf("... and %d more matches", total-maxMatchesPerFile),
			Kind:   matchSummary,
		})
	}

	return matches, total, base64Count, confusableCount
}

func scanFile(path string, opts scanOpts) *fileResult {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	matches, total, base64Count, confusableCount := scanBytes(data, opts)
	if total == 0 {
		return nil
	}
	return &fileResult{
		Path:            path,
		Matches:         matches,
		MatchCount:      total,
		Base64Count:     base64Count,
		ConfusableCount: confusableCount,
	}
}

// --- Post-scan skip filter ----------------------------------------------

// skipFilterResult is the outcome of applying skip patterns to one
// scanned file. kept is the (possibly trimmed) result to report
// normally; nil means every hit was suppressed. skipped collects one
// entry per pattern that silenced something.
type skipFilterResult struct {
	kept    *fileResult
	skipped []skippedEntry
}

// applySkips evaluates the three pattern-based skip flags against a
// scanned file's hits. Files matching --skip drop out entirely;
// per-category skips trim only that category, leaving the rest.
func applySkips(r *fileResult, dir string, skip, skipBase64, skipConfusables []string) skipFilterResult {
	relPath, _ := filepath.Rel(dir, r.Path)

	if matched, pattern := matchesSkip(relPath, skip); matched {
		return skipFilterResult{
			skipped: []skippedEntry{{
				Path:   r.Path,
				Reason: fmt.Sprintf("--skip %s (%s)", pattern, summarizeCounts(r.MatchCount, r.Base64Count, r.ConfusableCount)),
			}},
		}
	}

	matches := r.Matches
	matchCount := r.MatchCount
	base64Count := r.Base64Count
	confusableCount := r.ConfusableCount
	var skipped []skippedEntry

	if base64Count > 0 && len(skipBase64) > 0 {
		if matched, pattern := matchesSkip(relPath, skipBase64); matched {
			skipped = append(skipped, skippedEntry{
				Path:   r.Path,
				Reason: fmt.Sprintf("--skip-base64 %s (%d base64)", pattern, base64Count),
			})
			matches = dropMatchKind(matches, matchBase64)
			matchCount -= base64Count
			base64Count = 0
		}
	}

	if confusableCount > 0 && len(skipConfusables) > 0 {
		if matched, pattern := matchesSkip(relPath, skipConfusables); matched {
			skipped = append(skipped, skippedEntry{
				Path:   r.Path,
				Reason: fmt.Sprintf("--skip-confusables %s (%d confusable)", pattern, confusableCount),
			})
			matches = dropMatchKind(matches, matchConfusable)
			matchCount -= confusableCount
			confusableCount = 0
		}
	}

	if matchCount == 0 {
		return skipFilterResult{skipped: skipped}
	}

	// Re-derive the truncation summary from the surviving counts.
	matches = dropMatchKind(matches, matchSummary)
	if matchCount > len(matches) {
		matches = append(matches, match{
			Reason: fmt.Sprintf("... and %d more matches", matchCount-len(matches)),
			Kind:   matchSummary,
		})
	}

	return skipFilterResult{
		kept: &fileResult{
			Path:            r.Path,
			Matches:         matches,
			MatchCount:      matchCount,
			Base64Count:     base64Count,
			ConfusableCount: confusableCount,
		},
		skipped: skipped,
	}
}

func dropMatchKind(in []match, drop matchKind) []match {
	out := make([]match, 0, len(in))
	for _, m := range in {
		if m.Kind != drop {
			out = append(out, m)
		}
	}
	return out
}

// summarizeCounts renders the same "N matches + M base64 + K confusable"
// breakdown used in the regular per-file output.
func summarizeCounts(total, base64, confusable int) string {
	rune := total - base64 - confusable
	var parts []string
	if rune > 0 {
		label := "match"
		if rune != 1 {
			label = "matches"
		}
		parts = append(parts, fmt.Sprintf("%d %s", rune, label))
	}
	if base64 > 0 {
		parts = append(parts, fmt.Sprintf("%d base64", base64))
	}
	if confusable > 0 {
		parts = append(parts, fmt.Sprintf("%d confusable", confusable))
	}
	return strings.Join(parts, " + ")
}

// --- Skip matching -------------------------------------------------------

// matchesSkip checks whether a relative path matches any skip pattern.
//
// Patterns without a path separator are matched against each individual
// path component (e.g. "vendor" matches "a/vendor/b"). Patterns with a
// separator are matched against the full relative path using doublestar
// glob syntax: **, *, ?, [class], and {alt1,alt2} are all supported.
// A pattern without wildcards also matches as a path prefix, so
// "resources/icons" matches "resources/icons/logo.svg".
func matchesSkip(relPath string, patterns []string) (bool, string) {
	sep := string(filepath.Separator)
	components := strings.Split(relPath, sep)
	for _, p := range patterns {
		if strings.Contains(p, sep) || strings.Contains(p, "**") {
			// Path pattern: full doublestar match.
			if matched, _ := doublestar.PathMatch(p, relPath); matched {
				return true, p
			}
			// Prefix match: "dir/sub" matches "dir/sub/file.txt".
			prefix := p
			if !strings.HasSuffix(prefix, sep) {
				prefix += sep
			}
			if strings.HasPrefix(relPath, prefix) || relPath == strings.TrimSuffix(p, sep) {
				return true, p
			}
		} else {
			// Simple pattern: match against any single path component.
			for _, c := range components {
				if matched, _ := doublestar.PathMatch(p, c); matched {
					return true, p
				}
			}
		}
	}
	return false, ""
}

// hasSkippedExt checks whether a filename ends with one of the given
// extensions (case-insensitive, without leading dot).
func hasSkippedExt(path string, exts []string) (bool, string) {
	lower := strings.ToLower(path)
	for _, ext := range exts {
		suffix := "." + strings.ToLower(ext)
		if strings.HasSuffix(lower, suffix) {
			return true, ext
		}
	}
	return false, ""
}

// --- File listing --------------------------------------------------------

func isGitRepo(dir string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	return cmd.Run() == nil
}

type fileListResult struct {
	Files   []string
	Skipped []skippedEntry
}

type listOpts struct {
	diffBase     string
	all          bool
	gitignore    bool
	skipPatterns []string
	skipExts     []string
}

func listFiles(dir string, opts listOpts) (*fileListResult, error) {
	result := &fileListResult{}

	switch {
	case opts.diffBase != "":
		files, err := gitDiffFiles(dir, opts.diffBase)
		if err != nil {
			return nil, err
		}
		result.Files, result.Skipped = applyFilters(files, dir, opts)

	case opts.gitignore && isGitRepo(dir):
		files, err := gitListFiles(dir)
		if err != nil {
			return nil, err
		}
		result.Files, result.Skipped = applyFilters(files, dir, opts)

	default:
		// --skip patterns no longer prune the walk: every file gets
		// scanned so the post-scan filter can flag skipped files that
		// would have triggered. Only --skip-ext (binary pre-filter)
		// and the default .git exclusion still cut the walk short.
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" && !opts.all {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if matched, ext := hasSkippedExt(path, opts.skipExts); matched {
				result.Skipped = append(result.Skipped, skippedEntry{
					Path:   path,
					Reason: fmt.Sprintf("--skip-ext %s", ext),
				})
				return nil
			}
			result.Files = append(result.Files, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// applyFilters processes a precomputed file list (from git ls-files or
// git diff). Only --skip-ext is honored here; --skip patterns are
// evaluated post-scan in run() so suppressed files can be reported
// only when they would have triggered.
func applyFilters(raw []string, _ string, opts listOpts) ([]string, []skippedEntry) {
	var files []string
	var skipped []skippedEntry

	for _, f := range raw {
		if matched, ext := hasSkippedExt(f, opts.skipExts); matched {
			skipped = append(skipped, skippedEntry{
				Path:   f,
				Reason: fmt.Sprintf("--skip-ext %s", ext),
			})
			continue
		}
		info, err := os.Lstat(f)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		files = append(files, f)
	}
	return files, skipped
}

func gitDiffFiles(dir, base string) ([]string, error) {
	cmd := exec.Command("git", "-C", dir, "diff",
		"--name-only", "--diff-filter=ACMR", base, "--")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	var files []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, filepath.Join(dir, line))
		}
	}
	return files, nil
}

func gitListFiles(dir string) ([]string, error) {
	seen := map[string]bool{}
	var files []string

	addOutput := func(output []byte) {
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				path := filepath.Join(dir, line)
				if !seen[path] {
					seen[path] = true
					files = append(files, path)
				}
			}
		}
	}

	// Tracked files, including submodules.
	out, err := exec.Command("git", "-C", dir, "ls-files",
		"--recurse-submodules").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	addOutput(out)

	// Untracked-but-not-ignored files in the main repo.
	// (--recurse-submodules does not support --others)
	out, err = exec.Command("git", "-C", dir, "ls-files",
		"--others", "--exclude-standard").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files --others: %w", err)
	}
	addOutput(out)

	return files, nil
}

// --- Confusables mode ----------------------------------------------------

// confusablesTableForMode returns the RangeTable for the named --block-confusables
// mode, nil if disabled (empty string), or an error for an unknown mode.
func confusablesTableForMode(mode string) (*unicode.RangeTable, error) {
	switch mode {
	case "":
		return nil, nil
	case "alphanum":
		return latinConfusablesAlphanum, nil
	case "url":
		return latinConfusablesURL, nil
	case "strict":
		return latinConfusablesStrict, nil
	default:
		return nil, fmt.Errorf("--block-confusables: unknown mode %q (expected alphanum, url, or strict)", mode)
	}
}

// --- Configuration -------------------------------------------------------

type config struct {
	All              bool     `yaml:"all"`
	Allow            []string `yaml:"allow"`
	AllowBell        bool     `yaml:"allow-bell"`
	AllowBom         bool     `yaml:"allow-bom"`
	AllowEmoji       bool     `yaml:"allow-emoji"`
	AllowEscape      bool     `yaml:"allow-escape"`
	BlockBase64      int      `yaml:"block-base64"`
	SkipBase64       []string `yaml:"skip-base64"`
	BlockConfusables string   `yaml:"block-confusables"`
	SkipConfusables  []string `yaml:"skip-confusables"`
	Gitignore        bool     `yaml:"gitignore"`
	HideSkipped      bool     `yaml:"hide-skipped"`
	Quiet            bool     `yaml:"quiet"`
	Skip             []string `yaml:"skip"`
	SkipExt          []string `yaml:"skip-ext"`
	Verbose          bool     `yaml:"verbose"`
}

const configFileName = ".nobin.yaml"

// findConfigFile returns the path to the config file and any error.
// It checks the explicit path first, then scanDir itself, then scanDir's
// git repository root. This lets `nobin /path/to/repo` find the config
// in /path/to/repo even when invoked from a different working directory.
func findConfigFile(explicit, scanDir string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("config file: %w", err)
		}
		return explicit, nil
	}

	scanPath := filepath.Join(scanDir, configFileName)
	if _, err := os.Stat(scanPath); err == nil {
		return scanPath, nil
	}

	cmd := exec.Command("git", "-C", scanDir, "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", nil
	}
	root := strings.TrimSpace(string(output))
	if root == "" {
		return "", nil
	}

	rootPath := filepath.Join(root, configFileName)
	if rootPath == scanPath {
		return "", nil
	}
	if _, err := os.Stat(rootPath); err == nil {
		return rootPath, nil
	}
	return "", nil
}

func loadConfig(path string) (config, error) {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}

// --- Main ----------------------------------------------------------------

func main() {
	var (
		quiet               bool
		verbose             bool
		all                 bool
		gitignore           bool
		allowEscape         bool
		allowEmoji          bool
		allowBom            bool
		allowBell           bool
		hideSkipped         bool
		diffBase            string
		skipPatterns        []string
		skipExts            []string
		allowCodePts        []string
		blockBase64Str      string
		skipBase64          []string
		blockConfusablesStr string
		skipConfusables     []string
		configFlag          string
	)

	rootCmd := &cobra.Command{
		Use:   "nobin [directory]",
		Short: "Scan for non-printable and invisible characters",
		Long: `Scan a directory for files containing non-printable or invisible characters:
ASCII controls, zero-width Unicode, bidi overrides, variation selectors
(Glassworm-style), private-use area, and invalid UTF-8. All files are
assumed to be UTF-8; other encodings are reported as invalid.

By default, scans all files except the .git directory. Use --skip and
--skip-ext to exclude paths; skipped entries are listed in the output
as a reminder that coverage is incomplete.

Settings can also be placed in a .nobin.yaml config file in the current
directory or git repository root. Command-line flags override config
values; list flags (--skip, --skip-ext, --allow) extend the config lists.

Skip patterns support glob syntax: * (any non-separator chars),
** (zero or more directories), ? (single char), [class] (character
class), and {alt1,alt2} (alternation). For example:
  --skip 'vendor'                  any component named vendor
  --skip '**/*.{woff,woff2}'       woff/woff2 files at any depth
  --skip 'pkg/**/fonts/**'         everything under fonts`,
		Version:       version.Version,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			// Load config file.
			var cfg config
			cfgPath, err := findConfigFile(configFlag, dir)
			if err != nil {
				return err
			}
			if cfgPath != "" {
				cfg, err = loadConfig(cfgPath)
				if err != nil {
					return err
				}
			}

			// CLI flags override config scalars when explicitly set.
			if cmd.Flags().Changed("all") {
				cfg.All = all
			}
			if cmd.Flags().Changed("block-confusables") {
				cfg.BlockConfusables = blockConfusablesStr
			}
			if cmd.Flags().Changed("allow-bell") {
				cfg.AllowBell = allowBell
			}
			if cmd.Flags().Changed("allow-bom") {
				cfg.AllowBom = allowBom
			}
			if cmd.Flags().Changed("allow-emoji") {
				cfg.AllowEmoji = allowEmoji
			}
			if cmd.Flags().Changed("allow-escape") {
				cfg.AllowEscape = allowEscape
			}
			if cmd.Flags().Changed("gitignore") {
				cfg.Gitignore = gitignore
			}
			if cmd.Flags().Changed("hide-skipped") {
				cfg.HideSkipped = hideSkipped
			}
			if cmd.Flags().Changed("quiet") {
				cfg.Quiet = quiet
			}
			if cmd.Flags().Changed("verbose") {
				cfg.Verbose = verbose
			}

			// CLI lists extend config lists.
			cfg.Allow = append(cfg.Allow, allowCodePts...)
			cfg.Skip = append(cfg.Skip, skipPatterns...)
			cfg.SkipBase64 = append(cfg.SkipBase64, skipBase64...)
			cfg.SkipConfusables = append(cfg.SkipConfusables, skipConfusables...)
			cfg.SkipExt = append(cfg.SkipExt, skipExts...)

			// Build the allowed-runes set from merged config.
			allowRunes := map[rune]bool{}
			if cfg.AllowEscape {
				allowRunes[0x1B] = true
			}
			if cfg.AllowBell {
				allowRunes[0x07] = true
			}
			if cfg.AllowEmoji {
				allowRunes[0xFE0E] = true
				allowRunes[0xFE0F] = true
			}
			for _, s := range cfg.Allow {
				r, err := parseCodePoint(s)
				if err != nil {
					return err
				}
				allowRunes[r] = true
			}

			// Handle --block-base64 (CLI overrides config when set).
			blockBase64 := cfg.BlockBase64
			if cmd.Flags().Changed("block-base64") {
				n, err := strconv.Atoi(blockBase64Str)
				if err != nil || n < 1 {
					return fmt.Errorf("--block-base64: expected positive integer, got %q", blockBase64Str)
				}
				blockBase64 = n
			}

			// Resolve --block-confusables mode to a RangeTable (or nil).
			confusablesTable, err := confusablesTableForMode(cfg.BlockConfusables)
			if err != nil {
				return err
			}

			if cfgPath != "" && !cfg.Quiet {
				fmt.Fprintf(os.Stderr, "Config: %s\n", cfgPath)
			}

			return run(dir, runOpts{
				allowBom:        cfg.AllowBom,
				allowRunes:      allowRunes,
				quiet:           cfg.Quiet,
				verbose:         cfg.Verbose,
				all:             cfg.All,
				gitignore:       cfg.Gitignore,
				hideSkipped:     cfg.HideSkipped,
				diffBase:        diffBase,
				skipPatterns:    cfg.Skip,
				skipExts:        cfg.SkipExt,
				blockBase64:     blockBase64,
				skipBase64:      cfg.SkipBase64,
				confusables:     confusablesTable,
				skipConfusables: cfg.SkipConfusables,
			})
		},
	}

	f := rootCmd.Flags()
	f.BoolVarP(&quiet, "quiet", "q", false, "print only file paths with issues")
	f.BoolVarP(&verbose, "verbose", "v", false, "show line, column, and code point for each match")
	f.BoolVar(&all, "all", false, "include .git directory (excluded by default)")
	f.BoolVar(&gitignore, "gitignore", false, "respect .gitignore rules")
	f.BoolVar(&allowBell, "allow-bell", false, "allow BEL (0x07)")
	f.BoolVar(&allowBom, "allow-bom", false, "allow UTF-8 BOM at the start of files")
	f.BoolVar(&allowEmoji, "allow-emoji", false, "allow VS15/VS16 (U+FE0E, U+FE0F) emoji presentation selectors")
	f.BoolVar(&allowEscape, "allow-escape", false, "allow ESC (0x1B) for ANSI terminal sequences")
	f.StringArrayVar(&allowCodePts, "allow", nil, "allow a specific code point, as hex: U+FEFF, 0xFEFF, or FEFF (repeatable)")
	f.BoolVar(&hideSkipped, "hide-skipped", false, "hide the list of skipped files from output")
	f.StringVar(&configFlag, "config", "", "path to config file (default: .nobin.yaml in current directory or git root)")
	f.StringVar(&diffBase, "diff", "", "scan only files changed since BASE (branch, tag, or commit)")
	f.StringArrayVar(&skipPatterns, "skip", nil, "skip paths matching glob `PATTERN` relative to scan root (repeatable)")
	f.StringArrayVar(&skipBase64, "skip-base64", nil, "skip base64 detection for paths matching glob `PATTERN` (repeatable)")
	f.StringSliceVar(&skipExts, "skip-ext", nil, "skip files with these extensions (comma-separated, without dot)")
	f.StringVar(&blockBase64Str, "block-base64", "", "detect base64-encoded strings at least `N` characters long (default 32; override with =N, e.g. --block-base64=64)")
	rootCmd.Flag("block-base64").NoOptDefVal = "32"
	f.StringVar(&blockConfusablesStr, "block-confusables", "", "detect non-ASCII code points that mimic ASCII (`MODE`: alphanum, url, or strict; default alphanum; override with =MODE)")
	rootCmd.Flag("block-confusables").NoOptDefVal = "alphanum"
	f.StringArrayVar(&skipConfusables, "skip-confusables", nil, "skip confusable detection for paths matching glob `PATTERN` (repeatable)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "nobin: %v\n", err)
		os.Exit(1)
	}
}

type runOpts struct {
	quiet           bool
	verbose         bool
	all             bool
	gitignore       bool
	allowBom        bool
	allowRunes      map[rune]bool
	hideSkipped     bool
	diffBase        string
	skipPatterns    []string
	skipExts        []string
	blockBase64     int
	skipBase64      []string
	confusables     *unicode.RangeTable
	skipConfusables []string
}

func run(dir string, opts runOpts) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	lr, err := listFiles(dir, listOpts{
		diffBase:     opts.diffBase,
		all:          opts.all,
		gitignore:    opts.gitignore,
		skipPatterns: opts.skipPatterns,
		skipExts:     opts.skipExts,
	})
	if err != nil {
		return err
	}

	if !opts.quiet {
		fmt.Fprintf(os.Stderr, "Scanning %s (%d files) ...\n", dir, len(lr.Files))
	}

	// Scan every file with full detection. The post-scan filter below
	// applies --skip / --skip-base64 / --skip-confusables, suppressing
	// hits silently and surfacing each suppressed file in the Skipped
	// report only when it would otherwise have triggered.
	workers := runtime.NumCPU()
	ch := make(chan string, workers)
	resultCh := make(chan *fileResult, workers)

	sopts := scanOpts{
		allowBom:    opts.allowBom,
		allowRunes:  opts.allowRunes,
		blockBase64: opts.blockBase64,
		confusables: opts.confusables,
	}

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range ch {
				if r := scanFile(path, sopts); r != nil {
					resultCh <- r
				}
			}
		}()
	}

	go func() {
		for _, f := range lr.Files {
			ch <- f
		}
		close(ch)
		wg.Wait()
		close(resultCh)
	}()

	var raw []*fileResult
	for r := range resultCh {
		raw = append(raw, r)
	}

	results := make([]*fileResult, 0, len(raw))
	for _, r := range raw {
		filtered := applySkips(r, dir, opts.skipPatterns, opts.skipBase64, opts.skipConfusables)
		lr.Skipped = append(lr.Skipped, filtered.skipped...)
		if filtered.kept != nil {
			results = append(results, filtered.kept)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Path < results[j].Path
	})

	// Output issues.
	for _, r := range results {
		switch {
		case opts.quiet:
			fmt.Println(r.Path)
		case opts.verbose:
			for _, m := range r.Matches {
				fmt.Printf("%-50s  %s\n",
					fmt.Sprintf("%s:%d:%d", r.Path, m.Line, m.Col),
					m.Reason)
			}
		default:
			fmt.Printf("%-60s  %s\n", r.Path,
				summarizeCounts(r.MatchCount, r.Base64Count, r.ConfusableCount))
		}
	}

	// Output skipped entries.
	if !opts.quiet && !opts.hideSkipped && len(lr.Skipped) > 0 {
		sort.Slice(lr.Skipped, func(i, j int) bool {
			return lr.Skipped[i].Path < lr.Skipped[j].Path
		})
		fmt.Println()
		fmt.Println("Skipped:")
		for _, s := range lr.Skipped {
			fmt.Printf("  %-58s  %s\n", s.Path, s.Reason)
		}
	}

	if !opts.quiet {
		fmt.Fprintf(os.Stderr, "---\nScanned %d files, found %d with issues.\n",
			len(lr.Files), len(results))
	}

	if len(results) > 0 {
		os.Exit(1)
	}
	return nil
}
