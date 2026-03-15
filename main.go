package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// --- Types ---------------------------------------------------------------

type match struct {
	Line   int
	Col    int
	Reason string
}

type fileResult struct {
	Path       string
	Matches    []match
	MatchCount int // total matches (may exceed len(Matches) due to cap)
}

type skippedEntry struct {
	Path   string
	Reason string
}

// --- Unicode detection ---------------------------------------------------

type scanOpts struct {
	allowEscape bool
	allowEmoji  bool
}

// isForbidden returns true for characters that should not appear in source
// code: control characters (except tab/LF/CR), Unicode format characters
// (zero-width, bidi overrides), private-use area, and variation selectors.
func isForbidden(r rune, opts scanOpts) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	if r == 0x1B && opts.allowEscape {
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
	// VS15 (U+FE0E) and VS16 (U+FE0F) are emoji presentation selectors;
	// --allow-emoji permits these two while still flagging VS1-VS14.
	if r >= 0xFE00 && r <= 0xFE0F {
		if opts.allowEmoji && (r == 0xFE0E || r == 0xFE0F) {
			return false
		}
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

// --- File scanning -------------------------------------------------------

// maxMatchesPerFile caps the number of detailed matches stored per file.
// Beyond this limit, only the total count is tracked. This prevents
// multi-gigabyte allocations when scanning large binary files.
const maxMatchesPerFile = 20

// scanBytes checks content for forbidden characters and invalid UTF-8.
func scanBytes(data []byte, opts scanOpts) ([]match, int) {
	var matches []match
	total := 0

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
				})
			}
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

	// Append a summary if matches were truncated.
	if total > maxMatchesPerFile {
		matches = append(matches, match{
			Reason: fmt.Sprintf("... and %d more matches", total-maxMatchesPerFile),
		})
	}

	return matches, total
}

func scanFile(path string, opts scanOpts) *fileResult {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	matches, total := scanBytes(data, opts)
	if total == 0 {
		return nil
	}
	return &fileResult{Path: path, Matches: matches, MatchCount: total}
}

// --- Skip matching -------------------------------------------------------

// matchesSkip checks whether a relative path matches any skip pattern.
//
// Three pattern forms are supported:
//   - Simple (no separator): matched against each individual path component.
//     "vendor" matches "a/vendor/b".
//   - Path with "**": recursive glob. "**" matches zero or more directories.
//     "pkg/**/fonts/**/*.woff*" matches at any depth.
//   - Path without "**": matched as a glob against the full relative path,
//     then as a literal prefix. "resources/icons" matches
//     "resources/icons/logo.svg".
func matchesSkip(relPath string, patterns []string) (bool, string) {
	sep := string(filepath.Separator)
	components := strings.Split(relPath, sep)
	for _, p := range patterns {
		switch {
		case strings.Contains(p, "**"):
			if matchDoublestar(relPath, p) {
				return true, p
			}
		case strings.Contains(p, sep):
			// Path pattern: match against full relative path.
			if matched, _ := filepath.Match(p, relPath); matched {
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
		default:
			// Simple pattern: match against any single path component.
			for _, c := range components {
				if matched, _ := filepath.Match(p, c); matched {
					return true, p
				}
			}
		}
	}
	return false, ""
}

// matchDoublestar matches a path against a pattern containing "**".
// "**" matches zero or more path components.
func matchDoublestar(path, pattern string) bool {
	sep := string(filepath.Separator)
	return matchParts(
		strings.Split(pattern, sep),
		strings.Split(path, sep),
	)
}

func matchParts(patParts, pathParts []string) bool {
	for len(patParts) > 0 {
		if patParts[0] == "**" {
			rest := patParts[1:]
			// "**" at end of pattern matches everything.
			if len(rest) == 0 {
				return true
			}
			// Try matching the rest against every suffix of the path.
			for i := 0; i <= len(pathParts); i++ {
				if matchParts(rest, pathParts[i:]) {
					return true
				}
			}
			return false
		}
		if len(pathParts) == 0 {
			return false
		}
		matched, _ := filepath.Match(patParts[0], pathParts[0])
		if !matched {
			return false
		}
		patParts = patParts[1:]
		pathParts = pathParts[1:]
	}
	return len(pathParts) == 0
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
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" && !opts.all {
					return filepath.SkipDir
				}
				relPath, _ := filepath.Rel(dir, path)
				if matched, pattern := matchesSkip(relPath, opts.skipPatterns); matched {
					result.Skipped = append(result.Skipped, skippedEntry{
						Path:   path + "/",
						Reason: fmt.Sprintf("--skip %s", pattern),
					})
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			relPath, _ := filepath.Rel(dir, path)
			if matched, pattern := matchesSkip(relPath, opts.skipPatterns); matched {
				result.Skipped = append(result.Skipped, skippedEntry{
					Path:   path,
					Reason: fmt.Sprintf("--skip %s", pattern),
				})
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

func applyFilters(raw []string, dir string, opts listOpts) ([]string, []skippedEntry) {
	var files []string
	var skipped []skippedEntry

	for _, f := range raw {
		relPath, _ := filepath.Rel(dir, f)
		if matched, pattern := matchesSkip(relPath, opts.skipPatterns); matched {
			skipped = append(skipped, skippedEntry{
				Path:   f,
				Reason: fmt.Sprintf("--skip %s", pattern),
			})
			continue
		}
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

// --- Main ----------------------------------------------------------------

func main() {
	var (
		quiet        bool
		verbose      bool
		all          bool
		gitignore    bool
		allowEscape  bool
		allowEmoji   bool
		diffBase     string
		skipPatterns []string
		skipExts     []string
	)

	rootCmd := &cobra.Command{
		Use:   "nobin [directory]",
		Short: "Scan for non-printable and invisible characters",
		Long: `Scan a directory for files containing non-printable or invisible characters:
ASCII controls, zero-width Unicode, bidi overrides, variation selectors
(Glassworm-style), private-use area, and invalid UTF-8.

By default, scans all files except the .git directory. Use --skip and
--skip-ext to exclude paths; skipped entries are listed in the output
as a reminder that coverage is incomplete.`,
		Version:       version,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}
			return run(dir, runOpts{
				quiet:        quiet,
				verbose:      verbose,
				all:          all,
				gitignore:    gitignore,
				allowEscape:  allowEscape,
				allowEmoji:   allowEmoji,
				diffBase:     diffBase,
				skipPatterns: skipPatterns,
				skipExts:     skipExts,
			})
		},
	}

	f := rootCmd.Flags()
	f.BoolVarP(&quiet, "quiet", "q", false, "print only file paths with issues")
	f.BoolVarP(&verbose, "verbose", "v", false, "show line, column, and code point for each match")
	f.BoolVar(&all, "all", false, "include .git directory (excluded by default)")
	f.BoolVar(&gitignore, "gitignore", false, "respect .gitignore rules")
	f.BoolVar(&allowEscape, "allow-escape", false, "allow ESC (0x1B) for ANSI terminal sequences")
	f.BoolVar(&allowEmoji, "allow-emoji", false, "allow VS15/VS16 (U+FE0E, U+FE0F) emoji presentation selectors")
	f.StringVar(&diffBase, "diff", "", "scan only files changed since BASE (branch, tag, or commit)")
	f.StringArrayVar(&skipPatterns, "skip", nil, "skip paths matching glob `PATTERN` relative to scan root (repeatable)")
	f.StringSliceVar(&skipExts, "skip-ext", nil, "skip files with these extensions (comma-separated, without dot)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "nobin: %v\n", err)
		os.Exit(1)
	}
}

type runOpts struct {
	quiet        bool
	verbose      bool
	all          bool
	gitignore    bool
	allowEscape  bool
	allowEmoji   bool
	diffBase     string
	skipPatterns []string
	skipExts     []string
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

	// Scan files in parallel.
	workers := runtime.NumCPU()
	ch := make(chan string, workers)
	resultCh := make(chan *fileResult, workers)

	sopts := scanOpts{allowEscape: opts.allowEscape, allowEmoji: opts.allowEmoji}

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

	var results []*fileResult
	for r := range resultCh {
		results = append(results, r)
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
			n := r.MatchCount
			label := "matches"
			if n == 1 {
				label = "match"
			}
			fmt.Printf("%-60s  %d %s\n", r.Path, n, label)
		}
	}

	// Output skipped entries.
	if !opts.quiet && len(lr.Skipped) > 0 {
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
