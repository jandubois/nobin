package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// --- Configuration -------------------------------------------------------

// Default binary-extension filter. Files matching this pattern are skipped.
var defaultSkipExtRE = regexp.MustCompile(
	`(?i)\.(png|jpe?g|gif|bmp|ico|webp|tiff?|pdf|eps|ps|` +
		`woff2?|ttf|otf|eot|mp[34]|avi|mov|mkv|flv|wav|ogg|flac|aac|` +
		`zip|gz|bz2|xz|zst|lz4|tar|rar|7z|jar|war|ear|` +
		`whl|gem|deb|rpm|apk|dmg|iso|img|` +
		`bin|exe|dll|so|dylib|o|a|lib|` +
		`pyc|pyo|class|wasm|sqlite|db|mdb|` +
		`DS_Store|mo|pot|pb\.desc)$`)

// --- Types ---------------------------------------------------------------

type match struct {
	Line   int
	Col    int
	Reason string
}

type fileResult struct {
	Path    string
	Matches []match
}

// --- Unicode detection ---------------------------------------------------

// isForbidden returns true for characters that should not appear in source
// code: control characters (except tab/LF/CR), Unicode format characters
// (zero-width, bidi overrides), private-use area, and variation selectors.
func isForbidden(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
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

// --- File scanning -------------------------------------------------------

// scanBytes checks content for forbidden characters and invalid UTF-8.
func scanBytes(data []byte) []match {
	var matches []match

	line := 1
	col := 1
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])

		if r == utf8.RuneError && size == 1 {
			matches = append(matches, match{
				Line:   line,
				Col:    col,
				Reason: fmt.Sprintf("0x%02X invalid UTF-8", data[i]),
			})
		} else if isForbidden(r) {
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

		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
		i += size
	}

	return matches
}

func scanFile(path string) *fileResult {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	matches := scanBytes(data)
	if len(matches) == 0 {
		return nil
	}
	return &fileResult{Path: path, Matches: matches}
}

// --- File listing --------------------------------------------------------

func isGitRepo(dir string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	return cmd.Run() == nil
}

func listFiles(dir, diffBase string, useGitignore bool, skipExtRE *regexp.Regexp) ([]string, error) {
	var raw []string

	switch {
	case diffBase != "":
		cmd := exec.Command("git", "-C", dir, "diff",
			"--name-only", "--diff-filter=ACMR", diffBase, "--")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git diff: %w", err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				raw = append(raw, filepath.Join(dir, line))
			}
		}

	case useGitignore && isGitRepo(dir):
		cmd := exec.Command("git", "-C", dir, "ls-files",
			"--cached", "--others", "--exclude-standard")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git ls-files: %w", err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				raw = append(raw, filepath.Join(dir, line))
			}
		}

	default:
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				raw = append(raw, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// Filter by extension and skip non-regular files.
	var files []string
	for _, f := range raw {
		if skipExtRE != nil && skipExtRE.MatchString(f) {
			continue
		}
		info, err := os.Lstat(f)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		files = append(files, f)
	}
	return files, nil
}

// --- Main ----------------------------------------------------------------

func main() {
	diffBase := flag.String("diff", "", "scan only files changed since `BASE` (branch, tag, or commit)")
	quiet := flag.Bool("quiet", false, "print only file paths")
	verbose := flag.Bool("verbose", false, "show line, column, and code point for each match")
	skipExt := flag.String("skip-ext", "", "override the binary-extension filter (`REGEXP`)")
	noSkipExt := flag.Bool("no-skip-ext", false, "disable extension filtering; scan all files")
	noGitignore := flag.Bool("no-gitignore", false, "scan all files, ignoring .gitignore")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: nobin [OPTIONS] [DIRECTORY]

Scan DIRECTORY (default: current directory) for files containing non-printable
or invisible characters: ASCII controls, zero-width Unicode, bidi overrides,
variation selectors (Glassworm-style), private-use area, and invalid UTF-8.

Options:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	dir := "."
	if flag.NArg() > 0 {
		dir = flag.Arg(0)
	}

	// Validate directory.
	info, err := os.Stat(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nobin: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "nobin: %s is not a directory\n", dir)
		os.Exit(1)
	}

	// Build skip-extension regex.
	var skipExtRE *regexp.Regexp
	if !*noSkipExt {
		if *skipExt != "" {
			skipExtRE, err = regexp.Compile(*skipExt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "nobin: invalid --skip-ext pattern: %v\n", err)
				os.Exit(1)
			}
		} else {
			skipExtRE = defaultSkipExtRE
		}
	}

	// List files.
	files, err := listFiles(dir, *diffBase, !*noGitignore, skipExtRE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nobin: %v\n", err)
		os.Exit(1)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "Scanning %s (%d files) ...\n", dir, len(files))
	}

	// Scan files in parallel.
	workers := runtime.NumCPU()
	ch := make(chan string, workers)
	resultCh := make(chan *fileResult, workers)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range ch {
				if r := scanFile(path); r != nil {
					resultCh <- r
				}
			}
		}()
	}

	go func() {
		for _, f := range files {
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

	// Output.
	for _, r := range results {
		switch {
		case *quiet:
			fmt.Println(r.Path)
		case *verbose:
			for _, m := range r.Matches {
				fmt.Printf("%-50s  %s\n",
					fmt.Sprintf("%s:%d:%d", r.Path, m.Line, m.Col),
					m.Reason)
			}
		default:
			n := len(r.Matches)
			label := "matches"
			if n == 1 {
				label = "match"
			}
			fmt.Printf("%-60s  %d %s\n", r.Path, n, label)
		}
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "---\nScanned %d files, found %d with issues.\n",
			len(files), len(results))
	}

	if len(results) > 0 {
		os.Exit(1)
	}
}
