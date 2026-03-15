package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --- isForbidden ---------------------------------------------------------

func TestIsForbidden(t *testing.T) {
	allowed := []struct {
		name string
		r    rune
	}{
		{"tab", '\t'},
		{"LF", '\n'},
		{"CR", '\r'},
		{"space", ' '},
		{"printable ASCII a", 'a'},
		{"printable ASCII tilde", '~'},
		{"accented e", 'é'},
		{"emoji thumbs up", '👍'},
		{"CJK character", '中'},
		{"Arabic letter", 'ع'},
	}
	for _, tt := range allowed {
		t.Run("allow/"+tt.name, func(t *testing.T) {
			if isForbidden(tt.r, scanOpts{}) {
				t.Errorf("isForbidden(%U) = true, want false", tt.r)
			}
		})
	}

	forbidden := []struct {
		name string
		r    rune
	}{
		// C0 controls
		{"NULL", 0x00},
		{"BEL", 0x07},
		{"BS", 0x08},
		{"VT", 0x0B},
		{"FF", 0x0C},
		{"ESC", 0x1B},
		{"DEL", 0x7F},
		// C1 controls
		{"NEL", 0x85},
		{"SS2", 0x8E},
		{"CSI", 0x9B},
		// Zero-width / format (Cf)
		{"ZERO WIDTH SPACE", 0x200B},
		{"ZERO WIDTH NON-JOINER", 0x200C},
		{"ZERO WIDTH JOINER", 0x200D},
		{"LRO", 0x202D},
		{"RLO", 0x202E},
		{"WORD JOINER", 0x2060},
		{"RLI", 0x2067},
		{"ZWNBSP", 0xFEFF},
		{"SOFT HYPHEN", 0xAD},
		// Private Use Area
		{"PUA start", 0xE000},
		{"PUA end", 0xF8FF},
		{"PUA-A", 0xF0000},
		// Variation Selectors
		{"VS1", 0xFE00},
		{"VS16", 0xFE0F},
		{"VS17", 0xE0100},
		{"VS256", 0xE01EF},
	}
	for _, tt := range forbidden {
		t.Run("forbid/"+tt.name, func(t *testing.T) {
			if !isForbidden(tt.r, scanOpts{}) {
				t.Errorf("isForbidden(%U) = false, want true", tt.r)
			}
		})
	}

	// ESC is forbidden by default but allowed with allowEscape.
	t.Run("ESC/default", func(t *testing.T) {
		if !isForbidden(0x1B, scanOpts{}) {
			t.Error("ESC should be forbidden by default")
		}
	})
	t.Run("ESC/allow-escape", func(t *testing.T) {
		if isForbidden(0x1B, scanOpts{allowEscape: true}) {
			t.Error("ESC should be allowed with allowEscape")
		}
	})
}

// --- scanBytes -----------------------------------------------------------

func TestScanBytes(t *testing.T) {
	tests := []struct {
		name        string
		content     []byte
		wantMatches bool
		wantReasons []string // substrings that must appear in at least one reason
	}{
		// Clean files
		{"clean ASCII", []byte("hello world\n"), false, nil},
		{"clean UTF-8 accents", []byte("const x = \"\xc3\xa9l\xc3\xa8ve\";\n"), false, nil},
		{"clean emoji", []byte("# Comment with emoji \xf0\x9f\x91\x8d\n"), false, nil},
		{"clean newlines", []byte("line one\nline two\n"), false, nil},
		{"clean tabs", []byte("col1\tcol2\tcol3\n"), false, nil},
		{"clean CRLF", []byte("line\r\nwindows\r\n"), false, nil},
		{"empty", []byte{}, false, nil},

		// ASCII controls
		{"NUL", []byte("a\x00b\n"), true, []string{"U+0000", "NULL"}},
		{"BEL", []byte("a\x07b\n"), true, []string{"U+0007", "BELL"}},
		{"BS", []byte("a\x08b\n"), true, []string{"U+0008", "BACKSPACE"}},
		{"VT", []byte("a\x0bb\n"), true, []string{"U+000B", "VERTICAL TAB"}},
		{"FF", []byte("a\x0cb\n"), true, []string{"U+000C", "FORM FEED"}},
		{"ESC", []byte("a\x1b[31mb\n"), true, []string{"U+001B", "ESCAPE"}},
		{"DEL", []byte("a\x7fb\n"), true, []string{"U+007F", "DELETE"}},

		// C1 controls
		{"NEL", []byte("a\xc2\x85b\n"), true, []string{"U+0085", "NEXT LINE"}},
		{"SS2", []byte("a\xc2\x8eb\n"), true, []string{"U+008E", "CONTROL"}},

		// Zero-width / format (Cf)
		{"ZWSP", []byte("hello\xe2\x80\x8bworld\n"), true, []string{"U+200B", "ZERO WIDTH SPACE"}},
		{"ZWNJ", []byte("foo\xe2\x80\x8cbar\n"), true, []string{"U+200C", "ZERO WIDTH NON-JOINER"}},
		{"ZWJ", []byte("foo\xe2\x80\x8dbar\n"), true, []string{"U+200D", "ZERO WIDTH JOINER"}},
		{"WORD JOINER", []byte("foo\xe2\x81\xa0bar\n"), true, []string{"U+2060", "WORD JOINER"}},
		{"FEFF mid-file", []byte("x\xef\xbb\xbfy\n"), true, []string{"U+FEFF", "ZERO WIDTH NO-BREAK SPACE"}},

		// Bidi overrides
		{"LRO", []byte("a\xe2\x80\xadb\n"), true, []string{"U+202D"}},
		{"RLO", []byte("a\xe2\x80\xaeb\xe2\x80\xacc\n"), true, []string{"U+202E"}},
		{"RLI", []byte("a\xe2\x81\xa7b\n"), true, []string{"U+2067"}},

		// Private Use Area
		{"PUA BMP", []byte("a\xee\x80\x80b\n"), true, []string{"U+E000", "PRIVATE USE"}},
		{"PUA Supp-A", []byte("a\xf3\xb0\x80\x80b\n"), true, []string{"PRIVATE USE"}},

		// Variation Selectors (Glassworm)
		{"VS1", []byte("a\xef\xb8\x80b\n"), true, []string{"U+FE00", "VARIATION SELECTOR-1"}},
		{"VS16", []byte("a\xef\xb8\x8fb\n"), true, []string{"U+FE0F", "VARIATION SELECTOR-16"}},
		{"VS17", []byte("a\xf3\xa0\x84\x80b\n"), true, []string{"U+E0100", "VARIATION SELECTOR-17"}},
		{"VS256", []byte("a\xf3\xa0\x87\xafb\n"), true, []string{"U+E01EF", "VARIATION SELECTOR-256"}},

		// BOM
		{"BOM at start", []byte("\xef\xbb\xbfhello\n"), true, []string{"BOM"}},

		// Invalid UTF-8
		{"invalid UTF-8", []byte("a\xff\xfeb\n"), true, []string{"invalid UTF-8"}},

		// Mixed
		{"multiple issues", []byte("a\xe2\x80\x8bb\xe2\x80\xaec\xee\x80\x80d\n"), true,
			[]string{"U+200B", "U+202E", "U+E000"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, total := scanBytes(tt.content, scanOpts{})
			gotMatches := total > 0

			if gotMatches != tt.wantMatches {
				t.Errorf("scanBytes() returned %d matches, wantMatches=%v",
					len(matches), tt.wantMatches)
				for _, m := range matches {
					t.Logf("  line %d col %d: %s", m.Line, m.Col, m.Reason)
				}
				return
			}

			// Verify expected reasons appear.
			allReasons := ""
			for _, m := range matches {
				allReasons += m.Reason + "\n"
			}
			for _, want := range tt.wantReasons {
				if !strings.Contains(allReasons, want) {
					t.Errorf("expected %q in reasons, got:\n%s", want, allReasons)
				}
			}
		})
	}
}

// --- scanBytes: line/column tracking -------------------------------------

func TestScanBytesPosition(t *testing.T) {
	// Forbidden char at line 2, col 5
	content := []byte("abcd\nefgh\xe2\x80\x8bijk\n")
	matches, total := scanBytes(content, scanOpts{})
	if total != 1 {
		t.Fatalf("expected 1 match, got %d", total)
	}
	m := matches[0]
	if m.Line != 2 || m.Col != 5 {
		t.Errorf("position = %d:%d, want 2:5", m.Line, m.Col)
	}
}

// --- scanBytes: truncation -----------------------------------------------

func TestScanBytesTruncation(t *testing.T) {
	// Build a file with 100 null bytes — well over maxMatchesPerFile.
	data := make([]byte, 100)
	matches, total := scanBytes(data, scanOpts{})
	if total != 100 {
		t.Errorf("total = %d, want 100", total)
	}
	if len(matches) != maxMatchesPerFile+1 {
		t.Errorf("len(matches) = %d, want %d (cap + summary)",
			len(matches), maxMatchesPerFile+1)
	}
	last := matches[len(matches)-1]
	if !strings.Contains(last.Reason, "more matches") {
		t.Errorf("last match should be truncation summary, got: %s", last.Reason)
	}
}

// --- scanFile (integration) ----------------------------------------------

func TestScanFile(t *testing.T) {
	dir := t.TempDir()

	clean := filepath.Join(dir, "clean.js")
	os.WriteFile(clean, []byte("const x = 42;\n"), 0644)
	if r := scanFile(clean, scanOpts{}); r != nil {
		t.Errorf("clean file produced %d matches", len(r.Matches))
	}

	dirty := filepath.Join(dir, "dirty.js")
	os.WriteFile(dirty, []byte("const x = \"\xe2\x80\x8b\";\n"), 0644)
	if r := scanFile(dirty, scanOpts{}); r == nil {
		t.Error("dirty file produced no matches")
	}

	empty := filepath.Join(dir, "empty.txt")
	os.WriteFile(empty, []byte{}, 0644)
	if r := scanFile(empty, scanOpts{}); r != nil {
		t.Error("empty file should produce no matches")
	}

	missing := filepath.Join(dir, "missing.txt")
	if r := scanFile(missing, scanOpts{}); r != nil {
		t.Error("missing file should produce no matches")
	}
}

// --- matchesSkip ---------------------------------------------------------

func TestMatchesSkip(t *testing.T) {
	tests := []struct {
		path     string
		patterns []string
		want     bool
	}{
		// Simple patterns (no path separator)
		{"vendor/pkg/foo.go", []string{"vendor"}, true},
		{"src/vendor/foo.go", []string{"vendor"}, true},
		{"src/main.go", []string{"vendor"}, false},
		{"foo.pb.desc", []string{"*.pb.desc"}, true},
		{"src/foo.pb.desc", []string{"*.pb.desc"}, true},
		{"src/main.go", []string{"*.pb.desc"}, false},
		{"node_modules/pkg/index.js", []string{"node_modules"}, true},
		{"a/b/c.txt", []string{"b"}, true},
		{"a/b/c.txt", []string{"d"}, false},

		// Path patterns (with separator) — prefix matching
		{"resources/icons/logo.svg", []string{"resources/icons"}, true},
		{"resources/icons", []string{"resources/icons"}, true},
		{"resources", []string{"resources/icons"}, false},
		{"other/icons/logo.svg", []string{"resources/icons"}, false},

		// Path patterns — glob matching
		{"resources/foo.bin", []string{"resources/*"}, true},
		{"resources/sub/foo.bin", []string{"resources/*"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, _ := matchesSkip(tt.path, tt.patterns)
			if got != tt.want {
				t.Errorf("matchesSkip(%q, %v) = %v, want %v",
					tt.path, tt.patterns, got, tt.want)
			}
		})
	}
}

// --- listFiles -----------------------------------------------------------

func TestListFilesScansEverything(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n"), 0644)
	os.WriteFile(filepath.Join(dir, "b.png"), []byte{0x89, 'P', 'N', 'G'}, 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "c.js"), []byte("//c\n"), 0644)

	// Default: scans everything (no extension filtering)
	lr, err := listFiles(dir, listOpts{})
	if err != nil {
		t.Fatal(err)
	}

	names := map[string]bool{}
	for _, f := range lr.Files {
		names[filepath.Base(f)] = true
	}
	if !names["a.go"] {
		t.Error("expected a.go")
	}
	if !names["b.png"] {
		t.Error("expected b.png (default scans everything)")
	}
	if !names["c.js"] {
		t.Error("expected c.js")
	}
}

func TestListFilesSkipExt(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n"), 0644)
	os.WriteFile(filepath.Join(dir, "b.png"), []byte{0x89, 'P', 'N', 'G'}, 0644)
	os.WriteFile(filepath.Join(dir, "c.PNG"), []byte{0x89, 'P', 'N', 'G'}, 0644)

	lr, err := listFiles(dir, listOpts{skipExts: []string{"png"}})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range lr.Files {
		base := filepath.Base(f)
		if base == "b.png" || base == "c.PNG" {
			t.Errorf("%s should be filtered by --skip-ext", base)
		}
	}
	// Both .png files should appear in skipped
	count := 0
	for _, s := range lr.Skipped {
		if strings.HasSuffix(strings.ToLower(s.Path), ".png") {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 skipped .png files, got %d", count)
	}
}

func TestHasSkippedExt(t *testing.T) {
	tests := []struct {
		path string
		exts []string
		want bool
	}{
		{"foo.png", []string{"png"}, true},
		{"foo.PNG", []string{"png"}, true},
		{"foo.jpg", []string{"png"}, false},
		{"foo.tar.gz", []string{"gz"}, true},
		{"foo.go", []string{"png", "jpg", "gif"}, false},
		{"foo.JPG", []string{"png", "jpg", "gif"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, _ := hasSkippedExt(tt.path, tt.exts)
			if got != tt.want {
				t.Errorf("hasSkippedExt(%q, %v) = %v, want %v",
					tt.path, tt.exts, got, tt.want)
			}
		})
	}
}

func TestListFilesSkipPattern(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vendor", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "vendor", "pkg", "lib.go"), []byte("package pkg\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644)

	lr, err := listFiles(dir, listOpts{skipPatterns: []string{"vendor"}})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range lr.Files {
		if strings.Contains(f, "vendor") {
			t.Errorf("vendor files should be skipped, got: %s", f)
		}
	}
	// vendor/ should appear in skipped
	found := false
	for _, s := range lr.Skipped {
		if strings.Contains(s.Path, "vendor") {
			found = true
		}
	}
	if !found {
		t.Error("vendor should appear in skipped entries")
	}
}

func TestListFilesSkipsGitDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[core]\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644)

	lr, err := listFiles(dir, listOpts{})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range lr.Files {
		if strings.Contains(f, ".git") {
			t.Errorf("should skip .git directory, got: %s", f)
		}
	}
}

func TestListFilesAllIncludesGitDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[core]\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644)

	lr, err := listFiles(dir, listOpts{all: true})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range lr.Files {
		if strings.Contains(f, ".git") {
			found = true
		}
	}
	if !found {
		t.Error("--all should include .git directory")
	}
}

// --- runeDescription -----------------------------------------------------

func TestRuneDescription(t *testing.T) {
	tests := []struct {
		r    rune
		want string
	}{
		{0x00, "NULL"},
		{0x1B, "ESCAPE"},
		{0x200B, "ZERO WIDTH SPACE"},
		{0x202E, "RIGHT-TO-LEFT OVERRIDE"},
		{0xFE00, "VARIATION SELECTOR-1"},
		{0xFE0F, "VARIATION SELECTOR-16"},
		{0xE0100, "VARIATION SELECTOR-17"},
		{0xE01EF, "VARIATION SELECTOR-256"},
		{0xE000, "PRIVATE USE"},
		{0x03, "CONTROL"},
		{0x90, "CONTROL"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("U+%04X", tt.r), func(t *testing.T) {
			got := runeDescription(tt.r)
			if got != tt.want {
				t.Errorf("runeDescription(%U) = %q, want %q", tt.r, got, tt.want)
			}
		})
	}
}

// --- End-to-end (via go run) ---------------------------------------------

func TestEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()

	// Create clean and dirty files.
	os.WriteFile(filepath.Join(dir, "clean.js"),
		[]byte("const x = 42;\n"), 0644)
	os.WriteFile(filepath.Join(dir, "dirty.js"),
		[]byte("const x = \"\xe2\x80\x8b\";\n"), 0644)
	os.WriteFile(filepath.Join(dir, "bom.js"),
		[]byte("\xef\xbb\xbfconst y = 1;\n"), 0644)
	os.WriteFile(filepath.Join(dir, "binary.png"),
		[]byte{0x89, 'P', 'N', 'G', 0x00}, 0644)

	// Default scans everything (including .png).
	cmd := exec.Command("go", "run", ".", "--quiet", dir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected non-zero exit code")
	}

	out := string(output)
	if !strings.Contains(out, "dirty.js") {
		t.Errorf("expected dirty.js in output, got:\n%s", out)
	}
	if !strings.Contains(out, "bom.js") {
		t.Errorf("expected bom.js in output, got:\n%s", out)
	}
	if !strings.Contains(out, "binary.png") {
		t.Errorf("expected binary.png in output (default scans all), got:\n%s", out)
	}
	if strings.Contains(out, "clean.js") {
		t.Errorf("clean.js should not appear in output, got:\n%s", out)
	}

	// Clean-only directory should exit 0.
	cleanDir := t.TempDir()
	os.WriteFile(filepath.Join(cleanDir, "ok.txt"), []byte("hello\n"), 0644)
	cmd = exec.Command("go", "run", ".", "--quiet", cleanDir)
	if err := cmd.Run(); err != nil {
		t.Errorf("clean directory should exit 0: %v", err)
	}
}

func TestEndToEndSkip(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vendor"), 0755)
	os.WriteFile(filepath.Join(dir, "vendor", "lib.go"),
		[]byte("package lib\x00\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n"), 0644)

	// Skip vendor — should not report vendor/lib.go as an issue.
	cmd := exec.Command("go", "run", ".", "--skip", "vendor", "--quiet", dir)
	output, _ := cmd.CombinedOutput()
	out := string(output)

	if strings.Contains(out, "vendor") {
		t.Errorf("vendor should be skipped, got:\n%s", out)
	}
}
