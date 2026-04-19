package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// --- test helpers --------------------------------------------------------

func testBase64String(n int) string {
	// Interleaves letters with digits so that substrings at any length
	// are neither pure-hex nor pure-alpha.
	const alphabet = "SGVsbG8gV29ybGQ0MTIz+ABCDEFHIJKLMNOPQRSTUWXYZajkmnpqtuvwxiz567890"
	s := strings.Repeat(alphabet, (n/len(alphabet))+1)
	return s[:n]
}

func testHexString(n int) string {
	const hex = "0123456789abcdef"
	s := strings.Repeat(hex, (n/len(hex))+1)
	return s[:n]
}

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
			if isForbidden(tt.r, scanOpts{maxMatches: defaultMaxMatches}) {
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
			if !isForbidden(tt.r, scanOpts{maxMatches: defaultMaxMatches}) {
				t.Errorf("isForbidden(%U) = false, want true", tt.r)
			}
		})
	}

	// ESC is forbidden by default but allowed with allowEscape.
	// allowRunes suppresses specific code points.
	allow := func(runes ...rune) scanOpts {
		m := map[rune]bool{}
		for _, r := range runes {
			m[r] = true
		}
		return scanOpts{allowRunes: m, maxMatches: defaultMaxMatches}
	}

	t.Run("ESC/default", func(t *testing.T) {
		if !isForbidden(0x1B, scanOpts{maxMatches: defaultMaxMatches}) {
			t.Error("ESC should be forbidden by default")
		}
	})
	t.Run("ESC/allowed", func(t *testing.T) {
		if isForbidden(0x1B, allow(0x1B)) {
			t.Error("ESC should be allowed via allowRunes")
		}
	})

	t.Run("BEL/default", func(t *testing.T) {
		if !isForbidden(0x07, scanOpts{maxMatches: defaultMaxMatches}) {
			t.Error("BEL should be forbidden by default")
		}
	})
	t.Run("BEL/allowed", func(t *testing.T) {
		if isForbidden(0x07, allow(0x07)) {
			t.Error("BEL should be allowed via allowRunes")
		}
	})

	// VS15/VS16 allowed via allowRunes; VS1 remains forbidden.
	t.Run("VS15/default", func(t *testing.T) {
		if !isForbidden(0xFE0E, scanOpts{maxMatches: defaultMaxMatches}) {
			t.Error("VS15 should be forbidden by default")
		}
	})
	t.Run("VS16/default", func(t *testing.T) {
		if !isForbidden(0xFE0F, scanOpts{maxMatches: defaultMaxMatches}) {
			t.Error("VS16 should be forbidden by default")
		}
	})
	t.Run("VS15+VS16/allowed", func(t *testing.T) {
		opts := allow(0xFE0E, 0xFE0F)
		if isForbidden(0xFE0E, opts) {
			t.Error("VS15 should be allowed")
		}
		if isForbidden(0xFE0F, opts) {
			t.Error("VS16 should be allowed")
		}
		if !isForbidden(0xFE00, opts) {
			t.Error("VS1 should remain forbidden")
		}
	})
}

// --- parseCodePoint ------------------------------------------------------

func TestParseCodePoint(t *testing.T) {
	tests := []struct {
		input string
		want  rune
	}{
		{"FEFF", 0xFEFF},
		{"feff", 0xFEFF},
		{"0xFEFF", 0xFEFF},
		{"0xfeff", 0xFEFF},
		{"U+FEFF", 0xFEFF},
		{"u+feff", 0xFEFF},
		{"7", 0x07},
		{"1B", 0x1B},
		{"0x1b", 0x1B},
		{"U+200B", 0x200B},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseCodePoint(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseCodePoint(%q) = %U, want %U", tt.input, got, tt.want)
			}
		})
	}

	// Error cases
	for _, bad := range []string{"", "ZZZZ", "U+FFFFFFFFFF"} {
		t.Run("err/"+bad, func(t *testing.T) {
			_, err := parseCodePoint(bad)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// --- isPureHex -----------------------------------------------------------

func TestIsPureHex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"digits", "0123456789", true},
		{"upper hex", "ABCDEF", true},
		{"lower hex", "abcdef", true},
		{"mixed hex", "aAbBcCdDeEfF0099", true},
		{"empty", "", true},
		{"contains G", "abcdefG", false},
		{"contains g", "abcdefg", false},
		{"contains +", "abc+def", false},
		{"contains /", "abc/def", false},
		{"contains Z", "ABCDEZ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPureHex([]byte(tt.input))
			if got != tt.want {
				t.Errorf("isPureHex(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- isIdentifierLike ----------------------------------------------------

func TestIsIdentifierLike(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Pure alpha (zero digit groups)
		{"lowercase", "abcdefghij", true},
		{"uppercase", "ABCDEFGHIJ", true},
		{"mixed case", "HelloWorld", true},
		{"empty", "", true},
		// One digit group
		{"digits at end", "TestHTTP2", true},
		{"digits in middle", "TestTable80SameArch", true},
		{"digits at start", "123TestFunc", true},
		// Two or more digit groups
		{"two digit groups", "Test12Blah34", false},
		{"scattered digits", "a1b2c3", false},
		// Contains non-alphanumeric
		{"contains plus", "Hello+World", false},
		{"contains slash", "Hello/World", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIdentifierLike([]byte(tt.input))
			if got != tt.want {
				t.Errorf("isIdentifierLike(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- scanBase64 ----------------------------------------------------------

func TestScanBase64(t *testing.T) {
	t.Run("detects at threshold", func(t *testing.T) {
		data := []byte(testBase64String(32) + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if matches[0].Line != 1 || matches[0].Col != 1 {
			t.Errorf("position = %d:%d, want 1:1", matches[0].Line, matches[0].Col)
		}
		if !strings.Contains(matches[0].Reason, "32 chars") {
			t.Errorf("reason should mention 32 chars, got: %s", matches[0].Reason)
		}
	})

	t.Run("skips below threshold", func(t *testing.T) {
		data := []byte(testBase64String(31) + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})

	t.Run("skips pure hex", func(t *testing.T) {
		data := []byte(testHexString(64) + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 0 {
			t.Errorf("pure hex should not match, got %d matches", len(matches))
		}
	})

	t.Run("skips pure alpha", func(t *testing.T) {
		data := []byte(strings.Repeat("abcdefghijklmnopqrstuvwxyz", 3)[:64] + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 0 {
			t.Errorf("pure alpha should not match, got %d matches", len(matches))
		}
	})

	t.Run("skips identifier with one number", func(t *testing.T) {
		data := []byte("TestPrintInstanceTable80SameArch\n") // 31 alpha + 2 digits = 33 chars
		matches := scanBase64(data, 32)
		if len(matches) != 0 {
			t.Errorf("identifier-like string should not match, got %d matches", len(matches))
		}
	})

	t.Run("correct column offset", func(t *testing.T) {
		data := []byte("prefix " + testBase64String(32) + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}
		if matches[0].Line != 1 || matches[0].Col != 8 {
			t.Errorf("position = %d:%d, want 1:8", matches[0].Line, matches[0].Col)
		}
	})

	t.Run("multiple lines", func(t *testing.T) {
		data := []byte("clean\n" + testBase64String(32) + "\nclean\n" + testBase64String(48) + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 2 {
			t.Fatalf("expected 2 matches, got %d", len(matches))
		}
		if matches[0].Line != 2 {
			t.Errorf("first match line = %d, want 2", matches[0].Line)
		}
		if matches[1].Line != 4 {
			t.Errorf("second match line = %d, want 4", matches[1].Line)
		}
	})

	t.Run("non-base64 chars split runs", func(t *testing.T) {
		data := []byte(testBase64String(20) + " " + testBase64String(20) + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 0 {
			t.Errorf("split runs should not match, got %d matches", len(matches))
		}
	})

	t.Run("multiple runs on one line", func(t *testing.T) {
		data := []byte(testBase64String(32) + " " + testBase64String(32) + "\n")
		matches := scanBase64(data, 32)
		if len(matches) != 2 {
			t.Errorf("expected 2 matches on one line, got %d", len(matches))
		}
	})

	t.Run("no trailing newline", func(t *testing.T) {
		data := []byte(testBase64String(32))
		matches := scanBase64(data, 32)
		if len(matches) != 1 {
			t.Errorf("should detect without trailing newline, got %d matches", len(matches))
		}
	})
}

// --- scanBytes: block-base64 integration ---------------------------------

func TestScanBytesBlockBase64(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		data := []byte(testBase64String(100) + "\n")
		_, total, _, _ := scanBytes(data, scanOpts{maxMatches: defaultMaxMatches})
		if total != 0 {
			t.Errorf("base64 detection should be off by default, got %d matches", total)
		}
	})

	t.Run("detects when enabled", func(t *testing.T) {
		data := []byte(testBase64String(100) + "\n")
		matches, total, _, _ := scanBytes(data, scanOpts{blockBase64: 32, maxMatches: defaultMaxMatches})
		if total != 1 {
			t.Fatalf("expected 1 match, got %d", total)
		}
		if !strings.Contains(matches[0].Reason, "base64") {
			t.Errorf("reason should mention base64, got: %s", matches[0].Reason)
		}
	})

	t.Run("ignores pure hex", func(t *testing.T) {
		data := []byte(testHexString(100) + "\n")
		_, total, _, _ := scanBytes(data, scanOpts{blockBase64: 32, maxMatches: defaultMaxMatches})
		if total != 0 {
			t.Errorf("pure hex should not match, got %d matches", total)
		}
	})

	t.Run("combined with rune detection", func(t *testing.T) {
		data := []byte("hello\x00world\n" + testBase64String(100) + "\n")
		matches, total, _, _ := scanBytes(data, scanOpts{blockBase64: 32, maxMatches: defaultMaxMatches})
		if total != 2 {
			t.Fatalf("expected 2 matches (1 rune + 1 base64), got %d", total)
		}
		if !strings.Contains(matches[0].Reason, "NULL") {
			t.Errorf("first match should be NULL, got: %s", matches[0].Reason)
		}
		if !strings.Contains(matches[1].Reason, "base64") {
			t.Errorf("second match should be base64, got: %s", matches[1].Reason)
		}
	})
}

// --- scanBytes: BOM with allowBom ----------------------------------------

func TestScanBytesBomAllowed(t *testing.T) {
	bom := []byte("\xef\xbb\xbfhello\n")

	// Default: BOM flagged
	_, total, _, _ := scanBytes(bom, scanOpts{maxMatches: defaultMaxMatches})
	if total != 1 {
		t.Errorf("BOM should be flagged by default, got %d matches", total)
	}

	// With allowBom: BOM at start suppressed
	_, total, _, _ = scanBytes(bom, scanOpts{allowBom: true, maxMatches: defaultMaxMatches})
	if total != 0 {
		t.Errorf("BOM at start should be allowed with allowBom, got %d matches", total)
	}

	// Mid-file FEFF still flagged even with allowBom
	mid := []byte("x\xef\xbb\xbfy\n")
	_, total, _, _ = scanBytes(mid, scanOpts{allowBom: true, maxMatches: defaultMaxMatches})
	if total != 1 {
		t.Errorf("mid-file FEFF should still be flagged, got %d matches", total)
	}
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
			matches, total, _, _ := scanBytes(tt.content, scanOpts{maxMatches: defaultMaxMatches})
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
	matches, total, _, _ := scanBytes(content, scanOpts{maxMatches: defaultMaxMatches})
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
	data := make([]byte, 100) // 100 NULL bytes

	t.Run("storage cap honored", func(t *testing.T) {
		matches, total, _, _ := scanBytes(data, scanOpts{maxMatches: 20})
		if total != 100 {
			t.Errorf("total = %d, want 100", total)
		}
		if len(matches) != 21 {
			t.Errorf("len(matches) = %d, want 21 (20 cap + summary)", len(matches))
		}
		last := matches[len(matches)-1]
		if !strings.Contains(last.Reason, "80 more matches") {
			t.Errorf("last match should report 80 more, got: %s", last.Reason)
		}
	})

	t.Run("storage cap of 0 stores nothing", func(t *testing.T) {
		matches, total, _, _ := scanBytes(data, scanOpts{maxMatches: 0})
		if total != 100 {
			t.Errorf("total = %d, want 100", total)
		}
		if len(matches) != 0 {
			t.Errorf("len(matches) = %d, want 0 — counts still tracked, no storage", len(matches))
		}
	})

	t.Run("custom storage cap", func(t *testing.T) {
		matches, total, _, _ := scanBytes(data, scanOpts{maxMatches: 5})
		if total != 100 {
			t.Errorf("total = %d, want 100", total)
		}
		if len(matches) != 6 {
			t.Errorf("len(matches) = %d, want 6 (5 cap + summary)", len(matches))
		}
		if !strings.Contains(matches[5].Reason, "95 more matches") {
			t.Errorf("summary should say 95 more, got: %s", matches[5].Reason)
		}
	})
}

// --- scanFile (integration) ----------------------------------------------

func TestScanFile(t *testing.T) {
	dir := t.TempDir()

	clean := filepath.Join(dir, "clean.js")
	os.WriteFile(clean, []byte("const x = 42;\n"), 0644)
	if r := scanFile(clean, scanOpts{maxMatches: defaultMaxMatches}); r != nil {
		t.Errorf("clean file produced %d matches", len(r.Matches))
	}

	dirty := filepath.Join(dir, "dirty.js")
	os.WriteFile(dirty, []byte("const x = \"\xe2\x80\x8b\";\n"), 0644)
	if r := scanFile(dirty, scanOpts{maxMatches: defaultMaxMatches}); r == nil {
		t.Error("dirty file produced no matches")
	}

	empty := filepath.Join(dir, "empty.txt")
	os.WriteFile(empty, []byte{}, 0644)
	if r := scanFile(empty, scanOpts{maxMatches: defaultMaxMatches}); r != nil {
		t.Error("empty file should produce no matches")
	}

	missing := filepath.Join(dir, "missing.txt")
	if r := scanFile(missing, scanOpts{maxMatches: defaultMaxMatches}); r != nil {
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

		// Doublestar patterns
		{"pkg/assets/fonts/sub/font.woff2", []string{"pkg/assets/fonts/**/*.woff2"}, true},
		{"pkg/assets/fonts/font.woff2", []string{"pkg/assets/fonts/**/*.woff2"}, true},
		{"pkg/assets/fonts/a/b/c/font.woff2", []string{"pkg/assets/fonts/**/*.woff2"}, true},
		{"pkg/assets/fonts/font.ttf", []string{"pkg/assets/fonts/**/*.woff2"}, false},
		{"other/fonts/font.woff2", []string{"pkg/assets/fonts/**/*.woff2"}, false},

		// ** at end matches everything below
		{"vendor/pkg/foo.go", []string{"vendor/**"}, true},
		{"vendor/a/b/c.go", []string{"vendor/**"}, true},
		{"vendor", []string{"vendor/**"}, true},
		{"src/vendor/foo.go", []string{"vendor/**"}, false},

		// ** at start matches at any depth
		{"a/b/c/test/foo.go", []string{"**/test/*.go"}, true},
		{"test/foo.go", []string{"**/test/*.go"}, true},
		{"test/sub/foo.go", []string{"**/test/*.go"}, false},

		// ** in the middle
		{"src/pkg/internal/util.go", []string{"src/**/internal/*.go"}, true},
		{"src/internal/util.go", []string{"src/**/internal/*.go"}, true},
		{"src/a/b/c/internal/util.go", []string{"src/**/internal/*.go"}, true},
		{"other/internal/util.go", []string{"src/**/internal/*.go"}, false},

		// Standalone **
		{"anything/at/all.txt", []string{"**"}, true},
		{"file.txt", []string{"**"}, true},

		// Alternation {alt1,alt2}
		{"font.woff", []string{"*.{woff,woff2}"}, true},
		{"font.woff2", []string{"*.{woff,woff2}"}, true},
		{"font.ttf", []string{"*.{woff,woff2}"}, false},
		{"assets/font.woff", []string{"**/*.{woff,woff2}"}, true},
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

func TestListFilesIgnoresSkipPatterns(t *testing.T) {
	// listFiles no longer applies --skip; the post-scan filter does, so
	// every regular file (minus --skip-ext and .git) reaches the scanner.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vendor", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "vendor", "pkg", "lib.go"), []byte("package pkg\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0644)

	lr, err := listFiles(dir, listOpts{skipPatterns: []string{"vendor"}})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, f := range lr.Files {
		got[filepath.Base(f)] = true
	}
	if !got["lib.go"] {
		t.Error("vendor/pkg/lib.go should reach the scanner")
	}
	if !got["main.go"] {
		t.Error("main.go should reach the scanner")
	}
	for _, s := range lr.Skipped {
		t.Errorf("listFiles should not produce --skip entries, got %+v", s)
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

// --- loadConfig ----------------------------------------------------------

func TestLoadConfig(t *testing.T) {
	t.Run("parses all fields", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.yaml")
		os.WriteFile(path, []byte(`
all: true
allow:
  - "U+FEFF"
  - "0x1B"
allow-bell: true
allow-bom: true
allow-emoji: true
allow-escape: true
block-base64: 128
gitignore: true
hide-skipped: true
quiet: true
skip:
  - vendor
  - node_modules
skip-ext:
  - png
  - jpg
verbose: true
`), 0644)

		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.All {
			t.Error("All should be true")
		}
		if len(cfg.Allow) != 2 || cfg.Allow[0] != "U+FEFF" {
			t.Errorf("Allow = %v, want [U+FEFF 0x1B]", cfg.Allow)
		}
		if !cfg.AllowBell {
			t.Error("AllowBell should be true")
		}
		if !cfg.AllowBom {
			t.Error("AllowBom should be true")
		}
		if !cfg.AllowEmoji {
			t.Error("AllowEmoji should be true")
		}
		if !cfg.AllowEscape {
			t.Error("AllowEscape should be true")
		}
		if cfg.BlockBase64 != 128 {
			t.Errorf("BlockBase64 = %d, want 128", cfg.BlockBase64)
		}
		if !cfg.Gitignore {
			t.Error("Gitignore should be true")
		}
		if !cfg.HideSkipped {
			t.Error("HideSkipped should be true")
		}
		if !cfg.Quiet {
			t.Error("Quiet should be true")
		}
		if len(cfg.Skip) != 2 || cfg.Skip[0] != "vendor" {
			t.Errorf("Skip = %v, want [vendor node_modules]", cfg.Skip)
		}
		if len(cfg.SkipExt) != 2 || cfg.SkipExt[0] != "png" {
			t.Errorf("SkipExt = %v, want [png jpg]", cfg.SkipExt)
		}
		if cfg.Verbose != defaultMaxMatches {
			t.Errorf("Verbose = %d, want %d (verbose: true → defaultMaxMatches)", cfg.Verbose, defaultMaxMatches)
		}
	})

	t.Run("defaults to zero values", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.yaml")
		os.WriteFile(path, []byte("{}\n"), 0644)

		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.All || cfg.Quiet || cfg.Verbose != 0 || cfg.BlockBase64 != 0 {
			t.Error("empty config should produce zero values")
		}
		if len(cfg.Skip) != 0 || len(cfg.SkipExt) != 0 || len(cfg.Allow) != 0 {
			t.Error("empty config should have empty lists")
		}
	})

	t.Run("verbose accepts integer", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "verbose-int.yaml")
		os.WriteFile(path, []byte("verbose: 3\n"), 0644)

		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Verbose != 3 {
			t.Errorf("Verbose = %d, want 3", cfg.Verbose)
		}
	})

	t.Run("verbose accepts false", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "verbose-false.yaml")
		os.WriteFile(path, []byte("verbose: false\n"), 0644)

		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Verbose != 0 {
			t.Errorf("Verbose = %d, want 0 (verbose: false → 0)", cfg.Verbose)
		}
	})

	t.Run("verbose rejects non-numeric string", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "verbose-bogus.yaml")
		os.WriteFile(path, []byte("verbose: hello\n"), 0644)

		_, err := loadConfig(path)
		if err == nil {
			t.Error("expected error for verbose: hello")
		}
	})

	t.Run("rejects invalid YAML", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.yaml")
		os.WriteFile(path, []byte("skip: [missing bracket\n"), 0644)

		_, err := loadConfig(path)
		if err == nil {
			t.Error("expected error for invalid YAML")
		}
	})
}

// --- findConfigFile ------------------------------------------------------

func TestFindConfigFile(t *testing.T) {
	t.Run("explicit path found", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "custom.yaml")
		os.WriteFile(path, []byte("quiet: true\n"), 0644)

		got, err := findConfigFile(path, dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != path {
			t.Errorf("got %q, want %q", got, path)
		}
	})

	t.Run("explicit path missing", func(t *testing.T) {
		_, err := findConfigFile("/nonexistent/path.yaml", ".")
		if err == nil {
			t.Error("expected error for missing explicit config")
		}
	})

	t.Run("no config returns empty", func(t *testing.T) {
		dir := t.TempDir()
		got, err := findConfigFile("", dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Errorf("expected empty path, got %q", got)
		}
	})

	t.Run("finds in scan directory", func(t *testing.T) {
		dir := t.TempDir()
		want := filepath.Join(dir, ".nobin.yaml")
		os.WriteFile(want, []byte("quiet: true\n"), 0644)

		got, err := findConfigFile("", dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("finds in scan directory's git root", func(t *testing.T) {
		// Resolve symlinks because git rev-parse returns the canonical
		// path, while t.TempDir on macOS hands out a symlinked path.
		root, _ := filepath.EvalSymlinks(t.TempDir())
		if out, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
			t.Skipf("git init failed: %v: %s", err, out)
		}
		want := filepath.Join(root, ".nobin.yaml")
		os.WriteFile(want, []byte("quiet: true\n"), 0644)

		// Run from a sub-directory that lives inside the repo but does
		// not itself contain a config; findConfigFile should walk up to
		// the git root.
		sub := filepath.Join(root, "pkg", "deep")
		os.MkdirAll(sub, 0755)

		got, err := findConfigFile("", sub)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("finds config in scan target invoked from elsewhere", func(t *testing.T) {
		// Regression: nobin /path/to/repo run from a different cwd
		// must still find /path/to/repo/.nobin.yaml.
		scan := t.TempDir()
		want := filepath.Join(scan, ".nobin.yaml")
		os.WriteFile(want, []byte("quiet: true\n"), 0644)

		other := t.TempDir()
		orig, _ := os.Getwd()
		os.Chdir(other)
		defer os.Chdir(orig)

		got, err := findConfigFile("", scan)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// --- End-to-end: config file ---------------------------------------------

func TestEndToEndConfig(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "dirty.js"),
		[]byte("const x = \"\xe2\x80\x8b\";\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.js"),
		[]byte("const x = 42;\n"), 0644)

	cfgPath := filepath.Join(dir, ".nobin.yaml")
	os.WriteFile(cfgPath, []byte(`
allow:
  - "U+200B"
`), 0644)

	cmd := exec.Command("go", "run", ".", "--config", cfgPath, "--quiet", dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("config allowing U+200B should make scan clean, got:\n%s", string(output))
	}
}

func TestEndToEndConfigSkip(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vendor"), 0755)
	os.WriteFile(filepath.Join(dir, "vendor", "lib.go"),
		[]byte("package lib\x00\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n"), 0644)

	cfgPath := filepath.Join(dir, ".nobin.yaml")
	os.WriteFile(cfgPath, []byte(`
skip:
  - vendor
`), 0644)

	cmd := exec.Command("go", "run", ".", "--config", cfgPath, "--quiet", dir)
	output, _ := cmd.CombinedOutput()
	if strings.Contains(string(output), "vendor") {
		t.Errorf("config skip should exclude vendor, got:\n%s", string(output))
	}
}

func TestEndToEndConfigCLIOverride(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "dirty.js"),
		[]byte("const x = \"\xe2\x80\x8b\";\n"), 0644)

	cfgPath := filepath.Join(dir, ".nobin.yaml")
	os.WriteFile(cfgPath, []byte(`
verbose: true
`), 0644)

	cmd := exec.Command("go", "run", ".", "--config", cfgPath, "--quiet", dir)
	output, _ := cmd.CombinedOutput()
	out := string(output)

	// Quiet mode: only file paths, no line/col details.
	if strings.Contains(out, ":") {
		t.Errorf("--quiet should override config verbose, got:\n%s", out)
	}
	if !strings.Contains(out, "dirty.js") {
		t.Errorf("expected dirty.js in output, got:\n%s", out)
	}
}

func TestEndToEndConfigCLIExtendsList(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vendor"), 0755)
	os.MkdirAll(filepath.Join(dir, "dist"), 0755)
	os.WriteFile(filepath.Join(dir, "vendor", "lib.go"),
		[]byte("package lib\x00\n"), 0644)
	os.WriteFile(filepath.Join(dir, "dist", "bundle.js"),
		[]byte("var x=\x00;\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n"), 0644)

	cfgPath := filepath.Join(dir, ".nobin.yaml")
	os.WriteFile(cfgPath, []byte(`
skip:
  - vendor
`), 0644)

	cmd := exec.Command("go", "run", ".", "--config", cfgPath, "--skip", "dist", "--quiet", dir)
	output, _ := cmd.CombinedOutput()
	out := string(output)

	if strings.Contains(out, "vendor") {
		t.Errorf("config skip should exclude vendor, got:\n%s", out)
	}
	if strings.Contains(out, "dist") {
		t.Errorf("CLI --skip should exclude dist, got:\n%s", out)
	}
}

func TestEndToEndExplicitConfig(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "dirty.js"),
		[]byte("const x = \"\xe2\x80\x8b\";\n"), 0644)

	// Config at a custom path allows ZWSP.
	cfgPath := filepath.Join(dir, "custom-config.yaml")
	os.WriteFile(cfgPath, []byte(`
allow:
  - "U+200B"
`), 0644)

	cmd := exec.Command("go", "run", ".", "--config", cfgPath, "--quiet", dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("--config with allow should make scan clean, got:\n%s", string(output))
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

func TestEndToEndSingleFile(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	dirty := filepath.Join(dir, "dirty.js")
	clean := filepath.Join(dir, "clean.js")
	os.WriteFile(dirty, []byte("const x = \"\xe2\x80\x8b\";\n"), 0644)
	os.WriteFile(clean, []byte("const x = 42;\n"), 0644)

	t.Run("scans dirty file", func(t *testing.T) {
		cmd := exec.Command("go", "run", ".", "--quiet", dirty)
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected non-zero exit for dirty file")
		}
		if !strings.Contains(string(output), "dirty.js") {
			t.Errorf("expected dirty.js in output, got:\n%s", output)
		}
	})

	t.Run("clean file exits 0", func(t *testing.T) {
		cmd := exec.Command("go", "run", ".", "--quiet", clean)
		if err := cmd.Run(); err != nil {
			t.Errorf("clean file should exit 0: %v", err)
		}
	})

	t.Run("--diff with file errors", func(t *testing.T) {
		cmd := exec.Command("go", "run", ".", "--diff", "main", dirty)
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("--diff with single file should error")
		}
		if !strings.Contains(string(output), "--diff requires a directory") {
			t.Errorf("expected --diff error, got:\n%s", output)
		}
	})

	t.Run("--skip ignored for single file", func(t *testing.T) {
		// User explicitly named the file; --skip pattern matching the
		// file's name must not silence it.
		cmd := exec.Command("go", "run", ".", "--skip", "dirty.js", "--quiet", dirty)
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("--skip should not silence an explicitly-named file")
		}
		if !strings.Contains(string(output), "dirty.js") {
			t.Errorf("expected dirty.js in output, got:\n%s", output)
		}
	})

	t.Run("config from file's directory", func(t *testing.T) {
		// Place an .nobin.yaml in the same directory as the target file
		// that allows U+200B; the dirty file should then scan clean.
		os.WriteFile(filepath.Join(dir, ".nobin.yaml"),
			[]byte("allow:\n  - U+200B\n"), 0644)
		t.Cleanup(func() { os.Remove(filepath.Join(dir, ".nobin.yaml")) })

		cmd := exec.Command("go", "run", ".", "--quiet", dirty)
		if err := cmd.Run(); err != nil {
			t.Errorf("config in file's directory should apply: %v", err)
		}
	})
}

func TestEndToEndSkip(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vendor"), 0755)
	os.WriteFile(filepath.Join(dir, "vendor", "lib.go"),
		[]byte("package lib\x00\n"), 0644) // would trigger
	os.WriteFile(filepath.Join(dir, "vendor", "clean.go"),
		[]byte("package clean\n"), 0644) // clean
	os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n"), 0644)

	// Quiet mode: Skipped is suppressed, so vendor/lib.go should not
	// surface as an issue, and the run should exit 0.
	cmd := exec.Command("go", "run", ".", "--skip", "vendor", "--quiet", dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("--skip should keep exit 0 even when suppressed file would trigger: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "vendor") {
		t.Errorf("--quiet should not surface vendor in regular output, got:\n%s", output)
	}

	// Default mode: vendor/lib.go appears in Skipped (it would have hit),
	// vendor/clean.go does not (no hits to report).
	cmd = exec.Command("go", "run", ".", "--skip", "vendor", dir)
	output, _ = cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "Skipped:") {
		t.Errorf("expected Skipped section, got:\n%s", out)
	}
	if !strings.Contains(out, "vendor/lib.go") {
		t.Errorf("vendor/lib.go should appear in Skipped (would have triggered), got:\n%s", out)
	}
	if strings.Contains(out, "vendor/clean.go") {
		t.Errorf("vendor/clean.go should not appear in Skipped (no hits), got:\n%s", out)
	}
}

func TestApplySkips(t *testing.T) {
	dir := "/repo"
	makeResult := func(path string, runeN, base64N, confusableN int) *fileResult {
		ms := []match{}
		for i := 0; i < runeN; i++ {
			ms = append(ms, match{Reason: "rune", Kind: matchRune})
		}
		for i := 0; i < base64N; i++ {
			ms = append(ms, match{Reason: "b64", Kind: matchBase64})
		}
		for i := 0; i < confusableN; i++ {
			ms = append(ms, match{Reason: "conf", Kind: matchConfusable})
		}
		return &fileResult{
			Path:            filepath.Join(dir, path),
			Matches:         ms,
			MatchCount:      runeN + base64N + confusableN,
			Base64Count:     base64N,
			ConfusableCount: confusableN,
		}
	}

	t.Run("--skip suppresses entire file", func(t *testing.T) {
		r := makeResult("vendor/foo.go", 2, 1, 0)
		got := applySkips(r, dir, []string{"vendor"}, nil, nil)
		if got.kept != nil {
			t.Errorf("expected kept=nil, got %+v", got.kept)
		}
		if len(got.skipped) != 1 || !strings.Contains(got.skipped[0].Reason, "--skip vendor") {
			t.Errorf("expected one --skip entry, got %+v", got.skipped)
		}
	})

	t.Run("--skip-base64 trims only base64", func(t *testing.T) {
		r := makeResult("test/data.go", 1, 3, 0)
		got := applySkips(r, dir, nil, []string{"test/*"}, nil)
		if got.kept == nil {
			t.Fatal("expected kept != nil (rune match remains)")
		}
		if got.kept.MatchCount != 1 || got.kept.Base64Count != 0 {
			t.Errorf("kept counts = match %d base64 %d, want 1/0",
				got.kept.MatchCount, got.kept.Base64Count)
		}
		if len(got.skipped) != 1 || !strings.Contains(got.skipped[0].Reason, "3 base64") {
			t.Errorf("expected --skip-base64 entry with count 3, got %+v", got.skipped)
		}
	})

	t.Run("--skip-confusables trims only confusables", func(t *testing.T) {
		r := makeResult("i18n/foo.go", 0, 0, 5)
		got := applySkips(r, dir, nil, nil, []string{"i18n/*"})
		if got.kept != nil {
			t.Errorf("expected kept=nil (only confusables, all dropped), got %+v", got.kept)
		}
		if len(got.skipped) != 1 || !strings.Contains(got.skipped[0].Reason, "5 confusable") {
			t.Errorf("expected --skip-confusables entry with count 5, got %+v", got.skipped)
		}
	})

	t.Run("non-matching file passes through untouched", func(t *testing.T) {
		r := makeResult("src/main.go", 2, 0, 0)
		got := applySkips(r, dir, []string{"vendor"}, []string{"test/*"}, nil)
		if got.kept == nil {
			t.Fatal("expected kept != nil for non-matching file")
		}
		if got.kept.MatchCount != 2 {
			t.Errorf("MatchCount = %d, want 2", got.kept.MatchCount)
		}
		if len(got.skipped) != 0 {
			t.Errorf("expected no skipped entries, got %+v", got.skipped)
		}
	})

	t.Run("--skip beats per-category skips", func(t *testing.T) {
		r := makeResult("vendor/foo.go", 0, 5, 0)
		got := applySkips(r, dir,
			[]string{"vendor"}, []string{"vendor/*"}, nil)
		if got.kept != nil {
			t.Error("expected kept=nil")
		}
		if len(got.skipped) != 1 || !strings.Contains(got.skipped[0].Reason, "--skip vendor") {
			t.Errorf("expected only --skip entry, got %+v", got.skipped)
		}
	})
}

func TestEndToEndBlockBase64(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "encoded.txt"),
		[]byte(testBase64String(100)+"\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.txt"),
		[]byte("hello world\n"), 0644)

	// Without --block-base64: should exit 0
	cmd := exec.Command("go", "run", ".", "--quiet", dir)
	if err := cmd.Run(); err != nil {
		t.Errorf("without --block-base64, should exit 0: %v", err)
	}

	// With --block-base64: should detect
	cmd = exec.Command("go", "run", ".", "--block-base64", "--quiet", dir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("with --block-base64, expected non-zero exit")
	}
	if !strings.Contains(string(output), "encoded.txt") {
		t.Errorf("expected encoded.txt in output, got:\n%s", string(output))
	}

	// With --block-base64=200: 100-char string should not match
	cmd = exec.Command("go", "run", ".", "--block-base64=200", "--quiet", dir)
	if err := cmd.Run(); err != nil {
		t.Errorf("with --block-base64=200, 100-char string should not match: %v", err)
	}
}

func TestEndToEndSkipBase64(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()

	// File with base64 AND a forbidden character.
	os.WriteFile(filepath.Join(dir, "mixed.txt"),
		[]byte(testBase64String(100)+"\nhello\x00world\n"), 0644)
	// File with only base64.
	os.WriteFile(filepath.Join(dir, "b64only.txt"),
		[]byte(testBase64String(100)+"\n"), 0644)

	// --block-base64 without --skip-base64: both files flagged
	cmd := exec.Command("go", "run", ".", "--block-base64", "--quiet", dir)
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "mixed.txt") {
		t.Errorf("expected mixed.txt flagged, got:\n%s", out)
	}
	if !strings.Contains(out, "b64only.txt") {
		t.Errorf("expected b64only.txt flagged, got:\n%s", out)
	}

	// --skip-base64 for mixed.txt: still flagged for NUL, b64only.txt still flagged for base64
	cmd = exec.Command("go", "run", ".", "--block-base64", "--skip-base64", "mixed.txt", "--quiet", dir)
	output, _ = cmd.CombinedOutput()
	out = string(output)
	if !strings.Contains(out, "mixed.txt") {
		t.Errorf("mixed.txt should still be flagged for NUL, got:\n%s", out)
	}
	if !strings.Contains(out, "b64only.txt") {
		t.Errorf("b64only.txt should still be flagged for base64, got:\n%s", out)
	}

	// --skip-base64 appears in skipped report
	cmd = exec.Command("go", "run", ".", "--block-base64", "--skip-base64", "b64only.txt", dir)
	output, _ = cmd.CombinedOutput()
	out = string(output)
	if !strings.Contains(out, "--skip-base64 b64only.txt") {
		t.Errorf("expected skip-base64 entry in skipped report, got:\n%s", out)
	}

	// --skip-base64 for b64only.txt: should be clean now
	cmd = exec.Command("go", "run", ".", "--block-base64", "--skip-base64", "b64only.txt", "--quiet", dir)
	output, _ = cmd.CombinedOutput()
	out = string(output)
	if strings.Contains(out, "b64only.txt") {
		t.Errorf("b64only.txt should be clean with --skip-base64, got:\n%s", out)
	}
	if !strings.Contains(out, "mixed.txt") {
		t.Errorf("mixed.txt should still be flagged for NUL, got:\n%s", out)
	}
}

// --- latinConfusables tables ---------------------------------------------

func TestLatinConfusablesAlphanum(t *testing.T) {
	// Letters and digits — present in all three modes; alphanum is the
	// narrowest, so testing it implies presence in url and strict.
	confusable := []struct {
		name string
		r    rune
	}{
		{"Cyrillic small a", 0x0430},
		{"Cyrillic capital Er (→ P)", 0x0420},
		{"Greek small alpha", 0x03B1},
		{"Cherokee A", 0x13A0},
		{"Fullwidth small a", 0xFF41},
		{"Math bold small a", 0x1D41A},
		{"Math fraktur small a", 0x1D51E},
		{"Fullwidth digit 0", 0xFF10},
	}
	for _, tt := range confusable {
		t.Run("confusable/"+tt.name, func(t *testing.T) {
			if !unicode.Is(latinConfusablesAlphanum, tt.r) {
				t.Errorf("%U should be in alphanum confusables", tt.r)
			}
		})
	}

	clean := []struct {
		name string
		r    rune
	}{
		{"ASCII a", 'a'},
		{"ASCII Z", 'Z'},
		{"ASCII digit 5", '5'},
		{"Cyrillic Zhe (no Latin lookalike)", 0x0416},
		{"Cyrillic Ya (no Latin lookalike)", 0x042F},
		{"CJK middle", 0x4E2D},
		{"Party popper emoji", 0x1F389},
		{"Arabic letter meem", 0x0645},
	}
	for _, tt := range clean {
		t.Run("clean/"+tt.name, func(t *testing.T) {
			if unicode.Is(latinConfusablesAlphanum, tt.r) {
				t.Errorf("%U should not be in alphanum confusables", tt.r)
			}
		})
	}
}

func TestLatinConfusablesExcludesNumberOther(t *testing.T) {
	// Category No (Number, Other) folds to ASCII digits via NFKC but
	// renders visibly smaller or decorated, so it can't pose as a
	// Latin digit. The generator excludes all such code points.
	excluded := []struct {
		name string
		r    rune
	}{
		{"superscript 2 (²)", 0x00B2},
		{"superscript 9 (⁹)", 0x2079},
		{"subscript 0 (₀)", 0x2080},
		{"subscript 9 (₉)", 0x2089},
		{"circled 1 (①)", 0x2460},
		{"circled 0 (⓪)", 0x24EA},
		{"double-circled 21 (㉑)", 0x3251},
	}
	for _, tt := range excluded {
		t.Run("excluded/"+tt.name, func(t *testing.T) {
			for _, table := range []*unicode.RangeTable{
				latinConfusablesAlphanum,
				latinConfusablesURL,
				latinConfusablesStrict,
			} {
				if unicode.Is(table, tt.r) {
					t.Errorf("%U should be excluded from all modes", tt.r)
				}
			}
		})
	}

	// Roman numerals are category Nl (Letter), not No, so they remain
	// in the table — they are real homographs of Latin letters.
	romanLike := []struct {
		name string
		r    rune
	}{
		{"Roman I (Ⅰ)", 0x2160},
		{"Roman V (Ⅴ)", 0x2164},
		{"Roman X (Ⅹ)", 0x2169},
		{"Roman x lowercase (ⅹ)", 0x2179},
	}
	for _, tt := range romanLike {
		t.Run("kept/"+tt.name, func(t *testing.T) {
			if !unicode.Is(latinConfusablesAlphanum, tt.r) {
				t.Errorf("%U should remain in alphanum confusables", tt.r)
			}
		})
	}
}

func TestLatinConfusablesModeProgression(t *testing.T) {
	// Codepoints whose target characters demonstrate the mode tiers.
	tests := []struct {
		name       string
		r          rune
		inAlphanum bool
		inURL      bool
		inStrict   bool
	}{
		// Letter confusable: in every mode.
		{"Cyrillic а (→ a)", 0x0430, true, true, true},
		// One-dot leader (→ .): URL/strict only — `.` is not alphanum.
		{"One dot leader (→ .)", 0x2024, false, true, true},
		// En dash (→ -): URL/strict only.
		{"En dash (→ -)", 0x2013, false, true, true},
		// Right single quotation (→ '): strict only — `'` is not URL.
		{"Right single quote (→ ')", 0x2019, false, false, true},
		// Horizontal ellipsis (→ ...): URL/strict — `.` is in URL.
		{"Ellipsis (→ ...)", 0x2026, false, true, true},
		// Heavy right angle (→ >): strict only — `>` is not URL.
		{"Heavy right angle (→ >)", 0x276F, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unicode.Is(latinConfusablesAlphanum, tt.r); got != tt.inAlphanum {
				t.Errorf("alphanum: %U = %v, want %v", tt.r, got, tt.inAlphanum)
			}
			if got := unicode.Is(latinConfusablesURL, tt.r); got != tt.inURL {
				t.Errorf("url: %U = %v, want %v", tt.r, got, tt.inURL)
			}
			if got := unicode.Is(latinConfusablesStrict, tt.r); got != tt.inStrict {
				t.Errorf("strict: %U = %v, want %v", tt.r, got, tt.inStrict)
			}
		})
	}
}

func TestConfusablesTableForMode(t *testing.T) {
	tests := []struct {
		mode    string
		want    *unicode.RangeTable
		wantErr bool
	}{
		{"", nil, false},
		{"alphanum", latinConfusablesAlphanum, false},
		{"url", latinConfusablesURL, false},
		{"strict", latinConfusablesStrict, false},
		{"bogus", nil, true},
		{"ALPHANUM", nil, true}, // case-sensitive
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got, err := confusablesTableForMode(tt.mode)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for mode %q", tt.mode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("table mismatch for mode %q", tt.mode)
			}
		})
	}
}

// --- scanBytes: block-confusables integration ----------------------------

func TestScanBytesBlockConfusables(t *testing.T) {
	// Cyrillic small 'a' (U+0430), UTF-8: D0 B0.
	const cyA = "\xd0\xb0"

	t.Run("disabled by default", func(t *testing.T) {
		data := []byte("p" + cyA + "ypal.com\n")
		_, total, _, _ := scanBytes(data, scanOpts{maxMatches: defaultMaxMatches})
		if total != 0 {
			t.Errorf("confusable detection should be off by default, got %d matches", total)
		}
	})

	t.Run("detects when enabled", func(t *testing.T) {
		data := []byte("p" + cyA + "ypal.com\n")
		matches, total, _, confusable := scanBytes(data, scanOpts{confusables: latinConfusablesAlphanum, maxMatches: defaultMaxMatches})
		if total != 1 {
			t.Fatalf("expected 1 match, got %d", total)
		}
		if confusable != 1 {
			t.Errorf("confusableCount = %d, want 1", confusable)
		}
		if !strings.Contains(matches[0].Reason, "U+0430") {
			t.Errorf("reason should include U+0430, got: %s", matches[0].Reason)
		}
		if !strings.Contains(matches[0].Reason, "Latin confusable") {
			t.Errorf("reason should mention Latin confusable, got: %s", matches[0].Reason)
		}
	})

	t.Run("allowRunes suppresses specific code point", func(t *testing.T) {
		data := []byte("p" + cyA + "ypal.com\n")
		opts := scanOpts{
			confusables: latinConfusablesAlphanum,
			allowRunes:  map[rune]bool{0x0430: true},
		}
		_, total, _, _ := scanBytes(data, opts)
		if total != 0 {
			t.Errorf("allowRunes should suppress the confusable, got %d matches", total)
		}
	})

	t.Run("ASCII-only content not flagged", func(t *testing.T) {
		data := []byte("paypal.com\n")
		_, total, _, _ := scanBytes(data, scanOpts{confusables: latinConfusablesAlphanum, maxMatches: defaultMaxMatches})
		if total != 0 {
			t.Errorf("pure ASCII should not trigger confusable flag, got %d matches", total)
		}
	})

	t.Run("non-Latin script without Latin lookalike not flagged", func(t *testing.T) {
		// Ж (U+0416) is Cyrillic but does not resemble any Latin letter.
		data := []byte("\xd0\x96\n")
		_, total, _, _ := scanBytes(data, scanOpts{confusables: latinConfusablesAlphanum, maxMatches: defaultMaxMatches})
		if total != 0 {
			t.Errorf("non-confusable Cyrillic should not flag, got %d matches", total)
		}
	})

	t.Run("fullwidth URL all flagged", func(t *testing.T) {
		// ｐａｙｐａｌ — six fullwidth letters, all Latin confusables.
		data := []byte("\xef\xbd\x90\xef\xbd\x81\xef\xbd\x99\xef\xbd\x90\xef\xbd\x81\xef\xbd\x8c\n")
		_, total, _, confusable := scanBytes(data, scanOpts{confusables: latinConfusablesAlphanum, maxMatches: defaultMaxMatches})
		if total != 6 {
			t.Errorf("expected 6 fullwidth matches, got %d", total)
		}
		if confusable != 6 {
			t.Errorf("confusableCount = %d, want 6", confusable)
		}
	})

	t.Run("combined with rune detection", func(t *testing.T) {
		// NUL + Cyrillic 'a' → two distinct categories, separate counts.
		data := []byte("\x00p" + cyA + "y\n")
		_, total, _, confusable := scanBytes(data, scanOpts{confusables: latinConfusablesAlphanum, maxMatches: defaultMaxMatches})
		if total != 2 {
			t.Fatalf("expected 2 matches (1 NUL + 1 confusable), got %d", total)
		}
		if confusable != 1 {
			t.Errorf("confusableCount = %d, want 1", confusable)
		}
	})
}

// --- End-to-end: block-confusables ---------------------------------------

func TestEndToEndBlockConfusables(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	// URL with Cyrillic 'a' (U+0430) substituted for Latin 'a'.
	os.WriteFile(filepath.Join(dir, "spoof.txt"),
		[]byte("https://p\xd0\xb0ypal.com\n"), 0644)
	os.WriteFile(filepath.Join(dir, "clean.txt"),
		[]byte("https://paypal.com\n"), 0644)

	// Without --block-confusables: both files pass (non-ASCII is fine).
	cmd := exec.Command("go", "run", ".", "--quiet", dir)
	if err := cmd.Run(); err != nil {
		t.Errorf("without --block-confusables, should exit 0: %v", err)
	}

	// With --block-confusables: spoof.txt is flagged.
	cmd = exec.Command("go", "run", ".", "--block-confusables", "--quiet", dir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("with --block-confusables, expected non-zero exit")
	}
	out := string(output)
	if !strings.Contains(out, "spoof.txt") {
		t.Errorf("expected spoof.txt in output, got:\n%s", out)
	}
	if strings.Contains(out, "clean.txt") {
		t.Errorf("clean.txt should not appear, got:\n%s", out)
	}

	// Verbose: reason includes the U+XXXX code point.
	cmd = exec.Command("go", "run", ".", "--block-confusables", "--verbose", dir)
	output, _ = cmd.CombinedOutput()
	if !strings.Contains(string(output), "U+0430") {
		t.Errorf("verbose output should include U+0430, got:\n%s", string(output))
	}
}

func TestEndToEndSkipConfusables(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}

	dir := t.TempDir()
	// File with confusable AND a forbidden character.
	os.WriteFile(filepath.Join(dir, "mixed.txt"),
		[]byte("https://p\xd0\xb0ypal.com\nhello\x00world\n"), 0644)
	// File with only a confusable.
	os.WriteFile(filepath.Join(dir, "conf.txt"),
		[]byte("https://p\xd0\xb0ypal.com\n"), 0644)

	// --block-confusables alone: both files flagged.
	cmd := exec.Command("go", "run", ".", "--block-confusables", "--quiet", dir)
	output, _ := cmd.CombinedOutput()
	out := string(output)
	if !strings.Contains(out, "mixed.txt") {
		t.Errorf("expected mixed.txt flagged, got:\n%s", out)
	}
	if !strings.Contains(out, "conf.txt") {
		t.Errorf("expected conf.txt flagged, got:\n%s", out)
	}

	// --skip-confusables for mixed.txt: still flagged for NUL.
	cmd = exec.Command("go", "run", ".", "--block-confusables",
		"--skip-confusables", "mixed.txt", "--quiet", dir)
	output, _ = cmd.CombinedOutput()
	out = string(output)
	if !strings.Contains(out, "mixed.txt") {
		t.Errorf("mixed.txt should still be flagged for NUL, got:\n%s", out)
	}
	if !strings.Contains(out, "conf.txt") {
		t.Errorf("conf.txt should still be flagged, got:\n%s", out)
	}

	// --skip-confusables for conf.txt: entry appears in the skipped report.
	cmd = exec.Command("go", "run", ".", "--block-confusables",
		"--skip-confusables", "conf.txt", dir)
	output, _ = cmd.CombinedOutput()
	if !strings.Contains(string(output), "--skip-confusables conf.txt") {
		t.Errorf("expected skip-confusables entry in skipped report, got:\n%s",
			string(output))
	}

	// --skip-confusables for conf.txt: conf.txt should be clean.
	cmd = exec.Command("go", "run", ".", "--block-confusables",
		"--skip-confusables", "conf.txt", "--quiet", dir)
	output, _ = cmd.CombinedOutput()
	out = string(output)
	if strings.Contains(out, "conf.txt") {
		t.Errorf("conf.txt should be clean with --skip-confusables, got:\n%s", out)
	}
}
