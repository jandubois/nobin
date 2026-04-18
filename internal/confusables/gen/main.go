// Generator for the Latin-confusables RangeTables used by --block-confusables.
//
// Emits three RangeTables, one per detection mode, by unioning two sources
// for each mode:
//
//  1. UTS #39 confusables.txt entries whose skeleton characters all fall
//     inside the mode's target alphabet. These cover cross-script
//     homographs like Cyrillic а, Greek α, Cherokee Ꭺ, math-styled Latin.
//
//  2. Every non-ASCII code point whose NFKC compatibility decomposition
//     consists entirely of characters in the mode's target alphabet.
//     UTS #39 §5.2 treats these as confusable under "Highly Restrictive"
//     identifier rules; the skeleton data alone misses them (e.g.
//     fullwidth digits have no confusables.txt entry but fold via NFKC).
//
// The three target alphabets are:
//
//	alphanum: A-Z a-z 0-9
//	url:      alphanum + . - _ ~ / : @ ? & = # % +
//	strict:   all printable ASCII 0x20-0x7E
//
// Run from the repo root via: go generate ./...
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Paths are relative to this file's directory, so the generator can be
// invoked from any working directory via `go -C internal/confusables/gen`.
const (
	inputPath  = "../data/confusables.txt"
	outputPath = "../../../confusables_table.go"
)

type mode struct {
	name    string // exported Go identifier suffix
	desc    string // human description for the comment
	allowed func(r rune) bool
}

var modes = []mode{
	{"Alphanum", "A-Z a-z 0-9", isAlphanum},
	{"URL", "alphanum + . - _ ~ / : @ ? & = # % +", isURLChar},
	{"Strict", "all printable ASCII 0x20-0x7E", isPrintableASCII},
}

func isAlphanum(r rune) bool {
	return (r >= '0' && r <= '9') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z')
}

// isURLChar covers the unreserved and reserved characters from RFC 3986
// that commonly appear in displayed URLs: domain syntax (. - _ ~), path
// (/), userinfo (@), scheme (:), and query/fragment (? & = # % +).
// Sub-delims like ! $ ' ( ) * , ; and brackets [ ] are deliberately
// excluded — they're rare in normal URLs and add noise in source files.
func isURLChar(r rune) bool {
	if isAlphanum(r) {
		return true
	}
	switch r {
	case '.', '-', '_', '~', '/', ':', '@', '?', '&', '=', '#', '%', '+':
		return true
	}
	return false
}

func isPrintableASCII(r rune) bool {
	return r >= 0x20 && r <= 0x7E
}

type modeStats struct {
	sources   map[rune]bool
	entries   int
	nfkcAdded int
}

func newModeStats() *modeStats {
	return &modeStats{sources: map[rune]bool{}}
}

func main() {
	stats := make(map[string]*modeStats, len(modes))
	for _, m := range modes {
		stats[m.name] = newModeStats()
	}

	f, err := os.Open(inputPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var unicodeVersion string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# Version:") {
			unicodeVersion = strings.TrimSpace(strings.TrimPrefix(line, "# Version:"))
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ";")
		if len(parts) < 2 {
			continue
		}

		src, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 16, 32)
		if err != nil {
			continue
		}
		srcR := rune(src)
		if srcR < 0x80 {
			continue
		}

		tgtFields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(tgtFields) == 0 {
			continue
		}
		targets := make([]rune, 0, len(tgtFields))
		valid := true
		for _, t := range tgtFields {
			tn, err := strconv.ParseUint(t, 16, 32)
			if err != nil {
				valid = false
				break
			}
			targets = append(targets, rune(tn))
		}
		if !valid {
			continue
		}

		for _, m := range modes {
			if allRunesAllowed(targets, m.allowed) {
				st := stats[m.name]
				if !st.sources[srcR] {
					st.sources[srcR] = true
					st.entries++
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	// Augment each mode with codepoints whose NFKC form fits its alphabet.
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		folded := norm.NFKC.String(string(r))
		if folded == "" || folded == string(r) {
			continue
		}
		for _, m := range modes {
			if !allRunesInString(folded, m.allowed) {
				continue
			}
			st := stats[m.name]
			if !st.sources[r] {
				st.sources[r] = true
				st.nfkcAdded++
			}
		}
	}

	if err := emit(outputPath, unicodeVersion, stats); err != nil {
		log.Fatal(err)
	}
	for _, m := range modes {
		st := stats[m.name]
		fmt.Fprintf(os.Stderr,
			"  %-9s %5d code points (%d skeleton + %d NFKC)\n",
			m.name+":", len(st.sources), st.entries, st.nfkcAdded)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s (Unicode %s)\n", outputPath, unicodeVersion)
}

func allRunesAllowed(rs []rune, allowed func(rune) bool) bool {
	for _, r := range rs {
		if !allowed(r) {
			return false
		}
	}
	return true
}

func allRunesInString(s string, allowed func(rune) bool) bool {
	for _, r := range s {
		if !allowed(r) {
			return false
		}
	}
	return true
}

type runeRange struct {
	lo, hi rune
}

func compressRanges(sources []rune) []runeRange {
	var out []runeRange
	for _, r := range sources {
		if len(out) > 0 && out[len(out)-1].hi+1 == r {
			out[len(out)-1].hi = r
		} else {
			out = append(out, runeRange{r, r})
		}
	}
	return out
}

func emit(path, version string, stats map[string]*modeStats) error {
	var b strings.Builder
	fmt.Fprintln(&b, "// Code generated by internal/confusables/gen. DO NOT EDIT.")
	fmt.Fprintf(&b, "// Source: UTS #39 confusables.txt, Unicode version %s.\n", version)
	fmt.Fprintln(&b, "// Derived from data © Unicode, Inc. (Unicode License V3).")
	fmt.Fprintln(&b, "// License: internal/confusables/data/LICENSE")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "package main")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, `import "unicode"`)

	for _, m := range modes {
		st := stats[m.name]
		sources := make([]rune, 0, len(st.sources))
		for r := range st.sources {
			sources = append(sources, r)
		}
		sort.Slice(sources, func(i, j int) bool { return sources[i] < sources[j] })

		fmt.Fprintln(&b)
		fmt.Fprintf(&b,
			"// latinConfusables%s lists every non-ASCII code point whose UTS #39\n",
			m.name)
		fmt.Fprintf(&b,
			"// skeleton or NFKC form consists entirely of characters in: %s.\n",
			m.desc)
		fmt.Fprintf(&b,
			"// %d code points (%d from confusables.txt, %d added via NFKC).\n",
			len(sources), st.entries, st.nfkcAdded)
		emitTable(&b, "latinConfusables"+m.name, sources)
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func emitTable(b *strings.Builder, name string, sources []rune) {
	ranges := compressRanges(sources)
	var r16, r32 []runeRange
	for _, rr := range ranges {
		if rr.hi < 0x10000 {
			r16 = append(r16, rr)
		} else {
			r32 = append(r32, rr)
		}
	}
	latinOffset := 0
	for _, rr := range r16 {
		if rr.hi > unicode.MaxLatin1 {
			break
		}
		latinOffset++
	}

	fmt.Fprintf(b, "var %s = &unicode.RangeTable{\n", name)
	if len(r16) > 0 {
		fmt.Fprintln(b, "\tR16: []unicode.Range16{")
		for _, rr := range r16 {
			fmt.Fprintf(b, "\t\t{0x%04X, 0x%04X, 1},\n", rr.lo, rr.hi)
		}
		fmt.Fprintln(b, "\t},")
	}
	if len(r32) > 0 {
		fmt.Fprintln(b, "\tR32: []unicode.Range32{")
		for _, rr := range r32 {
			fmt.Fprintf(b, "\t\t{0x%X, 0x%X, 1},\n", rr.lo, rr.hi)
		}
		fmt.Fprintln(b, "\t},")
	}
	fmt.Fprintf(b, "\tLatinOffset: %d,\n", latinOffset)
	fmt.Fprintln(b, "}")
}
