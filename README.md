# nobin

Scan a directory tree for files containing non-printable or invisible
characters. Catches binary files committed without binary extensions,
zero-width Unicode smuggled into source code
([Glassworm](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode)),
and encoding errors.

## What it detects

| Category | Examples |
|---|---|
| ASCII controls | NUL, BEL, ESC, DEL (everything except TAB, LF, CR) |
| C1 controls | U+0080--U+009F |
| Zero-width characters | U+200B, U+200C, U+200D, U+FEFF |
| Bidi overrides | U+202A--U+202E, U+2066--U+2069 ([Trojan Source](https://trojansource.codes/)) |
| Private Use Area | U+E000--U+F8FF, supplementary planes |
| Variation Selectors | U+FE00--U+FE0F, U+E0100--U+E01EF (Glassworm payload encoding) |
| Invalid UTF-8 | Any byte sequence that does not decode as valid UTF-8 |
| BOM | U+FEFF at the start of a file |
| Base64 data (opt-in) | Long runs of base64 characters, with `--block-base64` |
| Latin confusables (opt-in) | Non-ASCII code points that mimic Latin, with `--block-confusables` |

## Install

```
go install github.com/jandubois/nobin@latest
```

Or build from source:

```
go build -o nobin .
```

## Usage

```
nobin [path] [flags]
```

The path can be a directory or a single file. nobin assumes all text
files are UTF-8 and reports other encodings (ISO-8859, UTF-16, etc.)
as invalid UTF-8 bytes — this is intentional, since non-UTF-8 source
files are themselves a problem worth catching.

By default, nobin scans every file under the given directory (or the
current directory), excluding only `.git`. With a single file as
target, nobin scans just that file and ignores the path-pattern skip
flags — you named it explicitly. It exits 0 if all scanned files are
clean, 1 if any issues are found.

### Examples

Scan a repository, skipping known binary extensions and vendored code:

```
nobin --skip-ext png,jpg,gif,pdf,gz --skip vendor ./my-repo
```

Show the exact line, column, and Unicode code point for each match:

```
nobin --verbose ./my-repo
```

CI mode -- scan only files changed since the main branch:

```
nobin --diff main
```

Allow ESC characters (for repos with ANSI terminal output in test fixtures):

```
nobin --allow-escape ./my-repo
```

Block base64-encoded data (e.g. binary payloads hidden in source files):

```
nobin --block-base64 ./my-repo
nobin --block-base64=64 ./my-repo    # require 64+ characters to flag
```

Block homograph characters (non-ASCII code points that look like ASCII):

```
nobin --block-confusables ./my-repo            # alphanum (default)
nobin --block-confusables=url ./my-repo        # alphanum + URL chars
nobin --block-confusables=strict ./my-repo     # all printable ASCII
```

### Flags

```
      --all                 include .git directory (excluded by default)
      --allow stringArray   allow a specific code point, as hex: U+FEFF, 0xFEFF, or FEFF (repeatable)
      --allow-bell          allow BEL (0x07)
      --allow-bom           allow UTF-8 BOM at the start of files
      --allow-emoji         allow VS15/VS16 (U+FE0E, U+FE0F) emoji presentation selectors
      --allow-escape        allow ESC (0x1B) for ANSI terminal sequences
      --block-base64[=N]    detect base64-encoded strings of N+ characters (default 32)
      --block-confusables[=MODE]  detect non-ASCII code points that mimic ASCII (alphanum, url, or strict; default alphanum)
      --config string       path to config file (default: .nobin.yaml in scan target or its git root)
      --no-config           ignore any .nobin.yaml file and use only command-line flags
      --diff string         scan only files changed since BASE (branch, tag, or commit)
      --gitignore           respect .gitignore rules
      --hide-skipped        hide the list of skipped files from output
  -q, --quiet               print only file paths with issues
      --skip PATTERN        skip paths matching glob PATTERN relative to scan root (repeatable)
      --skip-base64 PATTERN skip base64 detection for paths matching glob PATTERN (repeatable)
      --skip-confusables PATTERN skip confusable detection for paths matching glob PATTERN (repeatable)
      --skip-ext strings    skip files with these extensions (comma-separated, without dot)
  -v, --verbose[=N]         show line, column, and code point for the first N matches per file (default 20)
```

### Skip patterns

The `--skip` flag matches glob patterns against path components relative
to the scan root. Supported wildcards:

| Syntax | Meaning |
|---|---|
| `*` | Any sequence of non-separator characters |
| `**` | Zero or more directories |
| `?` | Any single character |
| `[class]` | Character class (`[a-z]`, `[^abc]` or `[!abc]`) |
| `{a,b}` | Alternation (`*.{woff,woff2}` matches both) |

Quote patterns containing wildcards to prevent shell expansion:

- `--skip vendor` skips any directory or file named "vendor" at any depth.
- `--skip '*.pb.desc'` skips files ending in `.pb.desc`.
- `--skip resources/icons` skips the `resources/icons` subtree.
- `--skip '**/*.{woff,woff2}'` skips woff and woff2 files at any depth.
- `--skip 'pkg/**/fonts/**'` skips everything under any `fonts` directory below `pkg`.

nobin scans every file regardless of `--skip`, `--skip-base64`, and
`--skip-confusables`, then decides what to show. The Skipped report
lists only suppressed files that *would* have triggered, along with
the silenced hit counts. Skip-matched files with no hits stay
invisible. The exit status considers only the regular output, so
silencing a real hit still produces a clean exit.

`--skip-ext` is the one exception: it stops nobin from opening the
file at all — the right call for known binaries like images — so
those entries always show up in the Skipped report without a count.

### Output modes

**Default** lists each file with its match count:

```
src/server.go                           1 match
lib/parser.js                           3 matches
```

**Verbose** (`-v`) shows each match with its location and code point:

```
src/server.go:42:15                     U+200B ZERO WIDTH SPACE
lib/parser.js:7:1                       U+202E RIGHT-TO-LEFT OVERRIDE
```

Bare `--verbose` shows the first 20 matches per file and tags the rest
with a summary line. Pass `--verbose=N` to set a different cap — `=3`
to keep output tight on dirty files, or `=200` to inspect a binary in
full.

**Quiet** (`-q`) prints only file paths, one per line, for use in scripts.

### Configuration file

nobin reads settings from a `.nobin.yaml` file. It looks in the current
directory first, then at the git repository root. Use `--config` to
specify a different path.

All flags except `--diff` and `--config` can be set in the config file.
Command-line flags override scalar values; list flags (`--skip`,
`--skip-base64`, `--skip-confusables`, `--skip-ext`, `--allow`) extend
the config lists rather than replace them.

See [`nobin.yaml`](nobin.yaml) for a sample file with all defaults.

### Base64 detection

The `--block-base64` flag detects base64-encoded data that might hide
binary payloads in otherwise text-only files. It scans each line for
contiguous runs of base64 characters (`A`--`Z`, `a`--`z`, `0`--`9`,
`+`). The `/` character is excluded because it causes false positives
on URLs and file paths.

To reduce false positives, two kinds of strings are ignored:
purely hexadecimal strings (`0`--`9`, `A`--`F`, `a`--`f`), which
catches SHA hashes, UUIDs, and similar identifiers; and
identifier-like strings, which are alphabetic characters with at
most one contiguous group of digits (e.g. `TestTable80SameArch`).
Real base64-encoded binary data scatters digits throughout the
string, producing multiple digit groups.

The default minimum length is 32 characters. To override, use `=`:

```
nobin --block-base64=64 ./my-repo
```

Note: `--block-base64 64` (space-separated) does not work; the `=`
is required when setting a custom length.

Use `--skip-base64` to exempt specific files from base64 detection
while still scanning them for invisible characters:

```
nobin --block-base64 --skip-base64 'docs/*.md' ./my-repo
```

### Confusable detection

The `--block-confusables` flag detects non-ASCII code points that look
like ASCII characters. These are the building blocks of homograph
attacks: an attacker substitutes Cyrillic `а` for Latin `a`, Cherokee
`Ꭺ` for Latin `A`, or mathematical-styled `𝐚𝐩𝐩𝐥𝐞` for `apple`, so a
URL or identifier appears legitimate but points somewhere else.

#### Modes

The flag takes an optional mode argument controlling which ASCII
characters the source code point may resemble:

| Mode | Target alphabet | Use case |
|---|---|---|
| `alphanum` *(default)* | `A-Z a-z 0-9` | identifier and word-shaped lookalikes |
| `url` | alphanum + `. - _ ~ / : @ ? & = # % +` | URL spoofing including domain-separator attacks like `paypal․com` (U+2024 → `.`) |
| `strict` | all printable ASCII | every confusable, including typographic punctuation |

Each broader mode is a strict superset of the narrower one. The
default mode catches the most common attack — cross-script letter
substitution — while keeping false positives near zero on
documentation containing smart quotes, em dashes, and ellipses.

```
nobin --block-confusables ./my-repo            # alphanum (default)
nobin --block-confusables=url ./my-repo        # + URL punctuation
nobin --block-confusables=strict ./my-repo     # all ASCII targets
```

#### Code-point sources

Each mode unions two data sources:

- Every UTS #39 `confusables.txt` entry whose skeleton consists
  entirely of characters in the mode's target alphabet. This covers
  cross-script lookalikes (Cyrillic, Greek, Armenian, Cherokee,
  Coptic, ...) and every styled-Latin block (bold, italic, script,
  fraktur, double-struck, sans-serif, monospace, fullwidth).
- Every code point whose NFKC compatibility decomposition consists
  entirely of characters in the mode's target alphabet. This closes
  the gap `confusables.txt` leaves for fullwidth digits and other
  compatibility forms.

Every mode excludes source code points in Unicode General Category
`No` (Number, Other): superscripts (¹²³ ⁰⁴-⁹), subscripts (₀-₉), and
circled digits (①-⑳ ⓪ ㉑-㊿). They fold to ASCII digits via NFKC but
render at a different size or with extra decoration, so they cannot
pose as a Latin digit in a URL or identifier. Roman numerals (Ⅰ Ⅱ Ⅲ
...) live in category `Nl` (Letter) and stay in the table — they pose
as real Latin letters.

The current data comes from Unicode 17.0.0. Regenerate the tables
with `go generate ./...` after bumping the vendored `confusables.txt`.

#### Tuning false positives

`--skip-confusables` exempts specific files (test fixtures, translation
catalogs, internationalized prose):

```
nobin --block-confusables --skip-confusables 'testdata/*' ./my-repo
```

`--allow` exempts specific code points repository-wide. Use this when
URL mode trips on common typographic punctuation in your prose:

```
# url mode for a docs-heavy repo, allowing typographic prose chars
nobin --block-confusables=url \
      --allow U+2011 \   # NON-BREAKING HYPHEN (‑)
      --allow U+2013 \   # EN DASH (–)
      --allow U+2026 \   # HORIZONTAL ELLIPSIS (…)
      ./my-repo
```

`--allow` takes precedence over confusable detection, so the listed
code points pass even though they otherwise mimic ASCII `-` or `.`.
This combination keeps domain-separator attacks like `paypal․com`
flagged while letting prose use real typographic punctuation.

## Background

### Invisible-character smuggling

In October 2025, [Koi Security discovered
Glassworm](https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension),
a self-propagating worm that hides malicious JavaScript payloads inside
source code using invisible Unicode characters. The technique encodes
each byte of a payload as one of 256 Variation Selector code points
(U+FE00--U+FE0F and U+E0100--U+E01EF), which render as blank space in
every editor, diff viewer, and syntax highlighter. A compact decoder
reconstructs the payload and passes it to `eval()`.

nobin detects these characters, along with all other non-printable and
non-text content that has no place in source code.

### Homograph attacks

In 2017, security researcher Xudong Zheng demonstrated a
[homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack)
by registering `xn--80ak6aa92e.com`, which Chrome and Firefox
displayed as `аpple.com` — with a Cyrillic `а` (U+0430) where
Latin `a` belongs. The proof of concept prompted both browsers to
tighten their IDN display policies the same week.

Source code is just as susceptible. An attacker who substitutes
Cyrillic `а` for Latin `a`, Cherokee `Ꭺ` for Latin `A`, fullwidth
`ｐａｙｐａｌ` for `paypal`, or any of roughly 1800 other Unicode code
points can hide a fake URL or identifier inside a comment, string
literal, or import path that survives code review unchanged.

nobin's `--block-confusables` flag detects every non-ASCII code point
whose Unicode skeleton or NFKC form folds to ASCII, denying the
attacker any path to a Latin-looking string with a hidden swap.

## License

[Apache License 2.0](LICENSE)
