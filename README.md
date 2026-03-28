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
nobin [directory] [flags]
```

nobin assumes all text files are UTF-8. Files in other encodings
(ISO-8859, UTF-16, etc.) will be reported as containing invalid UTF-8
bytes — this is intentional, since non-UTF-8 source files are
themselves a problem worth catching.

By default, nobin scans every file under the given directory (or the
current directory), excluding only `.git`. It exits 0 if all files are
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
nobin --block-base64=128 ./my-repo   # require 128+ characters to flag
```

### Flags

```
      --all                 include .git directory (excluded by default)
      --allow stringArray   allow a specific code point, as hex: U+FEFF, 0xFEFF, or FEFF (repeatable)
      --allow-bell          allow BEL (0x07)
      --allow-bom           allow UTF-8 BOM at the start of files
      --allow-emoji         allow VS15/VS16 (U+FE0E, U+FE0F) emoji presentation selectors
      --allow-escape        allow ESC (0x1B) for ANSI terminal sequences
      --block-base64[=N]    detect base64-encoded strings of N+ characters (default 64)
      --diff string         scan only files changed since BASE (branch, tag, or commit)
      --gitignore           respect .gitignore rules
      --hide-skipped        hide the list of skipped files from output
  -q, --quiet               print only file paths with issues
      --skip PATTERN        skip paths matching glob PATTERN relative to scan root (repeatable)
      --skip-ext strings    skip files with these extensions (comma-separated, without dot)
  -v, --verbose             show line, column, and code point for each match
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

Skipped entries appear in the output so you know coverage is incomplete.

### Output modes

**Default** lists each file with its match count:

```
src/server.go                           1 match
lib/parser.js                           3 matches
```

**Verbose** (`-v`) shows every match with its location and code point:

```
src/server.go:42:15                     U+200B ZERO WIDTH SPACE
lib/parser.js:7:1                       U+202E RIGHT-TO-LEFT OVERRIDE
```

Files with more than 20 matches (typically binaries) show the first 20
and a summary of the rest.

**Quiet** (`-q`) prints only file paths, one per line, for use in scripts.

### Base64 detection

The `--block-base64` flag detects base64-encoded data that might hide
binary payloads in otherwise text-only files. It scans each line for
contiguous runs of base64 characters (`A`--`Z`, `a`--`z`, `0`--`9`,
`+`, `/`).

To reduce false positives, strings that contain only hexadecimal
characters (`0`--`9`, `A`--`F`, `a`--`f`) are ignored. This excludes
SHA hashes, UUIDs, and similar hex-encoded identifiers, which are
common in source code and almost never base64-encoded binary data.

The default minimum length is 64 characters. To override, use `=`:

```
nobin --block-base64=128 ./my-repo
```

Note: `--block-base64 128` (space-separated) does not work; the `=`
is required when setting a custom length.

## Background

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

## License

[Apache License 2.0](LICENSE)
