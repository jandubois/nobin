// This module is for the code generator only. Keeping it separate from
// the main module avoids pulling golang.org/x/text and its data tables
// into the end-user binary.
module github.com/jandubois/nobin/internal/confusables/gen

go 1.25.0

require golang.org/x/text v0.36.0
