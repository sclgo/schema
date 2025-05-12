package schema

import "errors"

// ErrNotSupported is the not supported error.
var (
	ErrNotSupported = errors.New("not supported")

	// ErrWrongNumberOfArguments is the wrong number of arguments error.
	ErrWrongNumberOfArguments = errors.New("wrong number of arguments")
)
