package util

import (
	"fmt"
)

type StringerWithError func() (string, error)

func Must(err error) {
	if err != nil {
		panic(fmt.Errorf("internal error: %w", err))
	}
}

func MustString(fn StringerWithError) string {
	s, err := fn()
	if err != nil {
		panic(fmt.Errorf("internal error: %w", err))
	}
	return s
}

func Default(s string, defaultS string) string {
	if s == "" {
		return defaultS
	}
	return s
}

func DefaultIfError(fn StringerWithError, defaultS string) string {
	s, err := fn()
	if err != nil {
		return defaultS
	}
	return s
}

func DefaultIfNil(s *string, defaultS string) string {
	if s == nil {
		return defaultS
	}
	return *s
}
