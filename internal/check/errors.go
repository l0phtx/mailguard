package check

import (
	"errors"
	"fmt"
)

// permError is a broken configuration that receivers treat as a permanent
// error (RFC 7208 "permerror"). Any other error is a failed DNS lookup.
type permError struct{ msg string }

func (e *permError) Error() string { return e.msg }

func permErrorf(format string, args ...any) error {
	return &permError{msg: fmt.Sprintf(format, args...)}
}

// statusFor maps an error to StatusFail for broken records and StatusError
// for lookups that could not be completed.
func statusFor(err error) Status {
	var pe *permError
	if errors.As(err, &pe) {
		return StatusFail
	}
	return StatusError
}
