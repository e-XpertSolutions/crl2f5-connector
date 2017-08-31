package main

import (
	"time"
)

type duration struct {
	time.Duration
}

// UnmarshalText unmarshal and parses text into a duration.
func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}
