package main

import (
	"testing"
	"time"
)

func TestDuration_UnmarshalText(t *testing.T) {
	var d duration
	if err := d.UnmarshalText([]byte("12h42m")); err != nil {
		t.Fatalf("duration.UnmarhsalText: unexpected error %q", err.Error())
	}
	want := time.Duration(45720000000000)
	if got := d.Duration; got != want {
		t.Errorf("duration.UnmarhsalText: got %q; want %q", got, want)
	}
}
