package main

import (
	"bytes"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

// IMPORTANT: Note for further changes:
//    Flag name and type is preceded by 2 ASCII spaces
//    Flag description is preceded by 4 ASCII spaces and 1 ASCII tab
const wantUsage = `usage: crl2f5-connector.test
  -config string
    	path to configuration file (default "config.toml")
  -httptest.serve string
    	if non-empty, httptest.NewServer serves on this address and blocks
  -test.bench regexp
    	run only benchmarks matching regexp
  -test.benchmem
    	print memory allocations for benchmarks
  -test.benchtime d
    	run each benchmark for duration d (default 1s)
  -test.blockprofile file
    	write a goroutine blocking profile to file
  -test.blockprofilerate rate
    	set blocking profile rate (see runtime.SetBlockProfileRate) (default 1)
  -test.count n
    	run tests and benchmarks n times (default 1)
  -test.coverprofile file
    	write a coverage profile to file
  -test.cpu list
    	comma-separated list of cpu counts to run each test with
  -test.cpuprofile file
    	write a cpu profile to file
  -test.memprofile file
    	write a memory profile to file
  -test.memprofilerate rate
    	set memory profiling rate (see runtime.MemProfileRate)
  -test.mutexprofile string
    	write a mutex contention profile to the named file after execution
  -test.mutexprofilefraction int
    	if >= 0, calls runtime.SetMutexProfileFraction() (default 1)
  -test.outputdir dir
    	write profiles to dir
  -test.parallel n
    	run at most n tests in parallel (default 4)
  -test.run regexp
    	run only tests and examples matching regexp
  -test.short
    	run smaller test suite to save time
  -test.timeout d
    	fail test binary execution after duration d (0 means unlimited)
  -test.trace file
    	write an execution trace to file
  -test.v
    	verbose: print additional output
  -verbose
    	enable verbose mode
  -version
    	print current version and exit
`

func TestUsage(t *testing.T) {
	if os.Getenv("TEST_USAGE") == "1" {
		usage()
		// NOT REACHED
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestUsage")
	cmd.Env = append(os.Environ(), "TEST_USAGE=1")

	stderrBuf := new(bytes.Buffer)
	cmd.Stderr = stderrBuf

	err := cmd.Run()
	if err == nil {
		t.Fatal("usage(): expected error, got nil")
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("usage(): expected error of type exec.ExitError, got %v", reflect.TypeOf(err))
	}

	if gotUsage := stderrBuf.String(); gotUsage != wantUsage {
		t.Errorf("usage():\ngot output:\n\n%s\n\nwant:\n\n%s", gotUsage, wantUsage)
	}
}
