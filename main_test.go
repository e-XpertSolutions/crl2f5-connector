package main

import (
	"bytes"
	"os"
	"os/exec"
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

	cmd := exec.Command(os.Args[0], "-test.run="+t.Name())
	cmd.Env = append(os.Environ(), "TEST_USAGE=1")

	stderrBuf := new(bytes.Buffer)
	cmd.Stderr = stderrBuf

	err := cmd.Run()
	if err == nil {
		t.Fatal("usage(): expected error, got nil")
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("usage(): expected error of type exec.ExitError, got %T", err)
	}

	if gotUsage := stderrBuf.String(); gotUsage != wantUsage {
		t.Errorf("usage():\ngot output:\n\n%s\n\nwant:\n\n%s", gotUsage, wantUsage)
	}
}

func TestVersion(t *testing.T) {
	if os.Getenv("TEST_USAGE") == "1" {
		version()
		// NOT REACHED
	}

	cmd := exec.Command(os.Args[0], "-test.run="+t.Name())
	cmd.Env = append(os.Environ(), "TEST_USAGE=1")

	stdoutBuf := new(bytes.Buffer)
	cmd.Stdout = stdoutBuf

	err := cmd.Run()
	if err != nil {
		t.Fatalf("version(): unexpected error %q", err.Error())
	}

	wantVersion := "crl2f5-connector.test - 1.0.0\n"
	if gotVersion := stdoutBuf.String(); gotVersion != wantVersion {
		t.Errorf("version(): got output %q; want %q", gotVersion, wantVersion)
	}
}

func TestFatal(t *testing.T) {
	stderrBuf := new(bytes.Buffer)
	stderr = stderrBuf

	exit = func(status int) {
		if status != 1 {
			t.Errorf("fatal(%q): got exit with status %d; want %d", "test", status, 1)
		}
	}

	fatal("test")

	want := "fatal: test\n"
	if got := stderrBuf.String(); got != want {
		t.Errorf("fatal(%q): got %q; want %q", "test", got, want)
	}
}

func TestVerbose(t *testing.T) {
	t.Run("Enabled", testVerboseWhenEnabled)
	t.Run("Disabled", testVerboseWhenDisabled)
}

func testVerboseWhenEnabled(t *testing.T) {
	b := true
	verboseMode = &b

	stdoutBuf := new(bytes.Buffer)
	stdout = stdoutBuf

	verbose("test")

	want := "verbose: test\n"
	if got := stdoutBuf.String(); got != want {
		t.Errorf("verbose(%q): got %q; want %q", "test", got, want)
	}
}

func testVerboseWhenDisabled(t *testing.T) {
	var b bool
	verboseMode = &b

	stdoutBuf := new(bytes.Buffer)
	stdout = stdoutBuf

	verbose("test")

	want := ""
	if got := stdoutBuf.String(); got != want {
		t.Errorf("verbose(%q): got %q; want %q", "test", got, want)
	}
}

func TestInfo(t *testing.T) {
	stdoutBuf := new(bytes.Buffer)
	stdout = stdoutBuf

	info("test")

	want := "info: test\n"
	if got := stdoutBuf.String(); got != want {
		t.Errorf("info(%q): got %q; want %q", "test", got, want)
	}
}
