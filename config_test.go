package main

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

const validConfigFileContent = `[f5]
auth_method = "basic"
url = "http://localhost/bigip"
user = "admin"
password = "admin"
ssl_check = false

[[crl]]
url = "http://localhost/test.crl"
name = "test"
profile_name = "clientssl"
refresh_delay = "6h"
validate = true
`
const invalidConfigFileContent = `{invalid}`

func createTempConfigFile(data string) (*os.File, error) {
	f, err := ioutil.TempFile(os.TempDir(), "crl2f5-connector-test")
	if err != nil {
		return nil, errors.New("cannot create temporary configuration file")
	}
	if _, err := f.Write([]byte(data)); err != nil {
		f.Close()
		return nil, errors.New("cannot write configuration in temporary configuration file")
	}
	return f, nil
}

func TestReadConfig(t *testing.T) {
	// Setup temporary configuration files and make sure they will be deleted
	// at the end of this test.
	validFile, err := createTempConfigFile(validConfigFileContent)
	if err != nil {
		t.Fatal("setup: ", err)
	}
	defer os.Remove(validFile.Name())
	defer validFile.Close()

	invalidFile, err := createTempConfigFile(invalidConfigFileContent)
	if err != nil {
		t.Fatal("setup: ", err)
	}
	defer os.Remove(invalidFile.Name())
	defer invalidFile.Close()

	// Run subtests
	t.Run("Happy Path", func(t *testing.T) { testReadConfigHappyPath(t, validFile) })
	t.Run("Fail Open", testReadConfigFailOpen)
	t.Run("Fail Decode", func(t *testing.T) { testReadConfigFailDecode(t, invalidFile) })
}

func testReadConfigHappyPath(t *testing.T, validFile *os.File) {
	path := validFile.Name()

	cfg, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig(%q): unexpected error %q", path, err.Error())
	}
	want := config{}
	want.F5.AuthMethod = "basic"
	want.F5.URL = "http://localhost/bigip"
	want.F5.User = "admin"
	want.F5.Password = "admin"
	want.CRL = append(want.CRL, crlConfig{
		URL:          "http://localhost/test.crl",
		Name:         "test",
		ProfileName:  "clientssl",
		RefreshDelay: duration{Duration: 6 * time.Hour},
		Validate:     true,
	})
	if got := cfg.F5.AuthMethod; got != want.F5.AuthMethod {
		t.Errorf("readConfig(%q): got auth_method %q; want %q",
			path, got, want.F5.AuthMethod)
	}
	if got := cfg.F5.URL; got != want.F5.URL {
		t.Errorf("readConfig(%q): got url %q; want %q",
			path, got, want.F5.URL)
	}
	if got := cfg.F5.User; got != want.F5.User {
		t.Errorf("readConfig(%q): got user %q; want %q",
			path, got, want.F5.User)
	}
	if got := cfg.F5.Password; got != want.F5.Password {
		t.Errorf("readConfig(%q): got password %q; want %q",
			path, got, want.F5.Password)
	}
	if got := cfg.F5.SSLCheck; got != want.F5.SSLCheck {
		t.Errorf("readConfig(%q): got password %v; want %v",
			path, got, want.F5.SSLCheck)
	}
	if got := cfg.F5.LoginProviderName; got != want.F5.LoginProviderName {
		t.Errorf("readConfig(%q): got password %q; want %q",
			path, got, want.F5.LoginProviderName)
	}
	if got := len(cfg.CRL); got != 1 {
		t.Fatalf("readConfig(%q): got %d crl; want %d",
			path, got, len(want.CRL))
	}
	if got := cfg.CRL[0].URL; got != want.CRL[0].URL {
		t.Errorf("readConfig(%q): got password %q; want %q",
			path, got, want.CRL[0].URL)
	}
	if got := cfg.CRL[0].Name; got != want.CRL[0].Name {
		t.Errorf("readConfig(%q): got name %q; want %q",
			path, got, want.CRL[0].Name)
	}
	if got := cfg.CRL[0].ProfileName; got != want.CRL[0].ProfileName {
		t.Errorf("readConfig(%q): got profile_name %q; want %q",
			path, got, want.CRL[0].ProfileName)
	}
	if got := cfg.CRL[0].RefreshDelay; got != want.CRL[0].RefreshDelay {
		t.Errorf("readConfig(%q): got profile_name %q; want %q",
			path, got, want.CRL[0].RefreshDelay)
	}
	if got := cfg.CRL[0].Validate; got != want.CRL[0].Validate {
		t.Errorf("readConfig(%q): got validate %v; want %v",
			path, got, want.CRL[0].Validate)
	}
}

func testReadConfigFailOpen(t *testing.T) {
	invalidPath := "some-path-that-does-not-exist"
	_, err := readConfig(invalidPath)
	if err == nil {
		t.Fatalf("readConfig(%q): expected error, got nil", invalidPath)
	}
	wantErr := "cannot open configuration file: open some-path-that-does-not-exist: no such file or directory"
	if err.Error() != wantErr {
		t.Errorf("readConfig(%q): got error %q; want %q", invalidPath, err.Error(), wantErr)
	}
}

func testReadConfigFailDecode(t *testing.T, invalidFile *os.File) {
	path := invalidFile.Name()
	_, err := readConfig(path)
	if err == nil {
		t.Fatalf("readConfig(%q): expected error, got nil", path)
	}
	wantErr := "cannot read configuration file: Near line 0 (last key parsed ''): Bare keys cannot contain '{'."
	if err.Error() != wantErr {
		t.Errorf("readConfig(%q): got error %q; want %q", path, err.Error(), wantErr)
	}
}
