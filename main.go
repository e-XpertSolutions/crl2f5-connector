package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/e-XpertSolutions/f5-rest-client/f5"
)

const (
	major  = "1"
	minor  = "0"
	bugfix = "0"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s\n", filepath.Base(os.Args[0]))
	flag.PrintDefaults()
	os.Exit(1)
}

func version() {
	fmt.Printf("%s - %s.%s.%s\n", filepath.Base(os.Args[0]), major, minor, bugfix)
	os.Exit(0)
}

var (
	configPath   = flag.String("config", "config.toml", "path to configuration file")
	verboseMode  = flag.Bool("verbose", false, "enable verbose mode")
	printVersion = flag.Bool("version", false, "print current version and exit")
)

func fatal(v ...interface{}) {
	fmt.Fprintln(os.Stderr, "fatal: ", fmt.Sprint(v...))
	os.Exit(1)
}

func verbose(v ...interface{}) {
	if *verboseMode {
		fmt.Println("verbose: ", fmt.Sprint(v...))
	}
}

func info(v ...interface{}) {
	fmt.Println("info: ", fmt.Sprint(v...))
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *printVersion {
		version()
	}

	cfg, err := readConfig(*configPath)
	if err != nil {
		fatal(err)
	}

	if cfg.CRL == nil || len(cfg.CRL) == 0 {
		fatal("no crl distribution point provided in the configuration file")
	}

	var f5Client *f5.Client
	switch authMethod := cfg.F5.AuthMethod; authMethod {
	case "basic":
		f5Client, err = f5.NewBasicClient(cfg.F5.URL, cfg.F5.User, cfg.F5.Password)
	case "token":
		f5Client, err = f5.NewTokenClient(
			cfg.F5.URL,
			cfg.F5.User,
			cfg.F5.Password,
			cfg.F5.LoginProviderName,
			cfg.F5.SSLCheck,
		)
	default:
		fatal("unsupported auth method \"", authMethod)
	}
	if err != nil {
		fatal("cannot initialize f5 client: ", err)
	}
	if !cfg.F5.SSLCheck {
		f5Client.DisableCertCheck()
	}

	p := new(pool)
	for _, crlCfg := range cfg.CRL {
		p.addWorker(crlCfg)
	}
	if err := p.startAll(f5Client); err != nil {
		fatal("cannot start workers: ", err)
	}

	// Catch OS signal.
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, os.Kill)

	sig := <-sigChan
	verbose("signal received: ", sig)

	p.stopAll()

	info("bye.")
}
