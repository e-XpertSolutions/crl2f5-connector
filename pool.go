package main

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/e-XpertSolutions/f5-rest-client/f5"
	"github.com/e-XpertSolutions/f5-rest-client/f5/ltm"
	"github.com/e-XpertSolutions/f5-rest-client/f5/sys"
)

type worker struct {
	url          string
	crlName      string
	profileName  string
	refreshDelay time.Duration
	validate     bool

	stopCh chan struct{}
}

func (w *worker) run(f5Clients []*f5.Client, l logger) {
	w.stopCh = make(chan struct{})
	go func() {
		w.do(f5Clients, l)
		for {
			select {
			case <-time.After(w.refreshDelay):
				w.do(f5Clients, l)
			case <-w.stopCh:
				l.Notice("stop signal received, terminating worker routine")
				return
			}
		}
	}()
}

func (w *worker) do(f5Clients []*f5.Client, l logger) {
	// Make sure no panic will interrupt the program.
	defer func() {
		if r := recover(); r != nil {
			l.Error("panic recovered: ", r)
		}
	}()
	crl, err := fetchCRL(w.url)
	if err != nil {
		l.Error(err)
		return
	}
	for _, f5Client := range f5Clients {
		if err := w.pushCRLToClients(f5Client, crl); err != nil {
			l.Error(err)
		}
	}
}

func (w *worker) pushCRLToClients(f5Client *f5.Client, crl []byte) error {
	tx, err := f5Client.Begin()
	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(crl)
	crlName := w.crlName + "_" + strconv.FormatInt(time.Now().Unix(), 10)

	sysClient := sys.New(tx)
	err = sysClient.FileSSLCRL().CreateFromFile(crlName, buf, int64(buf.Len()))
	if err != nil {
		return err
	}

	ltmClient := ltm.New(tx)

	cfg, err := ltmClient.ProfileClientSSL().Get(w.profileName)
	if err != nil {
		return errors.New("cannot get client ssl: " + err.Error())
	}

	// .crl extension is automatically added while uploading the file, therefore
	// we need to concatenate it to crlName so thtat the client-ssl API can
	// retrieve it.
	cfg.CRLFile = crlName + ".crl"

	if err := ltmClient.ProfileClientSSL().Edit(w.profileName, *cfg); err != nil {
		return errors.New("cannot modify client-ssl: " + err.Error())
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Now that the transaction has been committed, we verify that everything
	// worked as intended.
	cfg, err = ltmClient.ProfileClientSSL().Get(w.profileName)
	if err != nil {
		return errors.New("cannot retrieve updated client ssl profile: " + err.Error())
	}
	if !strings.HasSuffix(cfg.CRLFile, crlName+".crl") {
		return errors.New("client-ssl has not been updated with the newly updated crl")
	}

	return nil
}

func (w *worker) stop() {
	w.stopCh <- struct{}{}
	close(w.stopCh)
}

type pool struct {
	workers []*worker
}

func (p *pool) addWorker(cfg crlConfig) {
	p.workers = append(p.workers, &worker{
		url:          cfg.URL,
		crlName:      cfg.Name,
		profileName:  cfg.ProfileName,
		refreshDelay: cfg.RefreshDelay.Duration * time.Hour,
		validate:     cfg.Validate,
	})
}

func (p *pool) startAll(f5Clients []*f5.Client, l logger) error {
	if f5Clients == nil {
		return errors.New("f5 clients list is nil")
	}
	if len(f5Clients) == 0 {
		return errors.New("f5 clients list is empty")
	}
	for _, w := range p.workers {
		w.run(f5Clients, l)
	}
	return nil
}

// XXX(gilliek): wait with timeout?
func (p *pool) stopAll() {
	var wg sync.WaitGroup
	for _, w := range p.workers {
		wg.Add(1)
		go func(ww *worker) {
			defer wg.Done()
			ww.stop()
		}(w)
	}
	wg.Wait()
}
