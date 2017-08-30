package main

import (
	"bytes"
	"errors"
	"log"
	"strconv"
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

func (w *worker) run(f5Client *f5.Client) {
	w.stopCh = make(chan struct{})
	go func() {
		if err := w.do(f5Client); err != nil {
			log.Print("error=", err)
		}
		for {
			select {
			case <-time.After(w.refreshDelay):
				if err := w.do(f5Client); err != nil {
					log.Print("error=", err)
				}
			case <-w.stopCh:
				log.Print("stop signal received")
				return
			}
		}
	}()
}

func (w *worker) do(f5Client *f5.Client) error {
	crl, err := fetchCRL(w.url)
	if err != nil {
		return err
	}

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
		return errors.New("cannot modify client ssl: " + err.Error())
	}

	if err := tx.Commit(); err != nil {
		return err
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
		refreshDelay: time.Duration(cfg.RefreshDelayInHours) * time.Hour,
		validate:     cfg.Validate,
	})
}

func (p *pool) startAll(f5Client *f5.Client) error {
	if f5Client == nil {
		return errors.New("f5 client is nil")
	}
	for _, w := range p.workers {
		w.run(f5Client)
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
