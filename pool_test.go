package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/e-XpertSolutions/f5-rest-client/f5"
)

func TestWorker_Run(t *testing.T) {
	var totalRequests int
	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests++
		http.Error(w, "acknowledged", http.StatusNotFound)
	}))
	defer tsCA.Close()

	w := &worker{
		url:          tsCA.URL,
		refreshDelay: 50 * time.Millisecond,
	}

	w.run(nil, &discardLogger{})

	time.Sleep(200 * time.Millisecond)

	w.stop()

	if totalRequests < 2 {
		t.Errorf("worker.run(): expected more calls to do() method (got %d)", totalRequests)
	}
}

func TestWorker_Do(t *testing.T) {
	t.Run("Happy Path", testWorkerDoHappyPath)
	t.Run("Invalid CRL distribution URL", testWorkerDoInvalidURL)
	t.Run("Fail Begin Transaction", testWorkerDoFailBeginTransaction)
	t.Run("Fail SSL CRL", testWorkerDoFailSSLCRL)
	t.Run("Fail Get Client SSL", testWorkerDoFailGetProfileClientSSL)
	t.Run("Fail Edit Client SSL", testWorkerDoFailEditProfileClientSSL)
	t.Run("Fail Commit Transaction", testWorkerDoFailCommitTransaction)
	t.Run("Fail Verify Request", testWorkerDoFailVerifyRequest)
	t.Run("Fail Verify", testWorkerDoFailVerify)
}

func testWorkerDoHappyPath(t *testing.T) {
	tsBigIP := httptest.NewServer(newBigIPServer())
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}
	f5Client.DisableCertCheck()

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err != nil {
		t.Errorf("worker.do: unexpected error %q", err.Error())
	}
}

func testWorkerDoInvalidURL(t *testing.T) {
	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(nil); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "cannot fetch crl due to http error: 404 Not Found"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailBeginTransaction(t *testing.T) {
	srv := newBigIPServer()
	srv.Disable = "begin_transaction"
	tsBigIP := httptest.NewServer(srv)
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "cannot create request for starting a new transaction: http response error: 404 Not Found"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailSSLCRL(t *testing.T) {
	srv := newBigIPServer()
	srv.Disable = "ssl-crl"
	tsBigIP := httptest.NewServer(srv)
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "failed to import crl file: http response error: 404 Not Found"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailGetProfileClientSSL(t *testing.T) {
	srv := newBigIPServer()
	srv.Disable = "client-ssl_get"
	tsBigIP := httptest.NewServer(srv)
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "cannot get client ssl: http response error: 404 Not Found"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailEditProfileClientSSL(t *testing.T) {
	srv := newBigIPServer()
	srv.Disable = "client-ssl_put"
	tsBigIP := httptest.NewServer(srv)
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "cannot modify client-ssl: http response error: 404 Not Found"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailCommitTransaction(t *testing.T) {
	srv := newBigIPServer()
	srv.Disable = "commit_transaction"
	tsBigIP := httptest.NewServer(srv)
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "cannot commit transaction: http response error: 404 Not Found"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailVerify(t *testing.T) {
	srv := newBigIPServer()
	srv.Disable = "client-ssl_get_updated_crl"
	tsBigIP := httptest.NewServer(srv)
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "client-ssl has not been updated with the newly updated crl"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailVerifyRequest(t *testing.T) {
	srv := newBigIPServer()
	srv.Disable = "client-ssl_get_once"
	tsBigIP := httptest.NewServer(srv)
	defer tsBigIP.Close()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Fatal("cannot instanciate f5 basic client: ", err)
	}

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	w := worker{
		url:          tsCA.URL,
		crlName:      "test",
		profileName:  "clientssl",
		refreshDelay: 300,
		stopCh:       make(chan struct{}),
	}
	if err := w.do(f5Client); err == nil {
		t.Error("worker.do: expected error, got nil")
	} else {
		wantErr := "cannot retrieve updated client ssl profile: http response error: 500 Internal Server Error"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func TestWorker_Stop(t *testing.T) {
	w := &worker{
		stopCh: make(chan struct{}),
	}
	go func() {
		w.stop()
	}()
	select {
	case <-w.stopCh:
		// Ok
	case <-time.After(100 * time.Millisecond):
		t.Fatal("worker.stop: did not receive stop signal")
	}
}

func TestPool_StartAll(t *testing.T) {
	t.Run("Happy Path", testPoolStartAll)
	t.Run("F5 Client nil", testPoolStartAllNilClient)
}

func testPoolStartAll(t *testing.T) {
	tsBigIP := httptest.NewServer(newBigIPServer())
	defer tsBigIP.Close()

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	pool := &pool{}
	pool.addWorker(crlConfig{
		URL:          tsCA.URL,
		Name:         "test",
		ProfileName:  "clientssl",
		RefreshDelay: duration{Duration: 300 * time.Hour},
	})
	pool.workers[0].refreshDelay = 1 * time.Second
	defer pool.stopAll()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Errorf("pool.startAll: unexpected error %q", err.Error())
		return
	}
	f5Client.DisableCertCheck()

	if err := pool.startAll(f5Client, &discardLogger{}); err != nil {
		t.Errorf("pool.startAll: unexpected error %q", err.Error())
	}
}

func testPoolStartAllNilClient(t *testing.T) {
	pool := &pool{}
	if err := pool.startAll(nil, &discardLogger{}); err == nil {
		t.Errorf("pool.startAll: expected error, got nil")
	} else {
		wantErr := "f5 client is nil"
		if err.Error() != wantErr {
			t.Errorf("pool.startAll: got error %q; want %q", err.Error(), wantErr)
		}
	}
}
