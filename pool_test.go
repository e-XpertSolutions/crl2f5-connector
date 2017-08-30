package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/e-XpertSolutions/f5-rest-client/f5"
)

const clientSSLProfile = `{"kind":"tm:ltm:profile:client-ssl:client-sslstate","name":"clientssl","fullPath":"clientssl","generation":1708,"selfLink":"https://localhost/mgmt/tm/ltm/profile/client-ssl/clientssl?ver=13.0.0","alertTimeout":"indefinite","allowDynamicRecordSizing":"disabled","allowExpiredCrl":"disabled","allowNonSsl":"disabled","appService":"none","authenticate":"once","authenticateDepth":9,"bypassOnClientCertFail":"disabled","bypassOnHandshakeAlert":"disabled","caFile":"none","cacheSize":262144,"cacheTimeout":3600,"cert":"/Common/default.crt","certReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~default.crt?ver=13.0.0"},"certExtensionIncludes":["basic-constraints","subject-alternative-name"],"certLifespan":30,"certLookupByIpaddrPort":"disabled","chain":"none","cipherGroup":"none","ciphers":"DEFAULT","clientCertCa":"none","crlFile":"/Common/test4.crl","crlFileReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-crl/~Common~test4.crl?ver=13.0.0"},"defaultsFrom":"none","description":"none","destinationIpBlacklist":"none","destinationIpWhitelist":"none","forwardProxyBypassDefaultAction":"intercept","genericAlert":"enabled","handshakeTimeout":"10","hostnameBlacklist":"none","hostnameWhitelist":"none","inheritCertkeychain":"false","key":"/Common/default.key","keyReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-key/~Common~default.key?ver=13.0.0"},"maxActiveHandshakes":"indefinite","maxAggregateRenegotiationPerMinute":"indefinite","maxRenegotiationsPerMinute":5,"maximumRecordSize":16384,"modSslMethods":"disabled","mode":"enabled","notifyCertStatusToVirtualServer":"disabled","ocspStapling":"disabled","tmOptions":["dont-insert-empty-fragments"],"peerCertMode":"ignore","peerNoRenegotiateTimeout":"10","proxyCaCert":"none","proxyCaKey":"none","proxySsl":"disabled","proxySslPassthrough":"disabled","renegotiateMaxRecordDelay":"indefinite","renegotiatePeriod":"indefinite","renegotiateSize":"indefinite","renegotiation":"enabled","retainCertificate":"true","secureRenegotiation":"require","serverName":"none","sessionMirroring":"disabled","sessionTicket":"disabled","sessionTicketTimeout":0,"sniDefault":"false","sniRequire":"false","sourceIpBlacklist":"none","sourceIpWhitelist":"none","sslForwardProxy":"disabled","sslForwardProxyBypass":"disabled","sslSignHash":"any","strictResume":"disabled","uncleanShutdown":"enabled","certKeyChain":[{"name":"default","appService":"none","cert":"/Common/default.crt","certReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~default.crt?ver=13.0.0"},"chain":"none","key":"/Common/default.key","keyReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-key/~Common~default.key?ver=13.0.0"}}]}`

const editProfileResp = `{"kind":"tm:sys:file:ssl-crl:ssl-crlstate","name":"test.crl","fullPath":"test.crl","generation":3488,"selfLink":"https://localhost/mgmt/tm/sys/file/ssl-crl/test.crl?ver=13.0.0","checksum":"SHA1:930:eb57c456aef899566a1a8166b1b8ec0390ae00f6","createTime":"2017-08-25T13:03:04Z","createdBy":"admin","lastUpdateTime":"2017-08-28T15:33:19Z","mode":33188,"revision":7,"size":930,"sourcePath":"file:/var/config/rest/downloads/test.crl","updatedBy":"admin"}`

const uploadResp = `{"remainingByteCount":0,"usedChunks":{"0":930},"totalByteCount":930,"localFilePath":"/var/config/rest/downloads/test.crl","temporaryFilePath":"/var/config/rest/downloads/tmp/test.crl","generation":0,"lastUpdateMicros":1503935541736191}`

const crlFile = `-----BEGIN X509 CRL-----
MIIChjCCAW4CAQEwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNV
BAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3Jp
dHkgRzIXDTE3MDgyNTAxMDAwMloXDTE3MDkwNDAxMDAwMlowgb4wGQIII134x0pw
UxAXDTE3MDgxMDA5NTEwOFowGQIIW+Bf6etmZUkXDTE3MDgxMDA5NTExOFowGQII
BTa7iwOcb8cXDTE3MDgxMDA5NTEyN1owGQIIHboJAg2j0doXDTE3MDgxMDA5NTEz
NlowJwIIAX6wMgl8WcQXDTE3MDcyNDA4Mzc1MVowDDAKBgNVHRUEAwoBBTAnAggx
2jOAGCr5shcNMTYwOTE1MjAyMjEzWjAMMAoGA1UdFQQDCgEDoDAwLjAfBgNVHSME
GDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzALBgNVHRQEBAICBmIwDQYJKoZIhvcN
AQELBQADggEBAIv5JdgQVOw+h2wC06zIOSmKrTPFe2FbQWZA0Gb7S5swsl4k97Y5
0YM4Q8/CndKKSD6djRB0Z6E8a92yobV5nRon0VHZNDiWhTDY45lPfmqNUnllTME+
EG6mmjpltjYnm4leJ0p4fZDiNh0xsqaU4XqZSqB7PGYpfRg7V5utNNPwsk9vyPBy
DSrVw83uH25Mv7D3ugGDY1KYJ9ilyFfCo1/WUpZEX0flUlylZRxLzGcqj1+o6Qk3
XcMvOojI+fCzog0hhQV9R+mst4kP9myNsT7l4QMC3ijyv+BPRkwoK/R6Q3Q72W4j
B6LgKO92SkGoL376RBzINiuZr/Esd3b4nv4=
-----END X509 CRL-----
`

func makeBigIPHandler(disable string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		switch path := r.URL.Path; path {
		case "/mgmt/tm/ltm/profile/client-ssl/clientssl":
			switch method := r.Method; method {
			case "GET":
				if disable == "client-ssl_get" {
					http.Error(w, "disabled", http.StatusNotFound)
					return
				}
				w.Write([]byte(clientSSLProfile))
			case "PUT":
				if disable == "client-ssl_put" {
					http.Error(w, "disabled", http.StatusNotFound)
					return
				}
				w.Write([]byte(editProfileResp))
			default:
				http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, path), http.StatusBadRequest)
			}
		case "/mgmt/tm/transaction":
			if disable == "begin_transaction" {
				http.Error(w, "disabled", http.StatusNotFound)
				return
			}
			switch method := r.Method; method {
			case "POST":
				w.Write([]byte(`{"transId": 123456789, "state": "STARTED"}`))
			default:
				http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, path), http.StatusBadRequest)
			}
		case "/mgmt/tm/transaction/123456789":
			if disable == "commit_transaction" {
				http.Error(w, "disabled", http.StatusNotFound)
				return
			}
			switch method := r.Method; method {
			case "PATCH":
				w.Write([]byte(`{}`))
			default:
				http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, path), http.StatusBadRequest)
			}

		// Dynamic routes
		default:
			switch {
			case strings.HasPrefix(path, "/mgmt/shared/file-transfer/uploads"):
				switch method := r.Method; method {
				case "POST":
					w.Write([]byte(uploadResp))
				default:
					http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, path), http.StatusBadRequest)
				}
			case strings.HasPrefix(path, "/mgmt/tm/sys/file/ssl-crl"):
				if disable == "ssl-crl" {
					http.Error(w, "disabled", http.StatusNotFound)
					return
				}
				var filename string
				switch method := r.Method; method {
				case "POST":
					data := make(map[string]string)
					dec := json.NewDecoder(r.Body)
					if err := dec.Decode(&data); err != nil {
						http.Error(w, "malformed request data: "+err.Error(), http.StatusBadRequest)
						return
					}
					var ok bool
					filename, ok = data["name"]
					if !ok {
						http.Error(w, "missing name in request data", http.StatusBadRequest)
						return
					}
				case "PUT": // PUT?
					filename = path[strings.LastIndex(path, "/")+1:]
				default:
					http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, path), http.StatusBadRequest)
					return
				}
				w.Write([]byte(fmt.Sprintf(`{"remainingByteCount":0,"usedChunks":{"0":930},"totalByteCount":930,"localFilePath":"/var/config/rest/downloads/%s","temporaryFilePath":"/var/config/rest/downloads/tmp/%s","generation":0,"lastUpdateMicros":1503997621775731}`, filename, filename)))
			default:
				http.Error(w, fmt.Sprintf("unsupported path %q", path), http.StatusNotFound)
			}
		}
	})
}

func TestWorker_Do(t *testing.T) {
	t.Run("Happy Path", testWorkerDoHappyPath)
	t.Run("Invalid CRL distribution URL", testWorkerDoInvalidURL)
	t.Run("Fail Begin Transaction", testWorkerDoFailBeginTransaction)
	t.Run("Fail SSL CRL", testWorkerDoFailSSLCRL)
	t.Run("Fail Get Client SSL", testWorkerDoFailGetProfileClientSSL)
	t.Run("Fail Edit Client SSL", testWorkerDoFailEditProfileClientSSL)
	t.Run("Fail Commit Transaction", testWorkerDoFailCommitTransaction)
}

func testWorkerDoHappyPath(t *testing.T) {
	tsBigIP := httptest.NewServer(makeBigIPHandler(""))
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
	tsBigIP := httptest.NewServer(makeBigIPHandler("begin_transaction"))
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
	tsBigIP := httptest.NewServer(makeBigIPHandler("ssl-crl"))
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
	tsBigIP := httptest.NewServer(makeBigIPHandler("client-ssl_get"))
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
	tsBigIP := httptest.NewServer(makeBigIPHandler("client-ssl_put"))
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
		wantErr := "cannot modify client ssl: http response error: 404 Not Found"
		if err.Error() != wantErr {
			t.Errorf("worker.do: got error %q; want %q", err.Error(), wantErr)
		}
	}
}

func testWorkerDoFailCommitTransaction(t *testing.T) {
	tsBigIP := httptest.NewServer(makeBigIPHandler("commit_transaction"))
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
	tsBigIP := httptest.NewServer(makeBigIPHandler(""))
	defer tsBigIP.Close()

	tsCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(crlFile))
	}))
	defer tsCA.Close()

	pool := &pool{}
	pool.addWorker(crlConfig{
		URL:                 tsCA.URL,
		Name:                "test",
		ProfileName:         "clientssl",
		RefreshDelayInHours: 300,
	})
	pool.workers[0].refreshDelay = 1 * time.Second
	defer pool.stopAll()

	f5Client, err := f5.NewBasicClient(tsBigIP.URL, "admin", "admin")
	if err != nil {
		t.Errorf("pool.startAll: unexpected error %q", err.Error())
		return
	}
	f5Client.DisableCertCheck()

	if err := pool.startAll(f5Client); err != nil {
		t.Errorf("pool.startAll: unexpected error %q", err.Error())
	}
}

func testPoolStartAllNilClient(t *testing.T) {
	pool := &pool{}
	if err := pool.startAll(nil); err == nil {
		t.Errorf("pool.startAll: expected error, got nil")
	} else {
		wantErr := "f5 client is nil"
		if err.Error() != wantErr {
			t.Errorf("pool.startAll: got error %q; want %q", err.Error(), wantErr)
		}
	}
}
