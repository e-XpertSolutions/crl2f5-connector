package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/e-XpertSolutions/f5-rest-client/f5/ltm"
)

// This file implement a mock of a F5 BigIP server that only implements relevant
// APIs for testing. No tests are implemented here.

const clientSSLProfile = `{"kind":"tm:ltm:profile:client-ssl:client-sslstate","name":"clientssl","fullPath":"clientssl","generation":1708,"selfLink":"https://localhost/mgmt/tm/ltm/profile/client-ssl/clientssl?ver=13.0.0","alertTimeout":"indefinite","allowDynamicRecordSizing":"disabled","allowExpiredCrl":"disabled","allowNonSsl":"disabled","appService":"none","authenticate":"once","authenticateDepth":9,"bypassOnClientCertFail":"disabled","bypassOnHandshakeAlert":"disabled","caFile":"none","cacheSize":262144,"cacheTimeout":3600,"cert":"/Common/default.crt","certReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~default.crt?ver=13.0.0"},"certExtensionIncludes":["basic-constraints","subject-alternative-name"],"certLifespan":30,"certLookupByIpaddrPort":"disabled","chain":"none","cipherGroup":"none","ciphers":"DEFAULT","clientCertCa":"none","crlFile":"%s","crlFileReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-crl/~Common~test4.crl?ver=13.0.0"},"defaultsFrom":"none","description":"none","destinationIpBlacklist":"none","destinationIpWhitelist":"none","forwardProxyBypassDefaultAction":"intercept","genericAlert":"enabled","handshakeTimeout":"10","hostnameBlacklist":"none","hostnameWhitelist":"none","inheritCertkeychain":"false","key":"/Common/default.key","keyReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-key/~Common~default.key?ver=13.0.0"},"maxActiveHandshakes":"indefinite","maxAggregateRenegotiationPerMinute":"indefinite","maxRenegotiationsPerMinute":5,"maximumRecordSize":16384,"modSslMethods":"disabled","mode":"enabled","notifyCertStatusToVirtualServer":"disabled","ocspStapling":"disabled","tmOptions":["dont-insert-empty-fragments"],"peerCertMode":"ignore","peerNoRenegotiateTimeout":"10","proxyCaCert":"none","proxyCaKey":"none","proxySsl":"disabled","proxySslPassthrough":"disabled","renegotiateMaxRecordDelay":"indefinite","renegotiatePeriod":"indefinite","renegotiateSize":"indefinite","renegotiation":"enabled","retainCertificate":"true","secureRenegotiation":"require","serverName":"none","sessionMirroring":"disabled","sessionTicket":"disabled","sessionTicketTimeout":0,"sniDefault":"false","sniRequire":"false","sourceIpBlacklist":"none","sourceIpWhitelist":"none","sslForwardProxy":"disabled","sslForwardProxyBypass":"disabled","sslSignHash":"any","strictResume":"disabled","uncleanShutdown":"enabled","certKeyChain":[{"name":"default","appService":"none","cert":"/Common/default.crt","certReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~default.crt?ver=13.0.0"},"chain":"none","key":"/Common/default.key","keyReference":{"link":"https://localhost/mgmt/tm/sys/file/ssl-key/~Common~default.key?ver=13.0.0"}}]}`

const editProfileResp = `{"kind":"tm:sys:file:ssl-crl:ssl-crlstate","name":"test.crl","fullPath":"test.crl","generation":3488,"selfLink":"https://localhost/mgmt/tm/sys/file/ssl-crl/test.crl?ver=13.0.0","checksum":"SHA1:930:eb57c456aef899566a1a8166b1b8ec0390ae00f6","createTime":"2017-08-25T13:03:04Z","createdBy":"admin","lastUpdateTime":"2017-08-28T15:33:19Z","mode":33188,"revision":7,"size":930,"sourcePath":"file:/var/config/rest/downloads/test.crl","updatedBy":"admin"}`

const uploadResp = `{"remainingByteCount":0,"usedChunks":{"0":930},"totalByteCount":930,"localFilePath":"/var/config/rest/downloads/test.crl","temporaryFilePath":"/var/config/rest/downloads/tmp/test.crl","generation":0,"lastUpdateMicros":1503935541736191}`

const crlFile = `-----BEGIN X509 CRL-----
MIIB6DCB0QIBATANBgkqhkiG9w0BAQsFADB4MQswCQYDVQQGEwJDSDEPMA0GA1UE
CBMGR2VuZXZhMRgwFgYDVQQHEw9QbGFuLWxlcy1PdWF0ZXMxHTAbBgNVBAoTFGUt
WHBlcnQgU29sdXRpb25zIFNBMQswCQYDVQQLEwJJVDESMBAGA1UEAxMJbG9jYWxo
b3N0Fw0xNzA5MDQxMjA0MTBaFw0yMzAyMjUxMjA0MTBaMACgIzAhMB8GA1UdIwQY
MBaAFLvZTBeieT0TR5i4fLXtXS3b0X3eMA0GCSqGSIb3DQEBCwUAA4IBAQAWOV/I
6CbhIFL7JTeOqp1sl/uHWhKtLBQ2NShUh2/3spdKbM0wl2yG0DFuRoBpmOx5xqD5
8XWZh0FuP3IeTSRpXj7Kz79RKho17P5cFKVkhYO1EfO8eiS/DfSf2XKEEPCyRiGf
Ibwbi8QDXBZSKowqH91nBlUO+bGpk93Bd/PpdKz8lwA4NGN4dJG4ntMcQb8zshbI
3Hg7YeVll1MKVKxuM6juH/i7MXIWjKUK3XzABIyjDjJzPBPbTvOjan9whYP3w4gg
GuQa/c9dOad5LWhOGf8MucoF5tub7gCOv3GFr/IYfYAIuj9S9v8As1Om/MUPYyZ1
hvcXBKIfbxsEW7jZ
-----END X509 CRL-----
`

type bigIPServer struct {
	Disable string
	crlFile string
	mux     *http.ServeMux

	callsToClientSSLGet int
}

func newBigIPServer() *bigIPServer {
	srv := &bigIPServer{
		mux: http.NewServeMux(),
	}
	srv.mux.HandleFunc("/mgmt/tm/ltm/profile/client-ssl/clientssl", srv.handleProfileClientSSL)
	srv.mux.HandleFunc("/mgmt/tm/transaction", srv.handleTransaction)
	srv.mux.HandleFunc("/mgmt/tm/transaction/", srv.handleTransaction)
	srv.mux.HandleFunc("/mgmt/shared/file-transfer/uploads", srv.handleFileTransferUploads)
	srv.mux.HandleFunc("/mgmt/shared/file-transfer/uploads/", srv.handleFileTransferUploads)
	srv.mux.HandleFunc("/mgmt/tm/sys/file/ssl-crl", srv.handleFileSSLCRL)
	srv.mux.HandleFunc("/mgmt/tm/sys/file/ssl-crl/", srv.handleFileSSLCRL)
	return srv
}

func (srv *bigIPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	srv.mux.ServeHTTP(w, r)
}

func (srv *bigIPServer) handleProfileClientSSL(w http.ResponseWriter, r *http.Request) {
	switch method := r.Method; method {
	case "GET":
		srv.callsToClientSSLGet++
		if srv.Disable == "client-ssl_get" {
			http.Error(w, "disabled", http.StatusNotFound)
			return
		}
		if srv.Disable == "client-ssl_get_once" && srv.callsToClientSSLGet > 1 {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if srv.Disable == "client-ssl_get_updated_crl" {
			w.Write([]byte(fmt.Sprintf(clientSSLProfile, "")))
		} else {
			w.Write([]byte(fmt.Sprintf(clientSSLProfile, srv.crlFile)))
		}
	case "PUT":
		if srv.Disable == "client-ssl_put" {
			http.Error(w, "disabled", http.StatusNotFound)
			return
		}
		var cfg ltm.ProfileClientSSLConfig
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&cfg); err != nil {
			http.Error(w, "malformed request json data", http.StatusBadRequest)
			return
		}
		srv.crlFile = cfg.CRLFile
		w.Write([]byte(editProfileResp))
	default:
		http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, r.URL.Path), http.StatusBadRequest)
	}
}

func (srv *bigIPServer) handleTransaction(w http.ResponseWriter, r *http.Request) {
	if srv.Disable == "begin_transaction" {
		http.Error(w, "disabled", http.StatusNotFound)
		return
	}
	switch path := strings.TrimSuffix(r.URL.Path, "/"); path {
	case "/mgmt/tm/transaction":
		switch method := r.Method; method {
		case "POST":
			w.Write([]byte(`{"transId": 123456789, "state": "STARTED"}`))
		default:
			http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, r.URL.Path), http.StatusBadRequest)
		}
	case "/mgmt/tm/transaction/123456789":
		if srv.Disable == "commit_transaction" {
			http.Error(w, "disabled", http.StatusNotFound)
			return
		}
		switch method := r.Method; method {
		case "PATCH":
			w.Write([]byte(`{}`))
		default:
			http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, path), http.StatusBadRequest)
		}
	}
}

func (srv *bigIPServer) handleFileTransferUploads(w http.ResponseWriter, r *http.Request) {
	switch method := r.Method; method {
	case "POST":
		w.Write([]byte(uploadResp))
	default:
		http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, r.URL.Path), http.StatusBadRequest)
	}
}

func (srv *bigIPServer) handleFileSSLCRL(w http.ResponseWriter, r *http.Request) {
	if srv.Disable == "ssl-crl" {
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
		filename = r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	default:
		http.Error(w, fmt.Sprintf("unsupported method %q for %q", method, r.URL.Path), http.StatusBadRequest)
		return
	}
	w.Write([]byte(fmt.Sprintf(`{"remainingByteCount":0,"usedChunks":{"0":930},"totalByteCount":930,"localFilePath":"/var/config/rest/downloads/%s","temporaryFilePath":"/var/config/rest/downloads/tmp/%s","generation":0,"lastUpdateMicros":1503997621775731}`, filename, filename)))
}
