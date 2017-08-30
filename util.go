package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// fetchCRL downloads a CRL, verifies it is correctly encoded and that it has
// not expired yet, and returns it as raw slice of bytes so that it can be
// forwarded right after.
//
// No matter what format is returned by the CRL distribution point, the function
// will return a PEM encoded CRL.
func fetchCRL(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.New("cannot fetch crl: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, errors.New("cannot fetch crl due to http error: " + resp.Status)
	}

	rawCRL, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("cannot read crl: " + err.Error())
	}

	// We need both, a DER encoded CRL and a PEM one. The former is required to
	// be parsed in order to validate that the CRL is valid while the latter
	// will  be returned by the function.
	var derCRL, pemCRL []byte
	if isPEM(rawCRL) {
		derCRL, err = convertPEMToDER(rawCRL)
		if err != nil {
			return nil, errors.New("cannot convert crl from pem to der: " + err.Error())
		}
		pemCRL = rawCRL
	} else {
		derCRL = rawCRL
		pemCRL = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: derCRL})
	}

	// TODO(gilliek): move this part into an external function
	crl, err := x509.ParseDERCRL(derCRL)
	if err != nil {
		return nil, errors.New("cannot parse crl: " + err.Error())
	}
	if crl.HasExpired(time.Now()) {
		return nil, errors.New("crl has expired")
	}

	return pemCRL, nil
}

// isPEM reports whether data contains a PEM encoded CRL.
func isPEM(data []byte) bool {
	return bytes.HasPrefix(data, []byte("-----BEGIN X509 CRL-----"))
}

// convertPEMToDER convers a PEM encoded CRL into DER.
func convertPEMToDER(pemCRL []byte) ([]byte, error) {
	block, _ := pem.Decode(pemCRL)
	if block == nil || block.Type != "X509 CRL" {
		return nil, errors.New("failed to decode PEM block containing X.509 CRL")
	}
	return block.Bytes, nil
}

// isNotFoundError reports whether err is a 404 not found error returned by the
// F5 iControl REST API.
func isNotFoundError(err error) bool {
	return strings.Contains(err.Error(), "(code: 404)")
}
