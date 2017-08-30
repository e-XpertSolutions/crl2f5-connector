package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decodeBase64(b64 string) []byte {
	bs, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic("cannot decode DER encoded CRL: " + err.Error())
	}
	return bs
}

func unsafePEMToDER(pemCRL string) []byte {
	block, _ := pem.Decode([]byte(pemCRL))
	if block == nil || block.Type != "X509 CRL" {
		panic("invalid test PEM CRL data")
	}
	return block.Bytes
}

// Google CRL (GIAG2.crl)
var derCRL = decodeBase64(`MIIChjCCAW4CAQEwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2ds
ZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIXDTE3MDgyNTAxMDAw
MloXDTE3MDkwNDAxMDAwMlowgb4wGQIII134x0pwUxAXDTE3MDgxMDA5NTEwOFowGQIIW+Bf6etm
ZUkXDTE3MDgxMDA5NTExOFowGQIIBTa7iwOcb8cXDTE3MDgxMDA5NTEyN1owGQIIHboJAg2j0doX
DTE3MDgxMDA5NTEzNlowJwIIAX6wMgl8WcQXDTE3MDcyNDA4Mzc1MVowDDAKBgNVHRUEAwoBBTAn
Aggx2jOAGCr5shcNMTYwOTE1MjAyMjEzWjAMMAoGA1UdFQQDCgEDoDAwLjAfBgNVHSMEGDAWgBRK
3QYWG7z2aLV29YG2u2IaulqBLzALBgNVHRQEBAICBmIwDQYJKoZIhvcNAQELBQADggEBAIv5JdgQ
VOw+h2wC06zIOSmKrTPFe2FbQWZA0Gb7S5swsl4k97Y50YM4Q8/CndKKSD6djRB0Z6E8a92yobV5
nRon0VHZNDiWhTDY45lPfmqNUnllTME+EG6mmjpltjYnm4leJ0p4fZDiNh0xsqaU4XqZSqB7PGYp
fRg7V5utNNPwsk9vyPByDSrVw83uH25Mv7D3ugGDY1KYJ9ilyFfCo1/WUpZEX0flUlylZRxLzGcq
j1+o6Qk3XcMvOojI+fCzog0hhQV9R+mst4kP9myNsT7l4QMC3ijyv+BPRkwoK/R6Q3Q72W4jB6Lg
KO92SkGoL376RBzINiuZr/Esd3b4nv4=
`)

// Google CRL (GIAG2.pem) in PEM
var pemCRL = []byte(`-----BEGIN X509 CRL-----
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
`)

// Truncated Google CRL (GIAG2.crl)
var malformedCRL = decodeBase64(`QEwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2ds
ZSBJbmMxJTAjBgNVBAMTHEdvdZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIXDTE3MDgyNTAxMDAw
MloXDTE3MDkwNDAxMDAwowg4wG4x0pwUxAXDTE3MDgxMDA5NTEwOFowGQIIW+Bf6etm
ZUkXDTE3MDgxMDA5NTExwQIBa7iwOcb8cXDTE3MDgxMDA5NTEyN1owGQIIHboJAg2j0doX
DTE3MDgxMDA5NlowIIAXwMl8WcQXDTE3MDcyNDA4Mzc1MVowDDAKBgNVHRUEAwoBBTAn
Aggx2jOAGCr5cMTYwE1WjAMMAoGA1UdFQQDCgEDoDAwLjAfBgNVHSMEGDAWgBRK
3QYWG7z2aLV2YGu2IaLALBgNVHRQEBAICBmIwDQYJKoZIhvcNAQELBQADggEBAIv5JdgQ
VOw+h2wC06zISmKrTFQA0Gb7S5swsl4k97Y50YM4Q8/CndKKSD6djRB0Z6E8a92yobV5
nRon0VHZNDiWTDY4lPmllTME+EG6mmjpltjYnm4leJ0p4fZDiNh0xsqaU4XqZSqB7PGYp
fRg7V5utNNPw9DrV83uH25Mv7D3ugGDY1KYJ9ilyFfCo1/WUpZEX0flUlylZRxLzGcq
j1+o6Qk3XcMvojICog0hhQV9R+mst4kP9myNsT7l4QMC3ijyv+BPRkwoK/R6Q3Q72W4jB6Lg
KO92SkGoL376BzINiuZr/Esd3b4nv4=
`)

// Truncated Google CRL in PEM (GIAG2.crl)
var malformedPEMCRL = []byte(`-----BEGIN X509 CRL-----
DQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNV
BAoTCkdvb2dsZSJbmMxMTHEdvb2dsZSBJbnRlcm5dCBBdXRob3Jp
dHkgRzIXDTE3MDTAxDAwMloXDTE3MDkwNDAxMDAwlowgb4wGQIII134x0pw
xAXDTE3MDgxMDA5EwFowGQII+f6etmZUkXDTE3MDMDA5NTExOFowGQII
Ta7iwOcb8cXDTE3MgxA5NTEy1wGQIIHboJAg2j0oXDTE3MDgxMDA5NTEz
NowJwIIAX6wMgl8WQXTE3MDcyNAMzc1MVowDDABNVHRUEAwoBBTAnAggx
2jAGCr5shcNMTYwOE1jAyMjEzWjMMAoGA1UdFQDCgEDoDAwLjAfBgNVHSME
GDAgBRK3QYWG7z2a2u2IaulqBLzABgNVHRQEAICBmIwDQYJKoZIhvcN
AQELQDggEBAIvJdgQOw+h2wC06zIOmrTPFe2bQWZA0Gb7S5swsl4k97Y5
0YM4Q/ndKKSD6jBZ6E8a92yobV5nRonVNiWhDY45lPfmqNUnllTME+
EG6mmjljYn4epfZDiNh0xsqaU4XqZSqB7PYpRg7V5utNNPwsk9vyPBy
DSrVw83u25v7D3uGDY1KYJ9ilyFfCo1/WUpEflUlylZRxLzGcqj1+o6Qk3
XcMvOojIfzog0hh9+t4kP9myNsT7l4QMC3ijv+BPRkwoK/R6Q3Q72W4j
B6LgKO92SkGoL376RzINiuZr/Esd3b4nv4=
-----END X509 CRL-----
`)

// Expired CRL from BELA/mb-linux-msli on unibe.ch:
//    https://goo.gl/gVVJ21
var expiredCRL = unsafePEMToDER(`-----BEGIN X509 CRL-----
MIIBsjCBmzANBgkqhkiG9w0BAQQFADBsMQswCQYDVQQGEwJDQTEQMA4GA1UECBMH
T250YXJpbzERMA8GA1UEChMIT3BlbnN3YW4xGDAWBgNVBAMTD2NhLm9wZW5zd2Fu
Lm9yZzEeMBwGCSqGSIb3DQEJARYPY2FAb3BlbnN3YW4ub3JnFw0wNDA1MjgxNjI4
MzBaFw0wNDA1MzAxNjI4MzBaMA0GCSqGSIb3DQEBBAUAA4IBAQCfZgIequGYqYgj
hUDMIesKoTu8AoUywWpLBr+wAzcZhWRyfE3neSTP0ObqNX3XFPAtSd+KuiDr31GS
jTPMNbjcZusdvd5IoWXRWARYp3301nvZ6K0AupTm0XCmhKNJ6R65Elsbml8WOAy7
23wkIne/SZ11bg+hBKTYkS3jV3c1KsN/h98TETWwgncr590t3v8zu0WP7YAofYFJ
WZbyLjf3VkX7ShyksO5RLoFmGonPqvxV2KM5+4TAOvJ5i4uee+BW52/kwHSPz8oe
rPZ3i33nzEqAyRlnIJDQuaVqKVEk5zvNQLJKzGugyVaMdKcfbteXALmvy/c4gPlJ
vX7UjFFR
-----END X509 CRL-----
`)

func TestFetchCRL(t *testing.T) {
	t.Run("Valid DER CRL", testFetchCRLWithValidCRL)
	t.Run("Valid PEM CRL", testFetchCRLWithValidPEMCRL)
	t.Run("Invalid DER CRL", testFetchCRLWithInvalidCRL)
	t.Run("Invalid PEM CRL", testFetchCRLWithInvalidPEMCRL)
	t.Run("Invalid URL", testFetchCRLWithInvalidURL)
	t.Run("HTTP Error", testFetchCRLWithHTTPError)
	t.Run("Expired CRL", testFetchCRLWithExpiredCRL)
}

func testFetchCRLWithValidCRL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(derCRL)
	}))
	defer ts.Close()
	crl, err := fetchCRL(ts.URL)
	if err != nil {
		t.Fatalf("fetchCRL: unexpected error %q", err.Error())
	}
	if !bytes.Equal(crl, pemCRL) {
		t.Errorf("fetchCRL: got \"%s\"; want \"%s\"", crl, pemCRL)
	}
}

func testFetchCRLWithValidPEMCRL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(pemCRL)
	}))
	defer ts.Close()
	crl, err := fetchCRL(ts.URL)
	if err != nil {
		t.Fatalf("fetchCRL: unexpected error %q", err.Error())
	}
	if !bytes.Equal(crl, pemCRL) {
		t.Errorf("fetchCRL: got \"%s\"; want \"%s\"", crl, pemCRL)
	}
}

func testFetchCRLWithInvalidCRL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(malformedCRL)
	}))
	defer ts.Close()
	_, err := fetchCRL(ts.URL)
	switch err {
	case nil:
		t.Error("fetchCRL: expected error; got nil")
	default:
		wantErr := "cannot parse crl: asn1: structure error: tags don't match (16 vs {class:1 tag:0 length:76 isCompound:false}) {optional:false explicit:false application:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} CertificateList @2"
		if got := err.Error(); got != wantErr {
			t.Errorf("fetchCRL: got error %q; want %q", got, wantErr)
		}
	}
}

func testFetchCRLWithInvalidPEMCRL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(malformedPEMCRL)
	}))
	defer ts.Close()
	_, err := fetchCRL(ts.URL)
	switch err {
	case nil:
		t.Error("fetchCRL: expected error; got nil")
	default:
		wantErr := "cannot convert crl from pem to der: failed to decode PEM block containing X.509 CRL"
		if got := err.Error(); got != wantErr {
			t.Errorf("fetchCRL: got error %q; want %q", got, wantErr)
		}
	}
}

func testFetchCRLWithInvalidURL(t *testing.T) {
	_, err := fetchCRL("some-invalid-url")
	switch err {
	case nil:
		t.Error("fetchCRL: expected error; got nil")
	default:
		wantErr := "cannot fetch crl: Get some-invalid-url: unsupported protocol scheme \"\""
		if got := err.Error(); got != wantErr {
			t.Errorf("fetchCRL: got error %q; want %q", got, wantErr)
		}
	}

}

func testFetchCRLWithHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer ts.Close()
	_, err := fetchCRL(ts.URL)
	switch err {
	case nil:
		t.Error("fetchCRL: expected error; got nil")
	default:
		wantErr := "cannot fetch crl due to http error: 404 Not Found"
		if got := err.Error(); got != wantErr {
			t.Errorf("fetchCRL: got error %q; want %q", got, wantErr)
		}
	}
}

func testFetchCRLWithExpiredCRL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(expiredCRL)
	}))
	defer ts.Close()
	_, err := fetchCRL(ts.URL)
	switch err {
	case nil:
		t.Error("fetchCRL: expected error; got nil")
	default:
		wantErr := "crl has expired"
		if got := err.Error(); got != wantErr {
			t.Errorf("fetchCRL: got error %q; want %q", got, wantErr)
		}
	}
}

func TestIsPEM(t *testing.T) {
	type testCase struct {
		data []byte
		want bool
	}
	tests := []testCase{
		{
			// PEM encoded CRL
			data: []byte(`-----BEGIN X509 CRL-----
MIICGTCCAQECAQEwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNV
BAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3Jp
dHkgRzIXDTE3MDIxMDAxMDAwMloXDTE3MDIyMDAxMDAwMlowUjAnAgh2S+3Tiv1R
9xcNMTcwMTEzMTQxODU4WjAMMAoGA1UdFQQDCgEDMCcCCDHaM4AYKvmyFw0xNjA5
MTUyMDIyMTNaMAwwCgYDVR0VBAMKAQOgMDAuMB8GA1UdIwQYMBaAFErdBhYbvPZo
tXb1gba7Yhq6WoEvMAsGA1UdFAQEAgIFhzANBgkqhkiG9w0BAQsFAAOCAQEAIWoB
ZnlsB4dumhCVwjEq7d1vSDD+2sFaO1DJYCVrOBuksPzjgChhgGqh/d1ExpAU3D/v
tCoaiMWJ9wXGrwiYj1SZ6fxARsgGe0BKWaDbqj4A+YICnck6o/hgs+KF8j2FXWcE
Rk//LG2JIt6mNeHm5uf5mv4h2mYi72VG7SZTCeHYl2mvEeO5qU/1gckmvRi1F60P
I1oSIz8b19jNDSN7SSupnMIwLR/XJ1ImpxtzZ/LlPr4aXDcFaV/4m9bSkzpOt8Cw
4CtDQ7yD7klQQYVUzWPEHXVqkkkh7hJKISg7+y288SITmUQhGKePI9BoiOaozj7p
fq9l6po4XF96Hhazvw==
-----END X509 CRL-----
`),
			want: true,
		},
		{
			// DER encoded CRL
			data: derCRL,
			want: false,
		},
	}
	for i, test := range tests {
		if got := isPEM(test.data); got != test.want {
			t.Errorf("%d. isPEM: got %v, want %v", i, got, test.want)
		}
	}
}

func TestConvertPEMToDER(t *testing.T) {
	type testCase struct {
		data    []byte
		want    []byte
		wantErr error
	}
	tests := []testCase{
		{
			data:    pemCRL,
			want:    derCRL,
			wantErr: nil,
		},
		{
			data:    nil,
			want:    nil,
			wantErr: errors.New("failed to decode PEM block containing X.509 CRL"),
		},
		{
			data: []byte(`-----BEGIN CERTIFICATE-----
MIIFGDCCBACgAwIBAgIQYwJwLrQW+AG/bY22XF7RSjANBgkqhkiG9w0BAQsFADBE
MQswCQYDVQQGEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEdMBsGA1UEAxMU
R2VvVHJ1c3QgU1NMIENBIC0gRzMwHhcNMTUwMjExMDAwMDAwWhcNMTgwMjEwMjM1
OTU5WjCBhTELMAkGA1UEBhMCQ0gxDzANBgNVBAgTBkdlbmV2YTEYMBYGA1UEBxQP
UGxhbi1sZXMtT3VhdGVzMR0wGwYDVQQKFBRlLVhwZXJ0IFNvbHV0aW9ucyBTQTEL
MAkGA1UECxQCSVQxHzAdBgNVBAMUFiouZS14cGVydHNvbHV0aW9ucy5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtt7JUybK63uC3YW2YzxxLsKRJ
OEMZV3tqz5uQsqu/NZY4gICtQciGWEShaDxezbXmtUffJLs3NHPCSMS8IcYXk1OM
ywOcvcaQ1OYZNpr0uxftIRU2+7e0WYN6o4MAvpguo/F5Vh8kMsuhxGHWv7zBS3Le
IZgkAafUwEl4lHuv9sj/K0IiszSJVwrMrgb36XfObWoHCGAz+YTdqNRP4tpCgUDg
HTjy6pGMtYFoOj6OQIJybv2Tnk/UWSs6PIgus31Pj92Kz5G+ZfNyDZssd3SR3U18
xBczw71h3xGhmD0bzdW3HA7atz7a+p6SQDDi9UItnJgc97oELUl5Wu0rck8FAgMB
AAGjggHCMIIBvjA3BgNVHREEMDAughYqLmUteHBlcnRzb2x1dGlvbnMuY29tghRl
LXhwZXJ0c29sdXRpb25zLmNvbTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDAr
BgNVHR8EJDAiMCCgHqAchhpodHRwOi8vZ24uc3ltY2IuY29tL2duLmNybDCBoQYD
VR0gBIGZMIGWMIGTBgpghkgBhvhFAQc2MIGEMD8GCCsGAQUFBwIBFjNodHRwczov
L3d3dy5nZW90cnVzdC5jb20vcmVzb3VyY2VzL3JlcG9zaXRvcnkvbGVnYWwwQQYI
KwYBBQUHAgIwNQwzaHR0cHM6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jlc291cmNlcy9y
ZXBvc2l0b3J5L2xlZ2FsMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAf
BgNVHSMEGDAWgBTSb/eW9IU/cjwwfSPahXibo3xafDBXBggrBgEFBQcBAQRLMEkw
HwYIKwYBBQUHMAGGE2h0dHA6Ly9nbi5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0
dHA6Ly9nbi5zeW1jYi5jb20vZ24uY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQCPQHYD
uSdXgDw/wUAfIADGSdZVsLI5jkCVLPmLv4vYpIjRF9hle0QiUMZ7nGHgPlnpF6f1
Mw3M/DPumdlY94SqxlO8p+P7E16PLnXgq4m8oDMFr3Iryd7nxQqHVdv7oyAjkZMn
52cTEUw4Uz9Oa7A3jzE4irZxLAb9U0dtmff+BRi7QqpGmu0unlyG6ErIhLnZEUA8
/TRzmVynEvorGZ9nsSv50mqVQkwHCYrX9NBN59G2/IQ1K3SxTC9yYXH37u+zhRXB
092dihU7Kn8pm1Z037NyYdePW1i+k9ruf44ySBqe3mHLwgp3uhCy3ek/lSeHfC4X
ofPxDc9Ze169o1Js
-----END CERTIFICATE-----
`),
			want:    nil,
			wantErr: errors.New("failed to decode PEM block containing X.509 CRL"),
		},
	}
	for i, test := range tests {
		got, err := convertPEMToDER(test.data)
		if err != nil {
			if test.wantErr != nil && err.Error() != test.wantErr.Error() {
				t.Errorf("%d. convertPEMToDER: got error %q; want %q", i, err.Error(), test.wantErr.Error())
			}
			continue
		}
		if !bytes.Equal(got, test.want) {
			t.Errorf("%d. convertPEMToDER: got \"%v\"; want \"%v\"", i, got, test.want)
		}
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := map[string]bool{
		"01020036:3: The requested ClientSSL Profile (/Common/clientssl-notexist) was not found. (code: 404)": true,
		"Forbidden. (code: 403)": false,
		"": false,
	}
	for input, want := range tests {
		if got := isNotFoundError(errors.New(input)); got != want {
			t.Errorf("isNotFoundError(%q): got %v; want %v", input, got, want)
		}
	}
}
