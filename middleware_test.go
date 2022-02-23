// +build !e2e

/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	resty "github.com/go-resty/resty/v2"
	uuid "github.com/gofrs/uuid"
	"github.com/oleiade/reflections"
	"github.com/rs/cors"
	strcase "github.com/stoewer/go-strcase"
	"github.com/stretchr/testify/assert"

	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	testEncryptionKey = "ZSeCYDUxIlhDrmPpa1Ldc7il384esSF2"
)

type fakeRequest struct {
	BasicAuth                     bool
	Cookies                       []*http.Cookie
	Expires                       time.Duration
	FormValues                    map[string]string
	Groups                        []string
	HasCookieToken                bool
	HasLogin                      bool
	HasToken                      bool
	Headers                       map[string]string
	Method                        string
	NotSigned                     bool
	OnResponse                    func(int, *resty.Request, *resty.Response)
	Password                      string
	ProxyProtocol                 string
	ProxyRequest                  bool
	RawToken                      string
	Redirects                     bool
	Roles                         []string
	SkipClientIDCheck             bool
	SkipIssuerCheck               bool
	RequestCA                     string
	TokenClaims                   map[string]interface{}
	URI                           string
	URL                           string
	Username                      string
	ExpectedCode                  int
	ExpectedContent               func(body string, testNum int)
	ExpectedContentContains       string
	ExpectedCookies               map[string]string
	ExpectedHeaders               map[string]string
	ExpectedLocation              string
	ExpectedNoProxyHeaders        []string
	ExpectedProxy                 bool
	ExpectedProxyHeaders          map[string]string
	ExpectedProxyHeadersValidator map[string]func(*testing.T, *Config, string)
	ExpectedCookiesValidator      map[string]func(*testing.T, *Config, string) bool
	ExpectedLoginCookiesValidator map[string]func(*testing.T, *Config, string) bool
}

type fakeProxy struct {
	config  *Config
	idp     *fakeAuthServer
	proxy   *oauthProxy
	cookies map[string]*http.Cookie
}

func newFakeProxy(c *Config, authConfig *fakeAuthConfig) *fakeProxy {
	log.SetOutput(ioutil.Discard)

	if c == nil {
		c = newFakeKeycloakConfig()
	}

	auth := newFakeAuthServer(authConfig)

	if authConfig.EnableProxy {
		c.OpenIDProviderProxy = auth.getProxyURL()
	}

	c.DiscoveryURL = auth.getLocation()
	c.Verbose = true
	c.DisableAllLogging = true
	proxy, err := newProxy(c)

	if err != nil {
		panic("failed to create fake proxy service, error: " + err.Error())
	}

	// proxy.log = zap.NewNop()
	proxy.upstream = &fakeUpstreamService{}
	if err = proxy.Run(); err != nil {
		panic("failed to create the proxy service, error: " + err.Error())
	}

	c.RedirectionURL = fmt.Sprintf("http://%s", proxy.listener.Addr().String())

	return &fakeProxy{c, auth, proxy, make(map[string]*http.Cookie)}
}

func (f *fakeProxy) getServiceURL() string {
	return fmt.Sprintf("http://%s", f.proxy.listener.Addr().String())
}

// RunTests performs a series of requests against a fake proxy service
// nolint:funlen
func (f *fakeProxy) RunTests(t *testing.T, requests []fakeRequest) {
	defer func() {
		f.idp.Close()
		f.proxy.server.Close()
	}()

	for i := range requests {
		c := requests[i]
		var upstream fakeUpstreamResponse

		f.config.NoRedirects = !c.Redirects
		f.config.SkipAccessTokenClientIDCheck = c.SkipClientIDCheck
		f.config.SkipAccessTokenIssuerCheck = c.SkipIssuerCheck
		// we need to set any defaults
		if c.Method == "" {
			c.Method = http.MethodGet
		}
		// create a http client
		client := resty.New()
		request := client.SetRedirectPolicy(resty.NoRedirectPolicy()).R()

		if c.ProxyProtocol != "" {
			client.SetTransport(&http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					conn, err := net.Dial("tcp", addr)
					if err != nil {
						return nil, err
					}
					header := fmt.Sprintf("PROXY TCP4 %s 10.0.0.1 1000 2000\r\n", c.ProxyProtocol)
					_, _ = conn.Write([]byte(header))

					return conn, nil
				},
			})
		}

		if c.RequestCA != "" {
			client.SetRootCertificateFromString(c.RequestCA)
		}

		// are we performing a oauth login beforehand
		if c.HasLogin {
			if err := f.performUserLogin(c.URI); err != nil {
				t.Errorf("case %d, unable to login to oauth server, error: %s", i, err)
				return
			}
		}
		if len(f.cookies) > 0 {
			for _, k := range f.cookies {
				client.SetCookie(k)
			}
		}
		if c.ExpectedProxy {
			request.SetResult(&upstream)
		}
		if c.ProxyRequest {
			client.SetProxy(f.getServiceURL())
		}
		if c.BasicAuth {
			request.SetBasicAuth(c.Username, c.Password)
		}
		if c.RawToken != "" {
			setRequestAuthentication(f.config, client, request, &c, c.RawToken)
		}
		if len(c.Cookies) > 0 {
			client.SetCookies(c.Cookies)
		}
		if len(c.Headers) > 0 {
			request.SetHeaders(c.Headers)
		}
		if c.FormValues != nil {
			request.SetFormData(c.FormValues)
		}
		if c.HasToken {
			token := newTestToken(f.idp.getLocation())
			if c.TokenClaims != nil && len(c.TokenClaims) > 0 {
				for i := range c.TokenClaims {
					err := reflections.SetField(&token.claims, strcase.UpperCamelCase(i), c.TokenClaims[i])
					assert.NoError(t, err)
				}
			}
			if len(c.Roles) > 0 {
				token.addRealmRoles(c.Roles)
			}
			if len(c.Groups) > 0 {
				token.addGroups(c.Groups)
			}
			if c.Expires > 0 || c.Expires < 0 {
				token.setExpiration(time.Now().Add(c.Expires))
			}
			if c.NotSigned {
				authToken, err := token.getUnsignedToken()
				assert.NoError(t, err)
				setRequestAuthentication(f.config, client, request, &c, authToken)
			} else {
				authToken, err := token.getToken()
				assert.NoError(t, err)
				setRequestAuthentication(f.config, client, request, &c, authToken)
			}
		}

		// step: execute the request
		var resp *resty.Response
		var err error
		switch c.URL {
		case "":
			resp, err = request.Execute(c.Method, f.getServiceURL()+c.URI)
		default:
			resp, err = request.Execute(c.Method, c.URL)
		}
		if err != nil {
			if !strings.Contains(err.Error(), "auto redirect is disabled") {
				assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err)
				continue
			}
		}
		status := resp.StatusCode()
		if c.ExpectedCode != 0 {
			assert.Equal(t, c.ExpectedCode, status, "case %d, expected status code: %d, got: %d", i, c.ExpectedCode, status)
		}
		if c.ExpectedLocation != "" {
			l, _ := url.Parse(resp.Header().Get("Location"))
			assert.True(t, strings.Contains(l.String(), c.ExpectedLocation), "expected location to contain %s", l.String())
			if l.Query().Get("state") != "" {
				state, err := uuid.FromString(l.Query().Get("state"))
				if err != nil {
					assert.Fail(t, "expected state parameter with valid UUID, got: %s with error %s", state.String(), err)
				}
			}
		}
		if len(c.ExpectedHeaders) > 0 {
			for k, v := range c.ExpectedHeaders {
				e := resp.Header().Get(k)
				assert.Equal(t, v, e, "case %d, expected header %s=%s, got: %s", i, k, v, e)
			}
		}
		if c.ExpectedProxy {
			assert.NotEmpty(t, resp.Header().Get(testProxyAccepted), "case %d, did not proxy request", i)
		} else {
			assert.Empty(t, resp.Header().Get(testProxyAccepted), "case %d, should NOT proxy request", i)
		}
		if c.ExpectedProxyHeaders != nil && len(c.ExpectedProxyHeaders) > 0 {
			for k, v := range c.ExpectedProxyHeaders {
				headers := upstream.Headers
				switch v {
				case "":
					assert.NotEmpty(t, headers.Get(k), "case %d, expected the proxy header: %s to exist", i, k)
				default:
					assert.Equal(t, v, headers.Get(k), "case %d, expected proxy header %s=%s, got: %s", i, k, v, headers.Get(k))
				}
			}
		}
		if c.ExpectedProxyHeadersValidator != nil && len(c.ExpectedProxyHeadersValidator) > 0 {
			for k, v := range c.ExpectedProxyHeadersValidator {
				headers := upstream.Headers
				switch v {
				case nil:
					assert.NotNil(t, v, "Validation function is nil, forgot to configure?")
				default:
					v(t, f.config, headers.Get(k))
				}
			}
		}
		if len(c.ExpectedNoProxyHeaders) > 0 {
			for _, k := range c.ExpectedNoProxyHeaders {
				assert.Empty(t, upstream.Headers.Get(k), "case %d, header: %s was not expected to exist", i, k)
			}
		}

		if c.ExpectedContent != nil {
			e := string(resp.Body())
			c.ExpectedContent(e, i)
		}
		if c.ExpectedContentContains != "" {
			e := string(resp.Body())
			assert.Contains(t, e, c.ExpectedContentContains, "case %d, expected content: %s, got: %s", i, c.ExpectedContentContains, e)
		}
		if len(c.ExpectedCookies) > 0 {
			for k, v := range c.ExpectedCookies {
				cookie := findCookie(k, resp.Cookies())
				if !assert.NotNil(t, cookie, "case %d, expected cookie %s not found", i, k) {
					continue
				}
				if v != "" {
					assert.Equal(t, cookie.Value, v, "case %d, expected cookie value: %s, got: %s", i, v, cookie.Value)
				}
			}
		}
		if len(c.ExpectedCookiesValidator) > 0 {
			for k, v := range c.ExpectedCookiesValidator {
				cookie := findCookie(k, resp.Cookies())

				if !assert.NotNil(t, cookie, "case %d, expected cookie %s not found", i, k) {
					continue
				}

				if v != nil {
					assert.True(
						t,
						v(t, f.config, cookie.Value),
						"case %d, invalid cookie value: %s in expected cookie validator",
						i,
						cookie.Value,
					)
				}
			}
		}
		if len(c.ExpectedLoginCookiesValidator) > 0 {
			for k, v := range c.ExpectedLoginCookiesValidator {
				cookie, ok := f.cookies[k]

				if !assert.True(t, ok, "case %d, expected cookie %s not found", i, k) {
					continue
				}

				if v != nil {
					assert.True(
						t,
						v(t, f.config, cookie.Value),
						"case %d, invalid cookie value in login cookie validator: %s",
						i,
						cookie.Value,
					)
				}
			}
		}
		if c.OnResponse != nil {
			c.OnResponse(i, request, resp)
		}
	}
}

func (f *fakeProxy) performUserLogin(uri string) error {
	resp, flowCookies, err := makeTestCodeFlowLogin(f.getServiceURL() + uri)
	if err != nil {
		return err
	}
	for _, c := range resp.Cookies() {
		if c.Name == f.config.CookieAccessName || c.Name == f.config.CookieRefreshName {
			f.cookies[c.Name] = &http.Cookie{
				Name:   c.Name,
				Path:   "/",
				Domain: "127.0.0.1",
				Value:  c.Value,
			}
		}
	}

	for i, cook := range flowCookies {
		f.cookies[cook.Name] = flowCookies[i]
	}

	defer resp.Body.Close()

	return nil
}

func setRequestAuthentication(cfg *Config, client *resty.Client, request *resty.Request, c *fakeRequest, token string) {
	switch c.HasCookieToken {
	case true:
		client.SetCookie(&http.Cookie{
			Name:  cfg.CookieAccessName,
			Path:  "/",
			Value: token,
		})
	default:
		request.SetAuthToken(token)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableMetrics = true
	cfg.LocalhostMetrics = true
	cfg.EnableRefreshTokens = true
	cfg.EnableEncryptedToken = true
	cfg.EncryptionKey = testEncryptionKey
	requests := []fakeRequest{
		{
			URI:           fakeAuthAllURL,
			HasLogin:      true,
			Redirects:     true,
			OnResponse:    delay,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           fakeAuthAllURL,
			Redirects:     false,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI: cfg.WithOAuthURI(metricsURL),
			Headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			ExpectedCode: http.StatusForbidden,
		},
		// Some request must run before this one to generate request status numbers
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "proxy_request_status_total",
		},
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"issued\"",
		},
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"exchange\"",
		},
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"login\"",
		},
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"logout\"",
		},
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"renew\"",
		},
	}
	p := newFakeProxy(cfg, &fakeAuthConfig{})
	p.idp.setTokenExpiration(1000 * time.Millisecond)
	p.RunTests(t, requests)
}

func TestOauthRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          "/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{
			URI:          "/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestAdminListener(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestAdminOnSameListener",
			ProxySettings: func(c *Config) {
				c.EnableMetrics = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     "/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
				},
				{
					URI:          "/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestAdminOnDifferentListener",
			ProxySettings: func(c *Config) {
				c.EnableMetrics = true
				c.ListenAdmin = "127.0.0.1:12300"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:          "/oauth/health",
					Redirects:    true,
					ExpectedCode: http.StatusNotFound,
				},
				{
					URI:          "/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusNotFound,
				},
				{
					URL:                     "http://127.0.0.1:12300/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
				},
				{
					URL:          "http://127.0.0.1:12300/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
				},
			},
		},
		{
			Name: "TestAdminOnDifferentListenerWithHTTPS",
			ProxySettings: func(c *Config) {
				c.EnableMetrics = true
				c.ListenAdmin = "127.0.0.1:12301"
				c.ListenAdminScheme = secureScheme
				c.TLSAdminCertificate = fmt.Sprintf("/tmp/gateadmin_crt_%d", rand.Intn(10000))
				c.TLSAdminPrivateKey = fmt.Sprintf("/tmp/gateadmin_priv_%d", rand.Intn(10000))
				c.TLSAdminCaCertificate = fmt.Sprintf("/tmp/gateadmin_ca_%d", rand.Intn(10000))
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     "https://127.0.0.1:12301/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
					RequestCA:               fakeCA,
				},
				{
					URL:          "https://127.0.0.1:12301/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
					RequestCA:    fakeCA,
				},
			},
		},
		{
			Name: "TestAdminOnDifferentListenerWithHTTPSandCommonCreds",
			ProxySettings: func(c *Config) {
				c.EnableMetrics = true
				c.ListenAdmin = "127.0.0.1:12302"
				c.ListenAdminScheme = secureScheme
				c.TLSCertificate = fmt.Sprintf("/tmp/gateadmin_crt_%d", rand.Intn(10000))
				c.TLSPrivateKey = fmt.Sprintf("/tmp/gateadmin_priv_%d", rand.Intn(10000))
				c.TLSCaCertificate = fmt.Sprintf("/tmp/gateadmin_ca_%d", rand.Intn(10000))
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     "https://127.0.0.1:12302/oauth/health",
					Redirects:               true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "OK",
					RequestCA:               fakeCA,
				},
				{
					URL:          "https://127.0.0.1:12302/oauth/metrics",
					Redirects:    true,
					ExpectedCode: http.StatusOK,
					RequestCA:    fakeCA,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		c := newFakeKeycloakConfig()
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)

				certFile := ""
				privFile := ""
				caFile := ""

				if c.TLSAdminCertificate != "" {
					certFile = c.TLSAdminCertificate
				}

				if c.TLSCertificate != "" {
					certFile = c.TLSCertificate
				}

				if c.TLSAdminPrivateKey != "" {
					privFile = c.TLSAdminPrivateKey
				}

				if c.TLSPrivateKey != "" {
					privFile = c.TLSPrivateKey
				}

				if c.TLSAdminCaCertificate != "" {
					caFile = c.TLSAdminCaCertificate
				}

				if c.TLSCaCertificate != "" {
					caFile = c.TLSCaCertificate
				}

				if certFile != "" {
					fakeCertByte := []byte(fakeCert)
					err := ioutil.WriteFile(certFile, fakeCertByte, 0644)

					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" {
					fakeKeyByte := []byte(fakePrivateKey)
					err := ioutil.WriteFile(privFile, fakeKeyByte, 0644)

					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" {
					fakeCAByte := []byte(fakeCA)
					err := ioutil.WriteFile(caFile, fakeCAByte, 0644)

					if err != nil {
						t.Fatalf("Problem writing cacertificate %s", err)
					}
					defer os.Remove(caFile)
				}

				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestOauthRequestsWithBaseURI(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.BaseURI = "/base-uri"
	requests := []fakeRequest{
		{
			URI:          "/base-uri/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{
			URI:          "/base-uri/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/base-uri/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:           "/oauth/authorize",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/callback",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/oauth/health",
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestMethodExclusions(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/post",
			Methods: []string{http.MethodPost, http.MethodPut},
		},
	}
	requests := []fakeRequest{
		{ // we should get a 401
			URI:          "/post",
			Method:       http.MethodPost,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // we should be permitted
			URI:           "/post",
			Method:        http.MethodGet,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestPreserveURLEncoding(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableLogging = true
	cfg.Resources = []*Resource{
		{
			URL:     "/api/v2/*",
			Methods: allHTTPMethods,
			Roles:   []string{"dev"},
		},
		{
			URL:     "/api/v1/auth*",
			Methods: allHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:         "/api/v1/*",
			Methods:     allHTTPMethods,
			WhiteListed: true,
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/test",
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // See KEYCLOAK-10864
			URI:                     "/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/",
			ExpectedContentContains: `"uri":"/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // See KEYCLOAK-11276
			URI:                     "/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png",
			ExpectedContentContains: `"uri":"/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // See KEYCLOAK-13315
			URI:                     "/rabbitmqui/%2F/replicate-to-central",
			ExpectedContentContains: `"uri":"/rabbitmqui/%2F/replicate-to-central"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{ // should work
			URI:           "/api/v1/auth",
			HasToken:      true,
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // should work
			URI:                     "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"admin"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
		{
			URI:          "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			HasToken:     true,
			Roles:        []string{"user"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // should work
			URI:                     "/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
		},
	}

	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestStrangeRoutingError(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/api/v1/events/123456789",
			Methods: allHTTPMethods,
			Roles:   []string{"user"},
		},
		{
			URL:     "/api/v1/events/404",
			Methods: allHTTPMethods,
			Roles:   []string{"monitoring"},
		},
		{
			URL:     "/api/v1/audit/*",
			Methods: allHTTPMethods,
			Roles:   []string{"auditor", "dev"},
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{"dev"},
		},
	}
	requests := []fakeRequest{
		{ // should work
			URI:                     "/api/v1/events/123456789",
			HasToken:                true,
			Redirects:               true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: `"uri":"/api/v1/events/123456789"`,
		},
		{ // should break with bad role
			URI:          "/api/v1/events/123456789",
			HasToken:     true,
			Redirects:    true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // good
			URI:           "/api/v1/events/404",
			HasToken:      true,
			Redirects:     false,
			Roles:         []string{"monitoring", "test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // this should fail with no roles - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // this should fail with bad role - hits catch all
			URI:          "/api/v1/event/1000",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // should work with catch-all
			URI:           "/api/v1/event/1000",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"dev"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}

	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestNoProxyingRequests(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/../%2e",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
	}
	newFakeProxy(c, &fakeAuthConfig{}).RunTests(t, requests)
}

const testAdminURI = "/admin/test"

func TestStrangeAdminRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:          "//admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "///admin/../admin//%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for escaping
			URI:          "/admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for prefix slashs
			URI:          "/" + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for double slashs
			URI:          testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for double slashs no redirects
			URI:          "/admin//test",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check for dodgy url
			URI:          "//admin/.." + testAdminURI,
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check for it works
			URI:           "/" + testAdminURI,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // check for is doens't work
			URI:          "//admin//test",
			HasToken:     true,
			Roles:        []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/help/../admin/test/21",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestWhiteListedRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
		{
			URL:         "/whitelist*",
			WhiteListed: true,
			Methods:     allHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{ // check whitelisted is passed
			URI:           "/whitelist",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check whitelisted is passed
			URI:           "/whitelist/test",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/test",
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestRequireAnyRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:            "/require_any_role/*",
			Methods:        allHTTPMethods,
			RequireAnyRole: true,
			Roles:          []string{"admin", "guest"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/require_any_role/test",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:           "/require_any_role/test",
			HasToken:      true,
			Roles:         []string{"guest"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/require_any_role/test",
			HasToken:     true,
			Roles:        []string{"guest1"},
			ExpectedCode: http.StatusForbidden,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestGroupPermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/with_role_and_group*",
			Methods: allHTTPMethods,
			Groups:  []string{"admin"},
			Roles:   []string{"admin"},
		},
		{
			URL:     "/with_group*",
			Methods: allHTTPMethods,
			Groups:  []string{"admin"},
		},
		{
			URL:     "/with_many_groups*",
			Methods: allHTTPMethods,
			Groups:  []string{"admin", "user", "tester"},
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Roles:        []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Groups:       []string{"admin"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_role_and_group/test",
			HasToken:      true,
			Groups:        []string{"admin"},
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_groupdd",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"test", "admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/with_many_groups/test",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"user"},
			Roles:         []string{"test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"tester", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"bad", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestRolePermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/test*",
			Methods: []string{"GET"},
			Roles:   []string{fakeTestRole},
		},
		{
			URL:     "/test_admin_role*",
			Methods: []string{"GET"},
			Roles:   []string{fakeAdminRole, fakeTestRole},
		},
		{
			URL:     "/section/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/section/one",
			Methods: allHTTPMethods,
			Roles:   []string{"one"},
		},
		{
			URL:     "/whitelist",
			Methods: []string{"GET"},
			Roles:   []string{},
		},
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // check for redirect
			URI:          "/",
			Redirects:    true,
			ExpectedCode: http.StatusSeeOther,
		},
		{ // check with a token but not test role
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token and wrong roles
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"one", "two"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, wrong roles
			URI:          "/test",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, but post method
			URI:           "/test",
			Method:        http.MethodPost,
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token
			URI:           "/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token on base
			URI:           "/",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token, not signed
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			NotSigned:    true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // check with correct token, signed
			URI:          "/admin/page",
			Method:       http.MethodPost,
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles (10)
			URI:          "/admin/page",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles
			URI:           "/admin/page",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole, fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url
			URI:          "/admin/..//admin/page",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // strange url, token
			URI:          "/admin/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"hehe"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token, role (15)
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, but good token
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, wrong roles
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token admin test role
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token but without both roles
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
			Roles:        []string{fakeAdminRole},
		},
		{ // check with a token with both roles (20)
			URI:           "/test_admin_role",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole, fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/test1",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole, fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/section/one",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole, fakeAdminRole},
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/section/one",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"one"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestCrossSiteHandler(t *testing.T) {
	cases := []struct {
		Cors    cors.Options
		Request fakeRequest
	}{
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*", "https://examples.com"},
			},
			Request: fakeRequest{
				URI: fakeAuthAllURL,
				Headers: map[string]string{
					"Origin": "127.0.0.1",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin": "*",
				},
			},
		},
		{
			Cors: cors.Options{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST"},
			},
			Request: fakeRequest{
				URI:    fakeAuthAllURL,
				Method: http.MethodOptions,
				Headers: map[string]string{
					"Origin":                        "127.0.0.1",
					"Access-Control-Request-Method": "GET",
				},
				ExpectedHeaders: map[string]string{
					"Access-Control-Allow-Origin":  "*",
					"Access-Control-Allow-Methods": "GET",
				},
			},
		},
	}

	for _, c := range cases {
		cfg := newFakeKeycloakConfig()
		cfg.CorsCredentials = c.Cors.AllowCredentials
		cfg.CorsExposedHeaders = c.Cors.ExposedHeaders
		cfg.CorsHeaders = c.Cors.AllowedHeaders
		cfg.CorsMaxAge = time.Duration(c.Cors.MaxAge) * time.Second
		cfg.CorsMethods = c.Cors.AllowedMethods
		cfg.CorsOrigins = c.Cors.AllowedOrigins

		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestRefreshToken(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestRefreshTokenEncryption",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                           fakeAuthAllURL,
					HasLogin:                      true,
					Redirects:                     true,
					OnResponse:                    delay,
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieRefreshName: checkRefreshTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieRefreshName: checkRefreshTokenEncryption},
				},
			},
		},
		{
			Name: "TestRefreshTokenExpiration",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                           fakeAuthAllURL,
					HasLogin:                      true,
					Redirects:                     true,
					OnResponse:                    doubleDelay,
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieRefreshName: checkRefreshTokenEncryption},
				},
				{
					URI:           fakeAuthAllURL,
					Redirects:     false,
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 1000 * time.Millisecond})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func delay(no int, req *resty.Request, resp *resty.Response) {
	if no == 0 {
		<-time.After(1000 * time.Millisecond)
	}
}

func doubleDelay(no int, req *resty.Request, resp *resty.Response) {
	if no == 0 {
		<-time.After(2000 * time.Millisecond)
	}
}

func checkAccessTokenEncryption(t *testing.T, cfg *Config, value string) bool {
	rawToken, err := decodeText(value, cfg.EncryptionKey)

	if err != nil {
		return false
	}

	token, err := jwt.ParseSigned(rawToken)

	if err != nil {
		return false
	}

	user, err := extractIdentity(token)

	if err != nil {
		return false
	}

	return assert.Contains(t, user.claims, "aud") && assert.Contains(t, user.claims, "email")
}

func checkRefreshTokenEncryption(t *testing.T, cfg *Config, value string) bool {
	rawToken, err := decodeText(value, cfg.EncryptionKey)

	if err != nil {
		return false
	}

	_, err = jwt.ParseSigned(rawToken)

	return err == nil
}

func TestAccessTokenEncryption(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	redisServer, err := miniredis.Run()

	if err != nil {
		t.Fatalf("Starting redis failed %s", err)
	}

	defer redisServer.Close()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEnableEncryptedTokenWithBoltDB",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
				c.StoreURL = "boltdb:////tmp/test.boltdb"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                           fakeAuthAllURL,
					HasLogin:                      true,
					Redirects:                     true,
					OnResponse:                    delay,
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
			},
		},
		{
			Name: "TestEnableEncryptedTokenWithRedis",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
				c.StoreURL = fmt.Sprintf("redis://%s", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                           fakeAuthAllURL,
					HasLogin:                      true,
					Redirects:                     true,
					OnResponse:                    delay,
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
			},
		},
		{
			Name: "TestEnableEncryptedToken",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                           fakeAuthAllURL,
					HasLogin:                      true,
					Redirects:                     true,
					OnResponse:                    delay,
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
			},
		},
		{
			Name: "ForceEncryptedCookie",
			ProxySettings: func(c *Config) {
				c.EnableRefreshTokens = true
				c.EnableEncryptedToken = false
				c.ForceEncryptedCookie = true
				c.Verbose = true
				c.EnableLogging = true
				c.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                           fakeAuthAllURL,
					HasLogin:                      true,
					Redirects:                     true,
					OnResponse:                    delay,
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
				{
					URI:                      fakeAuthAllURL,
					Redirects:                false,
					ExpectedProxy:            true,
					ExpectedCode:             http.StatusOK,
					ExpectedCookies:          map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *Config, string) bool{cfg.CookieAccessName: checkAccessTokenEncryption},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 1000 * time.Millisecond})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestCustomHeadersHandler(t *testing.T) {
	requests := []struct {
		Match   []string
		Request fakeRequest
	}{
		{
			Match: []string{"subject", "userid", "email", "username"},
			Request: fakeRequest{
				URI:      fakeAuthAllURL,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"sub":                "test-subject",
					"username":           "rohith",
					"preferred_username": "rohith",
					"email":              "gambol99@gmail.com",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Subject":  "test-subject",
					"X-Auth-Userid":   "rohith",
					"X-Auth-Email":    "gambol99@gmail.com",
					"X-Auth-Username": "rohith",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Match: []string{"given_name", "family_name", "preferred_username|Custom-Header"},
			Request: fakeRequest{
				URI:      fakeAuthAllURL,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"email":              "gambol99@gmail.com",
					"name":               "Rohith Jayawardene",
					"family_name":        "Jayawardene",
					"preferred_username": "rjayawardene",
					"given_name":         "Rohith",
				},
				ExpectedProxyHeaders: map[string]string{
					"X-Auth-Given-Name":  "Rohith",
					"X-Auth-Family-Name": "Jayawardene",
					"Custom-Header":      "rjayawardene",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.AddClaims = c.Match
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: allHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: allHTTPMethods,
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: allHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/admin",
			Roles:        []string{},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/admin",
			Roles:         []string{"admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/test",
			Roles:         []string{"test"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/either",
			Roles:         []string{"test", "admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/either",
			Roles:        []string{"no_roles"},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

// check to see if custom headers are hitting the upstream
func TestCustomHeaders(t *testing.T) {
	requests := []struct {
		Headers map[string]string
		Request fakeRequest
	}{
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
			},
			Request: fakeRequest{
				URI:           "/gambol99.htm",
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeader": "test",
			},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeader": "test",
				},
			},
		},
		{
			Headers: map[string]string{
				"TestHeaderOne": "one",
				"TestHeaderTwo": "two",
			},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				ExpectedProxy: true,
				ExpectedProxyHeaders: map[string]string{
					"TestHeaderOne": "one",
					"TestHeaderTwo": "two",
				},
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: allHTTPMethods}}
		cfg.Headers = c.Headers
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestRolesAdmissionHandlerClaims(t *testing.T) {
	requests := []struct {
		Matches map[string]string
		Request fakeRequest
	}{
		// jose.StringClaim test
		{
			Matches: map[string]string{"item": "test"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item": "tes"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "not_match"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  map[string]interface{}{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:          testAdminURI,
				HasToken:     true,
				TokenClaims:  map[string]interface{}{"item": "test"},
				ExpectedCode: http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Request: fakeRequest{
				URI:      testAdminURI,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"item":  "tester",
					"found": "something",
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": ".*"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*$"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item": "test"},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		// jose.StringsClaim test
		{
			Matches: map[string]string{"item1": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item1": []string{"nonMatchingClaim", "test", "anotherNonMatching"}},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
		{
			Matches: map[string]string{"item1": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item1": []string{"1test", "2test", "3test"}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{"item": "^t.*t"},
			Request: fakeRequest{
				URI:           testAdminURI,
				HasToken:      true,
				TokenClaims:   map[string]interface{}{"item1": []string{}},
				ExpectedProxy: false,
				ExpectedCode:  http.StatusForbidden,
			},
		},
		{
			Matches: map[string]string{
				"item1": "^t.*t",
				"item2": "^another",
			},
			Request: fakeRequest{
				URI:      testAdminURI,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"item1": []string{"randomItem", "test"},
					"item2": []string{"randomItem", "anotherItem"},
					"item3": []string{"randomItem2", "anotherItem3"},
				},
				ExpectedProxy: true,
				ExpectedCode:  http.StatusOK,
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.Resources = []*Resource{{URL: "/admin*", Methods: allHTTPMethods}}
		cfg.MatchClaims = c.Matches
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestGzipCompression(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	s := httptest.NewServer(&fakeUpstreamService{})

	requests := []struct {
		Name              string
		ProxySettings     func(c *Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestCompressionWithCustomURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = true
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/gambol99.htm",
					ExpectedProxy: true,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedHeaders: map[string]string{
						"Content-Encoding": "gzip",
					},
				},
			},
		},
		{
			Name: "TestCompressionWithAdminURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = true
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testAdminURI,
					ExpectedProxy: false,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedHeaders: map[string]string{
						"Content-Encoding": "gzip",
					},
				},
			},
		},
		{
			Name: "TestCompressionWithLogging",
			ProxySettings: func(c *Config) {
				c.EnableCompression = true
				c.EnableLogging = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URL:                     s.URL + "/test",
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "/test",
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedHeaders: map[string]string{
						"Content-Encoding": "gzip",
					},
				},
			},
		},
		{
			Name: "TestWithoutCompressionCustomURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = false
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/gambol99.htm",
					ExpectedProxy: true,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedNoProxyHeaders: []string{"Content-Encoding"},
				},
			},
		},
		{
			Name: "TestWithoutCompressionWithAdminURI",
			ProxySettings: func(c *Config) {
				c.EnableCompression = false
				c.EnableLogging = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           testAdminURI,
					ExpectedProxy: false,
					Headers: map[string]string{
						"Accept-Encoding": "gzip, deflate, br",
					},
					ExpectedNoProxyHeaders: []string{"Content-Encoding"},
				},
			},
		},
	}

	for _, testCase := range requests {
		testCase := testCase
		c := cfg
		c.Resources = []*Resource{{URL: "/admin*", Methods: allHTTPMethods}}

		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}
