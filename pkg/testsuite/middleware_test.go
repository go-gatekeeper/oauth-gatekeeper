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

package testsuite_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	opaserver "github.com/open-policy-agent/opa/v1/server"
	"github.com/rs/cors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestMetricsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableMetrics = true
	cfg.LocalhostMetrics = true
	cfg.EnableRefreshTokens = true
	cfg.EnableEncryptedToken = true
	cfg.EncryptionKey = testEncryptionKey
	uri := utils.WithOAuthURI(cfg.BaseURI, cfg.OAuthURI)(constant.MetricsURL)
	requests := []fakeRequest{
		{
			URI:       FakeAuthAllURL,
			HasLogin:  true,
			Redirects: true,
			OnResponse: func(int, *resty.Request, *resty.Response) {
				<-time.After(time.Duration(int64(2500)) * time.Millisecond)
			},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           FakeAuthAllURL,
			Redirects:     true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI: uri,
			Headers: map[string]string{
				constant.HeaderXForwardedFor: "10.0.0.1",
			},
			ExpectedCode: http.StatusForbidden,
		},
		// Some request must run before this one to generate request status numbers
		{
			URI:                     uri,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "proxy_request_status_total",
		},
		{
			URI:                     uri,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"issued\"",
		},
		{
			URI:                     uri,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"exchange\"",
		},
		{
			URI:                     uri,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "action=\"renew\"",
		},
	}
	p := newFakeProxy(cfg, &fakeAuthConfig{})
	p.idp.setTokenExpiration(2000 * time.Millisecond)
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

//nolint:cyclop
func TestAdminListener(t *testing.T) {
	testCases := []struct {
		Name              string
		ProxySettings     func(conf *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestAdminOnSameListener",
			ProxySettings: func(conf *config.Config) {
				conf.EnableMetrics = true
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
			ProxySettings: func(conf *config.Config) {
				conf.EnableMetrics = true
				conf.ListenAdmin = "127.0.0.1:12300"
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
			ProxySettings: func(conf *config.Config) {
				conf.EnableMetrics = true
				conf.ListenAdmin = "127.0.0.1:12301"
				conf.ListenAdminScheme = constant.SecureScheme
				//nolint:gosec
				conf.TLSAdminCertificate = os.TempDir() + FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSAdminPrivateKey = os.TempDir() + FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSAdminCaCertificate = os.TempDir() + FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))
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
			ProxySettings: func(conf *config.Config) {
				conf.EnableMetrics = true
				conf.ListenAdmin = "127.0.0.1:12302"
				conf.ListenAdminScheme = constant.SecureScheme
				//nolint:gosec
				conf.TLSCertificate = os.TempDir() + FakeCertFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSPrivateKey = os.TempDir() + FakePrivFilePrefix + strconv.Itoa(rand.Intn(10000))
				//nolint:gosec
				conf.TLSCaCertificate = os.TempDir() + FakeCaFilePrefix + strconv.Itoa(rand.Intn(10000))
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
		cfg := newFakeKeycloakConfig()
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(cfg)

				certFile := ""
				privFile := ""
				caFile := ""

				if cfg.TLSAdminCertificate != "" {
					certFile = cfg.TLSAdminCertificate
				}

				if cfg.TLSCertificate != "" {
					certFile = cfg.TLSCertificate
				}

				if cfg.TLSAdminPrivateKey != "" {
					privFile = cfg.TLSAdminPrivateKey
				}

				if cfg.TLSPrivateKey != "" {
					privFile = cfg.TLSPrivateKey
				}

				if cfg.TLSAdminCaCertificate != "" {
					caFile = cfg.TLSAdminCaCertificate
				}

				if cfg.TLSCaCertificate != "" {
					caFile = cfg.TLSCaCertificate
				}

				if certFile != "" {
					fakeCertByte := []byte(fakeCert)
					err := os.WriteFile(certFile, fakeCertByte, 0o600)
					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" {
					fakeKeyByte := []byte(fakePrivateKey)
					err := os.WriteFile(privFile, fakeKeyByte, 0o600)
					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" {
					fakeCAByte := []byte(fakeCA)
					err := os.WriteFile(caFile, fakeCAByte, 0o600)
					if err != nil {
						t.Fatalf("Problem writing cacertificate %s", err)
					}
					defer os.Remove(caFile)
				}

				p := newFakeProxy(cfg, &fakeAuthConfig{})
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
	cfg.NoRedirects = true
	cfg.Resources = []*authorization.Resource{
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
			Redirects:    false,
		},
		{ // we should be permitted
			URI:           "/post",
			Method:        http.MethodGet,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestPreserveURLEncoding(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableLogging = true
	cfg.NoRedirects = true
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/api/v2/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"dev"},
		},
		{
			URL:     "/api/v1/auth*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:         "/api/v1/*",
			Methods:     utils.AllHTTPMethods,
			WhiteListed: true,
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"user"},
		},
	}

	requests := []fakeRequest{
		{
			URI:          FakeTestURL,
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
			Redirects:    false,
		},
		{ // See KEYCLOAK-10864
			//nolint:lll
			URI: "/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/",
			//nolint:lll
			ExpectedContentContains: `"uri":"/administrativeMonitor/hudson.diagnosis.ReverseProxySetupMonitor/testForReverseProxySetup/https%3A%2F%2Flocalhost%3A6001%2Fmanage/"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			Redirects:               false,
		},
		{ // See KEYCLOAK-11276
			URI:                     "/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png",
			ExpectedContentContains: `"uri":"/iiif/2/edepot_local:ST%2F00001%2FST00005_00001.jpg/full/1000,/0/default.png"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			Redirects:               false,
		},
		{ // See KEYCLOAK-13315
			URI:                     "/rabbitmqui/%2F/replicate-to-central",
			ExpectedContentContains: `"uri":"/rabbitmqui/%2F/replicate-to-central"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			Redirects:               false,
		},
		{ // should work
			URI:           "/api/v1/auth",
			HasToken:      true,
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
		{ // should work
			URI:                     "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"admin"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			Redirects:               false,
		},
		{
			URI:          "/api/v1/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			HasToken:     true,
			Roles:        []string{"user"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{ // should work
			URI:                     "/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth",
			ExpectedContentContains: `"uri":"/api/v3/auth?referer=https%3A%2F%2Fwww.example.com%2Fauth"`,
			HasToken:                true,
			Roles:                   []string{"user"},
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			Redirects:               false,
		},
	}

	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestStrangeRoutingError(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/api/v1/events/123456789",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"user"},
		},
		{
			URL:     "/api/v1/events/404",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"monitoring"},
		},
		{
			URL:     "/api/v1/audit/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"auditor", "dev"},
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"dev"},
		},
	}

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
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
			},
		},
		{
			Name: "TestRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
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
			},
		},
	}

	for _, testCase := range testCases {
		cfg := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&cfg)
				newFakeProxy(&cfg, &fakeAuthConfig{}).RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestNoProxyingRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
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
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

const testAdminURI = "/admin/test"

func TestStrangeAdminRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/admin*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{FakeAdminRole},
		},
	}

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{ // check for double slashs no redirects
					URI:          "/admin//test",
					Redirects:    false,
					HasToken:     true,
					ExpectedCode: http.StatusForbidden,
				},
				{
					URI:          "/help/../admin/test/21",
					Redirects:    false,
					ExpectedCode: http.StatusUnauthorized,
				},
			},
		},
		{
			Name: "TestRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
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
				{ // check for dodgy url
					URI:          "//admin/.." + testAdminURI,
					Redirects:    true,
					ExpectedCode: http.StatusSeeOther,
				},
				{ // check for it works
					URI:           "/" + testAdminURI,
					HasToken:      true,
					Roles:         []string{FakeAdminRole},
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
				},
				{ // check for is doens't work
					URI:          "//admin//test",
					HasToken:     true,
					Roles:        []string{"bad"},
					ExpectedCode: http.StatusForbidden,
				},
			},
		},
	}

	for _, testCase := range testCases {
		cfg := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&cfg)
				newFakeProxy(&cfg, &fakeAuthConfig{}).RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestWhiteListedRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{FakeTestRole},
		},
		{
			URL:         "/whitelist*",
			WhiteListed: true,
			Methods:     utils.AllHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{ // check whitelisted is passed
			URI:           "/whitelist",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
			Redirects:     false,
		},
		{ // check whitelisted is passed
			URI:           "/whitelist/test",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
			Redirects:     false,
		},
		{
			URI:          FakeTestURL,
			HasToken:     true,
			Roles:        []string{"nothing"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
			Redirects:    false,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			Roles:         []string{FakeTestRole},
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestRequireAnyRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*authorization.Resource{
		{
			URL:            "/require_any_role/*",
			Methods:        utils.AllHTTPMethods,
			RequireAnyRole: true,
			Roles:          []string{"admin", "guest"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/require_any_role/test",
			ExpectedCode: http.StatusUnauthorized,
			Redirects:    false,
		},
		{
			URI:           "/require_any_role/test",
			HasToken:      true,
			Roles:         []string{"guest"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
			Redirects:     false,
		},
		{
			URI:          "/require_any_role/test",
			HasToken:     true,
			Roles:        []string{"guest1"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

//nolint:funlen
func TestHeaderPermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	requests := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestMissingHeadersCodeFlow",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/with_headers*",
						Methods: utils.AllHTTPMethods,
						Headers: []string{
							"x-test-header1:validvalue",
							"x-test-header2:validvalue",
						},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/with_headers",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestHeadersCodeFlow",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/with_headers*",
						Methods: utils.AllHTTPMethods,
						Headers: []string{
							"x-test-header1:validvalue",
							"x-test-header2:validvalue",
						},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/with_headers",
					ExpectedProxy: true,
					HasToken:      true,
					Headers: map[string]string{
						"x-test-header1": "validvalue",
						"x-test-header2": "validvalue",
					},
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gzip",
				},
			},
		},
		{
			Name: "TestMissingHeadersNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.NoRedirects = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/with_headers*",
						Methods: utils.AllHTTPMethods,
						Headers: []string{
							"x-test-header1:validvalue",
							"x-test-header2:validvalue",
						},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/with_headers",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestOnlyOneHeaderNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.NoRedirects = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/with_headers*",
						Methods: utils.AllHTTPMethods,
						Headers: []string{
							"x-test-header1:validvalue",
							"x-test-header2:validvalue",
						},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/with_headers",
					ExpectedProxy: false,
					HasToken:      true,
					Headers: map[string]string{
						"x-test-header1": "validvalue",
					},
					ExpectedCode: http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestHeadersNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.NoRedirects = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/with_headers*",
						Methods: utils.AllHTTPMethods,
						Headers: []string{
							"x-test-header1:validvalue",
							"x-test-header2:validvalue",
						},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/with_headers",
					ExpectedProxy: true,
					HasToken:      true,
					Headers: map[string]string{
						"x-test-header1": "validvalue",
						"x-test-header2": "validvalue",
					},
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: "gzip",
				},
			},
		},
		{
			Name: "TestMissingHeadersNoProxyNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.NoRedirects = true
				conf.NoProxy = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/with_headers*",
						Methods: utils.AllHTTPMethods,
						Headers: []string{
							"x-test-header1:validvalue",
							"x-test-header2:validvalue",
						},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/with_headers",
					ExpectedProxy: false,
					HasToken:      true,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
		{
			Name: "TestHeadersNoProxyNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.NoRedirects = true
				conf.NoProxy = true
				conf.Resources = []*authorization.Resource{
					{
						URL:     "/with_headers*",
						Methods: utils.AllHTTPMethods,
						Headers: []string{
							"x-test-header1:validvalue",
							"x-test-header2:validvalue",
						},
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           "/with_headers",
					ExpectedProxy: false,
					HasToken:      true,
					Headers: map[string]string{
						"x-test-header1": "validvalue",
						"x-test-header2": "validvalue",
					},
					ExpectedCode: http.StatusOK,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
		},
	}

	for _, testCase := range requests {
		c := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&c)
				p := newFakeProxy(&c, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestGroupPermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/with_role_and_group*",
			Methods: utils.AllHTTPMethods,
			Groups:  []string{"admin"},
			Roles:   []string{"admin"},
		},
		{
			URL:     "/with_group*",
			Methods: utils.AllHTTPMethods,
			Groups:  []string{"admin"},
		},
		{
			URL:     "/with_many_groups*",
			Methods: utils.AllHTTPMethods,
			Groups:  []string{"admin", "user", "tester"},
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"user"},
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
			Redirects:    false,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Roles:        []string{"admin"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:          "/with_role_and_group/test",
			HasToken:     true,
			Groups:       []string{"admin"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:           "/with_role_and_group/test",
			HasToken:      true,
			Groups:        []string{"admin"},
			Roles:         []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:          "/with_groupdd",
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:          "/with_group/hello",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
		{
			URI:           "/with_group/hello",
			HasToken:      true,
			Groups:        []string{"test", "admin"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
		{
			URI:          "/with_many_groups/test",
			HasToken:     true,
			Groups:       []string{"bad"},
			ExpectedCode: http.StatusForbidden,
			Redirects:    false,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"user"},
			Roles:         []string{"test"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"tester", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
		{
			URI:           "/with_many_groups/test",
			HasToken:      true,
			Groups:        []string{"bad", "user"},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
			Redirects:     false,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

//nolint:funlen
func TestRolePermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*authorization.Resource{
		{
			URL:     "/admin*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{FakeAdminRole},
		},
		{
			URL:     "/test*",
			Methods: []string{"GET"},
			Roles:   []string{FakeTestRole},
		},
		{
			URL:     "/test_admin_role*",
			Methods: []string{"GET"},
			Roles:   []string{FakeAdminRole, FakeTestRole},
		},
		{
			URL:     "/section/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{FakeAdminRole},
		},
		{
			URL:     "/section/one",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"one"},
		},
		{
			URL:     "/whitelist",
			Methods: []string{"GET"},
			Roles:   []string{},
		},
		{
			URL:     "/*",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{FakeTestRole},
		},
	}

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:          "/",
					ExpectedCode: http.StatusUnauthorized,
					Redirects:    false,
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
					URI:          FakeTestURL,
					Redirects:    false,
					HasToken:     true,
					Roles:        []string{"bad_role"},
					ExpectedCode: http.StatusForbidden,
				},
				{ // token, but post method
					URI:           FakeTestURL,
					Method:        http.MethodPost,
					Redirects:     false,
					HasToken:      true,
					Roles:         []string{FakeTestRole},
					ExpectedCode:  http.StatusOK,
					ExpectedProxy: true,
				},
				{ // check with correct token
					URI:           FakeTestURL,
					Redirects:     false,
					HasToken:      true,
					Roles:         []string{FakeTestRole},
					ExpectedCode:  http.StatusOK,
					ExpectedProxy: true,
				},
				{ // check with correct token on base
					URI:           "/",
					Redirects:     false,
					HasToken:      true,
					Roles:         []string{FakeTestRole},
					ExpectedCode:  http.StatusOK,
					ExpectedProxy: true,
				},
				{ // check with correct token, not signed
					URI:          "/",
					Redirects:    false,
					HasToken:     true,
					NotSigned:    true,
					Roles:        []string{FakeTestRole},
					ExpectedCode: http.StatusForbidden,
				},
				{ // check with correct token, signed
					URI:          "/admin/page",
					Method:       http.MethodPost,
					Redirects:    false,
					HasToken:     true,
					Roles:        []string{FakeTestRole},
					ExpectedCode: http.StatusForbidden,
				},
				{ // check with correct token, signed, wrong roles (10)
					URI:          "/admin/page",
					Redirects:    false,
					HasToken:     true,
					Roles:        []string{FakeTestRole},
					ExpectedCode: http.StatusForbidden,
				},
				{ // check with correct token, signed, wrong roles
					URI:           "/admin/page",
					Redirects:     false,
					HasToken:      true,
					Roles:         []string{FakeTestRole, FakeAdminRole},
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
					Roles:         []string{FakeAdminRole},
					ExpectedCode:  http.StatusOK,
					ExpectedProxy: true,
				},
				{ // strange url, token, but good token
					URI:           "/test/../admin",
					Redirects:     false,
					HasToken:      true,
					Roles:         []string{FakeAdminRole},
					ExpectedCode:  http.StatusOK,
					ExpectedProxy: true,
				},
				{ // strange url, token, wrong roles
					URI:          "/test/../admin",
					Redirects:    false,
					HasToken:     true,
					Roles:        []string{FakeTestRole},
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
					Roles:        []string{FakeAdminRole},
				},
				{ // check with a token with both roles (20)
					URI:           "/test_admin_role",
					Redirects:     false,
					HasToken:      true,
					Roles:         []string{FakeAdminRole, FakeTestRole},
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
					Roles:         []string{FakeTestRole, FakeAdminRole},
					ExpectedCode:  http.StatusOK,
					ExpectedProxy: true,
				},
				{
					URI:          "/section/one",
					Redirects:    false,
					HasToken:     true,
					Roles:        []string{FakeTestRole, FakeAdminRole},
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
			},
		},
		{
			Name: "TestRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
				{ // check for redirect
					URI:          "/",
					Redirects:    true,
					ExpectedCode: http.StatusSeeOther,
				},
			},
		},
	}

	for _, testCase := range testCases {
		cfg := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&cfg)
				newFakeProxy(&cfg, &fakeAuthConfig{}).RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
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
				URI: FakeAuthAllURL,
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
				URI: FakeAuthAllURL,
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
				URI:    FakeAuthAllURL,
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

	for _, testCase := range cases {
		cfg := newFakeKeycloakConfig()
		cfg.CorsCredentials = testCase.Cors.AllowCredentials
		cfg.CorsExposedHeaders = testCase.Cors.ExposedHeaders
		cfg.CorsHeaders = testCase.Cors.AllowedHeaders
		cfg.CorsMaxAge = time.Duration(testCase.Cors.MaxAge) * time.Second
		cfg.CorsMethods = testCase.Cors.AllowedMethods
		cfg.CorsOrigins = testCase.Cors.AllowedOrigins

		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{testCase.Request})
	}
}

func TestRefreshToken(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	testCases := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestRefreshTokenEncryption",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieRefreshName: checkRefreshTokenEncryption,
					},
				},
				{
					URI:           FakeAuthAllURL,
					Redirects:     false,
					HasLogin:      false,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
				},
			},
		},
		{
			Name: "TestRefreshTokenWithIdpSessionCheck",
			ProxySettings: func(conf *config.Config) {
				conf.EnableIDPSessionCheck = true
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieRefreshName: checkRefreshTokenEncryption,
					},
				},
				{
					URI:           FakeAuthAllURL,
					Redirects:     false,
					HasLogin:      false,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
				},
			},
		},
		{
			Name: "TestRefreshTokenEncryptionWithClientIDAndIssuerCheckOn",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
				conf.SkipAccessTokenClientIDCheck = false
				conf.SkipAccessTokenIssuerCheck = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeAuthAllURL,
					HasLogin:      true,
					Redirects:     true,
					OnResponse:    delay,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieRefreshName: checkRefreshTokenEncryption,
					},
				},
				{
					URI:           FakeAuthAllURL,
					Redirects:     false,
					HasLogin:      false,
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
				},
			},
		},
		{
			Name: "TestRefreshTokenExpiration",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
				conf.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       FakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(3200)) * time.Millisecond)
					},
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieRefreshName: checkRefreshTokenEncryption,
					},
				},
				{
					URI:           FakeAuthAllURL,
					Redirects:     true,
					HasLogin:      false,
					ExpectedProxy: false,
					ExpectedCode:  http.StatusSeeOther,
				},
			},
		},
	}

	for _, testCase := range testCases {
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 1500 * time.Millisecond})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func delay(no int, _ *resty.Request, _ *resty.Response) {
	if no == 0 {
		<-time.After(1000 * time.Millisecond)
	}
}

func checkAccessTokenEncryption(t *testing.T, cfg *config.Config, value string) bool {
	t.Helper()
	rawToken, err := encryption.DecodeText(value, cfg.EncryptionKey)
	if err != nil {
		return false
	}

	user, err := session.ExtractIdentity(rawToken)
	if err != nil {
		return false
	}

	return assert.Contains(t, user.Claims, "aud") && assert.Contains(t, user.Claims, "email")
}

func checkRefreshTokenEncryption(_ *testing.T, cfg *config.Config, value string) bool {
	rawToken, err := encryption.DecodeText(value, cfg.EncryptionKey)
	if err != nil {
		return false
	}

	_, err = jwt.ParseSigned(rawToken, constant.SignatureAlgs[:])

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
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestEnableEncryptedTokenWithRedis",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
				conf.StoreURL = fmt.Sprintf("redis://%s/2", redisServer.Addr())
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       FakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: checkAccessTokenEncryption,
					},
				},
				{
					URI:             FakeAuthAllURL,
					Redirects:       false,
					ExpectedProxy:   true,
					ExpectedCode:    http.StatusOK,
					ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: checkAccessTokenEncryption,
					},
				},
			},
		},
		{
			Name: "TestEnableEncryptedToken",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       FakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: checkAccessTokenEncryption,
					},
				},
				{
					URI:             FakeAuthAllURL,
					Redirects:       false,
					ExpectedProxy:   true,
					ExpectedCode:    http.StatusOK,
					ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: checkAccessTokenEncryption,
					},
				},
			},
		},
		{
			Name: "ForceEncryptedCookie",
			ProxySettings: func(conf *config.Config) {
				conf.EnableRefreshTokens = true
				conf.EnableEncryptedToken = false
				conf.ForceEncryptedCookie = true
				conf.Verbose = true
				conf.EnableLogging = true
				conf.EncryptionKey = testEncryptionKey
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       FakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy: true,
					ExpectedCode:  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: checkAccessTokenEncryption,
					},
				},
				{
					URI:             FakeAuthAllURL,
					Redirects:       false,
					ExpectedProxy:   true,
					ExpectedCode:    http.StatusOK,
					ExpectedCookies: map[string]string{cfg.CookieAccessName: ""},
					ExpectedCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{
						cfg.CookieAccessName: checkAccessTokenEncryption,
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		cfgCopy := *cfg
		c := &cfgCopy
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(c)
				p := newFakeProxy(c, &fakeAuthConfig{Expiration: 2000 * time.Millisecond})
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
				URI:      FakeAuthAllURL,
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
				URI:      FakeAuthAllURL,
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

func TestCustomHeadersHandlerNoProxyNoRedirects(t *testing.T) {
	requests := []struct {
		Match         []string
		ProxySettings func(c *config.Config)
		Request       fakeRequest
	}{
		{
			Match: []string{"subject", "userid", "email", "username"},
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.NoRedirects = true
				conf.NoProxy = true
			},
			Request: fakeRequest{
				URI:      FakeAuthAllURL,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"sub":                "test-subject",
					"username":           "rohith",
					"preferred_username": "rohith",
					"email":              "gambol99@gmail.com",
				},
				ExpectedHeaders: map[string]string{
					"X-Auth-Subject":  "test-subject",
					"X-Auth-Userid":   "rohith",
					"X-Auth-Email":    "gambol99@gmail.com",
					"X-Auth-Username": "rohith",
				},
				ExpectedCode: http.StatusOK,
				ExpectedContent: func(body string, _ int) {
					assert.Equal(t, "", body)
				},
			},
		},
		{
			Match: []string{"given_name", "family_name", "preferred_username|Custom-Header"},
			ProxySettings: func(conf *config.Config) {
				conf.EnableDefaultDeny = true
				conf.NoRedirects = true
				conf.NoProxy = true
			},
			Request: fakeRequest{
				URI:      FakeAuthAllURL,
				HasToken: true,
				TokenClaims: map[string]interface{}{
					"email":              "gambol99@gmail.com",
					"name":               "Rohith Jayawardene",
					"family_name":        "Jayawardene",
					"preferred_username": "rjayawardene",
					"given_name":         "Rohith",
				},
				ExpectedHeaders: map[string]string{
					"X-Auth-Given-Name":  "Rohith",
					"X-Auth-Family-Name": "Jayawardene",
					"Custom-Header":      "rjayawardene",
				},
				ExpectedCode: http.StatusOK,
				ExpectedContent: func(body string, _ int) {
					assert.Equal(t, "", body)
				},
			},
		},
	}
	for _, c := range requests {
		cfg := newFakeKeycloakConfig()
		cfg.AddClaims = c.Match
		c.ProxySettings(cfg)
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*authorization.Resource{
		{
			URL:     FakeAdminURL,
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:     FakeTestURL,
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: utils.AllHTTPMethods,
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: utils.AllHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{
			URI:          FakeAdminURL,
			Roles:        []string{},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           FakeAdminURL,
			Roles:         []string{"admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           FakeTestURL,
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

// check to see if custom headers are hitting the upstream.
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
		cfg.Resources = []*authorization.Resource{{URL: "/admin*", Methods: utils.AllHTTPMethods}}
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
		cfg.Resources = []*authorization.Resource{{URL: "/admin*", Methods: utils.AllHTTPMethods}}
		cfg.MatchClaims = c.Matches
		newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, []fakeRequest{c.Request})
	}
}

func TestGzipCompression(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	server := httptest.NewServer(&FakeUpstreamService{})

	requests := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestCompressionWithCustomURI",
			ProxySettings: func(c *config.Config) {
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
			ProxySettings: func(c *config.Config) {
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
					ExpectedNoProxyHeaders: []string{"Content-Encoding"},
				},
			},
		},
		{
			Name: "TestCompressionWithLogging",
			ProxySettings: func(c *config.Config) {
				c.EnableCompression = true
				c.EnableLogging = true
				c.Upstream = server.URL
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                     FakeTestURL,
					ProxyRequest:            true,
					ExpectedProxy:           true,
					ExpectedCode:            http.StatusOK,
					ExpectedContentContains: FakeTestURL,
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
			ProxySettings: func(c *config.Config) {
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
			ProxySettings: func(c *config.Config) {
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
		cfg := *cfg
		cfg.Resources = []*authorization.Resource{{URL: "/admin*", Methods: utils.AllHTTPMethods}}

		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&cfg)
				p := newFakeProxy(&cfg, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestEnableUma(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	requests := []struct {
		Name               string
		ProxySettings      func(c *config.Config)
		ExecutionSettings  []fakeRequest
		AuthServerSettings *fakeAuthConfig
	}{
		{
			Name: "TestUmaNoTokenNoRedirects",
			ProxySettings: func(conf *config.Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.NoRedirects = true
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: false,
					Redirects:     false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
			AuthServerSettings: &fakeAuthConfig{},
		},
		{
			Name: "TestUmaDisabledWhenPerResourceNoRedirect",
			ProxySettings: func(conf *config.Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
				conf.Resources = []*authorization.Resource{
					{
						URL:        FakeTestURL,
						Methods:    utils.AllHTTPMethods,
						NoRedirect: true,
					},
				}
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: false,
					ExpectedCode:  http.StatusUnauthorized,
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "")
					},
				},
			},
			AuthServerSettings: &fakeAuthConfig{
				ResourceSetHandlerFailure: true,
			},
		},
		{
			Name: "TestUmaTokenWithoutAuthzWithNoResourcesInAuthServer",
			ProxySettings: func(conf *config.Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:                FakeTestURL,
					ExpectedProxy:      false,
					HasToken:           true,
					ExpectedCode:       http.StatusForbidden,
					TokenAuthorization: &models.Permissions{},
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "")
					},
				},
			},
			AuthServerSettings: &fakeAuthConfig{
				ResourceSetHandlerFailure: true,
			},
		},
		{
			Name: "TestUmaTokenWithoutResourceId",
			ProxySettings: func(conf *config.Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: true,
					HasToken:      true,
					ExpectedCode:  http.StatusOK,
					TokenAuthorization: &models.Permissions{
						Permissions: []models.Permission{
							{
								Scopes:       []string{"test"},
								ResourceID:   "",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
			AuthServerSettings: &fakeAuthConfig{},
		},
		{
			Name: "TestUmaTokenWithoutScope",
			ProxySettings: func(conf *config.Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: true,
					HasToken:      true,
					ExpectedCode:  http.StatusOK,
					TokenAuthorization: &models.Permissions{
						Permissions: []models.Permission{
							{
								Scopes:       []string{},
								ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
			AuthServerSettings: &fakeAuthConfig{},
		},
		{
			Name: "TestUmaOK",
			ProxySettings: func(conf *config.Config) {
				conf.EnableUma = true
				conf.EnableDefaultDeny = true
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.PatRetryCount = 5
				conf.PatRetryInterval = 2 * time.Second
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: true,
					HasToken:      true,
					ExpectedCode:  http.StatusOK,
					TokenAuthorization: &models.Permissions{
						Permissions: []models.Permission{
							{
								Scopes:       []string{"test"},
								ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
								ResourceName: "some",
							},
						},
					},
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
			AuthServerSettings: &fakeAuthConfig{},
		},
	}

	for _, testCase := range requests {
		c := *cfg
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				testCase.ProxySettings(&c)
				p := newFakeProxy(&c, testCase.AuthServerSettings)
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestLogRealIP(t *testing.T) {
	testCases := []struct {
		Headers    map[string]string
		ExpectedIP string
	}{
		{
			Headers:    map[string]string{},
			ExpectedIP: "127.0.0.1",
		},
		{
			Headers:    map[string]string{constant.HeaderXForwardedFor: "192.168.1.1"},
			ExpectedIP: "192.168.1.1",
		},
		{
			Headers:    map[string]string{constant.HeaderXForwardedFor: "192.168.1.1, 192.168.1.2"},
			ExpectedIP: "192.168.1.1",
		},
		{
			Headers:    map[string]string{constant.HeaderXRealIP: "10.0.0.1"},
			ExpectedIP: "10.0.0.1",
		},
		{
			Headers:    map[string]string{constant.HeaderXForwardedFor: "192.168.1.1", constant.HeaderXRealIP: "10.0.0.1"},
			ExpectedIP: "192.168.1.1",
		},
	}

	cfg := newFakeKeycloakConfig()
	cfg.EnableLogging = true
	cfg.Verbose = true

	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	testLog := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(writer), zapcore.InfoLevel))

	for _, testCase := range testCases {
		req := fakeRequest{
			URI:           "/",
			HasToken:      true,
			Headers:       testCase.Headers,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		}

		auth := newFakeAuthServer(&fakeAuthConfig{})
		cfg.DiscoveryURL = auth.getLocation()
		_ = cfg.Update()

		proxy, _ := proxy.NewProxy(cfg, testLog, &FakeUpstreamService{})
		_, _ = proxy.Run()

		cfg.RedirectionURL = "http://" + proxy.Listener.Addr().String()
		fp := &fakeProxy{cfg, auth, proxy, make(map[string]*http.Cookie)}
		fp.RunTests(t, []fakeRequest{req})

		_ = writer.Flush()
		rows := buffer.String()
		buffer.Reset()

		logRow := struct {
			ClientIP string `json:"client_ip"`
		}{}

		var rowFound bool
		for _, row := range strings.Split(rows, "\n") {
			if err := json.Unmarshal([]byte(row), &logRow); err == nil && len(logRow.ClientIP) > 0 {
				rowFound = true
				break
			}
		}

		assert.True(t, rowFound)
		assert.Equal(t, testCase.ExpectedIP, logRow.ClientIP)
	}
}

//nolint:funlen
func TestEnableOpa(t *testing.T) {
	upstreamService := httptest.NewServer(&FakeUpstreamService{})
	upstreamURL := upstreamService.URL

	requests := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
		AuthzPolicy       string
		StartOpa          bool
	}{
		{
			Name: "TestEnableOpaOK",
			ProxySettings: func(conf *config.Config) {
				conf.EnableOpa = true
				conf.EnableDefaultDeny = true
				conf.OpaTimeout = 60 * time.Second
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.Upstream = upstreamURL
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: true,
					Method:        "POST",
					FormValues: map[string]string{
						"Name": "Whatever",
					},
					HasToken:     true,
					Redirects:    false,
					ExpectedCode: http.StatusOK,
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
						assert.Contains(t, body, "Whatever")
					},
				},
			},
			AuthzPolicy: `
			package authz

			default allow := false

			allow if {
				input.method = "POST"
				input.path = FakeTestURL
				contains(input.body, "Whatever")
			}
			`,
			StartOpa: true,
		},
		{
			Name: "TestEnableOpaUnAuthorized",
			ProxySettings: func(conf *config.Config) {
				conf.EnableOpa = true
				conf.EnableDefaultDeny = true
				conf.OpaTimeout = 60 * time.Second
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: false,
					HasToken:      true,
					Redirects:     false,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
			AuthzPolicy: `
			package authz

			default allow := false

			allow if {
				input.method = "GETTT"
				input.path = FakeTestURL
			}
			`,
			StartOpa: true,
		},
		{
			Name: "TestMissingOpaPolicy",
			ProxySettings: func(conf *config.Config) {
				conf.EnableOpa = true
				conf.EnableDefaultDeny = true
				conf.OpaTimeout = 60 * time.Second
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: false,
					HasToken:      true,
					Redirects:     false,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
			AuthzPolicy: ``,
			StartOpa:    true,
		},
		{
			Name: "TestOpaStopped",
			ProxySettings: func(conf *config.Config) {
				conf.EnableOpa = true
				conf.EnableDefaultDeny = true
				conf.OpaTimeout = 60 * time.Second
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: false,
					HasToken:      true,
					Redirects:     false,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
			AuthzPolicy: ``,
			StartOpa:    false,
		},
		{
			Name: "TestOpaLoginForbiddenWithoutTemplate",
			ProxySettings: func(conf *config.Config) {
				conf.EnableOpa = true
				conf.EnableDefaultDeny = true
				conf.OpaTimeout = 60 * time.Second
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: false,
					HasToken:      true,
					Redirects:     true,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Equal(t, "", body)
					},
				},
			},
			AuthzPolicy: ``,
			StartOpa:    true,
		},
		{
			Name: "TestOpaLoginForbiddenWithTemplate",
			ProxySettings: func(conf *config.Config) {
				conf.EnableOpa = true
				conf.EnableDefaultDeny = true
				conf.OpaTimeout = 60 * time.Second
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				//nolint:goconst
				conf.ForbiddenPage = "../../templates/forbidden.html.tmpl"
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: false,
					HasToken:      true,
					Redirects:     true,
					ExpectedCode:  http.StatusForbidden,
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "Permission Denied")
					},
				},
			},
			AuthzPolicy: ``,
			StartOpa:    true,
		},
		{
			Name: "TestOpaLogin",
			ProxySettings: func(conf *config.Config) {
				conf.EnableOpa = true
				conf.EnableDefaultDeny = true
				conf.OpaTimeout = 60 * time.Second
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:           FakeTestURL,
					ExpectedProxy: true,
					HasLogin:      true,
					OnResponse:    delay,
					Redirects:     true,
					ExpectedCode:  http.StatusOK,
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
				{
					URI:           FakeTestURL,
					ExpectedProxy: true,
					HasLogin:      false,
					Redirects:     false,
					ExpectedCode:  http.StatusOK,
					ExpectedContent: func(body string, _ int) {
						assert.Contains(t, body, "test")
						assert.Contains(t, body, "method")
					},
				},
			},
			AuthzPolicy: `
			package authz

			default allow := false

			allow if {
				input.method = "GET"
				input.path = FakeTestURL
			}
			`,
			StartOpa: true,
		},
	}

	for _, testCase := range requests {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				cfg := newFakeKeycloakConfig()
				testCase.ProxySettings(cfg)

				ctx := context.Background()
				authzPolicy := testCase.AuthzPolicy
				opaAddress := ""
				var server *opaserver.Server

				if testCase.StartOpa {
					server = authorization.StartOpaServer(ctx, t, authzPolicy)
					addrs := server.Addrs()
					opaAddress = addrs[0]
				}

				authzURI := fmt.Sprintf(
					"http://%s/%s",
					opaAddress,
					"v1/data/authz/allow",
				)
				authzURL, err := url.ParseRequestURI(authzURI)
				if err != nil {
					t.Fatalf("problem parsing authzURL")
				}

				cfg.OpaAuthzURL = authzURL

				p := newFakeProxy(cfg, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}

func TestAuthenticationMiddleware(t *testing.T) {
	tok := NewTestToken("example")
	tok.SetExpiration(time.Now().Add(-5 * time.Minute))
	unsignedToken, err := tok.GetUnsignedToken()
	if err != nil {
		t.Fatal(err.Error())
	}

	badlySignedToken := unsignedToken + FakeSignature
	cfg := newFakeKeycloakConfig()

	requests := []struct {
		Name              string
		ProxySettings     func(c *config.Config)
		ExecutionSettings []fakeRequest
	}{
		{
			Name: "TestForgedExpiredTokenWithIdpSessionCheckDisabled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableIDPSessionCheck = false
				conf.EnableRefreshTokens = true
				conf.EncryptionKey = testEncryptionKey
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:               FakeAuthAllURL,
					HasLogin:          true,
					Redirects:         true,
					SkipClientIDCheck: true,
					SkipIssuerCheck:   true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{cfg.CookieAccessName: nil},
				},
				{
					URI:               FakeAuthAllURL,
					Redirects:         true,
					SkipClientIDCheck: true,
					SkipIssuerCheck:   true,
					HasLogin:          false,
					RawToken:          badlySignedToken,
					HasCookieToken:    true,
					ExpectedProxy:     false,
					ExpectedCode:      http.StatusForbidden,
				},
			},
		},
		{
			Name: "TestForgedExpiredTokenWithIdpSessionCheckEnabled",
			ProxySettings: func(conf *config.Config) {
				conf.EnableIDPSessionCheck = true
				conf.EnableRefreshTokens = true
				conf.EncryptionKey = testEncryptionKey
				conf.ClientID = ValidUsername
				conf.ClientSecret = ValidPassword
				conf.NoRedirects = false
			},
			ExecutionSettings: []fakeRequest{
				{
					URI:       FakeAuthAllURL,
					HasLogin:  true,
					Redirects: true,
					OnResponse: func(int, *resty.Request, *resty.Response) {
						<-time.After(time.Duration(int64(2500)) * time.Millisecond)
					},
					ExpectedProxy:                 true,
					ExpectedCode:                  http.StatusOK,
					ExpectedLoginCookiesValidator: map[string]func(*testing.T, *config.Config, string) bool{cfg.CookieAccessName: nil},
				},
				{
					URI:               FakeAuthAllURL,
					Redirects:         true,
					SkipClientIDCheck: true,
					SkipIssuerCheck:   true,
					HasLogin:          false,
					RawToken:          badlySignedToken,
					HasCookieToken:    true,
					ExpectedProxy:     false,
					ExpectedCode:      http.StatusForbidden,
				},
			},
		},
	}

	for _, testCase := range requests {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				cfg := newFakeKeycloakConfig()
				testCase.ProxySettings(cfg)
				p := newFakeProxy(cfg, &fakeAuthConfig{})
				p.RunTests(t, testCase.ExecutionSettings)
			},
		)
	}
}
