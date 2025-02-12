//go:build !e2e
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

//nolint:testpackage
package config

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
)

const (
	fakeAdminRoleURL      = "/admin*"
	fakeAdminRole         = "role:admin"
	fakeTestAdminRolesURL = "/test_admin_roles"
	fakeTestRole          = "role:test"
)

func TestNewDefaultConfig(t *testing.T) {
	if config := NewDefaultConfig(); config == nil {
		t.Error("we should have received a config")
	}
}

func TestReadConfiguration(t *testing.T) {
	testCases := []struct {
		Content string
		Ok      bool
	}{
		{
			Content: `
discovery-url: https://keyclock.domain.com/
client-id: <client_id>
client-secret: <secret>
`,
		},
		{
			Content: `
discovery-url: https://keyclock.domain.com
client-id: <client_id>
client-secret: <secret>
upstream-url: http://127.0.0.1:8080
redirection-url: http://127.0.0.1:3000
`,
			Ok: true,
		},
	}

	for idx, test := range testCases {
		// step: write the fake config file
		file := core.WriteFakeConfigFile(t, test.Content)

		config := new(Config)
		err := config.ReadConfigFile(file.Name())

		if config.ClientID != "<client_id>" || config.ClientSecret != "<secret>" {
			os.Remove(file.Name())
			t.Errorf(
				"seems that test case %d doesn't read data properly, config: %v",
				idx,
				config,
			)
		}

		if test.Ok && err != nil {
			os.Remove(file.Name())
			t.Errorf(
				"test case %d should not have failed, config: %v, error: %s",
				idx,
				config,
				err,
			)
		}
		os.Remove(file.Name())
	}
}

func TestIsConfig(t *testing.T) {
	tests := []struct {
		Config *Config
		Ok     bool
	}{
		{
			Config: &Config{},
		},
		{
			Config: &Config{
				DiscoveryURL: "http://127.0.0.1:8080",
			},
		},
		{
			Config: &Config{
				DiscoveryURL: "http://127.0.0.1:8080",
				ClientID:     "client",
				ClientSecret: "client",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				TLSMinVersion:       constant.TLS12,
			},
			Ok: true,
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        0,
				MaxIdleConnsPerHost: 0,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 200,
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
				MatchClaims: map[string]string{
					"test": "&&&[",
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "this should fail",
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "http://120.0.0.1",
				Upstream:            "this should fail",
				SecureCookie:        true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
			},
		},
		{
			Config: &Config{
				Listen:              ":8080",
				DiscoveryURL:        "http://127.0.0.1:8080",
				ClientID:            "client",
				ClientSecret:        "client",
				RedirectionURL:      "https://120.0.0.1",
				Upstream:            "http://someupstream",
				SecureCookie:        true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				TLSMinVersion:       constant.TLS13,
			},
			Ok: true,
		},
	}

	for i, c := range tests {
		if err := c.Config.IsValid(); err != nil && c.Ok {
			t.Errorf("test case %d, the config should not have errored, error: %s", i, err)
		}
	}
}

func TestIsListenValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidListen",
			Config: &Config{
				Listen: ":8080",
			},
			Valid: true,
		},
		{
			Name: "InValidListen",
			Config: &Config{
				Listen: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isListenValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsListenAdminSchemeValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "HTTPValidListenAdminScheme",
			Config: &Config{
				ListenAdminScheme: constant.UnsecureScheme,
			},
			Valid: true,
		},
		{
			Name: "HTTPSValidListenAdminScheme",
			Config: &Config{
				ListenAdminScheme: constant.SecureScheme,
			},
			Valid: true,
		},
		{
			Name: "InValidListenAdminScheme",
			Config: &Config{
				Listen: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isListenAdminSchemeValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsOpenIDProviderProxyValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidOpenIDProviderProxy",
			Config: &Config{
				OpenIDProviderProxy: "http://aklsdsdo",
			},
			Valid: true,
		},
		{
			Name: "ValidOpenIDProviderProxyValidEmpty",
			Config: &Config{
				OpenIDProviderProxy: "",
			},
			Valid: true,
		},
		{
			Name: "InValidOpenIDProviderProxyValidInvalidURI",
			Config: &Config{
				OpenIDProviderProxy: "asas",
			},
			Valid: false,
		},
		{
			Name: "ValidSkipOpenIDProviderTLSVerify",
			Config: &Config{
				OpenIDProviderProxy:         "http://ssss",
				SkipOpenIDProviderTLSVerify: true,
			},
			Valid: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isOpenIDProviderProxyValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsMaxIdlleConnValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidMaxIdleConns",
			Config: &Config{
				MaxIdleConns: 50,
			},
			Valid: true,
		},
		{
			Name: "ValidMaxIdleConnsPerHost",
			Config: &Config{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 30,
			},
			Valid: true,
		},
		{
			Name: "NegativeInValidMaxIdleConns",
			Config: &Config{
				MaxIdleConns: -1,
			},
			Valid: false,
		},
		{
			Name: "NegativeInValidMaxIdleConnsPerHost",
			Config: &Config{
				MaxIdleConnsPerHost: -1,
			},
			Valid: false,
		},
		{
			Name: "GreaterThanMaxIdleConnsInValidMaxIdleConnsPerHost",
			Config: &Config{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 100,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isMaxIdlleConnValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsSameSiteValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "EmptyValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: "",
			},
			Valid: true,
		},
		{
			Name: "StrictValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: constant.SameSiteStrict,
			},
			Valid: true,
		},
		{
			Name: "LaxValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: constant.SameSiteLax,
			},
			Valid: true,
		},
		{
			Name: "NoneValidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: constant.SameSiteNone,
			},
			Valid: true,
		},
		{
			Name: "InvalidSameSiteCookie",
			Config: &Config{
				SameSiteCookie: "scrambled",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isSameSiteValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

//nolint:cyclop
func TestIsTLSFilesValid(t *testing.T) {
	testCases := []struct {
		Name                       string
		Config                     *Config
		Valid                      bool
		TLSCertificateExists       bool
		TLSClientCertificateExists bool
		TLSPrivateKeyExists        bool
		TLSCaCertificateExists     bool
	}{
		{
			Name: "ValidPrivateAndCertificate",
			Config: &Config{
				//nolint:gosec
				TLSCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSPrivateKey: fmt.Sprintf(os.TempDir()+"/gateconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                      true,
			TLSCertificateExists:       true,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        true,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateFile",
			Config: &Config{
				//nolint:gosec
				TLSCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSPrivateKey: fmt.Sprintf(os.TempDir()+"/gateconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       true,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivate",
			Config: &Config{
				//nolint:gosec
				TLSCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_crt_%d", rand.IntN(10000)),
				TLSPrivateKey:  "",
			},
			Valid:                      false,
			TLSCertificateExists:       true,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificateFile",
			Config: &Config{
				//nolint:gosec
				TLSCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSPrivateKey: fmt.Sprintf(os.TempDir()+"/gateconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        true,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificate",
			Config: &Config{
				TLSCertificate: "",
				//nolint:gosec
				TLSPrivateKey: fmt.Sprintf(os.TempDir()+"/gateconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        true,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateAndCertificateFile",
			Config: &Config{
				//nolint:gosec
				TLSCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSPrivateKey: fmt.Sprintf(os.TempDir()+"/gateconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "ValidCaCertificate",
			Config: &Config{
				//nolint:gosec
				TLSCaCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_ca_%d", rand.IntN(10000)),
			},
			Valid:                      true,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     true,
		},
		{
			Name: "InValidMissingCaCertificateFile",
			Config: &Config{
				//nolint:gosec
				TLSCaCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_ca_%d", rand.IntN(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "ValidClientCertificate",
			Config: &Config{
				//nolint:gosec
				TLSClientCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_client_%d", rand.IntN(10000)),
			},
			Valid:                      true,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: true,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
		{
			Name: "InvalidValidMissingClientCertificate",
			Config: &Config{
				//nolint:gosec
				TLSClientCertificate: fmt.Sprintf(os.TempDir()+"/gateconfig_client_%d", rand.IntN(10000)),
			},
			Valid:                      false,
			TLSCertificateExists:       false,
			TLSClientCertificateExists: false,
			TLSPrivateKeyExists:        false,
			TLSCaCertificateExists:     false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				certFile := ""
				clientCertFile := ""
				privFile := ""
				caFile := ""
				cfg := testCase.Config

				if cfg.TLSCertificate != "" {
					certFile = cfg.TLSCertificate
				}

				if cfg.TLSClientCertificate != "" {
					clientCertFile = cfg.TLSClientCertificate
				}

				if cfg.TLSPrivateKey != "" {
					privFile = cfg.TLSPrivateKey
				}

				if cfg.TLSCaCertificate != "" {
					caFile = cfg.TLSCaCertificate
				}

				if certFile != "" && testCase.TLSCertificateExists {
					err := os.WriteFile(
						certFile,
						[]byte(""),
						0o600,
					)
					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if clientCertFile != "" && testCase.TLSClientCertificateExists {
					err := os.WriteFile(clientCertFile, []byte(""), 0o600)
					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" && testCase.TLSPrivateKeyExists {
					err := os.WriteFile(privFile, []byte(""), 0o600)
					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" && testCase.TLSCaCertificateExists {
					err := os.WriteFile(caFile, []byte(""), 0o600)
					if err != nil {
						t.Fatalf("Problem writing cacertificate %s", err)
					}
					defer os.Remove(caFile)
				}

				err := testCase.Config.isTLSFilesValid()

				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

//nolint:cyclop
func TestIsAdminTLSFilesValid(t *testing.T) {
	testCases := []struct {
		Name                            string
		Config                          *Config
		Valid                           bool
		TLSAdminCertificateExists       bool
		TLSAdminClientCertificateExists bool
		TLSAdminPrivateKeyExists        bool
		TLSAdminCaCertificateExists     bool
	}{
		{
			Name: "ValidPrivateAndCertificate",
			Config: &Config{
				//nolint:gosec
				TLSAdminCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSAdminPrivateKey: fmt.Sprintf(os.TempDir()+"/gateadminconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                           true,
			TLSAdminCertificateExists:       true,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        true,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateFile",
			Config: &Config{
				//nolint:gosec
				TLSAdminCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSAdminPrivateKey: fmt.Sprintf(os.TempDir()+"/gateadminconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       true,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivate",
			Config: &Config{
				//nolint:gosec
				TLSAdminCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_crt_%d", rand.IntN(10000)),
				TLSAdminPrivateKey:  "",
			},
			Valid:                           false,
			TLSAdminCertificateExists:       true,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificateFile",
			Config: &Config{
				//nolint:gosec
				TLSAdminCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSAdminPrivateKey: fmt.Sprintf(os.TempDir()+"/gateadminconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        true,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingCertificate",
			Config: &Config{
				TLSAdminCertificate: "",
				//nolint:gosec
				TLSAdminPrivateKey: fmt.Sprintf(os.TempDir()+"/gateadminconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        true,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InValidMissingPrivateAndCertificateFile",
			Config: &Config{
				//nolint:gosec
				TLSAdminCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_crt_%d", rand.IntN(10000)),
				//nolint:gosec
				TLSAdminPrivateKey: fmt.Sprintf(os.TempDir()+"/gateadminconfig_priv_%d", rand.IntN(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "ValidCaCertificate",
			Config: &Config{
				//nolint:gosec
				TLSAdminCaCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_ca_%d", rand.IntN(10000)),
			},
			Valid:                           true,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     true,
		},
		{
			Name: "InValidMissingCaCertificateFile",
			Config: &Config{
				//nolint:gosec
				TLSAdminCaCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_ca_%d", rand.IntN(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "ValidClientCertificate",
			Config: &Config{
				//nolint:gosec
				TLSAdminClientCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_client_%d", rand.IntN(10000)),
			},
			Valid:                           true,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: true,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
		{
			Name: "InvalidValidMissingClientCertificate",
			Config: &Config{
				//nolint:gosec
				TLSAdminClientCertificate: fmt.Sprintf(os.TempDir()+"/gateadminconfig_client_%d", rand.IntN(10000)),
			},
			Valid:                           false,
			TLSAdminCertificateExists:       false,
			TLSAdminClientCertificateExists: false,
			TLSAdminPrivateKeyExists:        false,
			TLSAdminCaCertificateExists:     false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				certFile := ""
				clientCertFile := ""
				privFile := ""
				caFile := ""
				cfg := testCase.Config

				if cfg.TLSAdminCertificate != "" {
					certFile = cfg.TLSAdminCertificate
				}

				if cfg.TLSAdminClientCertificate != "" {
					clientCertFile = cfg.TLSAdminClientCertificate
				}

				if cfg.TLSAdminPrivateKey != "" {
					privFile = cfg.TLSAdminPrivateKey
				}

				if cfg.TLSAdminCaCertificate != "" {
					caFile = cfg.TLSAdminCaCertificate
				}

				if certFile != "" && testCase.TLSAdminCertificateExists {
					err := os.WriteFile(certFile, []byte(""), 0o600)
					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if clientCertFile != "" && testCase.TLSAdminClientCertificateExists {
					err := os.WriteFile(clientCertFile, []byte(""), 0o600)
					if err != nil {
						t.Fatalf("Problem writing certificate %s", err)
					}
					defer os.Remove(certFile)
				}

				if privFile != "" && testCase.TLSAdminPrivateKeyExists {
					err := os.WriteFile(privFile, []byte(""), 0o600)
					if err != nil {
						t.Fatalf("Problem writing privateKey %s", err)
					}
					defer os.Remove(privFile)
				}

				if caFile != "" && testCase.TLSAdminCaCertificateExists {
					err := os.WriteFile(caFile, []byte(""), 0o600)
					if err != nil {
						t.Fatalf("Problem writing cacertificate %s", err)
					}
					defer os.Remove(caFile)
				}

				err := testCase.Config.isAdminTLSFilesValid()

				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsLetsEncryptValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "NotUseValidUseLetsEncrypt",
			Config: &Config{
				UseLetsEncrypt: false,
			},
			Valid: true,
		},
		{
			Name: "ValidUseLetsEncryptWithCacheDir",
			Config: &Config{
				UseLetsEncrypt:      true,
				LetsEncryptCacheDir: "/somedir",
			},
			Valid: true,
		},
		{
			Name: "InvalidUseLetsEncrypt",
			Config: &Config{
				UseLetsEncrypt:      true,
				LetsEncryptCacheDir: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isLetsEncryptValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsForwardingProxySettingsValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidForwardingProxySettings",
			Config: &Config{
				EnableForwarding:      true,
				PatRetryCount:         5,
				PatRetryInterval:      2 * time.Second,
				OpenIDProviderTimeout: 30 * time.Second,
				ClientID:              "some-client",
				DiscoveryURL:          "https://somediscoveryurl",
				ForwardingGrantType:   core.GrantTypeUserCreds,
				ForwardingUsername:    "someuser",
				ForwardingPassword:    "somepass",
			},
			Valid: true,
		},
		{
			Name: "ValidForwardingProxySettingsDisabledForwarding",
			Config: &Config{
				EnableForwarding: false,
			},
			Valid: true,
		},
		{
			Name: "InValidForwardingProxySettingsMissingClientID",
			Config: &Config{
				EnableForwarding:      true,
				PatRetryCount:         5,
				PatRetryInterval:      2 * time.Second,
				OpenIDProviderTimeout: 30 * time.Second,
				ClientID:              "",
				DiscoveryURL:          "https://somediscoveryurl",
				ForwardingGrantType:   core.GrantTypeUserCreds,
				ForwardingUsername:    "someuser",
				ForwardingPassword:    "somepass",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingProxySettingsRedundantTLSCertificate",
			Config: &Config{
				EnableForwarding:      true,
				PatRetryCount:         5,
				PatRetryInterval:      2 * time.Second,
				OpenIDProviderTimeout: 30 * time.Second,
				ClientID:              "some-client",
				DiscoveryURL:          "https://somediscoveryurl",
				ForwardingGrantType:   core.GrantTypeUserCreds,
				ForwardingUsername:    "someuser",
				ForwardingPassword:    "somepass",
				TLSCertificate:        "/sometest",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingProxySettingsRedundantTLSPrivateKey",
			Config: &Config{
				EnableForwarding:      true,
				PatRetryCount:         5,
				PatRetryInterval:      2 * time.Second,
				OpenIDProviderTimeout: 30 * time.Second,
				ClientID:              "some-client",
				DiscoveryURL:          "https://somediscoveryurl",
				ForwardingGrantType:   core.GrantTypeUserCreds,
				ForwardingUsername:    "someuser",
				ForwardingPassword:    "somepass",
				TLSPrivateKey:         "/sometest",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isForwardingProxySettingsValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsReverseProxySettingsValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidReverseProxySettings",
			Config: &Config{
				EnableForwarding: false,
				ClientID:         "some-client",
				DiscoveryURL:     "https://somediscoveryurl",
				Upstream:         "https://test.com",
			},
			Valid: true,
		},
		{
			Name: "ValidReverseProxySettingsDisabled",
			Config: &Config{
				EnableForwarding:      true,
				PatRetryCount:         5,
				PatRetryInterval:      2 * time.Second,
				OpenIDProviderTimeout: 30 * time.Second,
			},
			Valid: true,
		},
		{
			Name: "InValidReverseProxySettings",
			Config: &Config{
				EnableForwarding: false,
				ClientID:         "some-client",
				DiscoveryURL:     "https://somediscoveryurl",
				Upstream:         "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isReverseProxySettingsValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsTokenVerificationSettingsValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidTokenVerificationSettings",
			Config: &Config{
				ClientID:     "some-client",
				DiscoveryURL: "https://somediscoveryurl",
			},
			Valid: true,
		},
		{
			Name: "InValidTokenVerificationSettings",
			Config: &Config{
				ClientID:            "some-client",
				DiscoveryURL:        "https://somediscoveryurl",
				EnableRefreshTokens: true,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isTokenVerificationSettingsValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsTLSMinValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "InvalidEmptyTLS",
			Config: &Config{
				TLSMinVersion: "",
			},
			Valid: false,
		},
		{
			Name: "ValidTLS1.0",
			Config: &Config{
				TLSMinVersion: "tlsv1.0",
			},
			Valid: false,
		},
		{
			Name: "ValidTLS1.1",
			Config: &Config{
				TLSMinVersion: "tlsv1.1",
			},
			Valid: false,
		},
		{
			Name: "ValidTLS1.2",
			Config: &Config{
				TLSMinVersion: constant.TLS12,
			},
			Valid: true,
		},
		{
			Name: "ValidTLS1.3",
			Config: &Config{
				TLSMinVersion: constant.TLS13,
			},
			Valid: true,
		},
		{
			Name: "InvalidTLS",
			Config: &Config{
				TLSMinVersion: "tlsv1.4",
			},
			Valid: false,
		},
		{
			Name: "InvalidTLS",
			Config: &Config{
				TLSMinVersion: "eddredd",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isTLSMinValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsNoProxyValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidNoProxy",
			Config: &Config{
				NoProxy:     true,
				NoRedirects: true,
			},
			Valid: true,
		},
		{
			Name: "ValidNoProxy",
			Config: &Config{
				NoProxy:     true,
				NoRedirects: false,
			},
			Valid: true,
		},
		{
			Name: "InValidNoProxy",
			Config: &Config{
				NoProxy:        true,
				NoRedirects:    false,
				RedirectionURL: "http://some",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isNoProxyValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsUpstreamValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidUpstream",
			Config: &Config{
				Upstream: "http://aklsdsdo",
			},
			Valid: true,
		},
		{
			Name: "InValidUpstreamEmpty",
			Config: &Config{
				Upstream: "",
			},
			Valid: false,
		},
		{
			Name: "InValidUpstreamInvalidURI",
			Config: &Config{
				Upstream: "asas",
			},
			Valid: false,
		},
		{
			Name: "InValidSkipUpstreamTLSVerify",
			Config: &Config{
				Upstream:              "http://ssss",
				SkipUpstreamTLSVerify: true,
				UpstreamCA:            "/ssss",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isUpstreamValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsUpstreamProxyValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidUpstream",
			Config: &Config{
				UpstreamProxy: "http://aklsdsdo",
			},
			Valid: true,
		},
		{
			Name: "ValidUpstreamEmpty",
			Config: &Config{
				UpstreamProxy: "",
			},
			Valid: true,
		},
		{
			Name: "InValidUpstreamInvalidURI",
			Config: &Config{
				UpstreamProxy: "asas",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isUpstreamProxyValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsClientIDValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidClientID",
			Config: &Config{
				ClientID: "some-client",
			},
			Valid: true,
		},
		{
			Name: "InValidClientID",
			Config: &Config{
				ClientID: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isClientIDValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsDiscoveryURLValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidDiscoveryURL",
			Config: &Config{
				DiscoveryURL: "someurl",
			},
			Valid: true,
		},
		{
			Name: "InValidDiscoveryURL",
			Config: &Config{
				DiscoveryURL: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isDiscoveryURLValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsForwardingGrantValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidForwardingcore.GrantTypeUserCreds",
			Config: &Config{
				ForwardingGrantType: core.GrantTypeUserCreds,
				ForwardingUsername:  "someuser",
				ForwardingPassword:  "somepass",
			},
			Valid: true,
		},
		{
			Name: "InValidForwardingcore.GrantTypeUserCredsMissingUsername",
			Config: &Config{
				ForwardingGrantType: core.GrantTypeUserCreds,
				ForwardingUsername:  "",
				ForwardingPassword:  "somepass",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingcore.GrantTypeUserCredsMissingPassword",
			Config: &Config{
				ForwardingGrantType: core.GrantTypeUserCreds,
				ForwardingUsername:  "",
				ForwardingPassword:  "somepass",
			},
			Valid: false,
		},
		{
			Name: "InValidForwardingcore.GrantTypeUserCredsBoth",
			Config: &Config{
				ForwardingGrantType: core.GrantTypeUserCreds,
				ForwardingUsername:  "",
				ForwardingPassword:  "",
			},
			Valid: false,
		},
		{
			Name: "ValidForwardingGrantTypeClientCreds",
			Config: &Config{
				ForwardingGrantType: core.GrantTypeClientCreds,
				ClientSecret:        "somesecret",
			},
			Valid: true,
		},
		{
			Name: "InValidForwardingGrantTypeClientCreds",
			Config: &Config{
				ForwardingGrantType: core.GrantTypeClientCreds,
				ClientSecret:        "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isForwardingGrantValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsSecurityFilterValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidSecurityFilterSettings",
			Config: &Config{
				EnableHTTPSRedirect:    true,
				EnableBrowserXSSFilter: true,
				EnableFrameDeny:        true,
				ContentSecurityPolicy:  "default-src 'self'",
				Hostnames:              []string{"test"},
				EnableSecurityFilter:   true,
			},
			Valid: true,
		},
		{
			Name: "InValidSecurityFilterSettingsEnableHTTPSRedirect",
			Config: &Config{
				EnableHTTPSRedirect:  true,
				EnableSecurityFilter: false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsEnableBrowserXSSFilter",
			Config: &Config{
				EnableBrowserXSSFilter: true,
				EnableSecurityFilter:   false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsEnableFrameDeny",
			Config: &Config{
				EnableFrameDeny:      true,
				EnableSecurityFilter: false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsContentSecurityPolicy",
			Config: &Config{
				ContentSecurityPolicy: "default-src 'self'",
				EnableSecurityFilter:  false,
			},
			Valid: false,
		},
		{
			Name: "InValidSecurityFilterSettingsContentSecurityPolicy",
			Config: &Config{
				Hostnames:            []string{"test"},
				EnableSecurityFilter: false,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isSecurityFilterValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsTokenEncryptionValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidTokenEncryptionSettings",
			Config: &Config{
				EnableEncryptedToken: true,
				ForceEncryptedCookie: true,
				EncryptionKey:        "sdkljfalisujeoir",
				EnableRefreshTokens:  true,
			},
			Valid: true,
		},
		{
			Name: "InValidTokenEncryptionEncryptedTokenMissingEncryptionKey",
			Config: &Config{
				EnableEncryptedToken: true,
				ForceEncryptedCookie: true,
				EncryptionKey:        "",
			},
			Valid: false,
		},
		{
			Name: "InValidTokenEncryptionForceEncryptedCookieMissingEncryptionKey",
			Config: &Config{
				ForceEncryptedCookie: true,
				EncryptionKey:        "",
			},
			Valid: false,
		},
		{
			Name: "InValidTokenEncryptionEnableRefreshTokensMissingEncryptionKey",
			Config: &Config{
				EnableRefreshTokens: true,
				EncryptionKey:       "",
			},
			Valid: false,
		},
		{
			Name: "InValidTokenEncryptionEnableRefreshTokensInvalidEncryptionKey",
			Config: &Config{
				EnableRefreshTokens: true,
				EncryptionKey:       "ssdsds",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isTokenEncryptionValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsSecureCookieValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidSecureCookie",
			Config: &Config{
				NoRedirects:    false,
				SecureCookie:   true,
				RedirectionURL: "https://someredirectionurl",
			},
			Valid: true,
		},
		{
			Name: "InValidSecureCookie",
			Config: &Config{
				NoRedirects:    false,
				SecureCookie:   true,
				RedirectionURL: "http://someredirectionurl",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isSecureCookieValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsStoreURLValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidIsStoreURL",
			Config: &Config{
				StoreURL: "redis://user:secret@localhost:6379/4?protocol=3",
			},
			Valid: true,
		},
		{
			Name: "InValidIsStoreURL",
			Config: &Config{
				StoreURL: "kwoie",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isStoreURLValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsResourceValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidResource",
			Config: &Config{
				Resources: []*authorization.Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "ValidResourceWithCustomHTTP",
			Config: &Config{
				CustomHTTPMethods: []string{"SOME"},
				Resources: []*authorization.Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"SOME"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: true,
		},
		{
			Name: "InValidResourceWithCustomHTTP",
			Config: &Config{
				Resources: []*authorization.Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"SOMER"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: false,
		},
		{
			Name: "InValidResourceMissingURL",
			Config: &Config{
				Resources: []*authorization.Resource{
					{
						URL:     "",
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     fakeTestAdminRolesURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: false,
		},
		{
			Name: "InValidResourceDefaultDenyWhitelistConflict",
			Config: &Config{
				EnableDefaultDeny: true,
				Resources: []*authorization.Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:         constant.AllPath,
						WhiteListed: true,
						Methods:     []string{"GET"},
						Roles:       []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: false,
		},
		{
			Name: "InValidResourceDefaultDenyUserDefinedConflict",
			Config: &Config{
				EnableDefaultDeny: true,
				Resources: []*authorization.Resource{
					{
						URL:     fakeAdminRoleURL,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole},
					},
					{
						URL:     constant.AllPath,
						Methods: []string{"GET"},
						Roles:   []string{fakeAdminRole, fakeTestRole},
					},
				},
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isResourceValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsMatchClaimValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidMatchClaim",
			Config: &Config{
				MatchClaims: map[string]string{
					"test": "/some[0-9]/",
				},
			},
			Valid: true,
		},
		{
			Name: "InValidMatchClaim",
			Config: &Config{
				MatchClaims: map[string]string{
					"test": "&&&[",
				},
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isMatchClaimValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestExternalAuthzValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidEnableUma",
			Config: &Config{
				EnableUma:    true,
				ClientID:     "test",
				ClientSecret: "test",
				NoRedirects:  true,
			},
			Valid: true,
		},
		{
			Name: "ConflictIdpSessionCheckEnableUma",
			Config: &Config{
				EnableUma:             true,
				ClientID:              "test",
				ClientSecret:          "test",
				NoRedirects:           true,
				EnableIDPSessionCheck: true,
			},
			Valid: false,
		},
		{
			Name: "MissingClientID",
			Config: &Config{
				EnableUma:    true,
				ClientID:     "",
				ClientSecret: "test",
			},
			Valid: false,
		},
		{
			Name: "MissingClientSecret",
			Config: &Config{
				EnableUma:    true,
				ClientID:     "test",
				ClientSecret: "",
			},
			Valid: false,
		},
		{
			Name: "TwoExternalAuthzEnabled",
			Config: &Config{
				EnableUma:    true,
				EnableOpa:    true,
				ClientID:     "test",
				ClientSecret: "",
			},
			Valid: false,
		},
		{
			Name: "ValidOpa",
			Config: &Config{
				EnableOpa:   true,
				OpaAuthzURI: "http://some/test",
			},
			Valid: true,
		},
		{
			Name: "InvalidOpa",
			Config: &Config{
				EnableOpa:   true,
				OpaAuthzURI: "",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isExternalAuthzValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestUpdateDiscoveryURI(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "OK",
			Config: &Config{
				DiscoveryURL: "http://127.0.0.1:8081/realms/test/.well-known/openid-configuration",
			},
			Valid: true,
		},
		{
			Name: "InValidDiscoveryURL",
			Config: &Config{
				DiscoveryURL: "://127.0.0.1:8081/realms/test/.well-known/openid-configuration",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.updateDiscoveryURI()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestExtractDiscoveryURIComponents(t *testing.T) {
	testCases := []struct {
		Name             string
		Config           *Config
		ExpectedRealm    string
		ExpectedIsLegacy bool
		Valid            bool
	}{
		{
			Name: "OK",
			Config: &Config{
				DiscoveryURI: &url.URL{
					Scheme: "http",
					Host:   "127.0.0.1",
					Path:   "/realms/test",
				},
			},
			ExpectedRealm:    "test",
			ExpectedIsLegacy: false,
			Valid:            true,
		},
		{
			Name: "OK",
			Config: &Config{
				DiscoveryURI: &url.URL{
					Scheme: "http",
					Host:   "127.0.0.1",
					Path:   "/realms/test",
				},
			},
			ExpectedRealm:    "test",
			ExpectedIsLegacy: false,
			Valid:            true,
		},
		{
			Name: "OK complex URI",
			Config: &Config{
				DiscoveryURI: &url.URL{
					Scheme: "http",
					Host:   "127.0.0.1",
					Path:   "/realms/custom-124_toto/.well-known/openid-configuration",
				},
			},
			ExpectedRealm:    "custom-124_toto",
			ExpectedIsLegacy: false,
			Valid:            true,
		},
		{
			Name: "OK Legacy well known",
			Config: &Config{
				DiscoveryURI: &url.URL{
					Scheme: "http",
					Host:   "127.0.0.1",
					Path:   "/auth/realms/test/.well-known/openid-configuration",
				},
			},
			ExpectedRealm:    "test",
			ExpectedIsLegacy: true,
			Valid:            true,
		},
		{
			Name: "InValidDiscoveryURL",
			Config: &Config{
				DiscoveryURI: &url.URL{
					Scheme: "http",
					Host:   "127.0.0.1",
					Path:   "/realms",
				},
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.extractDiscoveryURIComponents()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}

				if err == nil && testCase.Valid {
					if testCase.Config.Realm != testCase.ExpectedRealm {
						t.Fatalf(
							"Realm does not match, expected: %s, got: %s",
							testCase.ExpectedRealm,
							testCase.Config.Realm,
						)
					}

					if testCase.Config.IsDiscoverURILegacy != testCase.ExpectedIsLegacy {
						t.Fatalf(
							"IsDiscoverURILegacy does not match, expected: %t, got: %t",
							testCase.ExpectedIsLegacy,
							testCase.Config.IsDiscoverURILegacy,
						)
					}
				}
			},
		)
	}
}

func TestDefaultDenyValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidDefaultDeny",
			Config: &Config{
				EnableDefaultDeny: true,
				ClientID:          "test",
				ClientSecret:      "test",
				NoRedirects:       true,
			},
			Valid: true,
		},
		{
			Name: "ValidDefaultDenyStrict",
			Config: &Config{
				EnableDefaultDenyStrict: true,
				ClientID:                "test",
				ClientSecret:            "test",
				NoRedirects:             true,
			},
			Valid: true,
		},
		{
			Name: "InvalidDefaultDeny",
			Config: &Config{
				EnableDefaultDenyStrict: true,
				EnableDefaultDeny:       true,
				ClientID:                "test",
				ClientSecret:            "test",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isDefaultDenyValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsPKCEValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidEnablePKCE",
			Config: &Config{
				EnablePKCE:  true,
				NoRedirects: false,
			},
			Valid: true,
		},
		{
			Name: "InvalidEnablePKCE",
			Config: &Config{
				EnablePKCE:  true,
				NoRedirects: true,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isPKCEValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsPostLoginRedirectValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "OK",
			Config: &Config{
				PostLoginRedirectPath: "/some/path",
			},
			Valid: true,
		},
		{
			Name: "OK complex URI",
			Config: &Config{
				PostLoginRedirectPath: "/some/path?someparam=lala",
			},
			Valid: true,
		},
		{
			Name: "InvalidPostLoginRedirectPath",
			Config: &Config{
				PostLoginRedirectPath: "http://somehost/some/path",
			},
			Valid: false,
		},
		{
			Name: "InvalidCombinationPostLoginRedirectPathWithNoRedirects",
			Config: &Config{
				PostLoginRedirectPath: "/some/path",
				NoRedirects:           true,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isPostLoginRedirectValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsEnableHmacValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidEnableHmac",
			Config: &Config{
				EncryptionKey: "sdkljfalisujeoir",
				EnableHmac:    true,
			},
			Valid: true,
		},
		{
			Name: "MissinEncryptionKey",
			Config: &Config{
				EncryptionKey: "",
				EnableHmac:    true,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isEnableHmacValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsPostLogoutRedirectURIValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidIsPostLogoutRedirectURIValid",
			Config: &Config{
				EnableIDTokenCookie:   true,
				PostLogoutRedirectURI: "http://tata.com",
			},
			Valid: true,
		},
		{
			Name: "MissingIDTokenIsPostLogoutRedirectURIValid",
			Config: &Config{
				EnableIDTokenCookie:   false,
				PostLogoutRedirectURI: "http://tata.com",
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isPostLogoutRedirectURIValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsAllowedQueryParamsValid(t *testing.T) {
	testCases := []struct {
		Name           string
		Config         *Config
		Valid          bool
		ExptectedError error
	}{
		{
			Name: "AllowedQueryParamsValidValid",
			Config: &Config{
				AllowedQueryParams: map[string]string{"this": "that"},
				NoRedirects:        false,
			},
			Valid: true,
		},
		{
			Name: "AllowedQueryParamsValidWithNoRedirectsInvalid",
			Config: &Config{
				AllowedQueryParams: map[string]string{"this": "that"},
				NoRedirects:        true,
			},
			Valid:          false,
			ExptectedError: apperrors.ErrAllowedQueryParamsWithNoRedirects,
		},
		{
			Name: "DefaultAllowedQueryParamsValidWithNoRedirectsInvalid",
			Config: &Config{
				DefaultAllowedQueryParams: map[string]string{"this": "that"},
				NoRedirects:               true,
			},
			Valid:          false,
			ExptectedError: apperrors.ErrAllowedQueryParamsWithNoRedirects,
		},
		{
			Name: "DefaultAllowedQueryParamsWithEmptyValueInvalid",
			Config: &Config{
				AllowedQueryParams:        map[string]string{"this": "that"},
				DefaultAllowedQueryParams: map[string]string{"this": ""},
				NoRedirects:               false,
			},
			Valid:          false,
			ExptectedError: apperrors.ErrDefaultAllowedQueryParamEmpty,
		},
		{
			Name: "MoreDefaultParamsThanAllowedInvalid",
			Config: &Config{
				AllowedQueryParams:        map[string]string{"this": "that"},
				DefaultAllowedQueryParams: map[string]string{"this": "that", "thiiiis": "thoose"},
				NoRedirects:               false,
			},
			Valid:          false,
			ExptectedError: apperrors.ErrTooManyDefaultAllowedQueryParams,
		},
		{
			Name: "DefaultParamsDoesNotMatchAllowedInvalid",
			Config: &Config{
				AllowedQueryParams:        map[string]string{"this": "that"},
				DefaultAllowedQueryParams: map[string]string{"this": "thatt"},
				NoRedirects:               false,
			},
			Valid:          false,
			ExptectedError: apperrors.ErrDefaultQueryParamNotAllowed,
		},
		{
			Name: "DefaultParamsDoesNotMatchAllowedValid",
			Config: &Config{
				AllowedQueryParams:        map[string]string{"this": ""},
				DefaultAllowedQueryParams: map[string]string{"this": "thatt"},
				NoRedirects:               false,
			},
			Valid: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isAllowedQueryParamsValid()
				if err != nil {
					if testCase.Valid {
						t.Fatalf("Expected test not to fail")
					}
					if !errors.Is(err, testCase.ExptectedError) {
						t.Fatalf("Exptected %s, got %s", testCase.ExptectedError, err)
					}
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestEnableLoa(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidEnabLoA",
			Config: &Config{
				EnableLoA:   true,
				NoRedirects: false,
			},
			Valid: true,
		},
		{
			Name: "InvalidWithNoRedirects",
			Config: &Config{
				EnableLoA:   true,
				NoRedirects: true,
			},
			Valid: false,
		},
		{
			Name: "InvalidWithEnableUMA",
			Config: &Config{
				EnableLoA: true,
				EnableUma: true,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isEnableLoAValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}

func TestIsCorsValid(t *testing.T) {
	testCases := []struct {
		Name   string
		Config *Config
		Valid  bool
	}{
		{
			Name: "ValidOrigin",
			Config: &Config{
				CorsOrigins:     []string{"example.com"},
				CorsCredentials: false,
			},
			Valid: true,
		},
		{
			Name: "InvalidOrigin",
			Config: &Config{
				CorsOrigins:     []string{"*"},
				CorsCredentials: true,
			},
			Valid: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				err := testCase.Config.isCorsValid()
				if err != nil && testCase.Valid {
					t.Fatalf("Expected test not to fail")
				}

				if err == nil && !testCase.Valid {
					t.Fatalf("Expected test to fail")
				}
			},
		)
	}
}
