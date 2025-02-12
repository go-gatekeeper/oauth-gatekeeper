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

package testsuite_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectToAuthorizationUnauthorized(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	requests := []fakeRequest{
		{
			URI:          FakeAdminURL,
			ExpectedCode: http.StatusUnauthorized,
			Redirects:    false,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestRedirectToAuthorization(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:              FakeAdminURL,
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
	}
	newFakeProxy(nil, &fakeAuthConfig{}).RunTests(t, requests)
}

func TestRedirectToAuthorizationWith303Enabled(t *testing.T) {
	cfg := newFakeKeycloakConfig()

	requests := []fakeRequest{
		{
			URI:              FakeAdminURL,
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state",
			ExpectedCode:     http.StatusSeeOther,
		},
	}
	newFakeProxy(cfg, &fakeAuthConfig{}).RunTests(t, requests)
}

func assertAlmostEquals(t *testing.T, expected time.Duration, actual time.Duration) {
	t.Helper()
	delta := expected - actual
	if delta < 0 {
		delta = -delta
	}
	assert.Less(t, delta, time.Duration(1)*time.Minute, "Diff should be less than a minute but delta is %s", delta)
}

func TestGetAccessCookieExpiration_NoExp(t *testing.T) {
	token, err := NewTestToken("foo").GetToken()
	require.NoError(t, err)
	c := newFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := newFakeProxy(c, &fakeAuthConfig{}).proxy
	duration := session.GetAccessCookieExpiration(proxy.Log, c.AccessTokenDuration, token)
	assertAlmostEquals(t, c.AccessTokenDuration, duration)
}

func TestGetAccessCookieExpiration_ZeroExp(t *testing.T) {
	ft := NewTestToken("foo")
	ft.SetExpiration(time.Unix(0, 0))
	token, err := ft.GetToken()
	require.NoError(t, err)
	c := newFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := newFakeProxy(c, &fakeAuthConfig{}).proxy
	duration := session.GetAccessCookieExpiration(proxy.Log, c.AccessTokenDuration, token)
	assert.Greater(t, duration, 0*time.Second, "duration should be positive")
	assertAlmostEquals(t, c.AccessTokenDuration, duration)
}

func TestGetAccessCookieExpiration_PastExp(t *testing.T) {
	ft := NewTestToken("foo")
	ft.SetExpiration(time.Now().AddDate(-1, 0, 0))
	token, err := ft.GetToken()
	require.NoError(t, err)
	c := newFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := newFakeProxy(c, &fakeAuthConfig{}).proxy
	duration := session.GetAccessCookieExpiration(proxy.Log, c.AccessTokenDuration, token)
	assertAlmostEquals(t, c.AccessTokenDuration, duration)
}

func TestGetAccessCookieExpiration_ValidExp(t *testing.T) {
	fToken := NewTestToken("foo")
	token, err := fToken.GetToken()
	require.NoError(t, err)
	c := newFakeKeycloakConfig()
	c.AccessTokenDuration = time.Duration(1) * time.Hour
	proxy := newFakeProxy(c, &fakeAuthConfig{}).proxy
	duration := session.GetAccessCookieExpiration(proxy.Log, c.AccessTokenDuration, token)
	expectedDuration := time.Until(time.Unix(fToken.Claims.Exp, 0))
	assertAlmostEquals(t, expectedDuration, duration)
}
