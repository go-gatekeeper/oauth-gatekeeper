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

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"

	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	proxycore "github.com/gogatekeeper/gatekeeper/pkg/proxy/core"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

// EmptyHandler is responsible for doing nothing.
func EmptyHandler(_ http.ResponseWriter, _ *http.Request) {}

// HealthHandler is a health check handler for the service.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(constant.VersionHeader, proxycore.GetVersion())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK\n"))
}

// DebugHandler is responsible for providing the pprof
//
//nolint:cyclop
func DebugHandler(writer http.ResponseWriter, req *http.Request) {
	const symbolProfile = "symbol"

	name := chi.URLParam(req, "name")

	switch req.Method {
	case http.MethodGet:
		switch name {
		case "heap":
			fallthrough
		case "goroutine":
			fallthrough
		case "block":
			fallthrough
		case "threadcreate":
			pprof.Handler(name).ServeHTTP(writer, req)
		case "cmdline":
			pprof.Cmdline(writer, req)
		case "profile":
			pprof.Profile(writer, req)
		case "trace":
			pprof.Trace(writer, req)
		case symbolProfile:
			pprof.Symbol(writer, req)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	case http.MethodPost:
		switch name {
		case symbolProfile:
			pprof.Symbol(writer, req)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}
}

func MethodNotAllowHandlder(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write(nil)
}

// ProxyMetricsHandler forwards the request into the prometheus handler.
func ProxyMetricsHandler(
	localhostMetrics bool,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
	metricsHandler http.Handler,
) func(wrt http.ResponseWriter, req *http.Request) {
	return func(wrt http.ResponseWriter, req *http.Request) {
		if localhostMetrics {
			if !net.ParseIP(utils.RealIP(req)).IsLoopback() {
				accessForbidden(wrt, req)
				return
			}
		}
		metricsHandler.ServeHTTP(wrt, req)
	}
}

// RetrieveIDToken retrieves the id token from cookie.
func RetrieveIDToken(
	cookieIDTokenName string,
	enableEncryptedToken bool,
	forceEncryptedCookie bool,
	encryptionKey string,
	req *http.Request,
) (string, string, error) {
	var token string
	var err error
	var encrypted string

	token, err = session.GetTokenInCookie(req, cookieIDTokenName)
	if err != nil {
		return token, "", err
	}

	if enableEncryptedToken || forceEncryptedCookie {
		encrypted = token
		token, err = encryption.DecodeText(token, encryptionKey)
	}

	return token, encrypted, err
}

// discoveryHandler provides endpoint info.
func DiscoveryHandler(
	logger *zap.Logger,
	withOAuthURI func(string) string,
) func(wrt http.ResponseWriter, _ *http.Request) {
	return func(wrt http.ResponseWriter, _ *http.Request) {
		resp := &models.DiscoveryResponse{
			ExpiredURL: withOAuthURI(constant.ExpiredURL),
			LogoutURL:  withOAuthURI(constant.LogoutURL),
			TokenURL:   withOAuthURI(constant.TokenURL),
			LoginURL:   withOAuthURI(constant.LoginURL),
		}

		respBody, err := json.Marshal(resp)
		if err != nil {
			logger.Error(
				apperrors.ErrMarshallDiscoveryResp.Error(),
				zap.String("error", err.Error()),
			)

			wrt.WriteHeader(http.StatusInternalServerError)
			return
		}

		wrt.Header().Set(constant.HeaderContentType, "application/json")
		wrt.WriteHeader(http.StatusOK)
		_, err = wrt.Write(respBody)
		if err != nil {
			logger.Error(
				apperrors.ErrDiscoveryResponseWrite.Error(),
				zap.String("error", err.Error()),
			)
		}
	}
}

// getRedirectionURL returns the redirectionURL for the oauth flow.
func GetRedirectionURL(
	logger *zap.Logger,
	redirectionURL string,
	noProxy bool,
	noRedirects bool,
	secureCookie bool,
	cookieOAuthStateName string,
	withOAuthURI func(string) string,
) func(wrt http.ResponseWriter, req *http.Request) string {
	return func(wrt http.ResponseWriter, req *http.Request) string {
		var redirect string

		switch redirectionURL {
		case "":
			var scheme string
			var host string

			if noProxy && !noRedirects {
				scheme = req.Header.Get(constant.HeaderXForwardedProto)
				host = req.Header.Get(constant.HeaderXForwardedHost)
			} else {
				// need to determine the scheme, cx.Request.URL.Scheme doesn't have it, best way is to default
				// and then check for TLS
				scheme = constant.UnsecureScheme
				host = req.Host
				if req.TLS != nil {
					scheme = constant.SecureScheme
				}
			}

			if scheme == constant.UnsecureScheme && secureCookie {
				hint := "you have secure cookie set to true but using http "
				hint += "use https or secure cookie false"
				logger.Warn(hint)
			}

			redirect = fmt.Sprintf("%s://%s", scheme, host)
		default:
			redirect = redirectionURL
		}

		state, _ := req.Cookie(cookieOAuthStateName)

		if state != nil && req.URL.Query().Get("state") != state.Value {
			logger.Error("state parameter mismatch")
			wrt.WriteHeader(http.StatusForbidden)
			return ""
		}

		return fmt.Sprintf("%s%s", redirect, withOAuthURI(constant.CallbackURL))
	}
}

// ExpirationHandler checks if the token has expired.
func ExpirationHandler(
	logger *zap.Logger,
	provider *oidc3.Provider,
	clientID string,
	skipAccessTokenClientIDCheck bool,
	skipAccessTokenIssuerCheck bool,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (string, error),
	cookieAccessName string,
) func(wrt http.ResponseWriter, req *http.Request) {
	return func(wrt http.ResponseWriter, req *http.Request) {
		token, err := getIdentity(req, cookieAccessName, "")
		if err != nil {
			wrt.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(
			req.Context(),
			constant.DefaultOpenIDProviderTimeout,
		)
		defer cancel()

		_, err = utils.VerifyToken(
			ctx,
			provider,
			token,
			clientID,
			skipAccessTokenClientIDCheck,
			skipAccessTokenIssuerCheck,
		)
		if err != nil {
			if strings.Contains(err.Error(), "token is expired") {
				wrt.WriteHeader(http.StatusUnauthorized)
				return
			}
			wrt.WriteHeader(http.StatusForbidden)
			return
		}

		user, err := session.ExtractIdentity(token)
		if err != nil {
			wrt.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Debug("found the user identity",
			zap.String("id", user.ID),
			zap.String("name", user.Name),
			zap.String("email", user.Email),
			zap.String("roles", strings.Join(user.Roles, ",")),
			zap.String("groups", strings.Join(user.Groups, ",")))

		wrt.WriteHeader(http.StatusOK)
	}
}

// TokenHandler display access token to screen.
func TokenHandler(
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (string, error),
	cookieAccessName string,
	accessError func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(wrt http.ResponseWriter, req *http.Request) {
	return func(wrt http.ResponseWriter, req *http.Request) {
		rawToken, err := getIdentity(req, cookieAccessName, "")
		if err != nil {
			accessError(wrt, req)
			return
		}

		token, err := jwt.ParseSigned(rawToken, constant.SignatureAlgs[:])
		if err != nil {
			accessError(wrt, req)
			return
		}

		jsonMap := make(map[string]interface{})
		err = token.UnsafeClaimsWithoutVerification(&jsonMap)
		if err != nil {
			accessError(wrt, req)
			return
		}

		result, err := json.Marshal(jsonMap)
		if err != nil {
			accessError(wrt, req)
			return
		}

		wrt.Header().Set(constant.HeaderContentType, "application/json")
		_, _ = wrt.Write(result)
	}
}
