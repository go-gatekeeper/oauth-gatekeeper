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

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Nerzal/gocloak/v13"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

/*
	authorizationMiddleware is responsible for verifying permissions in access_token/uma_token
*/
//nolint:cyclop
func authorizationMiddleware(
	logger *zap.Logger,
	enableUma bool,
	enableUmaMethodScope bool,
	cookieUMAName string,
	noProxy bool,
	pat *PAT,
	oidcProvider *oidc3.Provider,
	idpClient *gocloak.GoCloak,
	openIDProviderTimeout time.Duration,
	realm string,
	enableEncryptedToken bool,
	forceEncryptedCookie bool,
	encryptionKey string,
	cookManager *cookie.Manager,
	enableOpa bool,
	opaTimeout time.Duration,
	opaAuthzURL *url.URL,
	discoveryURI *url.URL,
	clientID string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (string, error),
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}

			if scope.AccessDenied {
				next.ServeHTTP(wrt, req)
				return
			}

			scope.Logger.Debug("authorization middleware")

			user := scope.Identity
			var provider authorization.Provider
			var decision authorization.AuthzDecision
			var err error

			scope.Logger.Debug("query external authz provider for authz")

			if enableUma {
				var methodScope *string
				if enableUmaMethodScope {
					methSc := constant.UmaMethodScope + req.Method
					if noProxy {
						xForwardedMethod := req.Header.Get(constant.HeaderXForwardedMethod)
						if xForwardedMethod == "" {
							scope.Logger.Error(apperrors.ErrForwardAuthMissingHeaders.Error())
							accessForbidden(wrt, req)
							return
						}
						methSc = constant.UmaMethodScope + xForwardedMethod
					}
					methodScope = &methSc
				}

				authzPath := req.URL.Path
				if noProxy {
					authzPath = req.Header.Get(constant.HeaderXForwardedURI)
					if authzPath == "" {
						scope.Logger.Error(apperrors.ErrForwardAuthMissingHeaders.Error())
						accessForbidden(wrt, req)
						return
					}
				}

				authzFunc := func(
					targetPath string,
					userPerms models.Permissions,
				) (authorization.AuthzDecision, error) {
					pat.m.RLock()
					token := pat.Token.AccessToken
					pat.m.RUnlock()
					provider = authorization.NewKeycloakAuthorizationProvider(
						userPerms,
						targetPath,
						idpClient,
						openIDProviderTimeout,
						token,
						realm,
						methodScope,
					)
					return provider.Authorize()
				}

				decision, err = WithUMAIdentity(
					req,
					authzPath,
					user,
					cookieUMAName,
					oidcProvider,
					clientID,
					skipClientIDCheck,
					skipIssuerCheck,
					getIdentity,
					authzFunc,
				)
				if err != nil {
					var umaUser *models.UserContext
					scope.Logger.Error(err.Error())
					scope.Logger.Info("trying to get new uma token")

					umaUser, err = refreshUmaToken(
						req.Context(),
						pat,
						idpClient,
						realm,
						authzPath,
						user,
						methodScope,
					)
					if err == nil {
						umaToken := umaUser.RawToken
						if enableEncryptedToken || forceEncryptedCookie {
							if umaToken, err = encryption.EncodeText(umaToken, encryptionKey); err != nil {
								scope.Logger.Error(err.Error())
								accessForbidden(wrt, req)
								return
							}
						}

						cookManager.DropUMATokenCookie(req, wrt, umaToken, time.Until(umaUser.ExpiresAt))
						wrt.Header().Set(constant.UMAHeader, umaToken)
						scope.Logger.Debug("got uma token")
						decision, err = authzFunc(authzPath, umaUser.Permissions)
					}
				}
			} else if enableOpa {
				// initially request Body is stream read from network connection,
				// when read once, it is closed, so second time we would not be able to
				// read it, so what we will do here is that we will read body,
				// create copy of original request and pass body which we already read
				// to original req and to new copy of request,
				// new copy will be passed to authorizer, which also needs to read body
				reqBody, varErr := io.ReadAll(req.Body)
				if varErr != nil {
					decision = authorization.DeniedAuthz
					err = varErr
				} else {
					req.Body.Close()
					passReq := *req
					passReq.Body = io.NopCloser(bytes.NewReader(reqBody))
					req.Body = io.NopCloser(bytes.NewReader(reqBody))

					provider = authorization.NewOpaAuthorizationProvider(
						opaTimeout,
						*opaAuthzURL,
						&passReq,
					)
					decision, err = provider.Authorize()
				}
			}

			switch {
			case errors.Is(err, apperrors.ErrPermissionNotInToken):
				scope.Logger.Info(apperrors.ErrPermissionNotInToken.Error())
			case errors.Is(err, apperrors.ErrResourceRetrieve):
				scope.Logger.Info(apperrors.ErrResourceRetrieve.Error())
			case errors.Is(err, apperrors.ErrNoIDPResourceForPath):
				scope.Logger.Info(apperrors.ErrNoIDPResourceForPath.Error())
			case errors.Is(err, apperrors.ErrResourceIDNotPresent):
				scope.Logger.Info(apperrors.ErrResourceIDNotPresent.Error())
			case errors.Is(err, apperrors.ErrTokenScopeNotMatchResourceScope):
				scope.Logger.Info(apperrors.ErrTokenScopeNotMatchResourceScope.Error())
			case errors.Is(err, apperrors.ErrNoAuthzFound):
			default:
				if err != nil {
					scope.Logger.Error(apperrors.ErrFailedAuthzRequest.Error(), zap.Error(err))
				}
			}

			scope.Logger.Info("authz decision", zap.String("decision", decision.String()))

			if decision == authorization.DeniedAuthz {
				if enableUma {
					prv, ok := provider.(*authorization.KeycloakAuthorizationProvider)
					if !ok {
						scope.Logger.Error(apperrors.ErrAssertionFailed.Error())
						accessForbidden(wrt, req)
						return
					}

					//nolint:contextcheck
					ticket, err := prv.GenerateUMATicket()
					if err != nil {
						scope.Logger.Error(err.Error())
					} else {
						permHeader := fmt.Sprintf(
							`realm="%s", as_uri="%s", ticket="%s"`,
							realm,
							discoveryURI.Host,
							ticket,
						)
						wrt.Header().Add(constant.UMATicketHeader, permHeader)
					}
				}
				accessForbidden(wrt, req)
				return
			}
			next.ServeHTTP(wrt, req)
		})
	}
}

func levelOfAuthenticationMiddleware(
	logger *zap.Logger,
	scopes []string,
	enablePKCE bool,
	signInPage string,
	cookManager *cookie.Manager,
	newOAuth2Config func(redirectionURL string) *oauth2.Config,
	getRedirectionURL func(wrt http.ResponseWriter, req *http.Request) string,
	customSignInPage func(wrt http.ResponseWriter, authURL string),
	resource *authorization.Resource,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {
			// we don't need to continue is a decision has been made
			scope, assertOk := req.Context().Value(constant.ContextScopeName).(*models.RequestScope)
			if !assertOk {
				logger.Error(apperrors.ErrAssertionFailed.Error())
				return
			}
			if scope.AccessDenied {
				next.ServeHTTP(wrt, req)
				return
			}

			user := scope.Identity
			lLog := scope.Logger.With(
				zap.String("middleware", "levelOfAuthentication"),
				zap.String("userID", user.ID),
				zap.String("resource", resource.URL),
			)
			if len(resource.Acr) > 0 && user.Acr == "" {
				lLog.Error("token is missing acr claim=level of authentication")
				accessForbidden(wrt, req)
				return
			}
			if len(resource.Acr) > 0 && !utils.HasAccess(
				resource.Acr,
				[]string{user.Acr},
				false,
			) {
				lLog.Info("token doesn't match required level of authentication")
				allowedQueryParams := map[string]string{"acr_values": resource.Acr[0]}
				defaultAllowedQueryParams := map[string]string{"acr_values": resource.Acr[0]}
				uuid := cookManager.DropStateParameterCookie(req, wrt)
				query := req.URL.Query()
				query.Add("state", uuid)
				req.URL.RawQuery = query.Encode()
				oauthAuthorizationHandler(
					lLog,
					scopes,
					enablePKCE,
					false,
					signInPage,
					"",
					cookManager,
					newOAuth2Config,
					getRedirectionURL,
					customSignInPage,
					nil,
					allowedQueryParams,
					defaultAllowedQueryParams,
				)(wrt, req)
				return
			}

			next.ServeHTTP(wrt, req)
		})
	}
}
