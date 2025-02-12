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
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/cenkalti/backoff/v4"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
)

func getPAT(
	ctx context.Context,
	clientID string,
	clientSecret string,
	realm string,
	openIDProviderTimeout time.Duration,
	grantType string,
	idpClient *gocloak.GoCloak,
	forwardingUsername string,
	forwardingPassword string,
) (*gocloak.JWT, *jwt.Claims, error) {
	cntx, cancel := context.WithTimeout(
		ctx,
		openIDProviderTimeout,
	)
	defer cancel()

	var token *gocloak.JWT
	var err error

	switch grantType {
	case configcore.GrantTypeClientCreds:
		token, err = idpClient.LoginClient(
			cntx,
			clientID,
			clientSecret,
			realm,
		)
	case configcore.GrantTypeUserCreds:
		token, err = idpClient.Login(
			cntx,
			clientID,
			clientSecret,
			realm,
			forwardingUsername,
			forwardingPassword,
		)
	default:
		return nil, nil, apperrors.ErrInvalidGrantType
	}

	if err != nil {
		return nil, nil, err
	}

	parsedToken, err := jwt.ParseSigned(token.AccessToken, constant.SignatureAlgs[:])
	if err != nil {
		return nil, nil, err
	}

	stdClaims := &jwt.Claims{}
	err = parsedToken.UnsafeClaimsWithoutVerification(stdClaims)
	if err != nil {
		return nil, nil, err
	}

	return token, stdClaims, err
}

func refreshPAT(
	ctx context.Context,
	logger *zap.Logger,
	pat *PAT,
	clientID string,
	clientSecret string,
	realm string,
	openIDProviderTimeout time.Duration,
	patRetryCount int,
	patRetryInterval time.Duration,
	enableForwarding bool,
	forwardingGrantType string,
	idpClient *gocloak.GoCloak,
	forwardingUsername string,
	forwardingPassword string,
	done chan bool,
) error {
	initialized := false
	grantType := configcore.GrantTypeClientCreds

	if enableForwarding && forwardingGrantType == configcore.GrantTypeUserCreds {
		grantType = configcore.GrantTypeUserCreds
	}

	for {
		var token *gocloak.JWT
		var claims *jwt.Claims
		operation := func() error {
			var err error
			pCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			token, claims, err = getPAT(
				pCtx,
				clientID,
				clientSecret,
				realm,
				openIDProviderTimeout,
				grantType,
				idpClient,
				forwardingUsername,
				forwardingPassword,
			)
			return err
		}

		notify := func(err error, delay time.Duration) {
			logger.Error(
				err.Error(),
				zap.Duration("retry after", delay),
			)
		}

		bom := backoff.WithMaxRetries(
			backoff.NewConstantBackOff(patRetryInterval),
			//nolint:gosec
			uint64(patRetryCount),
		)
		boCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		box := backoff.WithContext(bom, boCtx)
		err := backoff.RetryNotify(operation, box, notify)
		if err != nil {
			return err
		}

		pat.m.Lock()
		pat.Token = token
		pat.m.Unlock()

		if !initialized {
			done <- true
			initialized = true
		}

		expiration := claims.Expiry.Time()
		refreshIn := utils.GetWithin(expiration, constant.PATRefreshInPercent)

		logger.Info(
			"waiting for access token expiration",
			zap.Float64("refresh_in", refreshIn.Seconds()),
		)

		refreshTimer := time.NewTimer(refreshIn)
		select {
		case <-ctx.Done():
			logger.Info("shutdown PAT refresh routine")
			refreshTimer.Stop()
			return nil
		case <-refreshTimer.C:
		}
	}
}

func WithUMAIdentity(
	req *http.Request,
	targetPath string,
	user *models.UserContext,
	cookieUMAName string,
	provider *oidc3.Provider,
	clientID string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (string, error),
	authzFunc func(targetPath string, userPerms models.Permissions) (authorization.AuthzDecision, error),
) (authorization.AuthzDecision, error) {
	token, err := getIdentity(req, cookieUMAName, constant.UMAHeader)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	_, err = utils.VerifyToken(
		req.Context(),
		provider,
		token,
		clientID,
		skipClientIDCheck,
		skipIssuerCheck,
	)
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return authorization.DeniedAuthz, apperrors.ErrUMATokenExpired
		}
		return authorization.DeniedAuthz, err
	}

	umaUser, err := session.ExtractIdentity(token)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	// make sure somebody doesn't sent one user access token
	// and others user valid uma token in one request
	if umaUser.ID != user.ID {
		return authorization.DeniedAuthz, apperrors.ErrAccessMismatchUmaToken
	}

	return authzFunc(targetPath, umaUser.Permissions)
}

// getRPT retrieves relaying party token.
func getRPT(
	ctx context.Context,
	pat *PAT,
	idpClient *gocloak.GoCloak,
	realm string,
	targetPath string,
	userToken string,
	methodScope *string,
) (*gocloak.JWT, error) {
	matchingURI := true
	resourceParam := gocloak.GetResourceParams{
		URI:         &targetPath,
		MatchingURI: &matchingURI,
		Scope:       methodScope,
	}

	pat.m.RLock()
	patTok := pat.Token.AccessToken
	pat.m.RUnlock()

	resources, err := idpClient.GetResourcesClient(
		ctx,
		patTok,
		realm,
		resourceParam,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%w %w",
			apperrors.ErrNoIDPResourceForPath,
			err,
		)
	}

	if len(resources) == 0 {
		return nil, apperrors.ErrNoIDPResourceForPath
	}
	if len(resources) > 1 {
		return nil, apperrors.ErrTooManyResources
	}

	resourceID := resources[0].ID
	resourceScopes := make([]string, 0)
	if len(*resources[0].ResourceScopes) == 0 {
		return nil, fmt.Errorf(
			"%w, resource: %s",
			apperrors.ErrMissingScopesForResource,
			*resourceID,
		)
	}

	if methodScope != nil {
		resourceScopes = append(resourceScopes, *methodScope)
	} else {
		for _, scope := range *resources[0].ResourceScopes {
			resourceScopes = append(resourceScopes, *scope.Name)
		}
	}

	permissions := []gocloak.CreatePermissionTicketParams{
		{
			ResourceID:     resourceID,
			ResourceScopes: &resourceScopes,
		},
	}

	permTicket, err := idpClient.CreatePermissionTicket(
		ctx,
		patTok,
		realm,
		permissions,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrPermissionTicketForResourceID.Error(),
			*resourceID,
			err,
		)
	}

	grantType := configcore.GrantTypeUmaTicket

	rptOptions := gocloak.RequestingPartyTokenOptions{
		GrantType: &grantType,
		Ticket:    permTicket.Ticket,
	}

	if userToken == "" {
		userToken = patTok
	}

	rpt, err := idpClient.GetRequestingPartyToken(ctx, userToken, realm, rptOptions)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrRetrieveRPT.Error(),
			*resourceID,
			err,
		)
	}

	return rpt, nil
}

func refreshUmaToken(
	ctx context.Context,
	pat *PAT,
	idpClient *gocloak.GoCloak,
	realm string,
	targetPath string,
	user *models.UserContext,
	methodScope *string,
) (*models.UserContext, error) {
	tok, err := getRPT(
		ctx,
		pat,
		idpClient,
		realm,
		targetPath,
		user.RawToken,
		methodScope,
	)
	if err != nil {
		return nil, err
	}

	umaUser, err := session.ExtractIdentity(tok.AccessToken)
	if err != nil {
		return nil, err
	}

	return umaUser, nil
}
