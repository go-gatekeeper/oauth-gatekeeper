package apperrors

import (
	"errors"
)

var (
	ErrPermissionNotInToken            = errors.New("permissions missing in token")
	ErrResourceRetrieve                = errors.New("problem getting resources from IDP")
	ErrTokenScopeNotMatchResourceScope = errors.New("scopes in token doesn't match scopes in IDP resource")
	ErrMissingScopesForResource        = errors.New("missing scopes for resource in IDP provider")
	ErrNoIDPResourceForPath            = errors.New("could not find resource matching path")
	ErrResourceIDNotPresent            = errors.New("resource id not present in token permissions")
	ErrPermissionTicketForResourceID   = errors.New("problem getting permission ticket for resourceId")
	ErrRetrieveRPT                     = errors.New("problem getting RPT for resource (hint: do you have permissions assigned to resource?)")
	ErrAccessMismatchUmaToken          = errors.New("access token and uma token user ID don't match")
	ErrNoAuthzFound                    = errors.New("no authz found")
	ErrFailedAuthzRequest              = errors.New("unexpected error occurred during authz request")
	ErrSessionNotFound                 = errors.New("authentication session not found")
	ErrNoSessionStateFound             = errors.New("no session state found")
	ErrZeroLengthToken                 = errors.New("token has zero length")
	ErrInvalidSession                  = errors.New("invalid session identifier")
	ErrRefreshTokenExpired             = errors.New("refresh token has expired")
	ErrUMATokenExpired                 = errors.New("uma token expired")
	ErrTokenVerificationFailure        = errors.New("token verification failed")
	ErrDecryption                      = errors.New("failed to decrypt token")
	ErrDefaultDenyWhitelistConflict    = errors.New("you've asked for a default denial but whitelisted everything")
	ErrDefaultDenyUserDefinedConflict  = errors.New("you've enabled default deny and at the same time defined own rules for /*")
	ErrBadDiscoveryURIFormat           = errors.New("bad discovery url format")
	ErrForwardAuthMissingHeaders       = errors.New("seems you are using gatekeeper as forward-auth, but you don't forward X-FORWARDED-* headers from front proxy")
	ErrPKCEWithCodeOnly                = errors.New("pkce can be enabled only with no-redirect=false")
	ErrPKCECodeCreation                = errors.New("creation of code verifier failed")
	ErrPKCECookieEmpty                 = errors.New("seems that pkce code verifier cookie value is empty string")
)
