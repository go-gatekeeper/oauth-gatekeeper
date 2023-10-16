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
	ErrTooManyResources                = errors.New("too many resources got from IDP (hint: probably you have multiple resources in IDP with same path and scopes combination)")
	ErrResourceIDNotPresent            = errors.New("resource id not present in token permissions")
	ErrPermissionTicketForResourceID   = errors.New("problem getting permission ticket for resourceId")
	ErrRetrieveRPT                     = errors.New("problem getting RPT for resource (hint: do you have permissions assigned to resource?)")
	ErrAccessMismatchUmaToken          = errors.New("access token and uma token user ID don't match")
	ErrNoAuthzFound                    = errors.New("no authz found")
	ErrGetIdentityFromUMA              = errors.New("problem getting identity from uma token")
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

	// config errors

	ErrInvalidPostLoginRedirectPath            = errors.New("post login redirect path invalid, should be only path not absolute url (no hostname, scheme)")
	ErrPostLoginRedirectPathNoRedirectsInvalid = errors.New("post login redirect path can be enabled only with no-redirect=false")
	ErrMissingListenInterface                  = errors.New("you have not specified the listening interface")
	ErrAdminListenerScheme                     = errors.New("scheme for admin listener must be one of [http, https]")
	ErrInvalidIdpProviderProxyURI              = errors.New("invalid proxy address for IDP provider proxy")
	ErrInvalidMaxIdleConnections               = errors.New("max-idle-connections must be a number > 0")
	ErrInvalidMaxIdleConnsPerHost              = errors.New(
		"maxi-idle-connections-per-host must be a " +
			"number > 0 and <= max-idle-connections",
	)
	ErrInvalidSameSiteCookie                 = errors.New("same-site-cookie must be one of Strict|Lax|None")
	ErrMissingPrivateKey                     = errors.New("you have not provided a private key")
	ErrMissingCert                           = errors.New("you have not provided a certificate file")
	ErrMissingAdminEndpointPrivateKey        = errors.New("you have not provided a private key for admin endpoint")
	ErrMissingAdminEndpointCert              = errors.New("you have not provided a certificate file for admin endpoint")
	ErrMissingLetsEncryptCacheDir            = errors.New("the letsencrypt cache dir has not been set")
	ErrMinimalTLSVersionEmpty                = errors.New("minimal TLS version should not be empty")
	ErrInvalidMinimalTLSVersion              = errors.New("invalid minimal TLS version specified")
	ErrInvalidForwardTLSCertOpt              = errors.New("you don't need to specify a tls-certificate, use tls-ca-certificate instead")
	ErrInvalidForwardTLSKeyOpt               = errors.New("you don't need to specify the tls-private-key, use tls-ca-key instead")
	ErrRedundantRedirectURIinForwardAuthMode = errors.New(
		"when in forward-auth mode = " +
			"noproxy=true with noredirect=false, redirectionURL " +
			"should not be set, will be composed from X-FORWARDED-* headers",
	)
	ErrMissingUpstream                   = errors.New("you have not specified an upstream endpoint to proxy to")
	ErrMissingClientID                   = errors.New("you have not specified the client id")
	ErrMissingDiscoveryURI               = errors.New("you have not specified the discovery url")
	ErrMissingForwardUser                = errors.New("no forwarding username")
	ErrMissingForwardPass                = errors.New("no forwarding password")
	ErrMissingClientSecret               = errors.New("you have not specified the client secret")
	ErrSecFilterDisabledForHTTPSRedirect = errors.New(
		"the security filter must be switch on for this feature: http-redirect",
	)
	ErrSecFilterDisabledForXSSFilter = errors.New(
		"the security filter must be switch on for this feature: browser-xss-filter",
	)
	ErrSecFilterDisabledForFrameDenyFilter = errors.New(
		"the security filter must be switch on " +
			"for this feature: frame-deny-filter",
	)
	ErrSecFilterDisabledForCSPFilter = errors.New(
		"the security filter must be switch on " +
			"for this feature: content-security-policy",
	)
	ErrSecFilterDisabledForHostnames = errors.New(
		"the security filter must be switch on for this feature: hostnames",
	)
	ErrMissingEncryptionKey = errors.New(
		"you have not specified an encryption key for encoding the access token",
	)
	ErrMissingEncryptionKeyForRefreshTokens = errors.New(
		"enable refresh tokens requires encryption key to be defined",
	)
	ErrSecureCookieWithNonTLSRedirectionURI = errors.New(
		"the cookie is set to secure but your redirection url is non-tls",
	)
	ErrTooManyExtAuthzEnabled = errors.New(
		"only one type of external authz can be enabled at once",
	)
	ErrMissingClientCredsWithUMA = errors.New("enable uma requires client credentials")
	ErrTooManyDefaultDenyOpts    = errors.New(
		"only one of enable-default-deny/enable-default-deny-strict can be true",
	)
)
