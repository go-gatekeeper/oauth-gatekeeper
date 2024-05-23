package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/Nerzal/gocloak/v12"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gogatekeeper/gatekeeper/pkg/keycloak/config"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type PAT struct {
	Token *gocloak.JWT
	m     sync.RWMutex
}

type RPT struct {
	Token string
	m     sync.RWMutex
}

// reverseProxy is a wrapper
type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

type OauthProxy struct {
	Provider          *oidc3.Provider
	Config            *config.Config
	Endpoint          *url.URL
	IdpClient         *gocloak.GoCloak
	Listener          net.Listener
	Log               *zap.Logger
	metricsHandler    http.Handler
	Router            http.Handler
	adminRouter       http.Handler
	Server            *http.Server
	Store             storage.Storage
	Upstream          reverseProxy
	pat               *PAT
	rpt               *RPT
	accessForbidden   func(wrt http.ResponseWriter, req *http.Request) context.Context
	accessError       func(wrt http.ResponseWriter, req *http.Request) context.Context
	customSignInPage  func(wrt http.ResponseWriter, authURL string)
	GetIdentity       func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error)
	Cm                *cookie.Manager
	WithOAuthURI      func(uri string) string
	getRedirectionURL func(wrt http.ResponseWriter, req *http.Request) string
	newOAuth2Config   func(redirectionURL string) *oauth2.Config
}
