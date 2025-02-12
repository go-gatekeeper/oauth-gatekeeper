package testsuite_test

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	jose2 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/grokify/go-pkce"
	"github.com/jochasinga/relay"
)

type RoleClaim struct {
	Roles []string `json:"roles"`
}

type DefaultTestTokenClaims struct {
	Aud               string               `json:"aud"`
	Azp               string               `json:"azp"`
	ClientSession     string               `json:"client_session"`
	Email             string               `json:"email"`
	FamilyName        string               `json:"family_name"`
	GivenName         string               `json:"given_name"`
	Username          string               `json:"username"`
	Iat               int64                `json:"iat"`
	Iss               string               `json:"iss"`
	Jti               string               `json:"jti"`
	Name              string               `json:"name"`
	Nbf               int                  `json:"nbf"`
	Exp               int64                `json:"exp"`
	PreferredUsername string               `json:"preferred_username"`
	SessionState      string               `json:"session_state"`
	Sub               string               `json:"sub"`
	Typ               string               `json:"typ"`
	Groups            []string             `json:"groups"`
	RealmAccess       RoleClaim            `json:"realm_access"`
	ResourceAccess    map[string]RoleClaim `json:"resource_access"`
	Item              string               `json:"item"`
	Found             string               `json:"found"`
	Item1             []string             `json:"item1"`
	Item2             []string             `json:"item2"`
	Item3             []string             `json:"item3"`
	Authorization     models.Permissions   `json:"authorization"`
}

//nolint:gochecknoglobals
var defTestTokenClaims = DefaultTestTokenClaims{
	Aud:               "test",
	Azp:               "clientid",
	ClientSession:     "f0105893-369a-46bc-9661-ad8c747b1a69",
	Email:             "gambol99@gmail.com",
	FamilyName:        "Jayawardene",
	GivenName:         "Rohith",
	Username:          "Jayawardene",
	Iat:               DefaultIat,
	Iss:               "test",
	Jti:               "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
	Name:              "Rohith Jayawardene",
	Nbf:               0,
	Exp:               0,
	PreferredUsername: "rjayawardene",
	SessionState:      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
	Sub:               "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
	Typ:               "Bearer",
	Groups:            []string{"default"},
	RealmAccess:       RoleClaim{Roles: []string{"default"}},
	ResourceAccess: map[string]RoleClaim{
		"defaultclient": {
			Roles: []string{"default"},
		},
	},
	Item:  "item",
	Item1: []string{"default"},
	Item2: []string{"default"},
	Item3: []string{"default"},
}

type FakeToken struct {
	Claims DefaultTestTokenClaims
}

func NewTestToken(issuer string) *FakeToken {
	claims := defTestTokenClaims
	claims.Exp = time.Now().Add(1 * time.Hour).Unix()
	claims.Iat = time.Now().Unix()
	claims.Iss = issuer

	return &FakeToken{Claims: claims}
}

func (t *FakeToken) GetToken() (string, error) {
	input := []byte("")
	block, _ := pem.Decode([]byte(fakePrivateKey))
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS8PrivateKey(input)
	if err0 != nil {
		return "", err0
	}

	alg := jose2.SignatureAlgorithm("RS256")
	privKey := &jose2.JSONWebKey{Key: priv, Algorithm: string(alg), KeyID: "test-kid"}
	signer, err := jose2.NewSigner(jose2.SigningKey{Algorithm: alg, Key: privKey}, nil)
	if err != nil {
		return "", err
	}

	b := jwt.Signed(signer).Claims(&t.Claims)
	jwt, err := b.Serialize()
	if err != nil {
		return "", err
	}

	return jwt, nil
}

func (t *FakeToken) GetUnsignedToken() (string, error) {
	input := []byte("")
	block, _ := pem.Decode([]byte(fakePrivateKey))
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS8PrivateKey(input)

	if err0 != nil {
		return "", err0
	}

	alg := jose2.SignatureAlgorithm("RS256")
	privKey := &jose2.JSONWebKey{Key: priv, Algorithm: string(alg), KeyID: ""}
	signer, err := jose2.NewSigner(jose2.SigningKey{Algorithm: alg, Key: privKey}, nil)
	if err != nil {
		return "", err
	}

	b := jwt.Signed(signer).Claims(&t.Claims)
	jwt, err := b.Serialize()
	if err != nil {
		return "", err
	}

	items := strings.Split(jwt, ".")
	jwt = strings.Join(items[0:2], ".")

	return jwt, nil
}

func (t *FakeToken) SetExpiration(tm time.Time) {
	t.Claims.Exp = tm.Unix()
}

func (t *FakeToken) addGroups(groups []string) {
	t.Claims.Groups = groups
}

func (t *FakeToken) addRealmRoles(roles []string) {
	t.Claims.RealmAccess.Roles = roles
}

func (t *FakeToken) addClientRoles(client string, roles []string) {
	t.Claims.ResourceAccess = make(map[string]RoleClaim)
	t.Claims.ResourceAccess[client] = RoleClaim{Roles: roles}
}

type fakeAuthServer struct {
	location                  *url.URL
	proxyLocation             string
	key                       jose2.JSONWebKey
	server                    *httptest.Server
	expiration                time.Duration
	resourceSetHandlerFailure bool
	fakeAuthConfig            *fakeAuthConfig
	pkceChallenge             string
}

const fakePrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0E2cxe1nDLCE7
U4k3Zvd4nMiAHqKZBxCPuADbzR15IcOlcLTqBBPNCpwgXSZwobgeEl1aDi9fAsEK
XZNPU2GbIPmw5nBHfE/RZ5JmU2GXdEm2R2Irnwpi8kk8hHWPK4ETN8+6yk4qKF1P
xkoHIilm37T8zWoqzYtIuj3/Obqi3Io67pvKYCsA1qMR3RRlI9IegUAc3WHMrKIL
YQShEo66pg8cTb7Q/LdgaSxR3KLi9eox0vTE72AmVQoBZlZ/ej7sJpwPKKmkszXU
AMPGf1s3Hx/lgDtM3MxtHk0pxLBHgP+P5i77dF9edW9hc/fMirdOmCpYZboox3Lr
IGoVcJodAgMBAAECggEAahX4OEV0BzArT7kR4GqvpgWvdRMXNVHdJt3+237GO0Nx
8DgqzKakR6pVeheGeto7DrRA/LnYnH+R3Bpum1AC85IEp3vKb8LDfxkmPVQn7ULb
3h/FrO8f/lTAYn+ihjrZ6sl5fpCKZfmrp0CpAfTVMT7fcANP5XF7+deGiKKo2iJW
g1O8ZflihEDclPtqBABpRjBejRiv+7YUR/8HeqNUjmLEWGwAHEqrsFwMz92CvJd+
N9U03Cs1LvpXkIXHG84SUvbDQRuyxoONXKauasYr01kMFqBTjOc86xXSNsMWCzu4
UaWB1ZtMugNjyMNdVQUSLz1EABI4aQhWptmJud4LwQKBgQDuq3L3gOEaCmi4+46B
vnHdu0j6shULDdjxb4r8xY4tf4T8c+/4Lm/siM2+Fb+g01OECVRPVQlFd0inoTy+
j8ARveuRvrrGzAS5CB1tl+PiLJ5HbdltzTrV3ZUb99fvbnHAi7up7daZg9IBfc1n
ABWTA1pdOzK82g8qDeFBMSCJUQKBgQDBJsVvbheKL2xdKyIzd2je3gwInkYpAUqa
S9zS6h5wpG8TqFt90OYvmawyvTwspgp3nUUHTv9Z5FChFPgtoZJJO/0OYt6DjpUs
Ohg3DhthG5q6fG+kS2zGGHxQSCzQB6CvKdeZ5iMO/L0arKs9UuIdLV/SNfMdKm6v
8tdcYCdRDQKBgQC5cCzbcR91BDFpyMpotHf0N9f0MPl4pUGyFWCAFV7qqvHA1LPW
uP3tYj25O1ywsIFrTXRcT03s00l4NSblSPuKzW2CyBaG722b9lonFKTSzqgMB6Ww
Uo0sLgX0vRThy4ZGfEtLNKhQjsNUtVIqfT5GA4zqc1xwr1yo6C/kXy9QgQKBgQCX
Vh552WOeRNv9/+7TLms/u/Dny8MjG7ztOiVyKDfjgCL73vyYjtXcU+ak9rowLYSk
BdhxCoduUkKOg5SUhDTPJq522CaKI2xj87zHXkk7g9pu5VLAAszeRY8ZhAOAl4lh
1UH1dmjftE0imkmtScSaodOjK9wpbPa+62GsIjaL/QKBgFdwyRTp7GzbTDsQ94bA
u6MoFT7Ln2I48zaA07G76r9t3oOAsO8doED+hdSwlzA7RyM2l6jOkJli+NXmVA1G
eJN9LU6cvrgsyw2XF54Zi+sRdXb1LU9pVHcINIOwY7zNMvYRAkStkxhPXUDBinxo
wqVzh3GBBzPxAb3aM8Tu0W+1
-----END PRIVATE KEY-----
`

const fakeCert = `
-----BEGIN CERTIFICATE-----
MIIDXjCCAkagAwIBAgIUVUN+CQWv4afaLwWyBYA3hzYUK1UwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAzMTcyMzU2NDFaFw00MTAz
MTIyMzU2NDFaMHgxCzAJBgNVBAYTAlhYMQwwCgYDVQQIDANOL0ExDDAKBgNVBAcM
A04vQTEgMB4GA1UECgwXU2VsZi1zaWduZWQgY2VydGlmaWNhdGUxKzApBgNVBAMM
IjEyMC4wLjAuMTogU2VsZi1zaWduZWQgY2VydGlmaWNhdGUwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0E2cxe1nDLCE7U4k3Zvd4nMiAHqKZBxCPuADb
zR15IcOlcLTqBBPNCpwgXSZwobgeEl1aDi9fAsEKXZNPU2GbIPmw5nBHfE/RZ5Jm
U2GXdEm2R2Irnwpi8kk8hHWPK4ETN8+6yk4qKF1PxkoHIilm37T8zWoqzYtIuj3/
Obqi3Io67pvKYCsA1qMR3RRlI9IegUAc3WHMrKILYQShEo66pg8cTb7Q/LdgaSxR
3KLi9eox0vTE72AmVQoBZlZ/ej7sJpwPKKmkszXUAMPGf1s3Hx/lgDtM3MxtHk0p
xLBHgP+P5i77dF9edW9hc/fMirdOmCpYZboox3LrIGoVcJodAgMBAAGjEzARMA8G
A1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAIyJDSwNHcr6xstklu/K
HypaivAFa95eAI1QrCsJF1V/mm9LEEGes/iHbvkpFJHQKhJkO6aoQmek8zF2wKc/
3RhnxrR32/ujHetJFka/LtvytVhXoSqkUWeaXOfBOCR/XrwTwRHzbbCNJpUsetXr
9aeDvSrtuB/AaRU2tBlQ9GR1H+CcoBgDmD3IpuKCievvJbmU+KzuW9AUg6d0yLNP
2VtZUA/9JpF9PZOMPw+iOhmjhTqfRD2QvbkR7e34d+1mLBn524KIc8Y2U3OMpDuG
BfVHOQ5JhTNGn9aogxpzF3L9oMUZ+fCbobVyHMMyE6b82H8FUpm1FDJpZaILI5kT
isg=
-----END CERTIFICATE-----
`

const fakeCA = `
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUCDok30ZdCF+fn3KuK/odxYyqJR0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTAzMTcyMzM0MTZaFw00MTAz
MTIyMzM0MTZaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDVwtjZoJiDALDrovZviHWRhCgPXBxaLYoi5d3sa1UX
F28fEHHcqHChMHng0XmQDwBRvdGXfEL+d+TyOk6H2EfC5YzF4BFA9jEuX/xvINWd
STYFkq4uqjFVl5/1WA6fme0UfpIT+BNSqMufH1Q63rBMgZmQS10/mYBWMXzW9MpC
Mc/VqGiNfVD1fGf3d86gmteHPSR0yABeIyF3BhWkea50sNu7jz7Vw65OdAZxuw9W
o0UGT0Bc2ml8clnkhnXipvyYUJQqVgyCcFsI5rc5Gsie8rJ36LyZsf3nnGF56hjw
i49YmH3z0xl70XUIxkm2o2h55P5tgA5KauZB3v0mFuTxAgMBAAGjUzBRMB0GA1Ud
DgQWBBQ5Fw8voBMO1GoQl1Qqm5UdFzbuHDAfBgNVHSMEGDAWgBQ5Fw8voBMO1GoQ
l1Qqm5UdFzbuHDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDU
msNwnbl8uI4VcFsiyrNS7Np2xLmcs6LgCfP9WzsA4h6Ag2K15d9eh+CgaL59oza8
q0pxRcasLFtuk0egRc+HwNR5ynwt4W2al4zB1dRpTWgrnNaoOBdhsb3ifNEjFcYD
di+dPoKLST6xqKGh0zl+W4FLevUDg7KzJVcttaQ8tFh5KafcmSHZ7PfNbFsfbx/R
wthh/acHnCkOndcTBEoHdIv283bONr1Zpe9Sok2mM3uVsCvv6fRYnG+mRqcZ3C9d
hHbOowWOqA2rxWxSHrkBTQju/uYQKG5GMnXWgZokUgwRDMaNMpdp03GG4Bgeg/06
8cad+/Bp0tBaKmnCtxOC
-----END CERTIFICATE-----
`

type fakeOidcDiscoveryResponse struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

type fakeAuthConfig struct {
	DiscoveryURLPrefix        string
	Expiration                time.Duration
	EnablePKCE                bool
	EnableTLS                 bool
	EnableProxy               bool
	ResourceSetHandlerFailure bool
}

// newFakeAuthServer simulates a oauth service.
func newFakeAuthServer(config *fakeAuthConfig) *fakeAuthServer {
	certBlock, _ := pem.Decode([]byte(fakeCert))

	var cert *x509.Certificate
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		panic("failed to parse certificate from block, error: " + err.Error())
	}

	x5tSHA256 := sha256.Sum256(cert.Raw)

	service := &fakeAuthServer{
		fakeAuthConfig: config,
		key: jose2.JSONWebKey{
			Key:                         cert.PublicKey,
			KeyID:                       "test-kid",
			Algorithm:                   "RS256",
			Certificates:                []*x509.Certificate{cert},
			CertificateThumbprintSHA256: x5tSHA256[:],
		},
	}

	baseURI := config.DiscoveryURLPrefix + "/realms/hod-test"

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Get(baseURI+constant.IdpWellKnownURI, service.discoveryHandler)
	router.Get(baseURI+constant.IdpCertsURI, service.keysHandler)
	router.Get(baseURI+constant.IdpTokenURI, service.tokenHandler)
	router.Get(baseURI+constant.IdpAuthURI, service.authHandler)
	router.Get(baseURI+constant.IdpUserURI, service.userInfoHandler)
	router.Post(baseURI+constant.IdpLogoutURI, service.logoutHandler)
	router.Post(baseURI+constant.IdpRevokeURI, service.revocationHandler)
	router.Post(baseURI+constant.IdpTokenURI, service.tokenHandler)
	router.Get(baseURI+constant.IdpResourceSetURI, service.ResourcesHandler)
	router.Get(baseURI+constant.IdpResourceSetURI+"/{id}", service.ResourceHandler)
	router.Post(baseURI+constant.IdpProtectPermURI, service.PermissionTicketHandler)

	if config.EnableTLS {
		service.server = httptest.NewTLSServer(router)
	} else {
		service.server = httptest.NewServer(router)
	}

	if config.EnableProxy {
		delay := time.Duration(0) * time.Second
		proxy := relay.NewProxy(delay, service.server)
		service.proxyLocation = proxy.URL
	}

	location, err := url.Parse(service.server.URL)
	if err != nil {
		panic("unable to create fake oauth service, error: " + err.Error())
	}
	service.location = location
	service.resourceSetHandlerFailure = config.ResourceSetHandlerFailure

	service.expiration = time.Duration(1) * time.Hour

	if config.Expiration.Seconds() > 0 {
		service.expiration = config.Expiration
	}

	return service
}

func (r *fakeAuthServer) Close() {
	r.server.Close()
}

func (r *fakeAuthServer) getProxyURL() string {
	return r.proxyLocation
}

func (r *fakeAuthServer) getLocation() string {
	return fmt.Sprintf(
		"%s://%s%s/realms/hod-test",
		r.location.Scheme,
		r.location.Host,
		r.fakeAuthConfig.DiscoveryURLPrefix,
	)
}

func (r *fakeAuthServer) getRevocationURL() string {
	return fmt.Sprintf(
		"%s://%s%s/realms/hod-test/protocol/openid-connect/revoke",
		r.location.Scheme,
		r.location.Host,
		r.fakeAuthConfig.DiscoveryURLPrefix,
	)
}

func (r *fakeAuthServer) setTokenExpiration(tm time.Duration) {
	r.expiration = tm
}

func (r *fakeAuthServer) discoveryHandler(wrt http.ResponseWriter, _ *http.Request) {
	base := fmt.Sprintf(
		"%s://%s%s/realms/hod-test",
		r.location.Scheme,
		r.location.Host,
		r.fakeAuthConfig.DiscoveryURLPrefix,
	)
	baseWithProto := "/protocol/openid-connect"
	renderJSON(http.StatusOK, wrt, fakeOidcDiscoveryResponse{
		Issuer:      base,
		AuthURL:     base + baseWithProto + "/auth",
		TokenURL:    base + baseWithProto + "/token",
		JWKSURL:     base + baseWithProto + "/certs",
		UserInfoURL: base + baseWithProto + "/userinfo",
		Algorithms:  []string{"RS256"},
	})
}

func (r *fakeAuthServer) keysHandler(w http.ResponseWriter, _ *http.Request) {
	renderJSON(http.StatusOK, w, jose2.JSONWebKeySet{Keys: []jose2.JSONWebKey{r.key}})
}

func (r *fakeAuthServer) authHandler(wrt http.ResponseWriter, req *http.Request) {
	state := req.URL.Query().Get("state")
	redirect := req.URL.Query().Get("redirect_uri")

	if redirect == "" {
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	if r.fakeAuthConfig.EnablePKCE {
		codeChallenge := req.URL.Query().Get("code_challenge")
		codeChallengeMethod := req.URL.Query().Get("code_challenge_method")

		if codeChallenge == "" || codeChallengeMethod != "S256" {
			wrt.WriteHeader(http.StatusBadRequest)
			return
		}

		r.pkceChallenge = codeChallenge
	}

	if state == "" {
		state = "/"
	}

	randString, err := getRandomString(OAuthCodeLength)
	if err != nil {
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	redirectionURL := fmt.Sprintf("%s?state=%s&code=%s", redirect, state, randString)

	http.Redirect(wrt, req, redirectionURL, http.StatusSeeOther)
}

func (r *fakeAuthServer) logoutHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (r *fakeAuthServer) revocationHandler(wrt http.ResponseWriter, req *http.Request) {
	// according RFC revocation endpoint can be access/refresh token, keycloak
	// implementation https://github.com/keycloak/keycloak/pull/6704, accepts
	// refresh/offline tokens
	if token := req.FormValue("token"); token == "" {
		wrt.WriteHeader(http.StatusBadRequest)
		return
	}

	wrt.WriteHeader(http.StatusOK)
}

func (r *fakeAuthServer) userInfoHandler(wrt http.ResponseWriter, req *http.Request) {
	items := strings.Split(req.Header.Get(constant.AuthorizationHeader), " ")
	authItems := 2
	if len(items) != authItems {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := session.ExtractIdentity(items[1])
	if err != nil {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	if user.IsExpired() {
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	renderJSON(http.StatusOK, wrt, map[string]interface{}{
		"sub":                user.Claims["sub"],
		"name":               user.Claims["name"],
		"given_name":         user.Claims["given_name"],
		"family_name":        user.Claims["familty_name"],
		"preferred_username": user.Claims["preferred_username"],
		"email":              user.Claims["email"],
		"picture":            user.Claims["picture"],
	})
}

//nolint:cyclop
func (r *fakeAuthServer) tokenHandler(writer http.ResponseWriter, req *http.Request) {
	expires := time.Now().Add(r.expiration)
	refreshExpirationFactor := 2
	refreshExpires := time.Now().Add(time.Duration(refreshExpirationFactor) * r.expiration)
	token := NewTestToken(r.getLocation())
	token.SetExpiration(expires)
	refreshToken := NewTestToken(r.getLocation())
	refreshToken.SetExpiration(refreshExpires)
	refreshToken.Claims.Aud = defTestTokenClaims.Aud
	codeVerifier := ""

	if req.FormValue("grant_type") == configcore.GrantTypeUmaTicket {
		token.Claims.Authorization = models.Permissions{
			Permissions: []models.Permission{
				{
					Scopes:       []string{"test"},
					ResourceID:   "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
					ResourceName: "some",
				},
			},
		}
	}

	if r.fakeAuthConfig.EnablePKCE {
		codeVerifier = req.FormValue("code_verifier")
		if codeVerifier == "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// sign the token with the private key
	jwtAccess, err := token.GetToken()
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	// sign the token with the private key
	jwtRefresh, err := refreshToken.GetToken()
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch req.FormValue("grant_type") {
	case configcore.GrantTypeUserCreds:
		username := req.FormValue("username")
		password := req.FormValue("password")

		if username == "" || password == "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		if username == ValidUsername && password == ValidPassword {
			renderJSON(http.StatusOK, writer, models.TokenResponse{
				TokenType:    "Bearer",
				IDToken:      jwtAccess,
				AccessToken:  jwtAccess,
				RefreshToken: jwtRefresh,
				ExpiresIn:    float64(expires.UTC().Second()),
			})
			return
		}

		renderJSON(http.StatusUnauthorized, writer, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid user credentials",
		})
	case configcore.GrantTypeClientCreds:
		clientID := req.FormValue("client_id")
		clientSecret := req.FormValue("client_secret")

		if clientID == "" || clientSecret == "" {
			u, p, ok := req.BasicAuth()
			clientID = u
			clientSecret = p

			if clientID == "" || clientSecret == "" || !ok {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		if clientID == ValidUsername && clientSecret == ValidPassword {
			renderJSON(http.StatusOK, writer, models.TokenResponse{
				TokenType:    "Bearer",
				IDToken:      jwtAccess,
				AccessToken:  jwtAccess,
				RefreshToken: jwtRefresh,
				ExpiresIn:    float64(expires.UTC().Second()),
			})
			return
		}

		renderJSON(http.StatusUnauthorized, writer, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid client credentials",
		})
	case configcore.GrantTypeRefreshToken:
		oldRefreshToken, err := jwt.ParseSigned(req.FormValue("refresh_token"), constant.SignatureAlgs[:])
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		stdClaims := &jwt.Claims{}

		err = oldRefreshToken.UnsafeClaimsWithoutVerification(stdClaims)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		expiration := time.Until(stdClaims.Expiry.Time())

		if expiration <= 0 {
			type ExpiredRefresh struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}

			expRefresh := ExpiredRefresh{"invalid_grant", "Token is not active"}
			respBody, err := json.Marshal(expRefresh)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}

			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write(respBody)

			return
		}

		renderJSON(http.StatusOK, writer, models.TokenResponse{
			TokenType:   "Bearer",
			IDToken:     jwtAccess,
			AccessToken: jwtAccess,
			ExpiresIn:   float64(expires.Second()),
		})
	case configcore.GrantTypeAuthCode:
		if r.fakeAuthConfig.EnablePKCE {
			codeChallenge := pkce.CodeChallengeS256(codeVerifier)
			if codeChallenge != r.pkceChallenge {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		}

		renderJSON(http.StatusOK, writer, models.TokenResponse{
			TokenType:    "Bearer",
			IDToken:      jwtAccess,
			AccessToken:  jwtAccess,
			RefreshToken: jwtRefresh,
			ExpiresIn:    float64(expires.Second()),
		})
	case configcore.GrantTypeUmaTicket:
		renderJSON(http.StatusOK, writer, models.TokenResponse{
			TokenType:    "Bearer",
			IDToken:      jwtAccess,
			AccessToken:  jwtAccess,
			RefreshToken: jwtRefresh,
			ExpiresIn:    float64(expires.Second()),
		})
	default:
		writer.WriteHeader(http.StatusBadRequest)
	}
}

func (r *fakeAuthServer) ResourcesHandler(w http.ResponseWriter, _ *http.Request) {
	response := []string{"6ef1b62e-0fd4-47f2-81fc-eead97a01c22"}
	renderJSON(http.StatusOK, w, response)
}

func (r *fakeAuthServer) ResourceHandler(wrt http.ResponseWriter, _ *http.Request) {
	if r.resourceSetHandlerFailure {
		renderJSON(http.StatusNotFound, wrt, []string{})
	}

	type Resource struct {
		Name               string              `json:"name"`
		Type               string              `json:"type"`
		Owner              struct{ ID string } `json:"owner"`
		OwnerManagedAccess bool                `json:"ownerManagedAccess"`
		Attributes         struct{}            `json:"attributes"`
		ID                 string              `json:"_id"`
		URIS               []string            `json:"uris"`
		ResourceScopes     []struct {
			Name string `json:"name"`
		} `json:"resource_scopes"`
		Scopes []struct {
			Name string `json:"name"`
		} `json:"scopes"`
	}

	response := Resource{
		Name:               "Default Resource",
		Type:               "urn:test-client:resources:default",
		Owner:              struct{ ID string }{ID: "6ef1b62e-0fd4-47f2-81fc-eead97a01c22"},
		OwnerManagedAccess: false,
		Attributes:         struct{}{},
		ID:                 "6ef1b62e-0fd4-47f2-81fc-eead97a01c22",
		URIS:               []string{"/*"},
		ResourceScopes: []struct {
			Name string `json:"name"`
		}{{Name: "test"}},
		Scopes: []struct {
			Name string `json:"name"`
		}{{Name: "test"}},
	}
	renderJSON(http.StatusOK, wrt, response)
}

func (r *fakeAuthServer) PermissionTicketHandler(wrt http.ResponseWriter, _ *http.Request) {
	token := NewTestToken(r.getLocation())
	acc, err := token.GetToken()
	if err != nil {
		wrt.WriteHeader(http.StatusInternalServerError)
		return
	}

	type Ticket struct {
		Ticket string `json:"ticket"`
	}

	response := Ticket{
		Ticket: acc,
	}
	renderJSON(http.StatusOK, wrt, response)
}

func getRandomString(n int) (string, error) {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	runes := make([]rune, n)
	for idx := range runes {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if err != nil {
			return "", err
		}

		runes[idx] = letterRunes[num.Int64()]
	}
	return string(runes), nil
}

func renderJSON(code int, w http.ResponseWriter, data interface{}) {
	w.Header().Set(constant.HeaderContentType, "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
