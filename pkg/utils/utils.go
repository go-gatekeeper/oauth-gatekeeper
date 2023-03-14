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

package utils

import (
	"bytes"
	cryptorand "crypto/rand"
	sha "crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/urfave/cli"
)

var (
	AllHTTPMethods = []string{
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	}
)

var (
	symbolsFilter = regexp.MustCompilePOSIX("[_$><\\[\\].,\\+-/'%^&*()!\\\\]+")
)

// getRequestHostURL returns the hostname from the request
func GetRequestHostURL(req *http.Request) string {
	scheme := constant.UnsecureScheme

	if req.TLS != nil {
		scheme = constant.SecureScheme
	}

	redirect := fmt.Sprintf("%s://%s",
		DefaultTo(req.Header.Get("X-Forwarded-Proto"), scheme),
		DefaultTo(req.Header.Get("X-Forwarded-Host"), req.Host))

	return redirect
}

// decodeKeyPairs converts a list of strings (key=pair) to a map
func DecodeKeyPairs(list []string) (map[string]string, error) {
	keyPairs := make(map[string]string)

	for _, pair := range list {
		items := strings.Split(pair, "=")

		if len(items) < 2 || items[0] == "" {
			return keyPairs, fmt.Errorf("invalid tag '%s' should be key=pair", pair)
		}

		keyPairs[items[0]] = strings.Join(items[1:], "=")
	}

	return keyPairs, nil
}

// IsValidHTTPMethod ensure this is a valid http method type
func IsValidHTTPMethod(method string) bool {
	for _, x := range AllHTTPMethods {
		if method == x {
			return true
		}
	}

	return false
}

// defaultTo returns the value of the default
func DefaultTo(v, d string) string {
	if v != "" {
		return v
	}

	return d
}

// fileExists check if a file exists
func FileExists(filename string) bool {
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// hasAccess checks we have all or any of the needed items in the list
func HasAccess(need, have []string, all bool) bool {
	if len(need) == 0 {
		return true
	}

	var matched int

	for _, x := range need {
		found := ContainedIn(x, have)

		switch found {
		case true:
			if !all {
				return true
			}
			matched++
		default:
			if all {
				return false
			}
		}
	}

	return matched > 0
}

// containedIn checks if a value in a list of a strings
func ContainedIn(value string, list []string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}

	return false
}

// containsSubString checks if substring exists
func ContainsSubString(value string, list []string) bool {
	for _, x := range list {
		if strings.Contains(value, x) {
			return true
		}
	}

	return false
}

// tryDialEndpoint dials the upstream endpoint via plain HTTP
func TryDialEndpoint(location *url.URL) (net.Conn, error) {
	switch dialAddress := DialAddress(location); location.Scheme {
	case constant.UnsecureScheme:
		return net.Dial("tcp", dialAddress)
	default:
		return tls.Dial("tcp", dialAddress, &tls.Config{
			Rand: cryptorand.Reader,
			//nolint:gas
			InsecureSkipVerify: true,
		})
	}
}

// isUpgradedConnection checks to see if the request is requesting
func IsUpgradedConnection(req *http.Request) bool {
	return req.Header.Get(constant.HeaderUpgrade) != ""
}

// transferBytes transfers bytes between the sink and source
func TransferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	return io.Copy(dest, src)
}

// tryUpdateConnection attempt to upgrade the connection to a http pdy stream
func TryUpdateConnection(req *http.Request, writer http.ResponseWriter, endpoint *url.URL) error {
	// step: dial the endpoint
	server, err := TryDialEndpoint(endpoint)

	if err != nil {
		return err
	}

	defer server.Close()

	// @check the the response writer implements the Hijack method
	hijacker, assertOk := writer.(http.Hijacker)

	if !assertOk {
		return fmt.Errorf("writer does not implement http.Hijacker method")
	}

	// @step: get the client connection object
	client, _, err := hijacker.Hijack()

	if err != nil {
		return err
	}

	defer client.Close()

	// step: write the request to upstream
	if err = req.Write(server); err != nil {
		return err
	}

	// @step: copy the data between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { _, _ = TransferBytes(server, client, &wg) }()
	go func() { _, _ = TransferBytes(client, server, &wg) }()
	wg.Wait()

	return nil
}

// dialAddress extracts the dial address from the url
func DialAddress(location *url.URL) string {
	items := strings.Split(location.Host, ":")

	if len(items) != 2 {
		switch location.Scheme {
		case constant.UnsecureScheme:
			return location.Host + ":80"
		default:
			return location.Host + ":443"
		}
	}

	return location.Host
}

// findCookie looks for a cookie in a list of cookies
func FindCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

// toHeader is a helper method to play nice in the headers
func ToHeader(v string) string {
	symbols := symbolsFilter.Split(v, -1)
	list := make([]string, 0, len(symbols))

	// step: filter out any symbols and convert to dashes
	for _, x := range symbols {
		list = append(list, Capitalize(x))
	}

	return strings.Join(list, "-")
}

// capitalize capitalizes the first letter of a word
func Capitalize(word string) string {
	if word == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(word)

	return string(unicode.ToUpper(r)) + word[n:]
}

// mergeMaps simples copies the keys from source to destination
func MergeMaps(dest, source map[string]string) map[string]string {
	for k, v := range source {
		dest[k] = v
	}

	return dest
}

// getWithin calculates a duration of x percent of the time period, i.e. something
// expires in 1 hours, get me a duration within 80%
func GetWithin(expires time.Time, within float64) time.Duration {
	left := expires.UTC().Sub(time.Now().UTC()).Seconds()

	if left <= 0 {
		return time.Duration(0)
	}

	seconds := int(left * within)

	return time.Duration(seconds) * time.Second
}

// getHashKey returns a hash of the encodes jwt token
func GetHashKey(token string) string {
	hash := sha.Sum512([]byte(token))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// printError display the command line usage and error
func PrintError(message string, args ...interface{}) *cli.ExitError {
	return cli.NewExitError(fmt.Sprintf("[error] "+message, args...), 1)
}

// realIP retrieves the client ip address from a http request
func RealIP(req *http.Request) string {
	rAddr := req.RemoteAddr

	if ip := req.Header.Get(constant.HeaderXForwardedFor); ip != "" {
		rAddr = strings.Split(ip, ", ")[0]
	} else if ip := req.Header.Get(constant.HeaderXRealIP); ip != "" {
		rAddr = ip
	} else {
		rAddr, _, _ = net.SplitHostPort(rAddr)
	}

	return rAddr
}

// GetRefreshTokenFromCookie returns the refresh token from the cookie if any
func GetRefreshTokenFromCookie(req *http.Request, cookieName string) (string, error) {
	token, err := GetTokenInCookie(req, cookieName)
	if err != nil {
		return "", err
	}

	return token, nil
}

// getTokenInRequest returns the access token from the http request
func GetTokenInRequest(req *http.Request, name string, skipAuthorizationHeaderIdentity bool) (string, bool, error) {
	bearer := true
	token := ""
	var err error

	if !skipAuthorizationHeaderIdentity {
		token, err = GetTokenInBearer(req)
		if err != nil && err != apperrors.ErrSessionNotFound {
			return "", false, err
		}
	}

	// step: check for a token in the authorization header
	if err != nil || (err == nil && skipAuthorizationHeaderIdentity) {
		if token, err = GetTokenInCookie(req, name); err != nil {
			return token, false, err
		}
		bearer = false
	}

	return token, bearer, nil
}

// getTokenInBearer retrieves a access token from the authorization header
func GetTokenInBearer(req *http.Request) (string, error) {
	token := req.Header.Get(constant.AuthorizationHeader)
	if token == "" {
		return "", apperrors.ErrSessionNotFound
	}

	items := strings.Split(token, " ")
	if len(items) != 2 {
		return "", apperrors.ErrInvalidSession
	}

	if items[0] != constant.AuthorizationType {
		return "", apperrors.ErrSessionNotFound
	}
	return items[1], nil
}

// getTokenInCookie retrieves the access token from the request cookies
func GetTokenInCookie(req *http.Request, name string) (string, error) {
	var token bytes.Buffer

	if cookie := FindCookie(name, req.Cookies()); cookie != nil {
		token.WriteString(cookie.Value)
	}

	// add also divided cookies
	for i := 1; i < 600; i++ {
		cookie := FindCookie(name+"-"+strconv.Itoa(i), req.Cookies())
		if cookie == nil {
			break
		} else {
			token.WriteString(cookie.Value)
		}
	}

	if token.Len() == 0 {
		return "", apperrors.ErrSessionNotFound
	}

	return token.String(), nil
}
