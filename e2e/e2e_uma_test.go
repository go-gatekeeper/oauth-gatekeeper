package e2e_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	resty "github.com/go-resty/resty/v2"
)

var _ = Describe("UMA Code Flow authorization", func() {
	var portNum string
	var proxyAddress string
	var umaCookieName = "TESTUMACOOKIE"

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--enable-uma=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing resource, where user is allowed to access", func() {
		It("should login with user/password and logout successfully", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaAllowedPath, http.StatusOK)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())

			By("Accessing not allowed path")
			resp, err = rClient.R().Get(proxyAddress + umaForbiddenPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})

	When("Accessing resource, which does not exist", func() {
		It("should be forbidden without permission ticket", func(ctx context.Context) {
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaNonExistentPath, http.StatusForbidden)

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())
		})
	})

	When("Accessing resource, which exists but user is not allowed and then allowed resource", func() {
		It("should be forbidden and then allowed", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaForbiddenPath, http.StatusForbidden)

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			By("Accessing allowed resource")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			By("Accessing allowed resource one more time, checking uma cookie set")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())
		})
	})
})

var _ = Describe("UMA Code Flow authorization with method scope", func() {
	var portNum string
	var proxyAddress string
	var umaCookieName = "TESTUMACOOKIE"

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--verbose=true",
			"--enable-logging=true",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It("should login with user/password, don't access forbidden resource and logout successfully", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaMethodAllowedPath, http.StatusOK)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())

			By("Accessing not allowed method")
			resp, err = rClient.R().Post(proxyAddress + umaMethodAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})
})

var _ = Describe("UMA no-redirects authorization with forwarding client credentials grant", func() {
	var portNum string
	var proxyAddress string
	var fwdPortNum string
	var fwdProxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		fwdPortNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		fwdProxyAddress = "http://localhost:" + fwdPortNum
		osArgs := []string{os.Args[0]}
		fwdOsArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=true",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--enable-idp-session-check=false",
		}

		fwdProxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + fwdPortNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--enable-forwarding=true",
			"--enable-authorization-header=true",
			"--forwarding-grant-type=client_credentials",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		fwdOsArgs = append(fwdOsArgs, fwdProxyArgs...)
		startAndWait(fwdPortNum, fwdOsArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It("should login with client secret, don't access forbidden resource", func(ctx context.Context) {
			rClient := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
			rClient.SetProxy(fwdProxyAddress)
			resp, err := rClient.R().Get(proxyAddress + umaFwdMethodAllowedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaFwdMethodAllowedPath)).To(BeTrue())

			By("Accessing resource without access for client id")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaAllowedPath)).To(BeFalse())

			By("Accessing not allowed method")
			resp, err = rClient.R().Post(proxyAddress + umaFwdMethodAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaFwdMethodAllowedPath)).To(BeFalse())
		})
	})
})

var _ = Describe("UMA no-redirects authorization with forwarding direct access grant", func() {
	var portNum string
	var proxyAddress string
	var fwdPortNum string
	var fwdProxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		fwdPortNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		fwdProxyAddress = "http://localhost:" + fwdPortNum
		osArgs := []string{os.Args[0]}
		fwdOsArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=true",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--verbose=true",
			"--enable-idp-session-check=false",
		}

		fwdProxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + fwdPortNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--forwarding-username=" + testUser,
			"--forwarding-password=" + testPass,
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--enable-forwarding=true",
			"--enable-authorization-header=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		fwdOsArgs = append(fwdOsArgs, fwdProxyArgs...)
		startAndWait(fwdPortNum, fwdOsArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It("should login with user/password, don't access forbidden resource", func(ctx context.Context) {
			rClient := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
			rClient.SetProxy(fwdProxyAddress)
			resp, err := rClient.R().Get(proxyAddress + umaMethodAllowedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaMethodAllowedPath)).To(BeTrue())
			Expect(resp.Header().Get(constant.UMAHeader)).NotTo(BeEmpty())

			By("Repeating access to allowed resource, we verify that uma was saved and reused")
			resp, err = rClient.R().Get(proxyAddress + umaMethodAllowedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			body = resp.Body()
			GinkgoLogr.Info(string(body))
			Expect(strings.Contains(string(body), umaMethodAllowedPath)).To(BeTrue())
			Expect(resp.Header().Get(constant.UMAHeader)).To(BeEmpty())
			// as first request should return uma token in header, it should be
			// saved in forwarding rpt structure and sent also in this request
			// so we should see it in response body
			Expect(strings.Contains(string(body), constant.UMAHeader)).To(BeTrue())

			By("Accessing resource without access for user")
			resp, err = rClient.SetTimeout(1 * time.Hour).R().Get(proxyAddress + umaForbiddenPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaForbiddenPath)).To(BeFalse())
			Expect(resp.Header().Get(constant.UMATicketHeader)).NotTo(BeEmpty())

			By("Accessing not allowed method")
			resp, err = rClient.R().Post(proxyAddress + umaMethodAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaMethodAllowedPath)).To(BeFalse())
		})
	})
})

var _ = Describe("UMA Code Flow, NOPROXY authorization with method scope", func() {
	var portNum string
	var proxyAddress string
	var umaCookieName = "TESTUMACOOKIE"
	// server := httptest.NewServer(&testsuite.FakeUpstreamService{})

	BeforeEach(func() {
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--no-redirects=false",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--no-proxy=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--verbose=true",
			"--enable-logging=true",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing allowed resource", func() {
		It("should be allowed and logout successfully", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			rClient.SetHeaders(map[string]string{
				"X-Forwarded-Proto":  "http",
				"X-Forwarded-Host":   strings.Split(proxyAddress, "//")[1],
				"X-Forwarded-URI":    umaMethodAllowedPath,
				"X-Forwarded-Method": "GET",
			})
			resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK)
			Expect(resp.Header().Get(constant.AuthorizationHeader)).ToNot(BeEmpty())

			resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})

	When("Accessing not allowed resource", func() {
		It("should be forbidden", func(ctx context.Context) {
			rClient := resty.New()
			rClient.SetHeaders(map[string]string{
				"X-Forwarded-Proto":  "http",
				"X-Forwarded-Host":   strings.Split(proxyAddress, "//")[1],
				"X-Forwarded-URI":    umaMethodAllowedPath,
				"X-Forwarded-Method": "POST",
			})
			resp := codeFlowLogin(rClient, proxyAddress, http.StatusForbidden)
			Expect(resp.Header().Get(constant.AuthorizationHeader)).To(BeEmpty())
		})
	})

	When("Accessing resource without X-Forwarded headers", func() {
		It("should be forbidden", func(ctx context.Context) {
			rClient := resty.New()
			rClient.SetHeaders(map[string]string{
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  strings.Split(proxyAddress, "//")[1],
				"X-Forwarded-URI":   umaMethodAllowedPath,
			})
			resp := codeFlowLogin(rClient, proxyAddress, http.StatusForbidden)
			Expect(resp.Header().Get(constant.AuthorizationHeader)).To(BeEmpty())
		})
	})
})
