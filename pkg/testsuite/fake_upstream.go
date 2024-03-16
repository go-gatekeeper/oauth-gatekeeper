package testsuite

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/websocket"
)

// fakeUpstreamResponse is the response from fake upstream
type fakeUpstreamResponse struct {
	URI     string      `json:"uri"`
	Method  string      `json:"method"`
	Address string      `json:"address"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
}

// FakeUpstreamService acts as a fake upstream service, returns the headers and request
type FakeUpstreamService struct{}

func (f *FakeUpstreamService) ServeHTTP(wrt http.ResponseWriter, req *http.Request) {
	upgrade := strings.ToLower(req.Header.Get("Upgrade"))
	if upgrade == "websocket" {
		wrt.Header().Set(TestProxyAccepted, "true")
		websocket.Handler(func(wsock *websocket.Conn) {
			defer wsock.Close()
			var data []byte
			err := websocket.Message.Receive(wsock, &data)
			if err != nil {
				wsock.WriteClose(http.StatusBadRequest)
				return
			}
			content, _ := json.Marshal(&fakeUpstreamResponse{
				URI:     req.RequestURI,
				Method:  req.Method,
				Address: req.RemoteAddr,
				Headers: req.Header,
			})
			_ = websocket.Message.Send(wsock, content)
		}).ServeHTTP(wrt, req)
	} else {
		reqBody, err := io.ReadAll(req.Body)
		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
		}

		wrt.Header().Set(TestProxyAccepted, "true")
		wrt.Header().Set("Content-Type", "application/json")
		content, err := json.Marshal(&fakeUpstreamResponse{
			// r.RequestURI is what was received by the proxy.
			// r.URL.String() is what is actually sent to the upstream service.
			// KEYCLOAK-10864, KEYCLOAK-11276, KEYCLOAK-13315
			URI:     req.URL.String(),
			Method:  req.Method,
			Address: req.RemoteAddr,
			Headers: req.Header,
			Body:    string(reqBody),
		})

		if err != nil {
			wrt.WriteHeader(http.StatusInternalServerError)
		} else {
			wrt.WriteHeader(http.StatusOK)
		}

		_, _ = wrt.Write(content)
	}
}
