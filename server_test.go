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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/stretchr/testify/assert"
)

const (
	fakeAdminRole          = "role:admin"
	fakeAdminRoleURL       = "/admin*"
	fakeAuthAllURL         = "/auth_all/*"
	fakeClientID           = "test"
	fakeSecret             = fakeClientID
	fakeTestAdminRolesURL  = "/test_admin_roles"
	fakeTestRole           = "role:test"
	fakeTestRoleURL        = "/test_role"
	fakeTestWhitelistedURL = "/auth_all/white_listed*"
	testProxyAccepted      = "Proxy-Accepted"
)

var (
	defaultTestTokenClaims = jose.Claims{
		"aud":                "test",
		"azp":                "clientid",
		"client_session":     "f0105893-369a-46bc-9661-ad8c747b1a69",
		"email":              "gambol99@gmail.com",
		"family_name":        "Jayawardene",
		"given_name":         "Rohith",
		"iat":                "1450372669",
		"iss":                "test",
		"jti":                "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
		"name":               "Rohith Jayawardene",
		"nbf":                0,
		"preferred_username": "rjayawardene",
		"session_state":      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
		"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
		"typ":                "Bearer",
	}
)

func TestNewKeycloakProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.DiscoveryURL = newFakeOAuthServer().getLocation()

	proxy, err := newProxy(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.config)
	assert.NotNil(t, proxy.router)
	assert.NotNil(t, proxy.endpoint)
}

func TestForwardingProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableForwarding = true
	cfg.ForwardingDomains = []string{}
	cfg.ForwardingUsername = "test"
	cfg.ForwardingPassword = "test"
	// create fake upstream
	s := httptest.NewServer(&testReverseProxy{})
	requests := []fakeRequest{
		{
			URL:                     s.URL + "/test",
			ProxyRequest:            true,
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Bearer ey",
		},
	}
	makeFakeRequestsWithDelay(t, requests, cfg, time.Duration(100)*time.Millisecond)
}

func TestForbiddenTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.ForbiddenPage = "templates/forbidden.html.tmpl"
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     "/",
			Redirects:               false,
			HasToken:                true,
			ExpectedCode:            http.StatusForbidden,
			ExpectedContentContains: "403 Permission Denied",
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestAuthorizationTemplate(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.SignInPage = "templates/sign_in.html.tmpl"
	cfg.Resources = []*Resource{
		{
			URL:     "/*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{
			URI:                     oauthURL + authorizationURL,
			Redirects:               true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Sign In",
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func newTestService() string {
	_, _, u := newTestProxyService(nil)
	return u
}

func newTestProxyService(config *Config) (*oauthProxy, *fakeOAuthServer, string) {
	log.SetOutput(ioutil.Discard)
	auth := newFakeOAuthServer()
	if config == nil {
		config = newFakeKeycloakConfig()
	}
	config.DiscoveryURL = auth.getLocation()
	config.RevocationEndpoint = auth.getRevocationURL()
	config.Verbose = false
	config.EnableLogging = false

	proxy, err := newProxy(config)
	if err != nil {
		panic("failed to create proxy service, error: " + err.Error())
	}

	// step: create an fake upstream endpoint
	proxy.upstream = new(testReverseProxy)
	service := httptest.NewServer(proxy.router)
	config.RedirectionURL = service.URL

	// step: we need to update the client config
	if proxy.client, proxy.idp, proxy.idpClient, err = newOpenIDClient(config); err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return proxy, auth, service.URL
}

// makeTestOauthLogin performs a fake oauth login into the service, retrieving the access token
func makeTestOauthLogin(location string) (string, error) {
	resp, err := makeTestCodeFlowLogin(location)
	if err != nil {
		return "", err
	}

	// step: check the cookie is there
	for _, c := range resp.Cookies() {
		if c.Name == "kc-access" {
			return c.Value, nil
		}
	}

	return "", errors.New("access cookie not found in response from oauth service")
}

func newFakeHTTPRequest(method, path string) *http.Request {
	return &http.Request{
		Method: method,
		Header: make(map[string][]string, 0),
		Host:   "127.0.0.1",
		URL: &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1",
			Path:   path,
		},
	}
}

func newFakeKeycloakConfig() *Config {
	return &Config{
		ClientID:                  fakeClientID,
		ClientSecret:              fakeSecret,
		CookieAccessName:          "kc-access",
		CookieRefreshName:         "kc-state",
		DiscoveryURL:              "127.0.0.1:8080",
		Listen:                    "127.0.0.1:443",
		ListenHTTP:                "127.0.0.1:80",
		EnableAuthorizationHeader: true,
		EnableLoginHandler:        true,
		EncryptionKey:             "AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j",
		Scopes:                    []string{},
		Resources: []*Resource{
			{
				URL:     fakeAdminRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole},
			},
			{
				URL:     fakeTestRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeTestRole},
			},
			{
				URL:     fakeTestAdminRolesURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole, fakeTestRole},
			},
			{
				URL:     fakeAuthAllURL,
				Methods: allHTTPMethods,
				Roles:   []string{},
			},
			{
				URL:         fakeTestWhitelistedURL,
				WhiteListed: true,
				Methods:     allHTTPMethods,
				Roles:       []string{},
			},
		},
	}
}

func makeTestCodeFlowLogin(location string) (*http.Response, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	// step: get the redirect
	var resp *http.Response
	for count := 0; count < 4; count++ {
		req, err := http.NewRequest(http.MethodGet, location, nil)
		if err != nil {
			return nil, err
		}
		// step: make the request
		resp, err = http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTemporaryRedirect {
			return nil, errors.New("no redirection found in resp")
		}
		location = resp.Header.Get("Location")
		if !strings.HasPrefix(location, "http") {
			location = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, location)
		}
	}

	return resp, nil
}

// testUpstreamResponse is the response from fake upstream
type testUpstreamResponse struct {
	URI     string      `json:"uri"`
	Method  string      `json:"method"`
	Address string      `json:"address"`
	Headers http.Header `json:"headers"`
}

type testReverseProxy struct{}

func (r *testReverseProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	resp := testUpstreamResponse{
		URI:     req.RequestURI,
		Method:  req.Method,
		Address: req.RemoteAddr,
		Headers: req.Header,
	}
	w.Header().Set(testProxyAccepted, "true")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoded, _ := json.Marshal(&resp)

	w.Write(encoded)
}

type fakeToken struct {
	claims jose.Claims
}

func newTestToken(issuer string) *fakeToken {
	claims := make(jose.Claims, 0)
	for k, v := range defaultTestTokenClaims {
		claims[k] = v
	}
	claims.Add("exp", float64(time.Now().Add(1*time.Hour).Unix()))
	claims.Add("iat", float64(time.Now().Unix()))
	claims.Add("iss", issuer)

	return &fakeToken{claims: claims}
}

func (t *fakeToken) mergeClaims(claims jose.Claims) {
	for k, v := range claims {
		t.claims.Add(k, v)
	}
}

func (t *fakeToken) getToken() jose.JWT {
	tk, _ := jose.NewJWT(jose.JOSEHeader{"alg": "RS256"}, t.claims)
	return tk
}

func (t *fakeToken) setExpiration(tm time.Time) {
	t.claims.Add("exp", float64(tm.Unix()))
}

func (t *fakeToken) setRealmsRoles(roles []string) {
	t.claims.Add("realm_access", map[string]interface{}{
		"roles": roles,
	})
}

func (t *fakeToken) setClientRoles(client string, roles []string) {
	t.claims.Add("resource_access", map[string]interface{}{
		client: map[string]interface{}{
			"roles": roles,
		},
	})
}
