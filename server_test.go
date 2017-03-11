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
	fakeClientID = "test"
	fakeSecret   = fakeClientID

	fakeAdminRoleURL       = "/admin*"
	fakeTestRoleURL        = "/test_role"
	fakeTestAdminRolesURL  = "/test_admin_roles"
	fakeAuthAllURL         = "/auth_all/*"
	fakeTestWhitelistedURL = "/auth_all/white_listed*"

	fakeAdminRole = "role:admin"
	fakeTestRole  = "role:test"
)

var (
	defaultFakeClaims = jose.Claims{
		"jti":            "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
		"nbf":            0,
		"iat":            "1450372669",
		"iss":            "https://keycloak.example.com/auth/realms/commons",
		"aud":            "test",
		"sub":            "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
		"typ":            "Bearer",
		"azp":            "clientid",
		"session_state":  "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
		"client_session": "f0105893-369a-46bc-9661-ad8c747b1a69",
		"resource_access": map[string]interface{}{
			"openvpn": map[string]interface{}{
				"roles": []string{
					"dev-vpn",
				},
			},
		},
		"email":              "gambol99@gmail.com",
		"name":               "Rohith Jayawardene",
		"family_name":        "Jayawardene",
		"preferred_username": "rjayawardene",
		"given_name":         "Rohith",
	}

	defaultTestTokenClaims = jose.Claims{
		"jti":                "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
		"nbf":                0,
		"iat":                "1450372669",
		"iss":                "test",
		"aud":                "test",
		"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
		"typ":                "Bearer",
		"azp":                "clientid",
		"session_state":      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
		"client_session":     "f0105893-369a-46bc-9661-ad8c747b1a69",
		"email":              "gambol99@gmail.com",
		"name":               "Rohith Jayawardene",
		"family_name":        "Jayawardene",
		"preferred_username": "rjayawardene",
		"given_name":         "Rohith",
	}

	defaultFakeRealmClaims = jose.Claims{
		"jti":            "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
		"nbf":            0,
		"iat":            "1450372669",
		"iss":            "https://keycloak.example.com/auth/realms/commons",
		"aud":            "test",
		"sub":            "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
		"typ":            "Bearer",
		"azp":            "clientid",
		"session_state":  "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
		"client_session": "f0105893-369a-46bc-9661-ad8c747b1a69",
		"realm_access": map[string]interface{}{
			"roles": []string{
				"dsp-dev-vpn",
				"vpn-user",
				"dsp-prod-vpn",
			},
		},
		"resource_access": map[string]interface{}{
			"openvpn": map[string]interface{}{
				"roles": []string{
					"dev-vpn",
				},
			},
		},
		"email":              "gambol99@gmail.com",
		"name":               "Rohith Jayawardene",
		"family_name":        "Jayawardene",
		"preferred_username": "rjayawardene",
		"given_name":         "Rohith",
	}
)

type testJWTToken struct {
	claims jose.Claims
}

func newTestToken(issuer string) *testJWTToken {
	claims := defaultTestTokenClaims
	claims.Add("exp", float64(time.Now().Add(1*time.Hour).Unix()))
	claims.Add("iat", float64(time.Now().Unix()))
	claims.Add("iss", issuer)

	return &testJWTToken{claims: claims}
}

func (t *testJWTToken) mergeClaims(claims jose.Claims) {
	for k, v := range claims {
		t.claims.Add(k, v)
	}
}

func (t *testJWTToken) getToken() jose.JWT {
	tk, _ := jose.NewJWT(jose.JOSEHeader{"alg": "RS256"}, t.claims)
	return tk
}

func (t *testJWTToken) setExpiration(tm time.Time) {
	t.claims.Add("exp", float64(tm.Unix()))
}

func (t *testJWTToken) setRealmsRoles(roles []string) {
	t.claims.Add("realm_access", map[string]interface{}{
		"roles": roles,
	})
}

func (t *testJWTToken) setClientRoles(client string, roles []string) {
	t.claims.Add("resource_access", map[string]interface{}{
		"openvpn": map[string]interface{}{
			"roles": roles,
		},
	})
}

func newFakeAccessToken(claims *jose.Claims, expire time.Duration) jose.JWT {
	if claims == nil {
		claims = &defaultFakeClaims
	}
	claims.Add("exp", float64(time.Now().Add(10*time.Hour).Unix()))
	if expire > 0 {
		claims.Add("exp", float64(time.Now().Add(expire).Unix()))
	}
	testToken, _ := jose.NewJWT(jose.JOSEHeader{"alg": "RS256"}, *claims)

	return testToken
}

func getFakeRealmAccessToken(t *testing.T) jose.JWT {
	return newFakeAccessToken(&defaultFakeRealmClaims, 0)
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
		EnableRefreshTokens:       false,
		EnableLoginHandler:        true,
		EncryptionKey:             "AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j",
		EnableLogging:             false,
		Scopes:                    []string{},
		SecureCookie:              false,
		SkipTokenVerification:     false,
		Verbose:                   false,
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

func newTestService() string {
	_, _, u := newTestProxyService(nil)

	return u
}

func newTestServiceWithConfig(cfg *Config) string {
	_, _, u := newTestProxyService(cfg)

	return u
}

func newTestProxyOnlyService() *oauthProxy {
	p, _, _ := newTestProxyService(nil)
	return p
}

func newTestProxyService(config *Config) (*oauthProxy, *fakeOAuthServer, string) {
	log.SetOutput(ioutil.Discard)
	auth := newFakeOAuthServer()
	if config == nil {
		config = newFakeKeycloakConfig()
	}
	// step: set the config
	config.DiscoveryURL = auth.getLocation()
	config.RevocationEndpoint = auth.getRevocationURL()
	config.Verbose = false
	config.EnableLogging = false

	// step: create a proxy
	proxy, err := newProxy(config)
	if err != nil {
		panic("failed to create proxy service, error: " + err.Error())
	}

	// step: create an fake upstream endpoint
	proxy.upstream = new(testReverseProxy)
	service := httptest.NewServer(proxy.router)
	config.RedirectionURL = service.URL

	// step: we need to update the client config
	proxy.client, proxy.idp, proxy.idpClient, err = newOpenIDClient(config)
	if err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return proxy, auth, service.URL
}

func newTestServiceWithWithResources(t *testing.T, resources []*Resource) (*oauthProxy, string) {
	config := newFakeKeycloakConfig()
	config.Resources = resources
	px, _, url := newTestProxyService(config)

	return px, url
}

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

const testProxyAccepted = "Proxy-Accepted"

type testReverseProxy struct{}

func (r testReverseProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	resp := testUpstreamResponse{
		URI:     req.RequestURI,
		Method:  req.Method,
		Address: req.RemoteAddr,
		Headers: req.Header,
	}
	w.Header().Set(testProxyAccepted, "true")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// step: encode the response
	encoded, _ := json.Marshal(&resp)

	w.Write(encoded)
}
