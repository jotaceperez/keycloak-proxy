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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/go-resty/resty"
	"github.com/labstack/echo/middleware"
	"github.com/stretchr/testify/assert"
)

type fakeRequest struct {
	URI                     string
	URL                     string
	Method                  string
	Redirects               bool
	HasToken                bool
	NotSigned               bool
	Headers                 map[string]string
	Expires                 time.Duration
	Roles                   []string
	FormValues              map[string]string
	BasicAuth               bool
	Username                string
	Password                string
	ProxyRequest            bool
	ExpectedProxy           bool
	ExpectedCode            int
	ExpectedHeaders         map[string]string
	ExpectedLocation        string
	ExpectedContent         string
	ExpectedContentContains string
}

func makeFakeRequests(t *testing.T, requests []fakeRequest, cfg *Config) {
	makeFakeRequestsWithDelay(t, requests, cfg, time.Duration(0))
}

func makeFakeRequestsWithDelay(t *testing.T, requests []fakeRequest, cfg *Config, delay time.Duration) {
	px, idp, svc := newTestProxyService(cfg)
	if delay > 0 {
		<-time.After(delay)
	}
	for i, c := range requests {
		px.config.NoRedirects = !c.Redirects

		// step: add the defaults
		if c.Method == "" {
			c.Method = http.MethodGet
		}

		// step: create a http client
		request := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy()).R()

		if c.ProxyRequest {
			request.SetProxy(svc)
		}

		// step: make the request
		if c.BasicAuth {
			request.SetBasicAuth(c.Username, c.Password)
		}
		// step: add the request parameters
		if c.HasToken {
			token := newTestToken(idp.getLocation())
			if len(c.Roles) > 0 {
				token.setRealmsRoles(c.Roles)
			}
			if c.Expires > 0 || c.Expires < 0 {
				token.setExpiration(time.Now().Add(c.Expires))
			}
			if c.NotSigned {
				unsigned := token.getToken()
				request.SetAuthToken(unsigned.Encode())
			} else {
				signed, err := idp.signToken(token.claims)
				if !assert.NoError(t, err, "case %d, unable to sign the token, error: %s", i, err) {
					continue
				}
				request.SetAuthToken(signed.Encode())
			}
		}
		// headers
		if len(c.Headers) > 0 {
			request.SetHeaders(c.Headers)
		}
		// form data
		if c.FormValues != nil {
			request.SetFormData(c.FormValues)
		}

		// step: execute the request
		var resp *resty.Response
		var err error
		switch c.URL {
		case "":
			resp, err = request.Execute(c.Method, svc+c.URI)
		default:
			resp, err = request.Execute(c.Method, c.URL)
		}
		if err != nil {
			if !strings.Contains(err.Error(), "Auto redirect is disable") {
				assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err)
				continue
			}
		}

		// step: check against the expected
		if c.ExpectedCode != 0 {
			assert.Equal(t, c.ExpectedCode, resp.StatusCode(), "case %d, uri: %s,  expected: %d, got: %d",
				i, c.URI, c.ExpectedCode, resp.StatusCode())
		}
		if c.ExpectedLocation != "" {
			location := resp.Header().Get("Location")
			assert.Equal(t, c.ExpectedLocation, location, "case %d, expected location: %s, got: %s",
				i, c.ExpectedLocation, location)
		}
		if len(c.ExpectedHeaders) > 0 {
			for k, v := range c.ExpectedHeaders {
				got := resp.Header().Get(k)
				assert.Equal(t, v, got, "case %d, expected header %s=%s, got: %s", i, k, v, got)
			}
		}
		if c.ExpectedProxy {
			assert.Equal(t, "true", resp.Header().Get(testProxyAccepted), "case %d, did not proxy request", i)
		} else {
			assert.Empty(t, resp.Header().Get(testProxyAccepted), "case %d, should not proxy %s", i, c.URI)
		}

		if c.ExpectedContent != "" {
			content := string(resp.Body())
			assert.Equal(t, c.ExpectedContent, content, "case %d, expect content: %s, got: %s",
				i, c.ExpectedContent, content)
		}
		if c.ExpectedContentContains != "" {
			content := string(resp.Body())
			assert.Contains(t, content, c.ExpectedContentContains, "case %d, expected contents: %s, got: %s",
				i, c.ExpectedContentContains, content)
		}
	}
}

func TestMetricsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableMetrics = true
	requests := []fakeRequest{
		{
			URI:                     oauthURL + metricsURL,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "http_request_total",
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestOauthRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:          "/oauth/authorize",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{
			URI:          "/oauth/callback",
			Redirects:    true,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          "/oauth/health",
			Redirects:    true,
			ExpectedCode: http.StatusOK,
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestStrangeAdminRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:          "//admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "///admin/../admin//%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:          "/admin%2Ftest",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for prefix slashs
			URI:          "//admin/test",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for double slashs
			URI:          "/admin//test",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for double slashs no redirects
			URI:          "/admin//test",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check for dodgy url
			URI:          "//admin/../admin/test",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check for it works
			URI:           "//admin/test",
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{ // check for it works
			URI:           "//admin//test",
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/help/../admin/test/21",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestWhiteListedRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:         "/whitelist",
			WhiteListed: true,
			Methods:     []string{"GET"},
			Roles:       []string{},
		},
		{
			URL:     "/",
			Methods: allHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
		{
			URL:         "/whitelisted",
			WhiteListed: true,
			Methods:     allHTTPMethods,
			Roles:       []string{fakeTestRole},
		},
	}
	requests := []fakeRequest{
		{ // check whitelisted is passed
			URI:           "/whitelist",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check whitelisted is passed
			URI:           "/whitelist/test",
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestRolePermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: allHTTPMethods,
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/test*",
			Methods: []string{"GET"},
			Roles:   []string{fakeTestRole},
		},
		{
			URL:     "/test_admin_role*",
			Methods: []string{"GET"},
			Roles:   []string{fakeAdminRole, fakeTestRole},
		},
		{
			URL:         "/whitelist",
			WhiteListed: true,
			Methods:     []string{"GET"},
			Roles:       []string{},
		},
		{
			URL:     "/",
			Methods: allHTTPMethods,
			Roles:   []string{fakeTestRole},
		},
	}
	// test cases
	requests := []fakeRequest{
		{
			URI:          "/",
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // check for redirect
			URI:          "/",
			Redirects:    true,
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{ // check with a token but not test role
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token and wrong roles
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"one", "two"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, wrong roles
			URI:          "/test",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"bad_role"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // token, wrong roles, no 'get' method (5)
			URI:           "/test",
			Method:        http.MethodPost,
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{"bad_role"},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token
			URI:           "/test",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token on base
			URI:           "/",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // check with correct token, not signed
			URI:          "/",
			Redirects:    false,
			HasToken:     true,
			NotSigned:    true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed
			URI:          "/admin/page",
			Method:       http.MethodPost,
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles (10)
			URI:          "/admin/page",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles
			URI:           "/admin/page",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeTestRole, fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url
			URI:          "/admin/..//admin/page",
			Redirects:    false,
			ExpectedCode: http.StatusUnauthorized,
		},
		{ // strange url, token
			URI:          "/admin/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{"hehe"},
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // strange url, token, role (15)
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, but good token
			URI:           "/test/../admin",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
		{ // strange url, token, wrong roles
			URI:          "/test/../admin",
			Redirects:    false,
			HasToken:     true,
			Roles:        []string{fakeTestRole},
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token admin test role
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{ // check with a token but without both roles
			URI:          "/test_admin_role",
			Redirects:    false,
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
			Roles:        []string{fakeAdminRole},
		},
		{ // check with a token with both roles (20)
			URI:           "/test_admin_role",
			Redirects:     false,
			HasToken:      true,
			Roles:         []string{fakeAdminRole, fakeTestRole},
			ExpectedCode:  http.StatusOK,
			ExpectedProxy: true,
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestCrossSiteHandler(t *testing.T) {
	cases := []struct {
		Method  string
		Cors    middleware.CORSConfig
		Headers map[string]string
	}{
		{
			Method: http.MethodGet,
			Cors: middleware.CORSConfig{
				AllowOrigins: []string{"*"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
		{
			Method: http.MethodGet,
			Cors: middleware.CORSConfig{
				AllowOrigins: []string{"*", "https://examples.com"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
		{
			Method: http.MethodGet,
			Cors: middleware.CORSConfig{
				AllowOrigins: []string{"*"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
		{
			Method: http.MethodOptions,
			Cors: middleware.CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"GET", "POST"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET,POST",
			},
		},
	}

	for i, c := range cases {
		cfg := newFakeKeycloakConfig()
		// update the cors options
		cfg.NoRedirects = false
		cfg.CorsCredentials = c.Cors.AllowCredentials
		cfg.CorsExposedHeaders = c.Cors.ExposeHeaders
		cfg.CorsHeaders = c.Cors.AllowHeaders
		cfg.CorsMaxAge = time.Duration(time.Duration(c.Cors.MaxAge) * time.Second)
		cfg.CorsMethods = c.Cors.AllowMethods
		cfg.CorsOrigins = c.Cors.AllowOrigins
		// create the test service
		svc := newTestServiceWithConfig(cfg)
		// login and get a token
		token, err := makeTestOauthLogin(svc + fakeAuthAllURL)
		if err != nil {
			t.Errorf("case %d, unable to login to service, error: %s", i, err)
			continue
		}
		// make a request and check the response
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetAuthToken(token).
			Execute(c.Method, svc+fakeAuthAllURL)
		if !assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err) {
			continue
		}
		if resp.StatusCode() < 200 || resp.StatusCode() > 300 {
			continue
		}
		// check the headers are present
		for k, v := range c.Headers {
			assert.NotEmpty(t, resp.Header().Get(k), "case %d did not find header: %s", i, k)
			assert.Equal(t, v, resp.Header().Get(k), "case %d expected: %s, got: %s", i, v, resp.Header().Get(k))
		}
	}
}

func TestCustomHeadersHandler(t *testing.T) {
	cs := []struct {
		Match   []string
		Claims  jose.Claims
		Expects map[string]string
	}{ /*
			{
				Match: []string{"subject", "userid", "email", "username"},
				Claims: jose.Claims{
					"id":    "test-subject",
					"name":  "rohith",
					"email": "gambol99@gmail.com",
				},
				Expects: map[string]string{
					"X-Auth-Subject":  "test-subject",
					"X-Auth-Userid":   "rohith",
					"X-Auth-Email":    "gambol99@gmail.com",
					"X-Auth-Username": "rohith",
				},
			},
			{
				Match: []string{"roles"},
				Claims: jose.Claims{
					"roles": []string{"a", "b", "c"},
				},
				Expects: map[string]string{
					"X-Auth-Roles": "a,b,c",
				},
			},*/
		{
			Match: []string{"given_name", "family_name"},
			Claims: jose.Claims{
				"email":              "gambol99@gmail.com",
				"name":               "Rohith Jayawardene",
				"family_name":        "Jayawardene",
				"preferred_username": "rjayawardene",
				"given_name":         "Rohith",
			},
			Expects: map[string]string{
				"X-Auth-Given-Name":  "Rohith",
				"X-Auth-Family-Name": "Jayawardene",
			},
		},
	}
	for i, x := range cs {
		cfg := newFakeKeycloakConfig()
		cfg.AddClaims = x.Match
		_, idp, svc := newTestProxyService(cfg)
		// create a token with those clams
		token := newTestToken(idp.getLocation())
		token.mergeClaims(x.Claims)
		signed, _ := idp.signToken(token.claims)
		// make the request
		var response testUpstreamResponse
		resp, err := resty.New().SetAuthToken(signed.Encode()).R().SetResult(&response).Get(svc + fakeAuthAllURL)
		if !assert.NoError(t, err, "case %d, unable to make the request, error: %s", i, err) {
			continue
		}
		// ensure the headers
		if !assert.Equal(t, http.StatusOK, resp.StatusCode(), "case %d, expected: %d, got: %d", i, http.StatusOK, resp.StatusCode()) {
			continue
		}
		for k, v := range x.Expects {
			assert.NotEmpty(t, response.Headers.Get(k), "case %d, did not have header: %s", i, k)
			assert.Equal(t, v, response.Headers.Get(k), "case %d, expected: %s, got: %s", i, v, response.Headers.Get(k))
		}
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: allHTTPMethods,
			Roles:   []string{"admin"},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: allHTTPMethods,
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: allHTTPMethods,
		},
	}
	requests := []fakeRequest{
		{
			URI:          "/admin",
			Roles:        []string{},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/admin",
			Roles:         []string{"admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/test",
			Roles:         []string{"test"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:           "/either",
			Roles:         []string{"test", "admin"},
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
		{
			URI:          "/either",
			Roles:        []string{"no_roles"},
			HasToken:     true,
			ExpectedCode: http.StatusForbidden,
		},
		{
			URI:           "/",
			HasToken:      true,
			ExpectedProxy: true,
			ExpectedCode:  http.StatusOK,
		},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestRolesAdmissionHandlerClaims(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*Resource{
		{
			URL:     "/admin*",
			Methods: allHTTPMethods,
		},
	}
	cs := []struct {
		Matches  map[string]string
		Claims   jose.Claims
		Expected int
	}{
		{
			Matches:  map[string]string{"cal": "test"},
			Claims:   jose.Claims{},
			Expected: http.StatusForbidden,
		},
		{
			Matches:  map[string]string{"item": "^tes$"},
			Claims:   jose.Claims{},
			Expected: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Claims: jose.Claims{
				"item": "tes",
			},
			Expected: http.StatusOK,
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Claims: jose.Claims{
				"item": "test",
			},
			Expected: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Claims: jose.Claims{
				"item":  "tester",
				"found": "something",
			},
			Expected: http.StatusOK,
		},
		{
			Matches: map[string]string{"item": ".*"},
			Claims: jose.Claims{
				"item": "test",
			},
			Expected: http.StatusOK,
		},
		{
			Matches:  map[string]string{"item": "^t.*$"},
			Claims:   jose.Claims{"item": "test"},
			Expected: http.StatusOK,
		},
	}

	for i, c := range cs {
		cfg.MatchClaims = c.Matches
		_, idp, svc := newTestProxyService(cfg)

		token := newTestToken(idp.getLocation())
		token.mergeClaims(c.Claims)
		jwt, err := idp.signToken(token.claims)
		if !assert.NoError(t, err) {
			continue
		}
		// step: inject a resource
		resp, err := resty.New().R().
			SetAuthToken(jwt.Encode()).
			Get(svc + "/admin")
		if !assert.NoError(t, err) {
			continue
		}
		assert.Equal(t, c.Expected, resp.StatusCode(), "case %d failed, expected: %d but got: %d", i, c.Expected, resp.StatusCode())
		if c.Expected == http.StatusOK {
			assert.NotEmpty(t, resp.Header().Get(testProxyAccepted))
		}
	}
}
