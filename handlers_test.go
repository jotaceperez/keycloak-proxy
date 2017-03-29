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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpirationHandler(t *testing.T) {
	uri := oauthURL + expiredURL
	requests := []fakeRequest{
		{
			URI:          uri,
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      time.Duration(-48 * time.Hour),
			ExpectedCode: http.StatusUnauthorized,
		},
		{
			URI:          uri,
			HasToken:     true,
			Expires:      time.Duration(14 * time.Hour),
			ExpectedCode: http.StatusOK,
		},
	}
	makeFakeRequests(t, requests, nil)
}

func TestOauthRequestNotProxying(t *testing.T) {
	requests := []fakeRequest{
		{URI: "/oauth/test"},
		{URI: "/oauth/..//oauth/test/"},
		{URI: "/oauth/expired", Method: http.MethodPost, ExpectedCode: http.StatusNotFound},
		{URI: "/oauth/expiring", Method: http.MethodPost},
		{URI: "/oauth%2F///../test%2F%2Foauth"},
	}
	makeFakeRequests(t, requests, nil)
}

func TestLoginHandlerDisabled(t *testing.T) {
	c := newFakeKeycloakConfig()
	c.EnableLoginHandler = false
	requests := []fakeRequest{
		{URI: oauthURL + loginURL, Method: http.MethodPost, ExpectedCode: http.StatusNotImplemented},
		{URI: oauthURL + loginURL, ExpectedCode: http.StatusNotFound},
	}
	makeFakeRequests(t, requests, c)
}

func TestLoginHandlerNotDisabled(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableLoginHandler = true
	requests := []fakeRequest{
		{URI: "/oauth/login", Method: http.MethodPost, ExpectedCode: http.StatusBadRequest},
	}
	makeFakeRequests(t, requests, cfg)
}

func TestLoginHandler(t *testing.T) {
	uri := oauthURL + loginURL
	requests := []fakeRequest{
		{
			URI:          uri,
			Method:       http.MethodPost,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"username": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			Method:       http.MethodPost,
			FormValues:   map[string]string{"password": "test"},
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "test",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			URI:    uri,
			Method: http.MethodPost,
			FormValues: map[string]string{
				"password": "test",
				"username": "notmypassword",
			},
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	makeFakeRequests(t, requests, nil)
}

func TestLogoutHandlerBadRequest(t *testing.T) {
	requests := []fakeRequest{
		{URI: oauthURL + logoutURL, ExpectedCode: http.StatusBadRequest},
	}
	makeFakeRequests(t, requests, nil)
}

func TestLogoutHandlerBadToken(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:          oauthURL + logoutURL,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:            oauthURL + logoutURL,
			HasCookieToken: true,
			RawToken:       "this.is.a.bad.token",
			ExpectedCode:   http.StatusBadRequest,
		},
		{
			URI:          oauthURL + logoutURL,
			RawToken:     "this.is.a.bad.token",
			ExpectedCode: http.StatusBadRequest,
		},
	}
	makeFakeRequests(t, requests, nil)
}

func TestLogoutHandlerGood(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:          oauthURL + logoutURL,
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:          oauthURL + logoutURL + "?redirect=http://example.com",
			HasToken:     true,
			ExpectedCode: http.StatusTemporaryRedirect,
			ExpectedHeaders: map[string]string{
				"Location": "http://example.com",
			},
		},
	}
	makeFakeRequests(t, requests, nil)
}

func TestTokenHandler(t *testing.T) {
	uri := oauthURL + tokenURL
	requests := []fakeRequest{
		{
			URI:          uri,
			HasToken:     true,
			ExpectedCode: http.StatusOK,
		},
		{
			URI:          uri,
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:          uri,
			RawToken:     "niothing",
			ExpectedCode: http.StatusBadRequest,
		},
		{
			URI:            uri,
			HasToken:       true,
			HasCookieToken: true,
			ExpectedCode:   http.StatusOK,
		},
	}
	makeFakeRequests(t, requests, nil)
}

func TestServiceRedirect(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedCode:     http.StatusTemporaryRedirect,
			ExpectedLocation: "/oauth/authorize?state=L2FkbWlu",
		},
		{
			URI:          "/admin",
			ExpectedCode: http.StatusUnauthorized,
		},
	}
	makeFakeRequests(t, requests, nil)
}

func TestAuthorizationRedirects(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:              "/admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state=L2FkbWlu",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              "/admin/test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state=L2FkbWluL3Rlc3Q=",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              "/help/../admin",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state=L2FkbWlu",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:              "/admin?test=yes&test1=test",
			Redirects:        true,
			ExpectedLocation: "/oauth/authorize?state=L2FkbWluP3Rlc3Q9eWVzJnRlc3QxPXRlc3Q=",
			ExpectedCode:     http.StatusTemporaryRedirect,
		},
		{
			URI:          "/oauth/test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
		{
			URI:          "/oauth/callback/..//test",
			Redirects:    true,
			ExpectedCode: http.StatusNotFound,
		},
	}
	makeFakeRequests(t, requests, nil)
}

func TestCallbackURL(t *testing.T) {
	_, _, u := newTestProxyService(nil)

	cs := []struct {
		URL         string
		ExpectedURL string
	}{
		{
			URL:         "/oauth/authorize?state=L2FkbWlu",
			ExpectedURL: "/admin",
		},
		{
			URL:         "/oauth/authorize",
			ExpectedURL: "/",
		},
		{
			URL:         "/oauth/authorize?state=L2FkbWluL3Rlc3QxP3Rlc3QxJmhlbGxv",
			ExpectedURL: "/admin/test1?test1&hello",
		},
	}
	for i, x := range cs {
		// step: call the authorization endpoint
		req, err := http.NewRequest("GET", u+x.URL, nil)
		if err != nil {
			continue
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if !assert.NoError(t, err, "case %d, should not have failed", i) {
			continue
		}
		openURL := resp.Header.Get("Location")
		if !assert.NotEmpty(t, openURL, "case %d, the open id redirection url is empty", i) {
			continue
		}
		req, _ = http.NewRequest("GET", openURL, nil)
		resp, err = http.DefaultTransport.RoundTrip(req)
		if !assert.NoError(t, err, "case %d, should not have failed calling the opend id url", i) {
			continue
		}
		callbackURL := resp.Header.Get("Location")
		if !assert.NotEmpty(t, callbackURL, "case %d, should have received a callback url", i) {
			continue
		}
		// step: call the callback url
		req, _ = http.NewRequest("GET", callbackURL, nil)
		resp, err = http.DefaultTransport.RoundTrip(req)
		if !assert.NoError(t, err, "case %d, unable to call the callback url", i) {
			continue
		}
		// step: check the callback location is as expected
		assert.Contains(t, resp.Header.Get("Location"), x.ExpectedURL,
			"case %d, expected location contains: %s, got: %s", i, x.ExpectedURL, resp.Header.Get("Location"))
	}
}

func TestHealthHandler(t *testing.T) {
	requests := []fakeRequest{
		{
			URI:             oauthURL + healthURL,
			ExpectedCode:    http.StatusOK,
			ExpectedContent: "OK\n",
		},
		{
			URI:          oauthURL + healthURL,
			Method:       http.MethodHead,
			ExpectedCode: http.StatusMethodNotAllowed,
		},
	}
	makeFakeRequests(t, requests, nil)
}
