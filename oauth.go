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
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
)

// getOAuthClient returns a oauth2 client from the openid client
func (r *oauthProxy) getOAuthClient(redirectionURL string) (*oauth2.Client, error) {
	return oauth2.NewClient(r.idpClient, oauth2.Config{
		Credentials: oauth2.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		AuthMethod:  oauth2.AuthMethodClientSecretBasic,
		AuthURL:     r.idp.AuthEndpoint.String(),
		RedirectURL: redirectionURL,
		Scope:       append(r.config.Scopes, oidc.DefaultScope...),
		TokenURL:    r.idp.TokenEndpoint.String(),
	})
}

// verifyToken verify that the token in the user context is valid
func verifyToken(client *oidc.Client, token jose.JWT) error {
	if err := client.VerifyJWT(token); err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return ErrAccessTokenExpired
		}

		return err
	}

	return nil
}

// getRefreshedToken attempts to refresh the access token, returning the parsed token and the time it expires or a error
func getRefreshedToken(client *oidc.Client, t string) (jose.JWT, time.Time, error) {
	// step: retrieve the client
	cl, err := client.OAuthClient()
	if err != nil {
		return jose.JWT{}, time.Time{}, err
	}
	response, err := getToken(cl, oauth2.GrantTypeRefreshToken, t)
	if err != nil {
		if strings.Contains(err.Error(), "token expired") {
			return jose.JWT{}, time.Time{}, ErrRefreshTokenExpired
		}
		return jose.JWT{}, time.Time{}, err
	}

	// step: parse the access token
	token, identity, err := parseToken(response.AccessToken)
	if err != nil {
		return jose.JWT{}, time.Time{}, err
	}

	return token, identity.ExpiresAt, nil
}

// exchangeAuthenticationCode exchanges the authentication code with the oauth server for a access token
func exchangeAuthenticationCode(client *oauth2.Client, code string) (oauth2.TokenResponse, error) {
	return getToken(client, oauth2.GrantTypeAuthCode, code)
}

// getUserinfo is responsible for getting the userinfo from the iDP
func getUserinfo(client *oauth2.Client, provider *oidc.ProviderConfig) (interface{}, error) {
	// step: creating the http request
	req, err := http.NewRequest(http.MethodGet, provider.UserInfoEndpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	// step: make the resposne
	resp, err := client.HttpClient().Do(req)
	if err != nil {
		return nil, err
	}
	// step: check the status code returned
	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError("token not validate by userinfo endpoint", resp.StatusCode)
	}

	return nil, nil
}

// getToken retrieves a code from the provider, extracts and verified the token
func getToken(client *oauth2.Client, grantType, code string) (oauth2.TokenResponse, error) {
	return client.RequestToken(grantType, code)
}

// parseToken retrieve the user identity from the token
func parseToken(t string) (jose.JWT, *oidc.Identity, error) {
	// step: parse and return the token
	token, err := jose.ParseJWT(t)
	if err != nil {
		return jose.JWT{}, nil, err
	}

	// step: parse the claims
	claims, err := token.Claims()
	if err != nil {
		return jose.JWT{}, nil, err
	}

	// step: get the identity
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return jose.JWT{}, nil, err
	}

	return token, identity, nil
}
