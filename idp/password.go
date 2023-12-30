// Copyright © 2017 Aaron Donovan <amdonov@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"errors"
	"fmt"
	"github.com/chriskery/sso-idp/client"
	"net/http"
	"net/url"

	"github.com/chriskery/sso-idp/model"
	"github.com/golang/protobuf/proto"
)

// ErrInvalidPassword should be returned by PasswordValidator if
// the account doesn't exist or the password is incorrect.
var ErrInvalidPassword = errors.New("invalid login or password")

// PasswordValidator validates a user's password
type PasswordValidator interface {
	Validate(user, password string) (map[string][]string, error)
}

type ldapValidator struct {
	ldapClient *client.LdapClient
}

// UserPassword holds a user and their associated password.
type UserPassword struct {
	Name     string
	Password string
}

func (l *ldapValidator) Validate(user, password string) (map[string][]string, error) {
	return l.ldapClient.Authenticate(user, password)
}

// LdapValidator returns a sample validator that compares passwords to the bcrypt stored values for a user's password defined in the users key of the IDP's configuration
func LdapValidator() (PasswordValidator, error) {
	return &ldapValidator{ldapClient: client.NewLdapClient()}, nil
}

// DefaultPasswordLoginHandler is the default implementation for the password login handler. It can be used as is, wrapped in other handlers, or replaced completely.
func (i *IDP) DefaultPasswordLoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			i.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requestID := r.Form.Get("requestId")
		err := func() error {
			data, err := i.TempCache.Get(requestID)
			if err != nil {
				return err
			}
			req := &model.AuthnRequest{}
			if err = proto.Unmarshal(data, req); err != nil {
				return err
			}
			user, err := i.loginWithPasswordForm(r, req)
			if user != nil {
				return i.respond(req, user, w, r)
			}
			if err == ErrInvalidPassword {
				err = errors.New("invalid login or password. Please try again")
				return err
			}
			return nil
		}()
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/idp/static/login.html?requestId=%s&error=%s",
				url.QueryEscape(requestID), url.QueryEscape(err.Error())),
				http.StatusFound)
		}
	}
}
